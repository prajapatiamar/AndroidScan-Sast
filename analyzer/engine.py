"""
Scanning engine: walks a directory of source code, applies the rule set from
rules.py, computes code metrics (including an approximate cyclomatic
complexity), and produces a single JSON-serializable result dict used by both
the web UI and the exported report.

Supports an optional progress callback so a caller (the Flask app) can run
this in a background thread and report live progress for large codebases.
"""
import os
import re
import uuid
import time
import hashlib

from .rules import ALL_RULES

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
CATEGORY_ORDER = ["vulnerability", "bug", "code_smell"]

SKIP_DIR_NAMES = {
    ".git", ".gradle", ".idea", "build", "out", "node_modules", ".venv",
    "__pycache__", "dist", ".next", ".expo", "vendor", "Pods", ".dart_tool",
}

# Extensions that get the full rule engine + (where applicable) code metrics.
CODE_EXTENSIONS = {
    ".kt", ".kts", ".java", ".js", ".jsx", ".ts", ".tsx",
    ".gradle", ".properties", ".pro",
}
MANIFEST_EXTENSIONS = {".xml"}
SCANNABLE_EXTENSIONS = CODE_EXTENSIONS | MANIFEST_EXTENSIONS

# Extensions that are never source and are auto-excluded outright — build
# artifacts, packaged/compressed apps, binaries, media, and signing material.
# (.apk is handled separately: decompiled with jadx rather than skipped.)
EXCLUDED_EXTENSIONS = {
    ".aab", ".ipa", ".bundle", ".jar", ".aar", ".zip", ".tar", ".gz", ".tgz",
    ".7z", ".rar", ".dex", ".so", ".dll", ".exe", ".class", ".o", ".a",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tiff",
    ".mp4", ".mp3", ".wav", ".mov", ".avi", ".webm",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".pdf", ".psd", ".sketch",
    ".db", ".sqlite", ".sqlite3", ".realm",
    ".lock",
}
# Signing/credential material: never scanned as source, but its mere presence
# in the tree is itself worth flagging.
CREDENTIAL_FILE_EXTENSIONS = {".jks", ".keystore", ".p12", ".pfx"}

DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB — larger text files are auto-skipped

FUN_RE = re.compile(r'\bfun\s+[A-Za-z_<>,\s]*\w+\s*\(')
JAVA_METHOD_RE = re.compile(
    r'\b(public|private|protected)\s+(static\s+)?[\w<>\[\],. ]+?\s+\w+\s*\([^;{]*\)\s*\{'
)
JS_FUNCTION_RE = re.compile(
    r'\bfunction\s+\w+\s*\(|\bfunction\s*\(|=>\s*\{?|\b\w+\s*\([^)]*\)\s*\{(?=[^{}]*?\breturn\b)'
)
CLASS_RE = re.compile(r'\b(class|interface|object|enum class)\s+\w+')
BLANK_OR_COMMENT_RE = re.compile(r'^\s*(//.*)?$')

# Approximate cyclomatic-complexity signal: count decision points. Not a real
# per-function AST-based complexity, but a reasonable file-level proxy.
COMPLEXITY_TOKEN_RE = re.compile(
    r'\bif\s*\(|\belse\s+if\s*\(|\bfor\s*\(|\bwhile\s*\(|\bcatch\s*\(|\bcase\s+|'
    r'\bwhen\s*[\({]|&&|\|\||\?\s*:'
)

HIGH_COMPLEXITY_PER_FUNCTION_THRESHOLD = 12
DEEP_NESTING_THRESHOLD = 7  # ~28 spaces of indent
LARGE_CLASS_FUNCTION_THRESHOLD = 25
LONG_PARAMETER_THRESHOLD = 6
DUPLICATE_BLOCK_WINDOW = 6          # lines per duplication-check window
DUPLICATE_BLOCK_MIN_CHARS = 60      # ignore trivial/near-empty windows
DUPLICATE_BLOCK_MAX_GROUP_SIZE = 200  # a "duplicate" repeated this often is boilerplate, not a real smell
DUPLICATE_BLOCK_MAX_FINDINGS = 60    # cap findings shown; still counted toward duplication %
STRING_LITERAL_RE = re.compile(r'"([^"\n]{4,80})"')
STRING_LITERAL_MIN_REPEATS = 4
IMPORT_PACKAGE_RE = re.compile(r'^\s*(import|package)\s')
PARAM_LIST_START_RE = re.compile(
    r'\bfun\s+\w+\s*(<[^>]*>)?\s*\(|'
    r'\b(public|private|protected)\s+(static\s+)?[\w<>\[\],. ]+?\s+\w+\s*\(|'
    r'\bfunction\s*\w*\s*\(|'
    r'\b(const|let|var)\s+\w+\s*=\s*(async\s+)?\('
)

# Quality-gate reference point, in the spirit of SonarQube's default Quality
# Gate (which requires a Security/Reliability Rating of A on new code — i.e.
# no unresolved Blocker/Critical issues). This is an informational baseline
# we compute the same way for every scan, not an official external standard.
QUALITY_GATE_MIN_SCORE = 80
QUALITY_GATE_MAX_CRITICAL = 0
QUALITY_GATE_MAX_HIGH = 0


IMPORT_STMT_RE = re.compile(r'^\s*import\s+(type\s+)?([^;\n]+?)\s+from\s+[\'"][^\'"]+[\'"]\s*;?', re.MULTILINE)


def _unused_js_imports(text):
    """Best-effort unused-import detector for JS/TS: parses `import ... from '...'`
    statements, extracts the local identifier(s) each one introduces, and flags
    any that never appear again in the rest of the file. Heuristic, not a real
    scope/AST analysis (e.g. re-exports or JSX-only usage in unusual patterns
    could be missed), but catches the common case cheaply."""
    identifiers = []
    import_spans = []
    for m in IMPORT_STMT_RE.finditer(text):
        clause = m.group(2)
        line_no = _line_number(text, m.start())
        import_spans.append((m.start(), m.end()))

        ns_match = re.search(r'\*\s+as\s+(\w+)', clause)
        if ns_match:
            identifiers.append((ns_match.group(1), line_no))
            continue

        brace_match = re.search(r'\{([^}]*)\}', clause)
        default_part = clause[:brace_match.start()] if brace_match else clause
        default_name = default_part.strip().rstrip(',').strip()
        if default_name and re.match(r'^[A-Za-z_$][\w$]*$', default_name):
            identifiers.append((default_name, line_no))

        if brace_match:
            for spec in brace_match.group(1).split(','):
                spec = re.sub(r'^\s*type\s+', '', spec.strip())
                local = spec.split(' as ')[-1].strip() if ' as ' in spec else spec.strip()
                if re.match(r'^[A-Za-z_$][\w$]*$', local):
                    identifiers.append((local, line_no))

    if not identifiers:
        return []

    masked = text
    for start, end in import_spans:
        masked = masked[:start] + (" " * (end - start)) + masked[end:]

    results = []
    seen = set()
    for name, line_no in identifiers:
        if name in seen:
            continue
        seen.add(name)
        if name == "React":
            continue  # default-imported for JSX scope under the classic transform; never referenced by name
        if not re.search(r'\b' + re.escape(name) + r'\b', masked):
            results.append((name, line_no))
    return results


EQUALS_OVERRIDE_RE = re.compile(
    r'\bpublic\s+boolean\s+equals\s*\(\s*Object\s+\w+\s*\)|'  # Java
    r'\boverride\s+fun\s+equals\s*\(\s*\w+\s*:\s*Any\?\s*\)'   # Kotlin
)
HASHCODE_OVERRIDE_RE = re.compile(
    r'\bpublic\s+int\s+hashCode\s*\(\s*\)|\boverride\s+fun\s+hashCode\s*\('
)
SERIALIZABLE_CLASS_RE = re.compile(r'\bimplements\b[^{]*\bSerializable\b')
SERIAL_VERSION_UID_RE = re.compile(r'\bserialVersionUID\b')

# "Opened but seemingly never released" resource-leak checks: if the open
# pattern appears anywhere in the file and the matching close pattern never
# does, flag it. A per-file heuristic (not real lifetime/scope tracking), but
# it catches the common real case of "we register/allocate this and there's
# no cleanup call anywhere in the file at all."
UNPAIRED_RESOURCE_CHECKS = [
    dict(
        id="unregistered-broadcast-receiver", title="BroadcastReceiver registered but never unregistered",
        open_re=re.compile(r'\bregisterReceiver\s*\('), close_re=re.compile(r'\bunregisterReceiver\s*\('),
        file_types=(".kt", ".java"), severity="medium", cwe="CWE-401",
        description="A receiver registered with registerReceiver() keeps the registering "
                     "component (and everything it references) reachable until it's unregistered — "
                     "with no unregisterReceiver() call anywhere in this file, that may never happen.",
        recommendation="Unregister in the matching lifecycle callback (e.g. onPause()/onStop() to match "
                        "onResume()/onStart()), or use a lifecycle-aware registration API.",
    ),
    dict(
        id="unregistered-location-listener", title="Location updates requested but never removed",
        open_re=re.compile(r'\brequestLocationUpdates\s*\('), close_re=re.compile(r'\bremoveUpdates\s*\('),
        file_types=(".kt", ".java"), severity="medium", cwe="CWE-401",
        description="requestLocationUpdates() keeps delivering callbacks (and keeping the listener's "
                     "owner alive) until removeUpdates() is called — no matching call was found in this "
                     "file.",
        recommendation="Call removeUpdates() in the matching lifecycle callback, typically onPause()/"
                        "onStop()/onDestroy().",
    ),
    dict(
        id="unregistered-sensor-listener", title="Sensor listener registered but never unregistered",
        open_re=re.compile(r'\bregisterListener\s*\('), close_re=re.compile(r'\bunregisterListener\s*\('),
        file_types=(".kt", ".java"), severity="medium", cwe="CWE-401",
        description="A SensorManager listener keeps receiving events (and keeping its owner alive) "
                     "until unregisterListener() is called — no matching call was found in this file.",
        recommendation="Unregister in onPause()/onStop() to match where you registered.",
    ),
    dict(
        id="unclosed-cursor", title="Cursor opened but never closed",
        open_re=re.compile(r'\.rawQuery\s*\(|\bquery\s*\('), close_re=re.compile(r'\.close\(\)|\.use\s*\{'),
        file_types=(".kt", ".java"), severity="medium", cwe="CWE-772",
        description="A Cursor holds a live connection to the underlying database/content provider until "
                     "closed — no .close() (or Kotlin .use {}) was found anywhere in this file.",
        recommendation="Wrap cursor usage in Kotlin's .use { } or a try/finally that calls close(), so "
                        "it's released even if an exception is thrown.",
    ),
    dict(
        id="bitmap-not-recycled", title="Bitmap decoded but never recycled",
        open_re=re.compile(r'BitmapFactory\.decode\w*\s*\('), close_re=re.compile(r'\.recycle\(\)'),
        file_types=(".kt", ".java"), severity="low", cwe="CWE-401",
        description="Bitmaps hold large native (off-heap) memory buffers. On older Android versions "
                     "especially, failing to recycle() a Bitmap you're done with can exhaust native "
                     "memory well before the Java heap looks full.",
        recommendation="Call recycle() once you're certain nothing still references this Bitmap (or rely "
                        "on a library like Glide/Coil that manages the lifecycle for you).",
    ),
    dict(
        id="rxjava-subscription-not-disposed", title="RxJava subscription never disposed",
        open_re=re.compile(r'\.subscribe\s*[\(\{]'),
        close_re=re.compile(r'\.dispose\(\)|CompositeDisposable|\.addTo\('),
        file_types=(".kt", ".java"), severity="medium", cwe="CWE-401",
        description="An RxJava subscription keeps its subscriber (commonly an Activity/Fragment/"
                     "ViewModel) alive for as long as the source keeps emitting — no dispose() or "
                     "CompositeDisposable usage was found in this file.",
        recommendation="Add the subscription to a CompositeDisposable and dispose() it in onDestroy()/"
                        "onCleared(), or use an Android-lifecycle-scoped RxJava binding.",
    ),
    dict(
        id="coroutine-scope-not-cancelled", title="Custom CoroutineScope created but never cancelled",
        open_re=re.compile(r'=\s*CoroutineScope\s*\('), close_re=re.compile(r'\.cancel\(\)'),
        file_types=(".kt",), severity="medium", cwe="CWE-401",
        description="A manually created CoroutineScope keeps every coroutine launched on it (and "
                     "whatever they capture) alive until cancel() is called — no cancel() was found in "
                     "this file.",
        recommendation="Cancel the scope in onCleared()/onDestroy(), or prefer viewModelScope/"
                        "lifecycleScope, which are cancelled for you automatically.",
    ),
    dict(
        id="js-addeventlistener-no-remove", title="Event listener added but never removed",
        open_re=re.compile(r'\.addEventListener\s*\('), close_re=re.compile(r'\.removeEventListener\s*\('),
        file_types=(".js", ".jsx", ".ts", ".tsx"), severity="low", cwe="CWE-401",
        description="An event listener keeps its callback (and whatever closure state it captures) alive "
                     "for as long as the target exists — with no removeEventListener() in this file, it "
                     "may never be released, which adds up across repeated mounts (e.g. a React "
                     "component that re-mounts).",
        recommendation="Remove the listener when it's no longer needed — e.g. in a React "
                        "useEffect cleanup function or a componentWillUnmount.",
    ),
    dict(
        id="js-setinterval-no-clear", title="setInterval started but never cleared",
        open_re=re.compile(r'\bsetInterval\s*\('), close_re=re.compile(r'\bclearInterval\s*\('),
        file_types=(".js", ".jsx", ".ts", ".tsx"), severity="medium", cwe="CWE-401",
        description="setInterval keeps firing (and keeping its callback's closure alive) until "
                     "clearInterval() is called — no matching clearInterval() was found in this file.",
        recommendation="Store the interval id and clearInterval() it on cleanup (component unmount, "
                        "page navigation, etc.).",
    ),
]
UNPAIRED_RESOURCE_CHECKS_BY_EXT = {}
for _check in UNPAIRED_RESOURCE_CHECKS:
    for _ext in _check["file_types"]:
        UNPAIRED_RESOURCE_CHECKS_BY_EXT.setdefault(_ext, []).append(_check)


def _collect_files(root_dir, max_file_size):
    """Single directory walk: returns (scannable_files, skipped_binary_count,
    skipped_large_count, credential_file_paths)."""
    scannable = []
    skipped_binary = 0
    skipped_large = 0
    credential_files = []

    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES and not d.startswith(".")]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            full_path = os.path.join(dirpath, fname)

            if ext in CREDENTIAL_FILE_EXTENSIONS:
                credential_files.append(os.path.relpath(full_path, root_dir))
                continue
            if ext == ".apk":
                continue  # handled separately (decompiled), not walked as plain source
            if ext in EXCLUDED_EXTENSIONS:
                skipped_binary += 1
                continue
            if ext not in SCANNABLE_EXTENSIONS:
                continue

            try:
                if os.path.getsize(full_path) > max_file_size:
                    skipped_large += 1
                    continue
            except OSError:
                continue

            scannable.append((full_path, ext))

    return scannable, skipped_binary, skipped_large, credential_files


def _line_number(text, offset):
    return text.count("\n", 0, offset) + 1


def _snippet(lines, line_no, context=1):
    start = max(0, line_no - 1 - context)
    end = min(len(lines), line_no + context)
    out = []
    for i in range(start, end):
        marker = ">" if (i + 1) == line_no else " "
        out.append(f"{marker} {i+1:>5} | {lines[i]}")
    return "\n".join(out)


def _file_metrics(text, ext):
    lines = text.splitlines()
    loc = len(lines)
    blank_or_comment = sum(1 for l in lines if BLANK_OR_COMMENT_RE.match(l))
    sloc = loc - blank_or_comment
    if ext in (".kt", ".kts"):
        functions = len(FUN_RE.findall(text))
    elif ext == ".java":
        functions = len(JAVA_METHOD_RE.findall(text))
    elif ext in (".js", ".jsx", ".ts", ".tsx"):
        functions = len(JS_FUNCTION_RE.findall(text))
    else:
        functions = 0
    classes = len(CLASS_RE.findall(text))
    complexity = len(COMPLEXITY_TOKEN_RE.findall(text))
    max_indent = 0
    for l in lines:
        stripped = l.lstrip(" ")
        indent_spaces = len(l) - len(stripped)
        depth = indent_spaces // 4  # 4-space indent convention; approximate nesting depth.
        if stripped:
            max_indent = max(max_indent, depth)
    return dict(
        loc=loc, sloc=sloc, functions=functions, classes=classes,
        complexity=complexity, max_nesting=max_indent,
    )


def _count_long_parameter_lists(text):
    """Finds `fun name(...)` / Java method signatures and counts top-level commas
    inside the balanced parens to approximate parameter count. Returns a list of
    (line_no, param_count) for signatures over the threshold."""
    results = []
    for m in PARAM_LIST_START_RE.finditer(text):
        open_paren = text.find("(", m.end() - 1)
        if open_paren == -1:
            continue
        depth = 0
        i = open_paren
        commas_at_top = 0
        in_string = False
        str_char = ""
        n = len(text)
        while i < n:
            ch = text[i]
            if in_string:
                if ch == "\\":
                    i += 1
                elif ch == str_char:
                    in_string = False
            elif ch in ("'", '"'):
                in_string = True
                str_char = ch
            elif ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
                if depth == 0 and ch == ")":
                    break
            elif ch == "," and depth == 1:
                commas_at_top += 1
            i += 1
        else:
            continue  # never closed; skip
        param_count = commas_at_top + 1 if i > open_paren + 1 else 0
        if param_count > LONG_PARAMETER_THRESHOLD:
            results.append((_line_number(text, open_paren), param_count))
    return results


def _duplicate_string_literals(text):
    """Returns [(literal, count, first_line_no), ...] for string literals that
    repeat often enough in this file to suggest they should be a named constant."""
    counts = {}
    first_line = {}
    for m in STRING_LITERAL_RE.finditer(text):
        lit = m.group(1)
        if not lit.strip() or lit.strip() in ("true", "false", "null", "TODO"):
            continue
        if lit.startswith("http") or lit.startswith("/") or "%" in lit or "{" in lit:
            continue  # URLs/paths/format strings are commonly repeated legitimately
        counts[lit] = counts.get(lit, 0) + 1
        first_line.setdefault(lit, _line_number(text, m.start()))
    return [
        (lit, c, first_line[lit]) for lit, c in counts.items()
        if c >= STRING_LITERAL_MIN_REPEATS
    ]


def _duplicate_block_windows(lines):
    """Yields (hash_key, filtered_index, orig_line_no) for every sliding
    DUPLICATE_BLOCK_WINDOW-line window in this file (stride 1), skipping
    import/blank lines. Sliding (not chunked) so duplicates are found
    regardless of where they happen to start in the file."""
    filtered = [
        (i + 1, ln.strip()) for i, ln in enumerate(lines)
        if ln.strip() and not BLANK_OR_COMMENT_RE.match(ln) and not IMPORT_PACKAGE_RE.match(ln)
    ]
    for start in range(0, len(filtered) - DUPLICATE_BLOCK_WINDOW + 1):
        chunk = filtered[start:start + DUPLICATE_BLOCK_WINDOW]
        text = "\n".join(normalized for _, normalized in chunk)
        if len(text) < DUPLICATE_BLOCK_MIN_CHARS:
            continue
        key = hashlib.md5(text.encode("utf-8", "replace")).hexdigest()
        yield key, start, chunk[0][0]


def _merge_duplicate_pairs(pair_locations):
    """pair_locations: {(fileA, fileB): [(idxA, idxB, lineA, lineB), ...]} (fileA<fileB).
    Merges runs where both filtered-indices advance by exactly 1 together — the
    signature of one contiguous duplicated block sliding through the window —
    into single spans: [(fileA, fileB, start_lineA, start_lineB, span_len), ...]."""
    spans = []
    for (file_a, file_b), pts in pair_locations.items():
        pts = sorted(set(pts))
        run_start = None
        prev = None
        run_len_windows = 0
        for idx_a, idx_b, line_a, line_b in pts:
            if prev is not None and idx_a == prev[0] + 1 and idx_b == prev[1] + 1:
                prev = (idx_a, idx_b, line_a, line_b)
                run_len_windows += 1
                continue
            if run_start is not None:
                spans.append((file_a, file_b, run_start[2], run_start[3], run_len_windows - 1 + DUPLICATE_BLOCK_WINDOW))
            run_start = (idx_a, idx_b, line_a, line_b)
            prev = run_start
            run_len_windows = 1
        if run_start is not None:
            spans.append((file_a, file_b, run_start[2], run_start[3], run_len_windows - 1 + DUPLICATE_BLOCK_WINDOW))
    return spans


def scan_project(root_dir, project_name="project", progress_cb=None, max_file_size=DEFAULT_MAX_FILE_SIZE):
    """
    progress_cb(current, total, phase, current_file) is called periodically
    (roughly once per file) if provided. Exceptions from progress_cb are
    swallowed so a UI hiccup can never break the scan itself.
    """
    findings = []
    files_scanned = []
    totals = {"loc": 0, "sloc": 0, "functions": 0, "classes": 0, "complexity": 0}
    per_file_metrics = []
    duplicate_block_locations = {}  # hash -> [(rel_path, line_no), ...]

    source_files, skipped_binary, skipped_large, credential_files = _collect_files(root_dir, max_file_size)
    total_files = len(source_files)

    for cred_path in credential_files:
        findings.append(dict(
            id="embedded-credential-file", title="Signing/keystore file committed to the project",
            severity="high", category="vulnerability", cwe="CWE-798", tags=[], file=cred_path, line=1,
            description="A keystore/certificate file (.jks/.keystore/.p12/.pfx) is present in the project. "
                         "If this is a real signing key (not a throwaway debug key) and the project is in "
                         "version control, anyone with repo access has the signing material.",
            recommendation="Keep production signing keys out of the repository; use a secrets manager or "
                            "CI secret storage, and rotate the key if it's already been committed.",
            snippet="",
        ))

    for idx, (path, ext) in enumerate(source_files):
        rel_path = os.path.relpath(path, root_dir)

        if progress_cb and (idx % 25 == 0 or idx == total_files - 1):
            try:
                progress_cb(idx + 1, total_files, "scanning", rel_path)
            except Exception:
                pass

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue

        files_scanned.append(rel_path)
        lines = text.splitlines()

        if ext in CODE_EXTENSIONS:
            m = _file_metrics(text, ext)
            per_file_metrics.append(dict(file=rel_path, **m))
            for k in totals:
                totals[k] += m[k]

            if m["loc"] > 500:
                findings.append(dict(
                    id="long-file", title="Very long file", severity="low", category="code_smell",
                    cwe=None, tags=[], file=rel_path, line=1,
                    description=f"This file is {m['loc']} lines long, which makes it harder to review and maintain.",
                    recommendation="Consider splitting into smaller, single-responsibility files.",
                    snippet="",
                ))
            if m["max_nesting"] >= DEEP_NESTING_THRESHOLD:
                findings.append(dict(
                    id="deep-nesting", title="Deeply nested code", severity="medium", category="code_smell",
                    cwe=None, tags=[], file=rel_path, line=1,
                    description=f"This file reaches roughly {m['max_nesting']} levels of nesting, which is "
                                 "hard to follow and easy to introduce logic bugs into.",
                    recommendation="Extract nested blocks into separate functions, use early returns/guard "
                                    "clauses, or flatten conditionals.",
                    snippet="",
                ))
            if m["functions"] > 0 and (m["complexity"] / m["functions"]) > HIGH_COMPLEXITY_PER_FUNCTION_THRESHOLD:
                findings.append(dict(
                    id="high-complexity-file", title="High cyclomatic complexity", severity="medium",
                    category="code_smell", cwe=None, tags=["performance"], file=rel_path, line=1,
                    description=f"This file averages roughly {m['complexity']/m['functions']:.0f} decision "
                                 f"points per function ({m['complexity']} total across {m['functions']} "
                                 "functions), suggesting some functions are doing too much.",
                    recommendation="Break large functions into smaller ones with single responsibilities; "
                                    "consider table-driven logic instead of long if/when chains.",
                    snippet="",
                ))
            if m["classes"] == 1 and m["functions"] >= LARGE_CLASS_FUNCTION_THRESHOLD:
                findings.append(dict(
                    id="large-class", title="Large class (too many responsibilities)", severity="medium",
                    category="code_smell", cwe=None, tags=[], file=rel_path, line=1,
                    description=f"This file's single class has roughly {m['functions']} functions/methods, "
                                 "which usually means it's taken on more than one responsibility and is "
                                 "hard to reuse or test in isolation.",
                    recommendation="Split by responsibility (e.g. extract a repository/mapper/validator) so "
                                    "each piece can be understood and reused on its own.",
                    snippet="",
                ))

            if ext in (".java", ".kt"):
                if EQUALS_OVERRIDE_RE.search(text) and not HASHCODE_OVERRIDE_RE.search(text):
                    findings.append(dict(
                        id="equals-without-hashcode", title="equals() overridden without hashCode()",
                        severity="medium", category="bug", cwe="CWE-581", tags=["runtime-error"], file=rel_path, line=1,
                        description="Overriding equals() without also overriding hashCode() breaks the "
                                     "contract that equal objects must have equal hash codes — instances "
                                     "can silently disappear from HashSet/HashMap lookups.",
                        recommendation="Override hashCode() consistently with equals() (most IDEs can "
                                        "generate both together).",
                        snippet="",
                    ))
                if ext == ".java" and SERIALIZABLE_CLASS_RE.search(text) and not SERIAL_VERSION_UID_RE.search(text):
                    findings.append(dict(
                        id="missing-serialversionuid", title="Serializable class without serialVersionUID",
                        severity="low", category="code_smell", cwe="CWE-1104", tags=[], file=rel_path, line=1,
                        description="Without an explicit serialVersionUID, the JVM derives one from class "
                                     "details that can change between compilations/JDK versions, silently "
                                     "breaking deserialization of previously-saved data.",
                        recommendation="Add a private static final long serialVersionUID = 1L; field (and "
                                        "bump it deliberately when the class's serialized shape changes).",
                        snippet="",
                    ))

            dup_literals = sorted(_duplicate_string_literals(text), key=lambda t: t[1], reverse=True)[:5]
            for lit, count, first_line in dup_literals:
                findings.append(dict(
                    id="duplicate-string-literal", title="Repeated string literal", severity="info",
                    category="code_smell", cwe=None, tags=[], file=rel_path, line=first_line,
                    description=f'The literal "{lit}" appears {count} times in this file as an inline '
                                 "string, instead of a single named constant.",
                    recommendation="Extract it to a named constant (or a resource/string table) so it's "
                                    "defined once and can be reused and updated safely.",
                    snippet="",
                ))

            for line_no, param_count in _count_long_parameter_lists(text):
                findings.append(dict(
                    id="long-parameter-list", title="Long parameter list", severity="low",
                    category="code_smell", cwe=None, tags=[], file=rel_path, line=line_no,
                    description=f"This function/method takes {param_count} parameters, which makes it hard "
                                 "to call correctly, test, and reuse.",
                    recommendation="Group related parameters into a data class/object, or split the "
                                    "function into smaller ones.",
                    snippet=_snippet(lines, line_no),
                ))

            for dup_hash, filt_idx, first_line in _duplicate_block_windows(lines):
                duplicate_block_locations.setdefault(dup_hash, []).append((rel_path, filt_idx, first_line))

            if ext in (".js", ".jsx", ".ts", ".tsx"):
                for name, line_no in _unused_js_imports(text):
                    findings.append(dict(
                        id="unused-import", title="Unused import", severity="info",
                        category="code_smell", cwe=None, tags=[], file=rel_path, line=line_no,
                        description=f"'{name}' is imported but never referenced anywhere else in this file.",
                        recommendation="Remove the unused import, or the export it came from if nothing "
                                        "else needs it either.",
                        snippet=_snippet(lines, line_no),
                    ))

        for rule in ALL_RULES:
            if ext not in rule["file_types"]:
                continue
            for match in rule["pattern"].finditer(text):
                line_no = _line_number(text, match.start())
                findings.append(dict(
                    id=rule["id"],
                    title=rule["title"],
                    severity=rule["severity"],
                    category=rule["category"],
                    cwe=rule["cwe"],
                    tags=rule.get("tags", []),
                    file=rel_path,
                    line=line_no,
                    description=rule["description"],
                    recommendation=rule["recommendation"],
                    snippet=_snippet(lines, line_no),
                ))

        if ext in UNPAIRED_RESOURCE_CHECKS_BY_EXT:
            for check in UNPAIRED_RESOURCE_CHECKS_BY_EXT[ext]:
                m = check["open_re"].search(text)
                if m and not check["close_re"].search(text):
                    line_no = _line_number(text, m.start())
                    findings.append(dict(
                        id=check["id"], title=check["title"], severity=check["severity"],
                        category="bug", cwe=check.get("cwe"), tags=["memory-leak"],
                        file=rel_path, line=line_no,
                        description=check["description"], recommendation=check["recommendation"],
                        snippet=_snippet(lines, line_no),
                    ))

    if progress_cb:
        try:
            progress_cb(total_files, total_files, "finalizing", "")
        except Exception:
            pass

    duplicate_groups = [
        (h, locs) for h, locs in duplicate_block_locations.items()
        if 2 <= len(locs) <= DUPLICATE_BLOCK_MAX_GROUP_SIZE
    ]
    duplicated_line_estimate = 0
    pair_locations = {}
    for _, locs in duplicate_groups:
        # Pair up occurrences within this hash group (usually exactly 2; for
        # larger groups, pair each with the first so widely-shared boilerplate
        # still contributes to the duplication % without exploding pair counts).
        anchor = locs[0]
        for other in locs[1:]:
            (file_a, idx_a, line_a), (file_b, idx_b, line_b) = sorted([anchor, other])
            pair_locations.setdefault((file_a, file_b), []).append((idx_a, idx_b, line_a, line_b))

    duplicate_spans = _merge_duplicate_pairs(pair_locations)
    duplicate_spans.sort(key=lambda s: s[4], reverse=True)
    duplicated_line_estimate = sum(s[4] for s in duplicate_spans)

    for file_a, file_b, line_a, line_b, span_len in duplicate_spans[:DUPLICATE_BLOCK_MAX_FINDINGS]:
        findings.append(dict(
            id="duplicate-code-block", title="Duplicated block of code", severity="medium",
            category="code_smell", cwe=None, tags=[], file=file_a, line=line_a,
            description=f"This ~{span_len}-line block also appears at {file_b}:{line_b}. Duplicated logic "
                         "means a bug fix or change made in one copy is easy to miss in the other.",
            recommendation="Extract the shared logic into a single function/method (or a shared "
                            "base class/utility) and call it from both locations instead of copy-pasting.",
            snippet="",
        ))

    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["file"], f["line"]))

    TRACKED_TAGS = ["memory-leak", "performance", "runtime-error"]
    severity_counts = {s: 0 for s in SEVERITY_ORDER}
    category_counts = {c: 0 for c in CATEGORY_ORDER}
    tag_counts = {t: 0 for t in TRACKED_TAGS}
    for f in findings:
        severity_counts[f["severity"]] += 1
        category_counts[f["category"]] += 1
        for t in f.get("tags", []):
            if t in tag_counts:
                tag_counts[t] += 1

    risk_score = sum(SEVERITY_WEIGHT[f["severity"]] for f in findings)

    # Health grade + normalized 0-100 security score, both derived from the same
    # severity-weighted findings-per-100-SLOC density so they stay consistent.
    sloc = max(totals["sloc"], 1)
    density = (risk_score / sloc) * 100
    if density == 0:
        grade = "A"
    elif density < 1:
        grade = "B"
    elif density < 3:
        grade = "C"
    elif density < 7:
        grade = "D"
    else:
        grade = "F"

    security_score = max(0, min(100, round(100 - density * 12)))
    quality_gate_passed = (
        severity_counts["critical"] <= QUALITY_GATE_MAX_CRITICAL
        and severity_counts["high"] <= QUALITY_GATE_MAX_HIGH
        and security_score >= QUALITY_GATE_MIN_SCORE
    )
    if quality_gate_passed:
        quality_gate_reason = "No critical/high findings, and overall issue density is within the typical release-readiness bar."
    else:
        reasons = []
        if severity_counts["critical"] > QUALITY_GATE_MAX_CRITICAL:
            reasons.append(f"{severity_counts['critical']} critical finding(s)")
        if severity_counts["high"] > QUALITY_GATE_MAX_HIGH:
            reasons.append(f"{severity_counts['high']} high finding(s)")
        if security_score < QUALITY_GATE_MIN_SCORE:
            reasons.append(f"security score {security_score}/100 is below the {QUALITY_GATE_MIN_SCORE}/100 bar")
        quality_gate_reason = "Not release-ready: " + ", ".join(reasons) + "."

    findings_by_file = {}
    for f in findings:
        findings_by_file.setdefault(f["file"], []).append(f)
    top_files = sorted(
        findings_by_file.items(),
        key=lambda kv: sum(SEVERITY_WEIGHT[f["severity"]] for f in kv[1]),
        reverse=True,
    )[:10]
    top_files = [dict(file=k, count=len(v), score=sum(SEVERITY_WEIGHT[f["severity"]] for f in v)) for k, v in top_files]

    duplication_percentage = round(min(100.0, (duplicated_line_estimate / sloc) * 100), 1)
    maintainability_ids = {"duplicate-code-block", "duplicate-string-literal", "large-class", "long-parameter-list"}
    maintainability_findings = [f for f in findings if f["id"] in maintainability_ids]
    maintainability_counts = {
        "duplicate-code-block": sum(1 for f in findings if f["id"] == "duplicate-code-block"),
        "duplicate-string-literal": sum(1 for f in findings if f["id"] == "duplicate-string-literal"),
        "large-class": sum(1 for f in findings if f["id"] == "large-class"),
        "long-parameter-list": sum(1 for f in findings if f["id"] == "long-parameter-list"),
    }

    # A slightly more granular breakdown for the "Top issue categories" chart:
    # split code_smell into "maintainability" (the reusability-focused checks
    # above) vs everything else still labeled code_smell.
    display_category_counts = {
        "vulnerability": category_counts["vulnerability"],
        "bug": category_counts["bug"],
        "maintainability": len(maintainability_findings),
        "code_smell": category_counts["code_smell"] - len(maintainability_findings),
    }

    return dict(
        scan_id=str(uuid.uuid4()),
        project_name=project_name,
        generated_at=time.strftime("%Y-%m-%d %H:%M:%S"),
        files_scanned=len(files_scanned),
        skipped_binary_files=skipped_binary,
        skipped_large_files=skipped_large,
        credential_files_found=credential_files,
        totals=totals,
        severity_counts=severity_counts,
        category_counts=category_counts,
        tag_counts=tag_counts,
        display_category_counts=display_category_counts,
        risk_score=risk_score,
        grade=grade,
        security_score=security_score,
        security_score_max=100,
        quality_gate_passed=quality_gate_passed,
        quality_gate_reason=quality_gate_reason,
        quality_gate_min_score=QUALITY_GATE_MIN_SCORE,
        duplication_percentage=duplication_percentage,
        maintainability_counts=maintainability_counts,
        maintainability_findings_count=len(maintainability_findings),
        findings=findings,
        top_files=top_files,
        per_file_metrics=per_file_metrics,
    )
