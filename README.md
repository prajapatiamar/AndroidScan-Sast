# AndroidScan — local static & security analyzer for Android projects

A self-hosted (localhost-only) web dashboard that scans Android projects —
Kotlin, Java, JS/TS, Gradle files, manifests, and `.apk`s (decompiled
automatically) — for security vulnerabilities, reliability bugs, and
maintainability/reusability issues, then scores the result so you can see,
at a glance, whether it's release-ready.

Everything runs on your machine. Uploaded files are written to a temp folder
just long enough to scan, then deleted — nothing leaves your computer, and
nothing is persisted after the server stops. Binary files, build artifacts,
and anything over 2 MB are auto-excluded, so you can hand it a whole project
folder as-is.

## Run it

Requires Python 3.9+.

```bash
cd androidscan
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5050** in your browser. The server only binds to
127.0.0.1 (localhost), so it isn't reachable from your network or the internet.

## The dashboard

AndroidScan is a small multi-page app (all client-side, no page reloads):

- **Dashboard** — the main overview:
  - A circular **security score** gauge (0–100) with a letter grade (A–F),
    project file/SLOC/duration/last-scanned info, and a progress bar with a
    marker for the typical release-readiness bar.
  - A pass/fail **quality gate** banner explaining exactly why (modeled on
    SonarQube's default Quality Gate — no critical/high findings and score
    ≥ 80/100 — presented as an informational benchmark, not an official
    standard).
  - Four stat tiles — **Vulnerabilities, Bugs, Code Smells, Total
    Findings** — each with an ↑/↓ trend arrow computed against your
    *previous* scan of the same project, so you can see whether things are
    improving.
  - A severity donut, a "Top Issue Categories" bar chart (Code Smell /
    Security Vulnerability / Maintainability / Bug, using real counts — not
    fabricated categories), and a **Security Score Trend** line chart across
    every scan you've run this session.
  - "Files with Most Findings" and "Latest Findings" panels.
- **Scan Projects** — upload a folder, `.zip`, or `.apk` and run a scan.
- **Scan History** — every scan run this session, click any row to reload it
  onto the Dashboard/Findings views.
- **Findings** — the full, filterable (by severity *and* by type) list for
  the currently selected scan, with pagination for very large result sets.
- **Reports** — export any past scan (this session) as a standalone HTML or
  JSON report.
- **Security Rules** — every rule AndroidScan checks for, searchable and
  filterable by type, pulled live from `/api/rules`.
- **Settings** — the active limits (upload size, per-file size cap, excluded
  extensions/directories, rule count, release-readiness bar).

The sidebar's "Powered by" name/role/company and the quotes are driven by a
single `BRAND` object at the top of `static/app.js` — edit that to
personalize it.

## Using it

1. Go to **Scan Projects**, enter a project name (optional), then either:
   - Click **Choose folder** and select your project's root directory
     (works in Chrome/Edge — the browser preserves the folder structure), or
   - Click **Choose .zip / .apk** and pick a zipped export of the project, a
     zip containing a built `.apk`, or an `.apk` file directly, or
   - Drag a folder, `.zip`, or `.apk` onto the drop area.

   When an `.apk` is involved, AndroidScan decompiles it locally with
   [jadx](https://github.com/skylot/jadx) before scanning, so you get findings
   against the recovered Java source and the app's real
   `AndroidManifest.xml` — no separate decompile step needed. This needs a
   Java runtime (JRE 11+) on your machine, and the *first* APK scan needs
   internet access once to download jadx (cached under `tools/` after that).
   Decompiling a large APK can take a few minutes; the live progress bar
   parses jadx's own progress output while it works.

   Scanning a whole APK also pulls in every bundled third-party library
   (Retrofit, OkHttp, Firebase, payment/reader SDKs, etc.), which dilutes the
   signal with library-code noise. For a focused pass, prefer scanning just
   your own module's decompiled `sources/<your.package>` folder, or your own
   source directly.
2. Click **Run scan** — you're taken to the Dashboard, where a live progress
   bar shows the current phase, percentage, and file being processed.
3. Read the hero card and stat tiles for the headline picture, then use the
   charts, "Files with Most Findings," and "Latest Findings" to see where the
   problems are concentrated.
4. Click into **Findings** for the full list, filterable by severity and by
   type, each with a plain-English explanation and a fix recommendation.
5. Check **Scan History** to compare runs, and **Reports** to export an HTML
   or JSON copy of any of them.

## What it checks

Rules are organized the way SonarQube organizes issues, into three types
(`analyzer/rules.py`, 98 rules total — browsable live on the **Security
Rules** page). On top of severity and category, findings also carry **tags**
— the same orthogonal concept SonarQube uses — and three are tracked with
their own dashboard visibility, filters, and a distinct badge on the finding
itself:

- 🛠 **memory-leak** (11 rules) — static Context/Activity/View references,
  `Handler.postDelayed` with no visible cleanup, and a family of "opened but
  never closed" checks: `registerReceiver`/`requestLocationUpdates`/
  `registerListener` without their matching unregister/remove call anywhere
  in the file, an unclosed `Cursor`, an un-recycled `Bitmap`, an RxJava
  `.subscribe()` never disposed, a custom `CoroutineScope` never cancelled,
  and JS `addEventListener`/`setInterval` without a matching removal/clear.
- **performance** (4 rules) — string concatenation inside a loop, nested
  loops (O(n²) or worse), `runBlocking`, `Thread.sleep`.
- **runtime-error** (10 rules) — bare `.first()`/`.last()` (throws if
  empty), unsafe `.toInt()`/`.toLong()`/etc. (throws on bad input),
  `equals()` overridden without `hashCode()`, Kotlin `!!`/TypeScript `!`
  non-null assertions, loose equality, and a few others.

A scan's `tag_counts` and each finding's `tags` are exposed through the API
and shown as their own "Special focus areas" tiles on the Dashboard and in
exported reports, plus a dedicated filter row on the Findings page — so
these three categories don't get lost in the general Bug/Code Smell noise.

Separately, every rule also has a **type** (Vulnerability, Bug, or Code
Smell — the three categories the dashboard's main tiles are built around):

- **Vulnerability** — hardcoded secrets/API keys/AWS keys/PEM private
  keys/JWT signing keys (including in `.properties` files), credentials
  embedded in a URL, weak hashes (MD5/SHA-1), weak/ECB ciphers, hardcoded
  cipher keys/IVs, non-cryptographic or fixed-seed RNG, weak RSA key sizes,
  outdated TLS protocol versions, disabled TLS/hostname verification
  (Kotlin/Java and Node/axios), cleartext HTTP, SQL injection, OS/Node
  command injection, path traversal, zip-slip, unsafe deserialization,
  unsafe YAML deserialization (`yaml.load`), XXE-prone XML parser setup, JS
  XSS sinks (`innerHTML`, `eval`, `document.write`), reverse-tabnabbing
  (`target="_blank"` without `rel="noopener"`), open-redirect-style
  `window.location` assignment, insecure cookie flags, JWT `none`-algorithm
  bypass, risky WebView JavaScript/file-access bridges, world-readable file
  modes, sensitive data in logs/SharedPreferences/clipboard/`localStorage`/
  `sessionStorage`, wildcard CORS, RegExp built from a variable (ReDoS/
  bypass risk), Kotlin `TODO()` (throws at runtime if reached), a committed
  keystore/signing file, disabled ProGuard obfuscation, and
  `AndroidManifest.xml` checks (`debuggable`, `allowBackup`, `exported`,
  `usesCleartextTraffic`, exported providers with no permission).
- **Bug** — empty/overly-broad catch blocks (Kotlin/Java/JS/TS, including
  ES2019 optional catch binding), catching `Throwable`/`Error` (Kotlin/Java,
  worse than catching Exception), throwing a bare generic `Exception`,
  `equals()` overridden without `hashCode()` (breaks the Java/Kotlin
  contract), Kotlin `!!` and TypeScript `!` non-null assertions, Java `==`
  string/float comparisons, JS/TS loose equality (`==`/`!=` instead of
  `===`/`!==`), promise chains missing `.catch()`, empty function/arrow
  bodies, `GlobalScope`/unscoped coroutine launches, `runBlocking` outside
  main/tests, React lists rendered without a `key` prop (or keyed by array
  index), direct `this.state` mutation, `useEffect` with no dependency
  array, deprecated `finalize()`, `Thread.sleep()`, likely resource leaks
  (streams opened outside try-with-resources/`.use{}`), and deprecated
  `AsyncTask` usage.
- **Code smell** (includes reusability/maintainability, broken out
  separately on the dashboard) — wildcard imports, **unused imports**
  (JS/TS — flags any `import` whose local name is never referenced again in
  the file), TypeScript `any` usage, `@ts-ignore`/`@ts-nocheck`, Kotlin
  `@Suppress`/`lateinit`, raw (non-generic) Java collection types, a
  `Serializable` Java class with no `serialVersionUID`, `var` instead of
  `let`/`const`, leftover `debugger` statements, TODO/FIXME markers,
  redundant boolean comparisons, stray print/`printStackTrace`/
  `System.exit`/`console.log` calls, large commented-out blocks, hardcoded
  IP addresses, **duplicated blocks of code** (detected across the whole
  project via sliding-window hashing, not just per file), **large/"god"
  classes** (too many methods for one class), **long parameter lists** (via
  a balanced-paren parameter counter that now
  also recognizes JS `function`/arrow declarations, not just Kotlin/Java),
  and **repeated string literals** that should be a named constant.

The engine also computes per-file metrics (lines of code, function/class
counts, an approximate cyclomatic complexity, and nesting depth), which
surface as their own findings — **very long files**, **deeply nested code**,
and **high cyclomatic complexity** — and roll up into the security score.

File types scanned: `.kt`, `.kts`, `.java`, `.js`, `.jsx`, `.ts`, `.tsx`,
`.gradle`, `.properties`, `.pro`, and `.xml` (manifests). Everything else —
binaries, build artifacts (`.apk` output, `.aab`, `.jar`, images, fonts,
media, `.jks`/`.keystore`/`.p12`), and files over 2 MB — is auto-excluded
from content scanning; `build/`, `node_modules/`, `.git/`, `dist/`, `Pods/`,
and similar directories are skipped entirely. A `.jks`/`.keystore`/`.p12`
file isn't scanned as source, but its mere presence is itself flagged as a
finding.

## Extending it

Every rule is a plain dict with a regex, severity, category (`vulnerability`
/ `bug` / `code_smell`), CWE reference, description, and remediation text —
see `analyzer/rules.py`. Add a new dict to `VULNERABILITY_RULES`, `BUG_RULES`,
or `CODE_SMELL_RULES` and it's automatically picked up by the engine, the
dashboard's filters and tiles, the Security Rules page, and the exported
report — no other code changes needed.

## How it works, and its limits

This is a regex/heuristic-based analyzer, not a full Kotlin/Java/TypeScript
AST or data-flow analyzer the way SonarQube's own analyzers are — it's fast
to run and easy to extend, but it can produce false positives/negatives on
code written in unusual styles, and it can't trace whether a value actually
originates from untrusted input. Treat findings as leads to review, not
proof of a vulnerability. It aims to cover a broad, practical slice of the
same issue categories SonarQube reports (not a 1:1 rule-for-rule port — that
would need a real parser). For deeper Kotlin/Android coverage, pairing this
with a proper AST-based tool such as [detekt](https://detekt.dev/) and/or
SonarQube itself is a reasonable next step.

**On TypeScript/TSX specifically**: SonarQube's TS/JS analyzer runs on top
of the real TypeScript compiler, so it has actual type information, scope
resolution, and control-flow graphs. AndroidScan's TS/TSX rules (unused
imports, `any` usage, non-null assertions, loose equality, missing
`useEffect` deps/list `key`s, unhandled promises, and the shared
secrets/injection/duplication/complexity checks) are pattern-based
approximations of the same ideas, not a type-checker — they'll catch the
common real-world cases but can miss things that need actual type/scope
information (e.g. an import re-exported under a different name, or a type
error that only shows up after generic inference). If TS/TSX is your
primary codebase, pairing this with `tsc --noEmit` and/or SonarQube's real
TS analyzer for a release gate is a reasonable belt-and-suspenders setup.

Scanning is asynchronous (a background thread per scan) specifically so
large projects and big APKs don't block the browser or hit an HTTP timeout —
the frontend polls for progress and only fetches the full result once the
job reports done. Upload size is capped at 2 GB; if you need more, raise
`MAX_CONTENT_LENGTH` in `app.py`.

Scan history, past results, and reports all live in server memory for the
current session only — restarting `app.py` clears them. There's no database
and nothing is written outside the temporary scan working directory (which
is deleted right after each scan).

## Dependencies

Deliberately minimal:

- **Python**: Flask (the only entry in `requirements.txt`) plus the standard
  library (`re`, `hashlib`, `zipfile`, `subprocess`, `threading`,
  `urllib.request`, `os`, `tempfile`, `shutil`, `uuid`, `time`, `json`, `io`).
  No database, no task queue, no ORM.
- **JavaScript**: none — `static/app.js` is plain vanilla JS with no
  framework, no charting library, and no build step. The donut chart is a
  CSS `conic-gradient`; the gauge ring and trend line are hand-built inline
  SVG.
- **External tool**: [jadx](https://github.com/skylot/jadx), downloaded once
  from its GitHub release and invoked via `subprocess` when an `.apk` needs
  decompiling. Requires a JRE on your machine.
- **Fonts**: Google Fonts (IBM Plex Sans/Mono for UI, Sacramento for the
  signature-style branding text), loaded via CSS `@import`.

## Project layout

```
androidscan/
├── app.py                 Flask app: uploads, async scan jobs, progress, history, report/rule APIs
├── analyzer/
│   ├── rules.py            All 63 rule definitions (vulnerability / bug / code smell)
│   └── engine.py           Walks files, applies rules, computes metrics, scores, duplication detection
├── templates/
│   ├── index.html           Full dashboard app shell (sidebar, topbar, all pages)
│   └── report.html          Standalone exportable report
├── static/
│   ├── style.css            All styling, incl. BRAND signature font
│   └── app.js                All frontend logic + the BRAND config object
├── tools/                  jadx gets downloaded/cached here on first APK scan
└── requirements.txt
```



https://github.com/user-attachments/assets/425a5956-d3a2-47f3-90bb-f6f23752e987


