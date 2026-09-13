"""
Rule definitions for the Kotlin/Java static analyzer.

Rules are organized the way SonarQube organizes issues, into three types:
  - "vulnerability"  security-relevant weaknesses (maps to CWE where possible)
  - "bug"            patterns that are likely to cause incorrect behavior or crashes
  - "code_smell"     maintainability issues that don't break anything but add risk/cost

Each rule is a dict:
  id           unique string id
  title        short human title
  severity     critical | high | medium | low | info
  category     vulnerability | bug | code_smell
  cwe          CWE reference string (or None)
  pattern      compiled regex applied against full file text
  file_types   list of extensions this rule applies to, e.g. ['.kt', '.kts']
  description  what the finding means
  recommendation  what to do about it

This is a regex/heuristic engine, not a full AST/data-flow analyzer like SonarQube's
own Kotlin/Java analyzers. It covers a broad, practical slice of the same issue
categories (hardcoded secrets, weak crypto, injection, unsafe IPC/WebView use,
resource handling, exception handling, dead/smelly code) but can't reason about
data flow, so treat findings as leads to review rather than proof of a bug.
"""
import re

KT = ['.kt', '.kts']
JAVA = ['.java']
KTJ = ['.kt', '.kts', '.java']  # Kotlin + decompiled Java (from an APK) share most Android/JVM API patterns
JS_TS = ['.js', '.jsx', '.ts', '.tsx']
MANIFEST = ['.xml']

# ============================================================================
# VULNERABILITY — security-relevant weaknesses
# ============================================================================
VULNERABILITY_RULES = [
    dict(
        id="hardcoded-secret",
        title="Hardcoded credential or secret",
        severity="critical", category="vulnerability", cwe="CWE-798", file_types=KTJ + JS_TS,
        pattern=re.compile(
            r'(?i)\b(password|passwd|pwd|secret|api[_-]?key|apikey|'
            r'access[_-]?key|client[_-]?secret|private[_-]?key|auth[_-]?token)'
            r'\s*(:\s*String)?\s*=\s*"(?!\s*"|\$\{|TODO|CHANGEME|xxx|\.\.\.)([^"]{4,})"',
            re.IGNORECASE,
        ),
        description="A credential-like variable is assigned a literal string value directly in source code.",
        recommendation="Move secrets to a secure source (environment variables, a keystore, or a secrets "
                        "manager) and never commit literal credentials to version control.",
    ),
    dict(
        id="hardcoded-aws-key",
        title="Hardcoded AWS access key",
        severity="critical", category="vulnerability", cwe="CWE-798", file_types=KTJ + JS_TS,
        pattern=re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
        description="A string matching the AWS access key ID format was found in source.",
        recommendation="Revoke this key immediately if it is real, then load credentials via IAM roles, "
                        "environment variables, or a secrets manager.",
    ),
    dict(
        id="hardcoded-private-key-block",
        title="Embedded PEM private key",
        severity="critical", category="vulnerability", cwe="CWE-798", file_types=KTJ + JS_TS + MANIFEST,
        pattern=re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        description="A private key is embedded directly in the app, where it can be extracted by anyone "
                     "with the APK/source.",
        recommendation="Never ship private keys inside an app. Keep them server-side, or use a hardware-"
                        "backed keystore (Android Keystore) if a per-device key is genuinely required.",
    ),
    dict(
        id="jwt-hardcoded-signing-key",
        title="Hardcoded JWT signing key",
        severity="critical", category="vulnerability", cwe="CWE-321", file_types=KTJ + JS_TS,
        pattern=re.compile(r'(Keys\.hmacShaKeyFor\(|Algorithm\.HMAC(256|384|512)\(\s*")[^)]*"[^)]*"'),
        description="A JWT signing/verification key is built from a string literal in code.",
        recommendation="Load signing keys from a secrets manager or secure config at runtime, and rotate "
                        "any key that has been committed to source.",
    ),
    dict(
        id="insecure-hash",
        title="Use of broken/weak hash algorithm",
        severity="high", category="vulnerability", cwe="CWE-327", file_types=KTJ,
        pattern=re.compile(r'MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"\s*\)|DigestUtils\.(md5|sha1)\w*\('),
        description="MD5 and SHA-1 are cryptographically broken and unsuitable for password hashing, "
                     "integrity, or signatures.",
        recommendation="Use SHA-256/SHA-3 for integrity checks, and a dedicated password hash "
                        "(Argon2, bcrypt, scrypt, or PBKDF2) for credentials.",
    ),
    dict(
        id="insecure-cipher-ecb",
        title="Cipher used in ECB mode (or with no mode specified)",
        severity="high", category="vulnerability", cwe="CWE-327", file_types=KTJ,
        pattern=re.compile(r'Cipher\.getInstance\(\s*"(AES|DES|DESede|RSA)(/ECB[^"]*)?"\s*\)'),
        description="ECB mode (or relying on a provider's default, which is often ECB) does not hide "
                     "data patterns and is not semantically secure.",
        recommendation='Use an authenticated mode, e.g. "AES/GCM/NoPadding", with a unique IV/nonce per '
                        'encryption.',
    ),
    dict(
        id="weak-cipher-des",
        title="Use of DES / weak symmetric cipher",
        severity="high", category="vulnerability", cwe="CWE-327", file_types=KTJ,
        pattern=re.compile(r'Cipher\.getInstance\(\s*"DES'),
        description="DES has a 56-bit key and is trivially brute-forced with modern hardware.",
        recommendation="Use AES-256 in GCM mode instead.",
    ),
    dict(
        id="hardcoded-cipher-key",
        title="Hardcoded symmetric key material",
        severity="critical", category="vulnerability", cwe="CWE-321", file_types=KTJ,
        pattern=re.compile(r'SecretKeySpec\(\s*"[^"]+"\s*\.toByteArray|SecretKeySpec\(\s*\{?\s*"[^"]+"\s*\.getBytes'),
        description="A symmetric encryption key is derived from a string literal, so anyone with the app "
                     "binary/source has the key.",
        recommendation="Derive keys from user input (e.g. via PBKDF2) plus a per-install salt, or use the "
                        "Android Keystore to generate and hold non-exportable keys.",
    ),
    dict(
        id="hardcoded-iv",
        title="Hardcoded / static initialization vector",
        severity="medium", category="vulnerability", cwe="CWE-329", file_types=KTJ,
        pattern=re.compile(r'IvParameterSpec\(\s*"[^"]*"\.toByteArray|IvParameterSpec\(\s*byteArrayOf\(\s*\d'),
        description="Reusing a fixed IV across encryptions with the same key leaks information about the "
                     "plaintext and can fully break some modes.",
        recommendation="Generate a fresh random IV per encryption (e.g. from SecureRandom) and store/send "
                        "it alongside the ciphertext.",
    ),
    dict(
        id="weak-random",
        title="Non-cryptographic random number generator",
        severity="medium", category="vulnerability", cwe="CWE-330", file_types=KTJ,
        pattern=re.compile(
            r'\bjava\.util\.Random\(|\bRandom\(\)(?!\.Companion)|kotlin\.random\.Random\.Default'
        ),
        description="java.util.Random / kotlin.random.Random are predictable and unsuitable for tokens, "
                     "OTPs, session IDs, or cryptographic keys.",
        recommendation="Use java.security.SecureRandom for anything security-sensitive.",
    ),
    dict(
        id="insecure-random-fixed-seed",
        title="Random number generator seeded with a constant",
        severity="medium", category="vulnerability", cwe="CWE-336", file_types=KTJ,
        pattern=re.compile(r'Random\(\s*\d+[Ll]?\s*\)|\.setSeed\(\s*\d+[Ll]?\s*\)'),
        description="Seeding a PRNG with a fixed constant makes its output sequence fully predictable.",
        recommendation="Don't fix the seed for anything security-relevant; let the PRNG self-seed, or use "
                        "SecureRandom.",
    ),
    dict(
        id="weak-key-size",
        title="Weak asymmetric key size",
        severity="high", category="vulnerability", cwe="CWE-326", file_types=KTJ,
        pattern=re.compile(r'\.initialize\(\s*(512|1024)\s*[,)]'),
        description="512/1024-bit RSA/DSA keys are considered breakable with modern computing resources.",
        recommendation="Use at least 2048-bit RSA (3072+ for long-lived keys), or an elliptic-curve "
                        "algorithm such as Ed25519/ECDSA with a modern curve.",
    ),
    dict(
        id="insecure-ssl-protocol",
        title="Outdated/insecure TLS protocol version pinned",
        severity="high", category="vulnerability", cwe="CWE-326", file_types=KTJ,
        pattern=re.compile(r'SSLContext\.getInstance\(\s*"(SSL|SSLv2|SSLv3|TLS(v1(\.0)?)?)"\s*\)'),
        description="SSLv2/SSLv3/TLS 1.0 and plain \"TLS\"/\"SSL\" (which can negotiate down) have known "
                     "weaknesses and are disabled by most modern servers.",
        recommendation='Pin to "TLSv1.2" or "TLSv1.3" explicitly, and let the platform negotiate the best '
                        'version within that floor.',
    ),
    dict(
        id="trust-all-certs",
        title="TLS certificate/hostname validation disabled",
        severity="critical", category="vulnerability", cwe="CWE-295", file_types=KTJ,
        pattern=re.compile(
            r'checkServerTrusted[\s\S]{0,40}?\{\s*\}|'
            r'HostnameVerifier\s*\{[\s\S]{0,80}?return\s+true|'
            r'ALLOW_ALL_HOSTNAME_VERIFIER'
        ),
        description="An empty checkServerTrusted() or a hostname verifier that always returns true disables "
                     "TLS certificate validation, allowing man-in-the-middle attacks.",
        recommendation="Never override certificate/hostname validation to accept everything, even for "
                        "debug builds. Use a debug-only network security config instead.",
    ),
    dict(
        id="cleartext-http",
        title="Hardcoded cleartext (http://) URL",
        severity="medium", category="vulnerability", cwe="CWE-319", file_types=KTJ + JS_TS,
        pattern=re.compile(r'"http://(?!localhost|127\.0\.0\.1|10\.0\.2\.2)[^"\s]+"'),
        description="Traffic to this URL is unencrypted and can be read or modified in transit.",
        recommendation="Use https:// endpoints, and set usesCleartextTraffic=false / a network security "
                        "config to enforce it app-wide.",
    ),
    dict(
        id="sql-injection",
        title="Possible SQL injection via string concatenation",
        severity="high", category="vulnerability", cwe="CWE-89", file_types=KTJ + JS_TS,
        pattern=re.compile(r'(rawQuery|execSQL|createQuery|compileStatement)\s*\([^)]*\+'),
        description="Building a SQL statement by concatenating variables into the query string risks SQL "
                     "injection.",
        recommendation="Use parameterized queries / bind arguments (e.g. rawQuery(sql, args)) or an ORM "
                        "(Room) instead of concatenation.",
    ),
    dict(
        id="command-injection",
        title="Possible OS command injection",
        severity="critical", category="vulnerability", cwe="CWE-78", file_types=KTJ,
        pattern=re.compile(r'(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\([^)]*\+'),
        description="Passing concatenated, potentially user-influenced strings to exec()/ProcessBuilder can "
                     "let an attacker run arbitrary shell commands.",
        recommendation="Avoid building shell commands from input. If unavoidable, pass arguments as a list "
                        "(not a single concatenated string) and validate/allow-list input.",
    ),
    dict(
        id="path-traversal",
        title="Possible path traversal",
        severity="medium", category="vulnerability", cwe="CWE-22", file_types=KTJ,
        pattern=re.compile(r'File\(\s*[\w.]+\s*,?\s*\w*\s*\+\s*\w+'),
        description="A file path built by concatenating a variable may allow '../' sequences to escape the "
                     "intended directory.",
        recommendation="Canonicalize the resulting path and verify it stays within the expected base "
                        "directory before using it.",
    ),
    dict(
        id="zip-slip",
        title="Possible zip-slip (unsanitized archive entry path)",
        severity="high", category="vulnerability", cwe="CWE-22", file_types=KTJ,
        pattern=re.compile(r'new\s+File\([^)]*\.getName\(\)\)|File\(\s*\w+\s*,\s*\w*\.name\)'),
        description="Extracting a zip/jar entry straight to a file built from its own name lets a "
                     "malicious archive write outside the target directory (e.g. via '../../').",
        recommendation="Resolve the destination path and verify (via canonical path comparison) that it "
                        "stays inside the intended extraction directory before writing.",
    ),
    dict(
        id="insecure-deserialization",
        title="Java object deserialization",
        severity="high", category="vulnerability", cwe="CWE-502", file_types=KTJ,
        pattern=re.compile(r'ObjectInputStream\('),
        description="Deserializing untrusted data with ObjectInputStream can lead to remote code execution "
                     "via gadget chains.",
        recommendation="Avoid Java native serialization for untrusted data; use a safe data format like "
                        "JSON with a schema, and validate input.",
    ),
    dict(
        id="xxe-vulnerable-parser",
        title="XML parser created without disabling external entities",
        severity="medium", category="vulnerability", cwe="CWE-611", file_types=KTJ,
        pattern=re.compile(r'DocumentBuilderFactory\.newInstance\(\)|SAXParserFactory\.newInstance\(\)|XMLInputFactory\.newInstance\(\)'),
        description="By default these XML parser factories resolve external entities/DTDs, which can be "
                     "abused for XXE (reading local files or making the server issue requests).",
        recommendation='Disable external entities/DTDs on the factory, e.g. '
                        '`setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`, before '
                        'parsing any untrusted XML.',
    ),
    dict(
        id="webview-js-interface",
        title="JavaScript interface exposed to WebView",
        severity="high", category="vulnerability", cwe="CWE-749", file_types=KTJ,
        pattern=re.compile(r'addJavascriptInterface\('),
        description="Exposing a Java/Kotlin object to WebView JavaScript can allow a malicious page to "
                     "reach app internals (pre-API 17, or if not carefully scoped).",
        recommendation="Avoid addJavascriptInterface unless required; if used, target API 17+, annotate "
                        "exposed methods with @JavascriptInterface, and never load untrusted content.",
    ),
    dict(
        id="webview-js-enabled",
        title="WebView JavaScript execution enabled",
        severity="medium", category="vulnerability", cwe="CWE-749", file_types=KTJ,
        pattern=re.compile(r'setJavaScriptEnabled\(\s*true\s*\)'),
        description="Enabling JavaScript widens the attack surface if the WebView can ever load untrusted "
                     "or attacker-influenced content.",
        recommendation="Only enable JavaScript when required, and only load trusted, origin-pinned content.",
    ),
    dict(
        id="webview-file-access",
        title="WebView allows file:// access from arbitrary content",
        severity="high", category="vulnerability", cwe="CWE-919", file_types=KTJ,
        pattern=re.compile(r'setAllowFileAccessFromFileURLs\(\s*true\s*\)|setAllowUniversalAccessFromFileURLs\(\s*true\s*\)'),
        description="These settings let file:// pages read other files or make cross-origin requests, "
                     "widening what a malicious or compromised page inside the WebView can reach.",
        recommendation="Leave these disabled (the modern default); if file access is genuinely needed, "
                        "serve content from a WebViewAssetLoader / https origin instead.",
    ),
    dict(
        id="world-readable-prefs",
        title="World-readable/writable file mode",
        severity="high", category="vulnerability", cwe="CWE-732", file_types=KTJ,
        pattern=re.compile(r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE'),
        description="These modes let any other app on the device read or write this file/preferences.",
        recommendation="Use MODE_PRIVATE and share data deliberately via a content provider with proper "
                        "permissions instead.",
    ),
    dict(
        id="world-writable-file-permission",
        title="File explicitly made world-readable/writable",
        severity="high", category="vulnerability", cwe="CWE-732", file_types=KTJ,
        pattern=re.compile(r'\.setReadable\(\s*true\s*,\s*false\s*\)|\.setWritable\(\s*true\s*,\s*false\s*\)|chmod\s+777'),
        description="Marking a file readable/writable by everyone (not just the owner) exposes it to any "
                     "other process/app on the device.",
        recommendation="Only grant owner access unless another process genuinely needs it, and prefer "
                        "app-private storage or a content provider with explicit permissions.",
    ),
    dict(
        id="log-sensitive-data",
        title="Sensitive value written to logs",
        severity="medium", category="vulnerability", cwe="CWE-532", file_types=KTJ,
        pattern=re.compile(
            r'Log\.[dviwe]\([^)]*\b(password|token|secret|apikey|api_key|auth)\b',
            re.IGNORECASE,
        ),
        description="Logging credentials or tokens can leak them via logcat, crash reports, or log "
                     "aggregation services.",
        recommendation="Redact or omit sensitive fields before logging; scrub logging statements in "
                        "release builds.",
    ),
    dict(
        id="sensitive-data-in-shared-prefs",
        title="Sensitive value stored in plain SharedPreferences",
        severity="high", category="vulnerability", cwe="CWE-312", file_types=KTJ,
        pattern=re.compile(r'putString\(\s*"?\w*(password|token|secret)\w*"?\s*,', re.IGNORECASE),
        description="Regular SharedPreferences are stored as plain XML on disk; on a rooted or backed-up "
                     "device this value is readable.",
        recommendation="Use EncryptedSharedPreferences (Jetpack Security) or the Android Keystore for "
                        "anything sensitive, not plain SharedPreferences.",
    ),
    dict(
        id="clipboard-sensitive-data",
        title="Sensitive value copied to the system clipboard",
        severity="medium", category="vulnerability", cwe="CWE-200", file_types=KTJ,
        pattern=re.compile(r'ClipData\.newPlainText\([^)]*\b(password|token|secret)\b', re.IGNORECASE),
        description="Anything placed on the system clipboard can potentially be read by other apps "
                     "(especially pre-Android 13, or via clipboard-monitoring accessibility services).",
        recommendation="Avoid copying credentials/tokens to the clipboard; if unavoidable, mark the clip "
                        "sensitive (ClipDescription.EXTRA_IS_SENSITIVE) and clear it promptly.",
    ),
    dict(
        id="open-redirect-intent",
        title="Intent built from a raw URI string",
        severity="medium", category="vulnerability", cwe="CWE-601", file_types=KTJ,
        pattern=re.compile(r'Intent\.parseUri\('),
        description="Building an Intent from an arbitrary URI string (e.g. from a deep link or server "
                     "response) can let an attacker redirect the app into launching unintended "
                     "components.",
        recommendation="Validate the scheme/host/component before use, and prefer explicit Intents over "
                        "parsing untrusted URIs into implicit ones.",
    ),
    dict(
        id="js-eval-usage",
        title="eval() / Function() constructor used",
        severity="high", category="vulnerability", cwe="CWE-95", file_types=JS_TS,
        pattern=re.compile(r'\beval\s*\(|new\s+Function\s*\('),
        description="eval() and the Function constructor execute arbitrary strings as code — if any of "
                     "that string can be influenced by user/network input, it's remote code execution.",
        recommendation="Avoid eval/Function entirely; use JSON.parse for data, and explicit function "
                        "references instead of dynamically built code.",
    ),
    dict(
        id="js-dom-xss-sink",
        title="Untrusted-looking value assigned to innerHTML/dangerouslySetInnerHTML",
        severity="high", category="vulnerability", cwe="CWE-79", file_types=JS_TS,
        pattern=re.compile(r'\.innerHTML\s*=(?!=)|dangerouslySetInnerHTML\s*=\s*\{'),
        description="Assigning raw strings (especially ones built from variables) into innerHTML or "
                     "dangerouslySetInnerHTML renders them as HTML/JS, which is a classic XSS sink.",
        recommendation="Use textContent for plain text, or sanitize with a library like DOMPurify before "
                        "assigning HTML; avoid dangerouslySetInnerHTML unless the content is fully trusted.",
    ),
    dict(
        id="js-document-write",
        title="document.write() used",
        severity="medium", category="vulnerability", cwe="CWE-79", file_types=JS_TS,
        pattern=re.compile(r'document\.write(ln)?\('),
        description="document.write blocks parsing and, like innerHTML, is a common XSS sink when fed "
                     "anything derived from user/URL input.",
        recommendation="Use safe DOM APIs (createElement/textContent) instead of document.write.",
    ),
    dict(
        id="node-command-injection",
        title="Possible OS command injection (Node child_process)",
        severity="critical", category="vulnerability", cwe="CWE-78", file_types=JS_TS,
        pattern=re.compile(r'\b(exec|execSync)\s*\(\s*[`"\'][^`"\']*\$\{|\b(exec|execSync)\s*\([^)]*\+'),
        description="Building a shell command string by interpolating/concatenating variables into "
                     "child_process.exec/execSync lets an attacker inject additional shell commands.",
        recommendation="Use execFile/spawn with an argument array (no shell interpretation) instead of "
                        "building a single command string.",
    ),
    dict(
        id="node-insecure-tls",
        title="TLS certificate validation disabled (Node/axios)",
        severity="critical", category="vulnerability", cwe="CWE-295", file_types=JS_TS,
        pattern=re.compile(r'rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\'"]?0'),
        description="Disabling certificate validation allows man-in-the-middle attacks against this "
                     "client's HTTPS connections.",
        recommendation="Remove the override and fix the underlying certificate issue (e.g. add the CA to "
                        "the trust store) instead of disabling validation.",
    ),
    dict(
        id="jwt-none-algorithm",
        title="JWT verification allows the 'none' algorithm",
        severity="critical", category="vulnerability", cwe="CWE-347", file_types=KTJ + JS_TS,
        pattern=re.compile(r'algorithms?\s*:\s*\[?[\'"]none[\'"]|setAllowedClockSkewSeconds.*none'),
        description="Accepting the 'none' algorithm means a token with no signature at all is treated as "
                     "valid — anyone can forge a token.",
        recommendation="Explicitly allow-list the real signing algorithm(s) you use (e.g. RS256/HS256) and "
                        "never include 'none'.",
    ),
    dict(
        id="js-math-random-sensitive-context",
        title="Math.random() used near a security-sounding name",
        severity="low", category="vulnerability", cwe="CWE-330", file_types=JS_TS,
        pattern=re.compile(
            r'(?i)\b(token|password|otp|session[_-]?id|secret|reset[_-]?code|verification[_-]?code)\b'
            r'[^\n;]{0,40}Math\.random\('
        ),
        description="Math.random() is not cryptographically secure; using it near something that looks "
                     "security-sensitive (a token/OTP/session id) suggests it may be predictable.",
        recommendation="For anything security-sensitive, use a CSPRNG: crypto.randomBytes/randomUUID in "
                        "Node, or window.crypto.getRandomValues in the browser.",
    ),
    dict(
        id="js-sensitive-data-web-storage",
        title="Sensitive value stored in localStorage/sessionStorage",
        severity="high", category="vulnerability", cwe="CWE-312", file_types=JS_TS,
        pattern=re.compile(
            r'(local|session)Storage\.setItem\(\s*[\'"`]?\w*(token|password|secret|apikey|api_key)\w*',
            re.IGNORECASE,
        ),
        description="localStorage/sessionStorage are plain text, persist across tabs/reloads, and are "
                     "readable by any JavaScript running on the page — including injected via XSS.",
        recommendation="Prefer a short-lived, httpOnly, secure cookie set by the server for tokens/session "
                        "data; if client storage is unavoidable, treat it as compromised the moment an XSS "
                        "bug exists.",
    ),
    dict(
        id="js-wildcard-cors",
        title="Wildcard CORS origin",
        severity="medium", category="vulnerability", cwe="CWE-942", file_types=JS_TS,
        pattern=re.compile(
            r'Access-Control-Allow-Origin[\'"]?\s*[,:]\s*[\'"]\*[\'"]|\bcors\(\s*\)\s*[;)]'
        ),
        description="Allowing any origin to make credentialed cross-origin requests defeats the "
                     "same-origin policy that protects your users' sessions on other sites.",
        recommendation="Allow-list the specific origins that legitimately need access instead of '*', "
                        "especially on any endpoint that reads cookies or an Authorization header.",
    ),
    dict(
        id="js-dynamic-regexp",
        title="RegExp built from a non-literal value",
        severity="medium", category="vulnerability", cwe="CWE-1333", file_types=JS_TS,
        pattern=re.compile(r'new\s+RegExp\(\s*[a-zA-Z_$][\w$]*(\.[a-zA-Z_$][\w$]*)*[\s,)]'),
        description="A regular expression built from a variable (rather than a fixed literal) can let "
                     "attacker-controlled input create a catastrophically slow pattern (ReDoS) or, if "
                     "used in a security check, bypass it entirely.",
        recommendation="Use a fixed, reviewed pattern where possible. If the pattern must be dynamic, "
                        "escape special regex characters in the input and consider a timeout/length limit.",
    ),
]

GRADLE_PROPERTIES_RULES = [
    dict(
        id="properties-hardcoded-secret",
        title="Hardcoded credential in a .properties file",
        severity="critical", category="vulnerability", cwe="CWE-798", file_types=['.properties'],
        pattern=re.compile(
            r'(?im)^\s*[\w.]*(password|passwd|secret|api[_-]?key|apikey|access[_-]?key|token)'
            r'\s*[:=]\s*(?!\$\{|%\(|\s*$)\S{4,}\s*$'
        ),
        description="gradle.properties / local.properties files are frequently committed to version "
                     "control by mistake, so credentials placed here often end up in source history.",
        recommendation="Keep secrets out of committed .properties files; use environment variables, a "
                        "secrets manager, or an untracked local file referenced via CI secrets.",
    ),
    dict(
        id="proguard-obfuscation-disabled",
        title="ProGuard/R8 obfuscation disabled",
        severity="low", category="vulnerability", cwe=None, file_types=['.pro'],
        pattern=re.compile(r'-dontobfuscate\b'),
        description="Disabling obfuscation makes reverse-engineering a release build significantly "
                     "easier (class/method names stay intact).",
        recommendation="Only disable obfuscation for debugging a specific release issue, and re-enable it "
                        "before shipping.",
    ),
]

VULNERABILITY_RULES = VULNERABILITY_RULES + GRADLE_PROPERTIES_RULES

DEEPER_VULNERABILITY_RULES = [
    dict(
        id="hardcoded-basic-auth-url",
        title="Credentials embedded in a URL",
        severity="high", category="vulnerability", cwe="CWE-522", file_types=KTJ + JS_TS,
        pattern=re.compile(r'[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:"\']+:[^/\s@"\']+@'),
        description="A username:password embedded directly in a URL ends up in logs, browser history, "
                     "and error messages wherever that URL is printed or stored.",
        recommendation="Pass credentials via headers (e.g. an Authorization header) or a secrets manager "
                        "instead of embedding them in the URL string.",
    ),
    dict(
        id="js-open-redirect",
        title="Navigation target assigned from a variable",
        severity="medium", category="vulnerability", cwe="CWE-601", file_types=JS_TS,
        pattern=re.compile(r'window\.location(\.href)?\s*=\s*[a-zA-Z_$][\w$.]*\s*[;)\}]'),
        description="Redirecting to a URL taken from a variable (e.g. a query parameter) without "
                     "validation lets an attacker send users to an attacker-controlled site.",
        recommendation="Validate the target against an allow-list of known paths/hosts before navigating, "
                        "or use relative in-app routes instead of a raw string.",
    ),
    dict(
        id="js-target-blank-no-rel",
        title="target=\"_blank\" link without rel=\"noopener noreferrer\"",
        severity="low", category="vulnerability", cwe="CWE-1022", file_types=JS_TS,
        pattern=re.compile(r'target\s*=\s*[\'"{]*_blank[\'"}]*(?![^>]*\brel\s*=)'),
        description="A page opened via target=\"_blank\" without rel=\"noopener\" can use "
                     "window.opener to navigate the original tab to a phishing page (reverse tabnabbing).",
        recommendation='Add rel="noopener noreferrer" to any target="_blank" link/anchor.',
    ),
    dict(
        id="js-insecure-yaml-load",
        title="Unsafe YAML deserialization",
        severity="high", category="vulnerability", cwe="CWE-502", file_types=JS_TS,
        pattern=re.compile(r'\byaml\.load\s*\('),
        description="js-yaml's load() (unlike safeLoad/loadSafe or the schema-restricted load in newer "
                     "versions) can be tricked into instantiating arbitrary types from untrusted YAML.",
        recommendation="Use yaml.load(input, { schema: yaml.FAILSAFE_SCHEMA }) or an equivalent restricted "
                        "schema, and never parse untrusted YAML with default settings.",
    ),
    dict(
        id="js-insecure-cookie-flags",
        title="Cookie set without Secure/HttpOnly",
        severity="medium", category="vulnerability", cwe="CWE-614", file_types=JS_TS,
        pattern=re.compile(r'res\.cookie\((?:(?!secure)(?!httponly).)*?\)', re.IGNORECASE | re.DOTALL),
        description="A session/auth cookie set without { secure: true, httpOnly: true } can be sent over "
                     "plain HTTP and read by client-side JavaScript (including via XSS).",
        recommendation="Set { httpOnly: true, secure: true, sameSite: 'lax' } (or stricter) on any cookie "
                        "carrying a session token.",
    ),
    dict(
        id="kotlin-todo-function",
        title="TODO() placeholder will throw at runtime",
        severity="medium", category="vulnerability", cwe=None, file_types=KT,
        tags=['runtime-error'],
        pattern=re.compile(r'\bTODO\(\)'),
        description="Kotlin's TODO() function always throws NotImplementedError when executed — if this "
                     "path is reachable in a shipped build, it's a guaranteed crash.",
        recommendation="Implement the function, or make sure this path is genuinely unreachable before "
                        "release.",
    ),
]

VULNERABILITY_RULES = VULNERABILITY_RULES + DEEPER_VULNERABILITY_RULES

VULNERABILITY_RULES_MANIFEST = [
    dict(
        id="manifest-debuggable",
        title="Manifest allows debugging in release",
        severity="medium", category="vulnerability", cwe="CWE-489", file_types=MANIFEST,
        pattern=re.compile(r'android:debuggable\s*=\s*"true"'),
        description="A debuggable app can be attached to and inspected/manipulated at runtime, including "
                     "on production devices.",
        recommendation='Remove android:debuggable or ensure it is false in release builds (Gradle sets '
                        'this automatically for release; check for manual overrides).',
    ),
    dict(
        id="manifest-backup-allowed",
        title="Manifest allows full app data backup",
        severity="low", category="vulnerability", cwe="CWE-530", file_types=MANIFEST,
        pattern=re.compile(r'android:allowBackup\s*=\s*"true"'),
        description="With backups enabled, app data (potentially including cached credentials or tokens) "
                     "can be extracted via adb backup on older/rooted devices.",
        recommendation="Set android:allowBackup=\"false\", or provide a backup rules file that excludes "
                        "sensitive data.",
    ),
    dict(
        id="manifest-exported-true",
        title="Component explicitly exported",
        severity="medium", category="vulnerability", cwe="CWE-926", file_types=MANIFEST,
        pattern=re.compile(r'android:exported\s*=\s*"true"'),
        description="An exported component (activity, service, receiver, provider) can be launched or "
                     "queried by any other app on the device.",
        recommendation="Set exported=\"false\" unless the component genuinely needs to be reachable by "
                        "other apps, and add permission checks if it does.",
    ),
    dict(
        id="manifest-cleartext-traffic",
        title="Manifest allows cleartext (HTTP) network traffic",
        severity="medium", category="vulnerability", cwe="CWE-319", file_types=MANIFEST,
        pattern=re.compile(r'android:usesCleartextTraffic\s*=\s*"true"'),
        description="The app permits plain HTTP traffic app-wide, which can be intercepted or modified "
                     "in transit.",
        recommendation='Set usesCleartextTraffic="false" and use a network security config to allow-list '
                        'any specific hosts that genuinely need HTTP.',
    ),
    dict(
        id="manifest-provider-exported-no-permission",
        title="Content provider exported without a permission",
        severity="high", category="vulnerability", cwe="CWE-926", file_types=MANIFEST,
        pattern=re.compile(
            r'<provider\b(?:(?!android:permission|/?>)[\s\S]){0,400}?android:exported\s*=\s*"true"'
            r'(?:(?!android:permission|/?>)[\s\S]){0,400}?/?>'
        ),
        description="An exported content provider with no android:permission can be queried by any app "
                     "on the device, potentially exposing app data.",
        recommendation="Add android:permission (or path-level <path-permission> rules), or set "
                        "exported=\"false\" if the provider is only used internally.",
    ),
]

# ============================================================================
# BUG — patterns likely to cause incorrect behavior or crashes
# ============================================================================
BUG_RULES = [
    dict(
        id="empty-catch",
        title="Empty catch block",
        severity="low", category="bug", cwe="CWE-390", file_types=KTJ + JS_TS,
        pattern=re.compile(r'catch\s*(\([^)]*\))?\s*\{\s*\}'),
        description="Exceptions are silently swallowed, which hides failures and makes debugging harder.",
        recommendation="At minimum log the exception; handle it or rethrow a more specific error.",
    ),
    dict(
        id="broad-catch",
        title="Overly broad exception catch",
        severity="low", category="bug", cwe="CWE-396", file_types=KTJ,
        pattern=re.compile(r'catch\s*\(\s*\w+\s*:\s*Exception\s*\)|catch\s*\(\s*Exception\s+\w+\s*\)'),
        description="Catching the generic Exception type can mask unrelated bugs and unexpected errors.",
        recommendation="Catch the most specific exception type(s) you can actually recover from.",
    ),
    dict(
        id="not-null-assertion",
        title="Non-null assertion operator (!!) used",
        severity="info", category="bug", cwe="CWE-476", file_types=KT,
        tags=['runtime-error'],
        pattern=re.compile(r'(?<![!=])!!(?!=)'),
        description="!! converts a nullable into a crash (NullPointerException) if the value is ever null.",
        recommendation="Prefer safe calls (?.), the Elvis operator (?:), or explicit null checks.",
    ),
    dict(
        id="ts-non-null-assertion",
        title="TypeScript non-null assertion (!) used",
        severity="info", category="bug", cwe="CWE-476", file_types=['.ts', '.tsx'],
        tags=['runtime-error'],
        pattern=re.compile(r'(?<![=!<>+\-*/&|])\b[A-Za-z_$][\w$]*!(?=\s*[.\)\],;:])'),
        description="The ! non-null assertion tells TypeScript to trust you that a value isn't null/"
                     "undefined, turning a compile-time check into a runtime crash if you're wrong.",
        recommendation="Prefer optional chaining (?.) with a fallback (??), or a real narrowing check "
                        "(if (x != null)) instead of asserting past the type checker.",
    ),
    dict(
        id="js-loose-equality",
        title="Loose equality (== / !=) instead of strict (=== / !==)",
        severity="low", category="bug", cwe="CWE-1023", file_types=JS_TS,
        tags=['runtime-error'],
        pattern=re.compile(r'(?<![=!<>])==(?!=)|(?<!!)!=(?!=)'),
        description="== and != coerce types before comparing (e.g. '' == 0 is true), which is a classic "
                     "source of subtle JavaScript bugs.",
        recommendation="Use === / !== unless you have a specific, commented reason to rely on type "
                        "coercion (e.g. `x == null` to catch both null and undefined).",
    ),
    dict(
        id="js-empty-function",
        title="Empty function/arrow function body",
        severity="info", category="bug", cwe=None, file_types=JS_TS,
        pattern=re.compile(r'function\s*\w*\s*\([^)]*\)\s*\{\s*\}|=>\s*\{\s*\}'),
        description="An empty function body is often an unfinished stub, a forgotten callback "
                     "implementation, or dead code.",
        recommendation="Implement it, remove it if unused, or add a comment explaining why it's "
                        "intentionally a no-op.",
    ),
    dict(
        id="js-unhandled-promise",
        title="Promise chain without a .catch()",
        severity="medium", category="bug", cwe="CWE-252", file_types=JS_TS,
        pattern=re.compile(r'\.then\s*\([^;]*?\)(?!\s*\.catch)(?=\s*;|\s*\n)'),
        description="A .then() chain with no .catch() means a rejected promise becomes an unhandled "
                     "promise rejection — silently swallowed in some environments, a hard crash in others "
                     "(e.g. modern Node terminates the process).",
        recommendation="Add a .catch() (or wrap the awaited call in try/catch if you're in an async "
                        "function) so failures are handled deliberately.",
    ),
    dict(
        id="react-missing-list-key",
        title="Rendered list without a key prop",
        severity="low", category="bug", cwe=None, file_types=['.jsx', '.tsx'],
        pattern=re.compile(r'\.map\s*\(\s*(\([^)]*\)|\w+)\s*=>\s*(<|\()(?![^>]*\bkey\s*=)'),
        description="React uses the key prop to track which list items changed; without it, list "
                     "re-renders can duplicate, drop, or mis-associate state between items.",
        recommendation='Add a stable, unique key={item.id} (not the array index, if the list can '
                        'reorder/filter) to the returned element.',
    ),
    dict(
        id="react-useeffect-missing-deps",
        title="useEffect with no dependency array",
        severity="low", category="bug", cwe=None, file_types=['.jsx', '.tsx'],
        pattern=re.compile(r'useEffect\s*\(\s*(\([^)]*\)|\w+)\s*=>\s*\{[\s\S]{0,400}?\}\s*\)\s*(?!,\s*\[)'),
        description="Without a dependency array, this effect re-runs after every render — often not what "
                     "was intended, and a common source of infinite render loops or extra network calls.",
        recommendation="Add a dependency array (even an empty [] for 'run once') listing every reactive "
                        "value the effect reads.",
    ),
    dict(
        id="string-equality-with-eq",
        title="String compared with == instead of .equals()",
        severity="medium", category="bug", cwe="CWE-597", file_types=JAVA,
        tags=['runtime-error'],
        pattern=re.compile(r'\b\w+\s*==\s*"[^"]*"|"[^"]*"\s*==\s*\w+\b'),
        description="In Java, == on String compares references, not content — it can be true or false "
                     "depending on string interning, which is a common source of subtle bugs.",
        recommendation='Use .equals() (or Objects.equals() to be null-safe) instead of == for String '
                        'comparison.',
    ),
    dict(
        id="floating-point-equality",
        title="Floating-point value compared with ==",
        severity="low", category="bug", cwe="CWE-697", file_types=KTJ,
        tags=['runtime-error'],
        pattern=re.compile(r'\b\w+\s*==\s*\d+\.\d+[fF]?\b'),
        description="Floating-point arithmetic is imprecise, so == comparisons can fail even when two "
                     "values are 'the same' mathematically.",
        recommendation="Compare against an epsilon range (e.g. kotlin.math.abs(a - b) < EPSILON) instead "
                        "of exact equality.",
    ),
    dict(
        id="deprecated-finalize",
        title="Deprecated finalize() override",
        severity="low", category="bug", cwe="CWE-568", file_types=KTJ,
        pattern=re.compile(r'\bprotected\s+(fun|void)\s+finalize\s*\('),
        description="finalize() runs at an unpredictable time (or not at all) and is deprecated since "
                     "Java 9 — relying on it for cleanup is unreliable.",
        recommendation="Use try-with-resources / Closeable, or a dedicated close()/release() method "
                        "called deterministically.",
    ),
    dict(
        id="sleep-in-code",
        title="Thread.sleep() call",
        severity="medium", category="bug", cwe="CWE-833", file_types=KTJ,
        tags=['performance'],
        pattern=re.compile(r'Thread\.sleep\('),
        description="A blocking sleep on the main/UI thread causes visible jank or an ANR; even on a "
                     "background thread it's usually a sign of polling instead of proper "
                     "signaling/callbacks.",
        recommendation="Use a Handler/coroutine delay, WorkManager, or a callback/Flow instead of "
                        "sleeping a thread.",
    ),
    dict(
        id="possible-resource-leak",
        title="Stream/file opened without try-with-resources or .use{}",
        severity="low", category="bug", cwe="CWE-772", file_types=KTJ,
        tags=['memory-leak'],
        pattern=re.compile(
            r'^(?!.*\btry\s*\().*\bnew\s+(FileInputStream|FileOutputStream|FileReader|FileWriter)\(',
            re.MULTILINE,
        ),
        description="If this stream isn't closed on every exit path (including exceptions), the "
                     "underlying file descriptor leaks.",
        recommendation="Wrap it in Kotlin's `.use { }` or Java's try-with-resources so it's always closed.",
    ),
    dict(
        id="deprecated-asynctask",
        title="Deprecated AsyncTask usage",
        severity="low", category="bug", cwe=None, file_types=KTJ,
        pattern=re.compile(r'\bextends\s+AsyncTask\b|:\s*AsyncTask\s*<'),
        description="AsyncTask has been deprecated since API 30 and has known lifecycle/leak pitfalls "
                     "(e.g. holding an Activity reference across a config change).",
        recommendation="Use Kotlin coroutines (viewModelScope/lifecycleScope), WorkManager, or "
                        "java.util.concurrent executors instead.",
    ),
    dict(
        id="kotlin-global-scope",
        title="GlobalScope used for a coroutine",
        severity="medium", category="bug", cwe=None, file_types=KT,
        tags=['memory-leak'],
        pattern=re.compile(r'\bGlobalScope\.(launch|async)\s*[\{(]'),
        description="A coroutine launched on GlobalScope runs for the lifetime of the whole application "
                     "and is never cancelled automatically — it isn't tied to any Activity/ViewModel/"
                     "lifecycle, which commonly leaks work and makes cancellation impossible.",
        recommendation="Launch from a scoped CoroutineScope instead — viewModelScope, lifecycleScope, or "
                        "a scope you create and cancel yourself.",
    ),
    dict(
        id="kotlin-runblocking",
        title="runBlocking used outside of tests/main",
        severity="medium", category="bug", cwe=None, file_types=KT,
        tags=['performance'],
        pattern=re.compile(r'\brunBlocking\s*[\{(]'),
        description="runBlocking blocks the current thread until the coroutine completes — on the main/UI "
                     "thread this causes visible jank or an ANR, defeating the purpose of using "
                     "coroutines at all.",
        recommendation="Use a suspend function and a proper coroutine scope instead; reserve runBlocking "
                        "for main() entry points and tests.",
    ),
    dict(
        id="java-catch-throwable",
        title="Catching Throwable or Error",
        severity="high", category="bug", cwe="CWE-396", file_types=KTJ,
        tags=['runtime-error'],
        pattern=re.compile(r'catch\s*\(\s*\w+\s*:\s*(Throwable|Error)\s*\)|catch\s*\(\s*(Throwable|Error)\s+\w+\s*\)'),
        description="Throwable/Error includes OutOfMemoryError, StackOverflowError, and other JVM-fatal "
                     "conditions that generally can't be recovered from — catching them can hide a crash "
                     "the process should have had.",
        recommendation="Catch specific Exception subtypes you can actually handle; let unrecoverable "
                        "Errors propagate.",
    ),
    dict(
        id="java-generic-exception-thrown",
        title="Generic Exception thrown",
        severity="low", category="bug", cwe="CWE-397", file_types=KTJ,
        pattern=re.compile(r'throw\s+new\s+Exception\s*\(|throw\s+Exception\s*\('),
        description="Throwing the generic Exception type forces every caller to catch (or declare) the "
                     "broadest possible type, making targeted error handling impossible.",
        recommendation="Throw (or define) a specific exception type that describes what actually went "
                       "wrong.",
    ),
    dict(
        id="react-index-as-key",
        title="Array index used as a React list key",
        severity="low", category="bug", cwe=None, file_types=['.jsx', '.tsx'],
        pattern=re.compile(r'key\s*=\s*\{\s*(index|idx|i)\s*\}'),
        description="Using the array index as a key defeats React's reconciliation when the list can "
                     "reorder, filter, or have items inserted/removed — items can keep the wrong state "
                     "attached as they shift position.",
        recommendation="Use a stable, unique identifier from the data itself (e.g. item.id) instead of "
                        "the loop index.",
    ),
    dict(
        id="react-direct-state-mutation",
        title="Direct mutation of this.state",
        severity="medium", category="bug", cwe=None, file_types=['.jsx', '.tsx'],
        tags=['runtime-error'],
        pattern=re.compile(r'\bthis\.state\.\w+(\.\w+)*\s*=(?!=)'),
        description="Mutating this.state directly doesn't trigger a re-render and can be silently "
                     "overwritten by the next setState call — React expects state to be treated as "
                     "immutable.",
        recommendation="Use this.setState({ ... }) (or a state updater function) instead of assigning to "
                        "this.state directly.",
    ),
    dict(
        id="static-context-reference",
        title="Static field holds a Context/Activity reference",
        severity="high", category="bug", cwe="CWE-401", file_types=KTJ,
        tags=["memory-leak"],
        pattern=re.compile(r'\bcompanion\s+object[\s\S]{0,200}?\bvar\s+\w+\s*:\s*(Activity|Context)\b|'
                            r'\bstatic\s+\w*\s*(Activity|Context)\s+\w+\s*;'),
        description="A static/companion-object field holding an Activity or Context outlives the "
                     "Activity itself — the whole Activity (and its View tree) stays in memory until "
                     "the process dies, because the static reference keeps the garbage collector from "
                     "ever reclaiming it.",
        recommendation="Use applicationContext instead of an Activity/Context reference in anything "
                        "static, or hold a WeakReference and null it out in onDestroy.",
    ),
    dict(
        id="static-view-reference",
        title="Static field holds a View reference",
        severity="high", category="bug", cwe="CWE-401", file_types=KTJ,
        tags=["memory-leak"],
        pattern=re.compile(
            r'\bcompanion\s+object[\s\S]{0,200}?\bvar\s+\w+\s*:\s*(View|TextView|ImageView|RecyclerView|'
            r'Button|EditText|WebView)\b|'
            r'\bstatic\s+\w*\s*(View|TextView|ImageView|RecyclerView|Button|EditText|WebView)\s+\w+\s*;'
        ),
        description="A static View field keeps that View — and transitively its Activity/Fragment and "
                     "everything it references — alive for the lifetime of the app process, not just the "
                     "screen that created it.",
        recommendation="Don't cache Views statically; hold the reference at the Activity/Fragment/"
                        "ViewHolder level and let it be garbage collected with its owner.",
    ),
    dict(
        id="handler-postdelayed-leak-risk",
        title="Handler.postDelayed without visible cleanup",
        severity="medium", category="bug", cwe="CWE-401", file_types=KTJ,
        tags=["memory-leak"],
        pattern=re.compile(r'\bpostDelayed\s*\('),
        description="A delayed Handler callback holds a reference to everything its closure captures "
                     "(commonly the enclosing Activity/Fragment/View). If the screen is destroyed before "
                     "the delay elapses and the callback is never removed, that whole object graph is "
                     "kept alive until the callback finally fires.",
        recommendation="Call handler.removeCallbacks(...) / removeCallbacksAndMessages(null) in "
                        "onDestroy()/onDestroyView(), or use a WeakReference-based Handler.",
    ),
    dict(
        id="string-concat-in-loop",
        title="String concatenation inside a loop",
        severity="low", category="bug", cwe="CWE-1050", file_types=KTJ,
        tags=["performance"],
        pattern=re.compile(r'\b(for|while)\s*\([^)]*\)\s*\{[^{}]{0,250}?\b\w+\s*\+=\s*("|\w+\.toString\(\))'),
        description="Each += on a String allocates a brand-new String and copies both operands into it — "
                     "inside a loop this is O(n\u00b2) allocation churn instead of O(n).",
        recommendation="Build the result with a StringBuilder (append() in the loop, toString() once at "
                        "the end) instead of concatenating Strings.",
    ),
    dict(
        id="nested-loop-complexity",
        title="Nested loop (O(n\u00b2) or worse)",
        severity="info", category="bug", cwe=None, file_types=KTJ + JS_TS,
        tags=["performance"],
        pattern=re.compile(
            r'\b(for|while)\s*\([^)]*\)\s*\{[^{}]*?\b(for|while)\s*\([^)]*\)\s*\{'
        ),
        description="A loop nested inside another loop over data that can grow means the work scales "
                     "quadratically (or worse) with input size — fine for small collections, a real "
                     "problem once they don't stay small.",
        recommendation="If both loops walk related data, consider a lookup map/set to bring this down to "
                        "roughly linear time instead of nested iteration.",
    ),
    dict(
        id="kotlin-bare-first-or-last",
        title="first()/last() called without checking for an empty collection",
        severity="low", category="bug", cwe="CWE-248", file_types=KT,
        tags=["runtime-error"],
        pattern=re.compile(r'(?<!Or)\.(first|last)\(\)'),
        description="first()/last() throw NoSuchElementException if the collection is empty — a runtime "
                     "crash rather than a handled case.",
        recommendation="Use firstOrNull()/lastOrNull() and handle the null case, unless you've already "
                        "proven the collection can't be empty here.",
    ),
    dict(
        id="kotlin-unsafe-string-to-int",
        title="String-to-Int conversion without a safe fallback",
        severity="low", category="bug", cwe="CWE-248", file_types=KT,
        tags=["runtime-error"],
        pattern=re.compile(r'\.toInt\(\)|\.toLong\(\)|\.toDouble\(\)|\.toFloat\(\)'),
        description="These throw NumberFormatException at runtime if the string isn't a valid number — "
                     "a common crash source for anything derived from user input, a form field, or an "
                     "external API response.",
        recommendation="Use toIntOrNull() (or the equivalent *OrNull()) and handle the null case, or wrap "
                        "the conversion in a try/catch if you already know it might fail.",
    ),
]

# ============================================================================
# CODE SMELL — maintainability issues
# ============================================================================
CODE_SMELL_RULES = [
    dict(
        id="ts-ignore-suppression",
        title="@ts-ignore / @ts-nocheck suppresses type checking",
        severity="info", category="code_smell", cwe=None, file_types=['.ts', '.tsx'],
        pattern=re.compile(r'//\s*@ts-(ignore|nocheck|expect-error)\b'),
        description="Suppressing the type checker hides whatever error TypeScript was about to report, "
                     "which can let a real bug through silently.",
        recommendation="Fix the underlying type error where possible; if the suppression is genuinely "
                        "needed, add a comment explaining why.",
    ),
    dict(
        id="kotlin-suppress-annotation",
        title="@Suppress annotation used",
        severity="info", category="code_smell", cwe=None, file_types=KT,
        pattern=re.compile(r'@Suppress\('),
        description="@Suppress silences a compiler/lint warning rather than addressing it — useful "
                     "sometimes, but worth a second look if there's no comment explaining why.",
        recommendation="Prefer fixing the underlying issue; if suppression is genuinely correct, add a "
                        "short comment saying why.",
    ),
    dict(
        id="kotlin-lateinit-var",
        title="lateinit property",
        severity="info", category="code_smell", cwe=None, file_types=KT,
        pattern=re.compile(r'\blateinit\s+var\s+\w+'),
        description="A lateinit property throws UninitializedPropertyAccessException if it's read before "
                     "being set — a runtime crash the compiler can't catch for you.",
        recommendation="Make sure every code path initializes this before first use, or consider a "
                        "nullable type / lazy delegate instead.",
    ),
    dict(
        id="java-raw-type",
        title="Raw (non-generic) collection type used",
        severity="info", category="code_smell", cwe=None, file_types=JAVA,
        pattern=re.compile(r'\b(List|Map|Set|ArrayList|HashMap|HashSet|LinkedList)\s+\w+\s*=\s*new\s+\w+\s*\(\s*\)\s*;'),
        description="Declaring a collection without a generic type parameter loses compile-time type "
                     "safety for everything added to or read from it.",
        recommendation="Add the generic type, e.g. List<String> instead of List.",
    ),
    dict(
        id="ts-explicit-any",
        title="TypeScript 'any' type used",
        severity="info", category="code_smell", cwe=None, file_types=['.ts', '.tsx'],
        pattern=re.compile(r':\s*any\b|<any>|\bas\s+any\b'),
        description="'any' turns off type checking for that value, silently disabling the safety net "
                     "TypeScript is there to provide — errors it would've caught become runtime bugs.",
        recommendation="Use a specific type/interface, 'unknown' plus a narrowing check, or a generic "
                        "instead of 'any'.",
    ),
    dict(
        id="js-var-declaration",
        title="'var' used instead of 'let'/'const'",
        severity="info", category="code_smell", cwe=None, file_types=JS_TS,
        pattern=re.compile(r'(?<!\.)\bvar\s+[A-Za-z_$]'),
        description="'var' is function-scoped (not block-scoped) and hoisted, which causes surprising "
                     "behavior in loops/closures that 'let'/'const' avoid.",
        recommendation="Use 'const' by default, 'let' when reassignment is needed.",
    ),
    dict(
        id="js-debugger-statement",
        title="'debugger' statement left in code",
        severity="low", category="code_smell", cwe=None, file_types=JS_TS,
        pattern=re.compile(r'(?<![\'"\w])debugger\s*;'),
        description="A 'debugger' statement pauses execution in any open devtools — harmless in "
                     "development, but confusing or disruptive if it ships to production.",
        recommendation="Remove it before committing/shipping.",
    ),
    dict(
        id="wildcard-import",
        title="Wildcard import",
        severity="info", category="code_smell", cwe=None, file_types=KTJ,
        pattern=re.compile(r'^\s*import\s+[\w.]+\.\*\s*;?\s*$', re.MULTILINE),
        description="Wildcard imports make it unclear where a symbol comes from and can cause silent "
                     "name clashes as dependencies evolve.",
        recommendation="Import only the specific classes/functions used.",
    ),
    dict(
        id="todo-fixme",
        title="TODO / FIXME marker",
        severity="info", category="code_smell", cwe=None, file_types=KTJ + JS_TS,
        pattern=re.compile(r'//\s*(TODO|FIXME)\b.*'),
        description="Marks unfinished work or known issues left in the codebase.",
        recommendation="Track these in an issue tracker and resolve or schedule them; avoid letting them "
                        "accumulate silently.",
    ),
    dict(
        id="empty-if-block",
        title="Empty if block",
        severity="low", category="code_smell", cwe=None, file_types=KTJ + JS_TS,
        pattern=re.compile(r'\bif\s*\([^)]*\)\s*\{\s*\}(?!\s*else)'),
        description="An if block with no body is usually leftover/dead code, or a bug where the intended "
                     "logic was never filled in.",
        recommendation="Remove the empty conditional, or fill in the intended logic.",
    ),
    dict(
        id="empty-function-body",
        title="Empty function body",
        severity="info", category="code_smell", cwe=None, file_types=KT,
        pattern=re.compile(r'\bfun\s+\w+\([^)]*\)\s*(:\s*\w+[\w<>?, ]*\s*)?\{\s*\}'),
        description="A function with an empty body may be an unfinished stub or dead override.",
        recommendation="Implement the function, remove it if unused, or add a comment explaining why it's "
                        "intentionally empty.",
    ),
    dict(
        id="boolean-literal-comparison",
        title="Redundant boolean literal comparison",
        severity="info", category="code_smell", cwe=None, file_types=KTJ + JS_TS,
        pattern=re.compile(r'==\s*(true|false)\b|\b(true|false)\s*=='),
        description="Comparing a boolean expression to true/false is redundant and harder to read than "
                     "the expression (or its negation) on its own.",
        recommendation="Use the boolean expression directly, e.g. `if (x)` / `if (!x)` instead of "
                        "`if (x == true)`.",
    ),
    dict(
        id="print-statement",
        title="print/println left in code",
        severity="info", category="code_smell", cwe="CWE-209", file_types=KTJ + JS_TS,
        pattern=re.compile(r'\bSystem\.out\.print(ln)?\(|(?<!\w)println\(|console\.(log|debug)\('),
        description="Raw print statements usually indicate leftover debugging output; on Android they "
                     "bypass Logcat's level/tag filtering and can leak into production output.",
        recommendation="Use a proper logger (Timber/Log with a tag) and remove debug prints before "
                        "shipping.",
    ),
    dict(
        id="print-stack-trace",
        title="printStackTrace() call",
        severity="low", category="code_smell", cwe="CWE-209", file_types=KTJ,
        pattern=re.compile(r'\.printStackTrace\(\)'),
        description="printStackTrace() writes straight to stderr, bypassing your logging pipeline/"
                     "redaction and potentially exposing internals in production output.",
        recommendation="Log the exception through your normal logger instead (e.g. Log.e(tag, msg, e)).",
    ),
    dict(
        id="system-exit-call",
        title="System.exit() call in application code",
        severity="low", category="code_smell", cwe="CWE-382", file_types=KTJ,
        pattern=re.compile(r'System\.exit\('),
        description="Forcing process termination from application code skips normal lifecycle cleanup "
                     "and is almost never appropriate on Android.",
        recommendation="Let the framework manage the process lifecycle; call finish()/finishAffinity() on "
                        "an Activity instead if you need to close the app.",
    ),
    dict(
        id="commented-out-code-block",
        title="Large block of commented-out code",
        severity="info", category="code_smell", cwe=None, file_types=KTJ + JS_TS,
        pattern=re.compile(r'(?:^[ \t]*//.*\n){4,}', re.MULTILINE),
        description="Long stretches of commented-out code clutter the file and drift out of sync with "
                     "the real implementation over time.",
        recommendation="Delete it — version control already has the history if it's needed again.",
    ),
    dict(
        id="hardcoded-ip-address",
        title="Hardcoded IP address",
        severity="info", category="code_smell", cwe="CWE-200", file_types=KTJ + JS_TS,
        pattern=re.compile(r'"(?!0\.0\.0\.0|127\.0\.0\.1|255\.255\.255\.255)(\d{1,3}\.){3}\d{1,3}"'),
        description="A hardcoded IP address is inflexible (can't be changed without a release) and can "
                     "reveal internal infrastructure.",
        recommendation="Use a configurable hostname/endpoint (build config, remote config, or DNS) "
                        "instead of a literal IP.",
    ),
]

ALL_RULES = VULNERABILITY_RULES + VULNERABILITY_RULES_MANIFEST + BUG_RULES + CODE_SMELL_RULES
CATEGORIES = sorted({r["category"] for r in ALL_RULES})
RULES_BY_ID = {r["id"]: r for r in ALL_RULES}
