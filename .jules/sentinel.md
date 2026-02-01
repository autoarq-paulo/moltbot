## 2026-01-28 - Security Headers and Control UI XSS Prevention

**Vulnerability:** The Moltbot Gateway and associated servers (Media, Browser Control) lacked standard security headers, increasing the risk of MIME-type sniffing, clickjacking, and cross-origin information leakage. Additionally, the Control UI injected configuration data into `<script>` tags using raw `JSON.stringify`, which is vulnerable to XSS if a string contains `</script>`.

**Learning:** Even internal-first applications benefit significantly from "Defense in Depth" security measures like standard HTTP headers. Templating data into scripts is a common XSS vector that is often overlooked when using simple `JSON.stringify`.

**Prevention:**
- Always set `X-Content-Type-Options: nosniff` and `X-Frame-Options: SAMEORIGIN` (or `DENY`) on all HTTP responses.
- When injecting JSON into HTML script tags, escape `<` as `\u003c` to prevent tag-breaking and XSS.

## 2026-02-05 - Path Traversal Prefix Matching and Header Consistency

**Vulnerability:** The Control UI was vulnerable to a "partial path traversal" because the root directory check used `startsWith` without ensuring the root path ended in a trailing separator. This would allow access to sibling directories starting with the same name (e.g., `/var/www-secret` could be accessed if the root was `/var/www`). Additionally, `isSafeRelativePath` only checked for forward-slash traversal, which could be bypassed on Windows using backslashes. Standard security headers were also missing from the standalone Canvas Host server.

**Learning:** When validating paths using `startsWith`, always ensure the root path ends with a directory separator. For web applications, always explicitly reject backslashes in relative paths to prevent OS-specific traversal bypasses. Consistency in security headers across all entry points is essential for defense in depth.

**Prevention:**
- Use the `applyStandardSecurityHeaders` utility for all HTTP responses.
- When validating subpaths, append `path.sep` to the root directory before checking with `startsWith`.
- Reject backslashes and null characters in user-provided relative paths.

## 2026-02-12 - Path Traversal in Memory Retrieval

**Vulnerability:** The Memory Index Manager's `readFile` method was vulnerable to partial path traversal (sibling directory access). It checked if the resolved path started with the workspace directory string without ensuring the prefix ended in a directory separator. This would allow an agent to read files from sibling directories like `workspace-secret/` if the intended workspace was `workspace/`.

**Learning:** Path containment checks using `startsWith` are dangerous unless the root path is guaranteed to end with a directory separator. Relative path validation should always include checks for null characters to prevent logic bypasses in path resolution.

**Prevention:**
- When using `startsWith` for directory containment, always append `path.sep` to the root directory first.
- Explicitly check for and reject null characters (`\0`) in user-provided relative paths.
