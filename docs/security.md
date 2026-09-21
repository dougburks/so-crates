# Security

SO-CRATES is designed to run locally/self-hosted for an analyst examining
potentially malicious files. What's built in by default (see
[Security Model](architecture/security-model.md) for implementation details
- function names, exact mechanisms):

- **Network binding** - `127.0.0.1` by default; only the Docker/Podman image binds `0.0.0.0` internally (for port-publishing), with actual exposure still controlled by the `-p`/port choice at run time; container users who want local-only exposure should publish with `-p 127.0.0.1:8000:8000` instead of `-p 8000:8000` (which binds all host interfaces)
- **No CORS** - no cross-origin access is allowed, not even a wildcard
- **Cross-site request defenses** - DNS-name `Host` headers other than localhost are rejected unless allowlisted via the `ALLOWED_HOSTS` environment variable (IP literals always work; exact names, `*.suffix` wildcards, or `*` to opt out), blocking DNS rebinding; POSTs with a cross-site `Origin` or `Sec-Fetch-Site` header are rejected; and JSON endpoints require `Content-Type: application/json`, which browsers cannot send cross-site without a CORS preflight - together blocking CSRF against the local instance
- **Strict Content Security Policy** - `script-src 'self'` with no inline-script carve-out (all handlers are wired via delegated listeners; the theme bootstrap is an external file), so injected markup renders as inert text instead of executing; the policy's `report-uri` logs any violation server-side via `/api/csp-report`
- **Input validation** - on all endpoints (IP, port, MD5, path traversal)
- **File-type routing** - PCAPs, log files, and everything else each only ever reach their own analyzer (Suricata, Zircolite/Sigma, YARA)
- **SSRF protection** - on "Load from URL", including a DNS-rebinding-safe resolve-then-connect
- **Zip safety** - zip-slip and zip-bomb (decompressed-size) protection on archive extraction
- **Upload limits** - a hard size ceiling plus an upfront disk-space check before accepting an upload
- **Generic error messages** - no internal details or stack traces leaked
- **Content-Security-Policy** - sent on every response, along with `X-Frame-Options: DENY` and `X-Content-Type-Options: nosniff`
- **Non-root container** - the Docker/Podman image runs as a non-root user
- **No startup network calls** - rule refresh is always an explicit, on-demand action from the Rules modal, never automatic
