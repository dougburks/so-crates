# API Reference

Base URL: `http://localhost:8000`

All endpoints return `Content-Type: application/json` unless noted. Errors return `{"error": "<message>"}` with the appropriate HTTP status code - except `501` for an unsupported method, which is the HTTP server's own HTML error page.

## Request Requirements

These apply to every request, before any endpoint-specific checks:

- **Host header:** a DNS name other than `localhost` is rejected with `403` unless it's allowed by the `ALLOWED_HOSTS` environment variable (see [Configuration](configuration.md)); IP literals always work
- **Cross-site POSTs:** a POST whose `Origin` names an untrusted host, or whose `Sec-Fetch-Site` is `cross-site`, is rejected with `403`
- **JSON bodies:** every POST endpoint that takes a JSON body - all of them except `/api/upload` (multipart) and `/api/csp-report` - requires `Content-Type: application/json` (`415` otherwise) and a JSON object body of at most 1 MB (`MAX_REQUEST_BODY_SIZE`)
- **Methods:** only GET and POST are served. `HEAD` returns `405` with `Allow: GET, POST` and no body; other methods return `501`
- **Unknown paths** return `404` with a JSON error

## Static Paths

| Path | Serves |
|---|---|
| `/socrates.html`, `/static/*` | The app itself |
| `/cyberchef` | `301` redirect to `/cyberchef/` |
| `/cyberchef/*` | The bundled [CyberChef](https://github.com/gchq/CyberChef), served from `CYBERCHEF_DIR` with its own Content-Security-Policy (see [Security Model](architecture/security-model.md)) |
| `/favicon.ico` | `204`, no body (each theme sets its own favicon) |

Directory listings are never served (`404`).

## GET Endpoints

### `GET /`

Redirects to `/socrates.html`.

---

### `GET /api/version`

Returns the running SO-CRATES version.

**Response:** `{"version": "4.4.0"}`

---

### `GET /api/version-check`

Checks GitHub's releases API for a newer SO-CRATES version. Only ever called by the frontend if the user has opted in (the "Check GitHub for newer releases" checkbox in the About modal, or its manual "Check Now" button) - never fetched automatically otherwise.

**Response:** `{"currentVersion": "<version>", "latestVersion": <string or null>, "updateAvailable": <boolean>}` - `latestVersion`/`updateAvailable` stay `null`/`false` on any failure to reach GitHub (never surfaces an error to the caller).

---

### `GET /api/theme`

Reads the active OhMyDebn theme's name and color palette, for the opt-in "Sync theme to OhMyDebn theme" feature. A no-op (`theme`/`customColors` both `null`) unless the `OHMYDEBN_THEME_DIR` environment variable is set.

**Response:** `{"theme": <string or null>, "customColors": <object or null>}` - `theme` is the raw theme name (from `<OHMYDEBN_THEME_DIR>/current/theme.name`) if it's set and passes a loose name-format check, else `null`. `customColors` is a set of ~25 CSS custom-property name/hex-value pairs synthesized from the theme's `colors.toml`/`alacritty.toml` palette (see [Themes](themes.md)), or `null` if no theme directory is configured or no palette could be derived.

---

### `GET /api/theme-sync-available`

Tells the frontend whether the "Sync theme to OhMyDebn theme" toggle could ever do anything, so it isn't shown as a dead control on deployments not launched via OhMyDebn.

**Response:** `{"available": <boolean>}` - `true` iff `OHMYDEBN_THEME_DIR` is set and its `current/theme.name` file is currently readable (regardless of whether its *contents* are valid - that's `/api/theme`'s concern).

---

### `GET /api/events`

Returns event data from Suricata's eve.json (via SQLite index or direct JSON parse).

**Query Parameters:**

| Parameter | Required | Default | Description |
|---|---|---|---|
| `md5` | Yes | - | MD5 hash of a historical analysis (`400` if omitted) |
| `type` | No | all | Filter by event type - any `event_type` Suricata's eve.json can produce (see [Event Types](architecture/event-types.md)), plus the app's own synthetic types (`filealerts`, `log`, `protocol_decode`, and `email`/`link` in an email analysis). Sigma alerts live in their own table and are served by `GET /api/sigma-alerts`, not here. |
| `q` | No | none | Full-text search query (searches all event JSON). Multiple `q` params AND together. |
| `offset` | No | `0` | Pagination offset. A non-integer `offset` or `limit` returns an empty list (`200`), not an error |
| `limit` | No | `1000` | Max events to return (capped at `MAX_QUERY_LIMIT`, 100,000 by default - see `GET /api/limits`) |
| `order_by` | No | none (sorts by `timestamp`) | Server-side sort column, e.g. `Source IP`. Only sortable for columns with a static JSON path for the given `type` (mirrors the same source-of-truth constraint as `GET /api/aggregation-data`); silently falls back to `timestamp` if the column isn't server-sortable for that type, rather than erroring |
| `sort_dir` | No | `asc` | `asc` or `desc`; any other value is treated as `asc` |
| `acknowledged` | No | none | `only` returns *only* acknowledged rows (see `POST /api/acknowledge-alert`) instead of the default, which excludes them entirely - used solely by the Acknowledged Alerts tab's own fetches |

**Response:** Array of eve.json event objects. Any event with a saved row-level
note (see `POST /api/row-note`) includes an extra `row_note` field with the
note text; events with no note omit the field entirely rather than sending
an empty string.

**Example:**
```text
GET /api/events?md5=<hash>&type=alert&limit=100
GET /api/events?md5=<hash>&q=192.168.1.1
GET /api/events?md5=<hash>&type=http&q=GET
GET /api/events?md5=<hash>&q=tcp&q=80          # AND: events containing both "tcp" and "80"
```

---

### `GET /api/stats`

Returns event-type counts for the current or specified analysis.

**Query Parameters:**

| Parameter | Required | Default | Description |
|---|---|---|---|
| `md5` | Yes | - | MD5 hash of a historical analysis |
| `q` | No | none | Full-text search query (counts only matching events). Multiple `q` params AND together. |

**Response:** `{"counts": <event type to count map>, "date_range": {"min": <timestamp or null>, "max": <timestamp or null>}}`

**Example:**
```json
{"counts": {"alert": 42, "dns": 1500, "http": 380, "tls": 95, "flow": 2200},
 "date_range": {"min": "2026-02-03T11:13:50.123456+0000", "max": "2026-02-03T11:16:02.654321+0000"}}
```

---

### `GET /api/count`

Returns total event count, optionally filtered by type or search query.

**Query Parameters:**

| Parameter | Required | Default | Description |
|---|---|---|---|
| `md5` | Yes | - | MD5 hash of a historical analysis |
| `type` | No | all | Filter by event type |
| `q` | No | none | Full-text search query (counts only matching events). Multiple `q` params AND together. |
| `acknowledged` | No | none | `only` counts *only* acknowledged rows instead of excluding them - see `GET /api/events`'s own `acknowledged` param |

**Response:** `{"count": <number>}`

---

### `GET /api/limits`

Returns server-enforced limits the client should respect (e.g. when validating the user-configurable query-limit setting).

**Response:** `{"maxQueryLimit": <number>, "maxUploadSize": <number>}` - `MAX_QUERY_LIMIT` (100,000 by default) and `MAX_UPLOAD_SIZE` in bytes (5,000 MB by default); both are hard ceilings that any client-requested override (`limit=`, or the `X-Max-Upload-Size` upload header) is clamped to server-side, regardless of what the client requests.

---

### `GET /api/rules-info`

Returns on-disk rule counts, last-updated times, and staleness for all three rulesets, for the Rules modal (gear menu > Rules) and the opt-in stale-rules notification (`checkForStaleRules()`). Purely a snapshot of what's currently on disk - no job/update state involved (that's `/api/rule-update-status`'s job), and no network access either.

**Response:** `{"suricata": {"count": <number or null>, "updated": <epoch or null>, "stale": <boolean or null>}, "yara": {"count": ..., "updated": ..., "stale": ...}, "sigma": {"windows": {"count": ..., "updated": ..., "stale": ...}, "linux": {...}}, "staleThresholdHours": <number>}` - `count`/`updated`/`stale` are all `null` if that ruleset has never been set up (rather than `stale: true`, since "never downloaded" is a different, more urgent problem the Rules modal's counts already surface, distinct from "downloaded but old"). `stale` is `true` once `updated` is older than `staleThresholdHours` (the server's `config.RULES_MAX_AGE_HOURS`) - the single source of truth both the Rules modal's own date-color warning and the notification read, rather than each hardcoding its own threshold.

The `suricata` object additionally carries the rule-source configuration the Rules modal edits via `POST /api/update-rules`: `enabledSources` (currently enabled slugs), `showProtocolDecodeAlerts` (boolean), `availableSources` (map of every known slug to its metadata, each with a `bakedIn` boolean telling the modal whether enabling that source for the first time needs internet), `defaultSources` (what "Revert to Default" restores - served here so the frontend can't drift from `DEFAULT_SURICATA_SOURCES`), and `sidRanges` (an array of `{"min", "max", "label"}` signature-ID ranges, the single source of truth `classifyRuleset()` in `static/socrates.js` uses to attribute an alert's `signature_id` to its ruleset).

---

### `GET /api/rule-update-status`

Returns the live/last-run state of each ruleset's update job, polled by the Rules modal while open.

**Response:** `{"suricata": {"running": <boolean>, "lines": [<string>, ...], "done": <boolean>, "error": <string or null>}, "yara": {...}, "sigma": {...}}` - `lines` accumulates progress messages for the current (or most recent) run of that ruleset.

---

### `POST /api/update-rules`

Starts an update for one ruleset, or all three. Triggered by the Rules modal's per-ruleset "Update" buttons and its "Update All" button.

**Request body:** `{"ruleset": "suricata"|"yara"|"sigma"|"all"}` - plus two optional Suricata-only fields (ignored for the other rulesets even under `"all"`): `sources`, a list of Suricata rule-source slugs to enable (validated against `SURICATA_RULE_SOURCES`), and `showProtocolDecodeAlerts`, a boolean.

**Response:** `{"status": "started"}`

**Errors:** `400` if `ruleset` isn't one of the four allowed values, if `sources` isn't a list of strings or names an unknown slug, or if `showProtocolDecodeAlerts` isn't a boolean. `409` ("Rule update already in progress") if the targeted ruleset (or, for `"all"`, any one of the three) is already running.

---

### `GET /api/sankey-data`

Returns a pre-aggregated `{nodes, links}` Sankey diagram (Source IP → Dest IP → Dest Port) computed server-side via `GROUP BY`, so the payload stays small regardless of how many events match - the client never needs to fetch raw events to render the diagram.

**Query Parameters:**

| Parameter | Required | Default | Description |
|---|---|---|---|
| `md5` | Yes | - | MD5 hash of the analysis |
| `type` | No | all | Filter by event type |
| `q` | No | none | Full-text search query. Multiple `q` params AND together. |

**Response:**
```json
{"nodes": [{"id": "0:1.2.3.4", "name": "1.2.3.4", "column": 0}, ...],
 "links": [{"source": "0:1.2.3.4", "target": "1:5.6.7.8", "value": 42}, ...]}
```
Each column is capped to the top 50 nodes by event count; the remainder is bucketed into a synthetic `Other` node per column so the response size doesn't grow with the dataset. `column` is `0` (Source IP), `1` (Dest IP), or `2` (Dest Port).

Unfiltered (no `q`) responses are cached server-side per `(md5, type)` and invalidated on delete/reanalyze - repeat requests for the same view are effectively instant.

---

### `GET /api/aggregation-data`

Returns per-column frequency tables (one page of values by count, 10 per page by default) for the given event type, computed server-side - the data behind the "Aggregations" panel.

**Query Parameters:**

| Parameter | Required | Default | Description |
|---|---|---|---|
| `md5` | Yes | - | MD5 hash of the analysis |
| `type` | No | all (merged view) | Event type (see [Event Types](architecture/event-types.md)), or omitted for the merged "All Events" view. Not supported for event types whose fields have no static JSON path to aggregate on server-side - currently `log`/`sigmaalert`/`binary` (dynamic/untrusted columns), `mqtt`/`ldap` (dynamically keyed by message/operation subtype) and `email`/`link`. These fall back to client-side computation instead (the UI also computes every tab of an email analysis client-side); see `AGGREGATION_JSON_PATHS` in `db.py` for the authoritative, current list. |
| `q` | No | none | Full-text search query. Multiple `q` params AND together. |
| `column` | No | none (all columns) | Restrict the response to a single column label, for paginating one column at a time |
| `page` | No | `1` | Page number for Prev/Next pagination; non-numeric values fall back to `1` |
| `page_size` | No | `10` | Values per page. Only `10`/`25`/`50`/`100` are accepted (the exact `AGG_PAGE_SIZE_OPTIONS` the "Items per page" selector offers); anything else falls back to the default 10 rather than erroring |

**Response:** Object mapping column label to an array of `{"value": ..., "count": ...}`, sorted descending by count and capped to one page (`page_size` values, default 10).
```json
{"Protocol": [{"value": "TCP", "count": 1200}, {"value": "UDP", "count": 340}],
 "Source IP": [{"value": "10.0.0.5", "count": 88}, ...]}
```

Unfiltered (no `q`) responses are cached server-side per `(md5, type, column, page, page_size)` (the Sankey cache's plain `(md5, type)` key doesn't apply here since these responses vary per page).

---

### `GET /api/aggregation-totals`

Returns the distinct-value count per aggregation column, matching the same column set and filtering as `/api/aggregation-data` - fetched once per section open/filter change (not on every Prev/Next click) so the client can compute page counts for `/api/aggregation-data`'s per-page results (a page can come back shorter than `page_size` purely because its offset is near the end, not because that's the overall total).

**Query Parameters:**

| Parameter | Required | Default | Description |
|---|---|---|---|
| `md5` | Yes | - | MD5 hash of the analysis |
| `type` | No | all (merged view) | Event type, or omitted for the merged "All Events" view. Same server-side-aggregation constraint as `/api/aggregation-data` - unsupported types return an empty object. |
| `q` | No | none | Full-text search query. Multiple `q` params AND together. |

**Response:** Object mapping column label to its total distinct-value count; columns with no values are omitted.
```json
{"Protocol": 2, "Source IP": 340}
```

Unfiltered (no `q`) responses are cached server-side per `(md5, type)`, same as `/api/sankey-data`.

---

The four stream endpoints below (`download-stream`, `ascii-stream`, `hexdump-stream`, `raw-stream`) share their parameter checks: `400` for an invalid IP, port or MD5, `404` if the analysis has no PCAP, and `500` if the packet tool times out - in addition to each one's own errors.

### `GET /api/download-stream`

Carves a single TCP/UDP stream from the PCAP using `tcpdump` and returns it as a `.pcap` download.

**Query Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `src` | Yes | Source IP address |
| `sport` | Yes | Source port |
| `dst` | Yes | Destination IP address |
| `dport` | Yes | Destination port |
| `md5` | Yes | MD5 hash of a historical analysis |

**Response:** `application/vnd.tcpdump.pcap` file download.

**Validation:** IP addresses and ports are validated before passing to tcpdump. Invalid values return `400`.

**Errors:** `404` if no packets match, `413` if the carved stream is over 200 MB (`MAX_STREAM_DOWNLOAD_SIZE`) - never a truncated file, `500` if carving times out.

---

### `GET /api/ascii-stream`

Extracts ASCII payload from a TCP/UDP stream using `tshark`. Tries TCP first, falls back to UDP. Capped to the first 500 lines (`MAX_TRANSCRIPT_LINES`) and to 100,000 characters (`MAX_TRANSCRIPT_SIZE`), whichever is hit first.

**Query Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `src` | Yes | Source IP address |
| `sport` | Yes | Source port |
| `dst` | Yes | Destination IP address |
| `dport` | Yes | Destination port |
| `md5` | Yes | MD5 hash of a historical analysis |

**Response:** `application/json` - `{"lines": [{"text": "...", "direction": "src"|"dst"}, ...], "truncated": false, "proto": "tcp"|"udp"}`. Each entry is one packet's payload, with non-printable characters replaced with `.`, tagged with which side of the connection sent it. TCP retransmissions are left out. `proto` says which protocol the flow was found as: the app joins a TCP stream's consecutive same-direction entries into one byte stream before splitting it into lines, but keeps each UDP datagram separate.

---

### `GET /api/hexdump-stream`

Extracts per-packet hex dumps from a TCP/UDP stream using `tcpdump -X`. Truncated to 100,000 characters or 500 packets.

**Query Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `src` | Yes | Source IP address |
| `sport` | Yes | Source port |
| `dst` | Yes | Destination IP address |
| `dport` | Yes | Destination port |
| `md5` | Yes | MD5 hash of a historical analysis |

**Response:** `application/json` - `{"packets": [{"header": "...", "lines": ["..."]}], "truncated": false}`.

**Validation:** IP addresses and ports are validated before passing to tcpdump. Invalid values return `400`.

---

### `GET /api/raw-stream`

Returns a TCP/UDP stream's exact payload bytes - nothing decoded, replaced or trimmed, unlike `/api/ascii-stream`. The flow is carved with `tcpdump`, then reassembled with `tshark`'s `follow ... raw` mode, which drops retransmitted segments and orders out-of-order ones. Tries TCP first, falls back to UDP.

**Query Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `src` | Yes | Source IP address |
| `sport` | Yes | Source port |
| `dst` | Yes | Destination IP address |
| `dport` | Yes | Destination port |
| `md5` | Yes | MD5 hash of a historical analysis |
| `direction` | No | `src` (bytes sent by `src`:`sport`), `dst` (bytes sent by the other side), or `both` (default - everything, in capture order) |

**Response:** `application/octet-stream` download.

**Errors:** `400` for invalid parameters, `404` if the flow has no payload in that direction, `413` if the payload is over 10 MB (`MAX_RAW_STREAM_SIZE`) - never a truncated payload. The size check covers the whole flow, so asking for one small direction of a flow whose other direction is huge also returns `413`.

---

### `GET /api/extracted-file`

Returns a file Suricata extracted from the analysis's traffic - or, for an email analysis, the message itself or one of its attachments - by its SHA256 (the `fileinfo.sha256` field of a `fileinfo` event).

**Query Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `md5` | Yes | MD5 hash of a historical analysis |
| `sha256` | Yes | Lowercase hex SHA256 of the extracted file |

**Response:** `application/octet-stream` download of the file's exact bytes.

**Errors:** `400` for an invalid `md5` or `sha256`, `404` if no file with that hash was stored (Suricata logs a `fileinfo` event for every transfer, but only stores files it could fully reassemble), `413` if the file is over 25 MB (`MAX_EXTRACTED_FILE_SIZE`). The file is looked up by hash only, inside the analysis's `filestore/` - no path is ever accepted from the client.

---

### `GET /api/analyses`

Lists all previously-analyzed files.

**Response:** Array of `{"md5": "<hash>", "name": "<display name>", "date_range": {"min": "<ISO timestamp or null>", "max": "<ISO timestamp or null>"}, "has_notes": <bool>}` sorted alphabetically by name. `date_range` reflects the sample's own event timestamps (not upload time), and is `{"min": null, "max": null}` if the analysis has no `events.db` yet. `has_notes` is `true` if a `notes.txt` file exists for the analysis.

---

### `GET /api/load-analysis`

Loads a historical analysis by MD5.

**Query Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `md5` | Yes | MD5 hash of the analysis to load |

**Response:**
```json
{"success": true, "md5": "<hash>", "file_name": "<filename>", "notes": "<notes text or empty string>"}
```

**Errors:** `400` if MD5 is invalid or path is unsafe. `404` if analysis not found. `400` if eve.json exceeds size limit.

---

### `GET /api/pcap-path`

Returns the filename (not the full filesystem path) of the PCAP file within an analysis's directory.

**Query Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `md5` | Yes | MD5 hash of the analysis |

**Response:** Plain text - the PCAP's filename only. `404` if no PCAP found.

---

### `GET /api/status`

Same status information as `POST /api/check-status`, but accessible via query parameters for read-only polling.

**Query Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `md5` | Yes | MD5 hash of the analysis |

**Response:**
```json
{"status": "ready", "meta": {"version": 1, "original": "<filename>", "extracted": "<filename>", "detected_type": "pcap", "extracted_at": "<ISO timestamp>"}, "hasRowNotes": false}
```
or
```json
{"status": "processing", "phase": "network", "meta": {...}, "hasRowNotes": false}
```
or, if analysis (Suricata/YARA/Zircolite/email parsing) failed:
```json
{"status": "error", "message": "<failure reason>", "hasRowNotes": false}
```

`meta` is present whenever `.meta` exists for the analysis (written after the file type is detected) and is omitted otherwise; it's absent entirely from the `error` response.

`hasRowNotes` is `true` if the analysis has at least one row-level note, and always `false` while it isn't ready (see `POST /api/row-note`) - used by the reanalyze confirmation dialog to conditionally warn that reanalyzing deletes them. This field is added only on this GET route, not on the identically-shaped `POST /api/check-status` response below - that endpoint is polled every 2 seconds during active processing, and the extra lookup has no reason to run that often.

**Errors:** `400` for invalid or malformed MD5. There is no `404` for a well-formed MD5 that doesn't correspond to an existing analysis directory - the directory's absence just reads the same as "not ready yet" (`{"status": "processing", "phase": ""}`), since this endpoint never separately checks for the directory's existence.

---

### `GET /api/sigma-alerts`

Returns Sigma alerts stored in `events.db` for the specified analysis.

**Query Parameters:**

| Parameter | Required | Default | Description |
|---|---|---|---|
| `md5` | Yes | - | MD5 hash of a historical analysis (`400` if omitted) |
| `offset` | No | `0` | Pagination offset. A non-integer `offset` or `limit` returns an empty list (`200`), not an error |
| `limit` | No | `1000` | Max alerts to return (capped at `MAX_QUERY_LIMIT`, 100,000 by default - see `GET /api/limits`) |
| `severity` | No | none | Filter by severity level |
| `q` | No | none | Full-text search query. Multiple `q` params AND together. |
| `acknowledged` | No | none | `only` returns *only* acknowledged alerts instead of excluding them - see `GET /api/events`'s own `acknowledged` param |

**Response:** Array of Sigma alert objects. Same `row_note` field convention
as `GET /api/events` above (present only when a note exists).

---

### `GET /api/sigma-count`

Returns the total Sigma alert count for the specified analysis, optionally filtered.

**Query Parameters:**

| Parameter | Required | Default | Description |
|---|---|---|---|
| `md5` | Yes | - | MD5 hash of a historical analysis |
| `severity` | No | none | Filter by severity level |
| `q` | No | none | Full-text search query. Multiple `q` params AND together. |
| `acknowledged` | No | none | `only` counts *only* acknowledged alerts instead of excluding them |

**Response:** `{"count": <number>}`

---

### `GET /api/sigma-stats`

Returns Sigma alert statistics (per-severity counts, total, and MITRE techniques) for the specified analysis.

**Query Parameters:**

| Parameter | Required | Default | Description |
|---|---|---|---|
| `md5` | Yes | - | MD5 hash of a historical analysis (`400` if omitted) |

**Response:** `{"by_severity": {"<severity>": <count>, ...}, "total": <number>, "mitre_techniques": ["<technique id>", ...]}` - `by_severity` is ordered critical/high/medium/low, and `mitre_techniques` is a sorted list of unique technique IDs (not counts). An empty object if the analysis has no `sigma_alerts` table.

---

### `GET /api/playbook`

Returns Security Onion Playbook investigation guidance (plain-English
questions to ask, per detection rule) for a Suricata or Sigma alert. Global
static reference data baked into the Docker image - unlike almost every
other route in this API, this one takes no `md5` and isn't scoped to an
analysis.

**Query Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `type` | Yes | `nids` (Suricata) or `sigma` |
| `id` | Yes | For `type=nids`, the alert's `signature_id` (1-10 digits). For `type=sigma`, the alert's `rule_id` (a UUID) |

**Response:** `{"playbook": {"name": "...", "description": "...", "questions": [{"question": "...", "context": "..."}, ...]}}` if a playbook exists (an exact match for that rule, or the generic engine-wide fallback if not), or `{"playbook": null}` if none is baked in at all (e.g. a manual install with nothing baked in, or an image built without the Dockerfile's `resources-builder` stage).

**Errors:** `400` if `type` isn't `nids`/`sigma` or `id` doesn't match the expected shape for that type.

---

### `GET /api/ai-summary`

Returns an AI-generated one-paragraph summary ("what this rule detects") for
a Suricata, Sigma, or YARA rule. Global static reference data baked into the
Docker image - same as `/api/playbook` above, this one takes no `md5` and
isn't scoped to an analysis.

**Query Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `type` | Yes | `nids` (Suricata), `sigma`, or `yara` |
| `id` | Yes | For `type=nids`, the alert's `signature_id` (1-10 digits). For `type=sigma`, the alert's `rule_id` (a UUID). For `type=yara`, the rule's name (bare identifier, up to 200 characters) |

**Response:** `{"summary": "..."}` if a summary exists for that exact rule,
or `{"summary": null}` if none is baked in (e.g. a manual install with
nothing baked in, an image built without the Dockerfile's `resources-builder`
stage, or a rule with no summary upstream). Unlike `/api/playbook`, there is
no engine-wide fallback - a summary for the wrong rule would be misleading.

**Errors:** `400` if `type` isn't `nids`/`sigma`/`yara` or `id` doesn't match the expected shape for that type.

---

## POST Endpoints

### `POST /api/upload`

Uploads a file for analysis. Accepts multipart form data.

**Request:** Multipart form with a file field. Accepts any file type, detected by content rather than name: PCAPs (by magic bytes, whatever the extension - e.g. `.pcap`, `.pcapng`, `.cap`, `.trace`, or none at all) get full Suricata network analysis; log files (recognized by content, or by a `.evtx`, `.json`, `.jsonl`, `.csv`, `.xml` or `.log` extension) get Zircolite Sigma detection; email messages (an `.eml` extension, or content that starts with an email's header block) get email analysis - headers, links and decoded attachments, each YARA-scanned - unless over 100 MB (`MAX_EMAIL_SIZE`), when they're scanned as a plain file; everything else gets YARA scanning. A known extension decides before content does. The same detection applies to each member of an uploaded ZIP.

**Size limit:** 1000 MB by default (`DEFAULT_UPLOAD_SIZE`). An `X-Max-Upload-Size` header (in bytes) can raise it, up to 5000 MB (`MAX_UPLOAD_SIZE`). A body over the limit is rejected with `400` ("Invalid Content-Length"), and `507` means the server doesn't have the disk space for it. A ZIP with more than 100 members (`MAX_ZIP_MEMBERS`) is rejected with `400`; files whose own names start with `.` or `__` (e.g. `.DS_Store`, or anything under `__MACOSX/`) are ignored, whatever their type, but still count toward that limit.

**Response (new file):**
```json
{"status": "processing", "md5": "<hash>", "phase": "network"}
```

or for non-PCAP files:

```json
{"status": "processing", "md5": "<hash>", "phase": "files"}
```

or for log files:

```json
{"status": "processing", "md5": "<hash>", "phase": "logs"}
```

or for email messages:

```json
{"status": "processing", "md5": "<hash>", "phase": "email"}
```

If the upload was a ZIP archive containing more than one supported file, every extracted file is analyzed, each as its own independent analysis - PCAPs get network analysis, everything else gets log, email, or binary analysis. One exception: hidden members (see the size-limit note above) are silently ignored - they get no analysis and aren't counted in `filesSkipped`. The response describes the primary file (a PCAP takes priority; otherwise the first non-hidden file) and gains an `additionalMd5s` array with the MD5 of every other file's analysis; a `filesSkipped` field appears only if individual files genuinely failed (hashing, commit, or filename-validation errors), with that count:

```json
{"status": "processing", "md5": "<hash>", "phase": "network", "additionalMd5s": ["<hash>", "<hash>"], "filesSkipped": 1}
```

**Response (already analyzed):**
```json
{"status": "ready", "md5": "<hash>"}
```

**Processing flow:**
1. Detects file type (PCAP magic bytes, log content, or ZIP `PK` magic bytes - except files with Office extensions like `.docx`/`.xlsx`, which are ZIPs internally but analyzed as regular files)
2. Computes MD5 hash
3. If already analyzed (`eve.json` for PCAPs, `events.db` for non-PCAPs), returns `ready`
4. For PCAPs: saves file, spawns Suricata in background thread, returns `processing` with `phase: "network"`
5. For log files: saves the file and imports it into `events.db` in the background, returns `processing` with `phase: "logs"`
6. For email messages: saves the message, then in the background parses it into `email`/`link` events and stores and YARA-scans the message and each decoded attachment (in the analysis's `filestore/`, the same layout Suricata uses), returns `processing` with `phase: "email"`
7. For other files: saves file, runs YARA/EXIF scans in the background, returns `processing` with `phase: "files"`
8. When analysis finishes, results are available in `events.db` (or `eve.json` for PCAPs)

**Special handling:** Password-protected zips are auto-decrypted using the common `infected` password; if the filename contains a `YYYY-MM-DD` date, the MTA-style dated password (`infected_YYYYMMDD`) is also tried.

**Client should poll** `POST /api/check-status` with the returned MD5 to know when analysis is complete.

---

### `POST /api/load-sample`

Analyzes one of the sample files built into SO-CRATES - the main screen's **Sample PCAP file** (`pcap`), **Sample log file** (`log`, a Sysmon JSON log), **Sample binary file** (`binary`, the payload from the sample story) and **Sample email file** (`email`). The sample is generated by the server (see `samples.py`), so this needs no internet access, and it is processed the same way as an upload. The sample is identical every time, so a second request returns `ready` for the existing analysis.

**Request Body:**
```json
{"name": "email"}
```

**Response:** the same as `POST /api/upload` - e.g. `{"status": "processing", "md5": "<hash>", "phase": "email"}`, or `{"status": "ready", "md5": "<hash>"}` once it has been analyzed.

**Errors:** `400` (`Unknown sample`) for any other name.

---

### `POST /api/load-url`

Downloads a file from a URL and analyzes it.

**Request Body:**
```json
{"url": "https://example.com/capture.pcap"}
```

An optional `maxUploadSize` field (in bytes) raises the download size limit the same way `/api/upload`'s `X-Max-Upload-Size` header does.

**Response:** Same as `/api/upload` - `{"status": "processing", "md5": "...", "phase": "..."}` or `{"status": "ready", "md5": "..."}`.

**Special handling:**
- Password-protected zips are auto-decrypted using the common `infected` password (same as `/api/upload`); for `malware-traffic-analysis.net` URLs specifically, the date-based password format (`infected_YYYYMMDD`, derived from the URL's `/YYYY/MM/DD/` path) is also tried, before the plain fallback
- URL safety validation blocks localhost, private IPs, link-local, and non-HTTP schemes
- Hostname is resolved to verify the resolved IP is not private

**Errors:** `400` for invalid URL or SSRF attempt. `413` if file exceeds upload size limit. `507` if the server doesn't have the disk space.

---

### `POST /api/check-status`

Polls whether analysis has finished for an uploaded file.

**Request Body:**
```json
{"md5": "<hash>"}
```

**Response:**
```json
{"status": "ready", "meta": {"version": 1, "original": "<filename>", "extracted": "<filename>", "detected_type": "pcap", "extracted_at": "<ISO timestamp>"}}
```
or
```json
{"status": "processing", "phase": "network", "meta": {...}}
```
or, if analysis (Suricata/YARA/Zircolite) failed:
```json
{"status": "error", "message": "<failure reason>"}
```

The `phase` field reflects the current analysis stage (`network`, `logs`, `email`, `files`, or `importing` - the SQLite build that runs after the YARA scan, just before results are ready), or an empty string if no phase file exists yet. `meta` is present whenever `.meta` exists for the analysis and omitted otherwise (including on the `error` response). Same "no 404 for a well-formed-but-nonexistent MD5" caveat as `GET /api/status` applies here too.

**Ready detection:** the same check for every file type - `events.db` exists and no `.phase` file is still present (`events.db` is created the instant ingest starts, well before it finishes, so its existence alone isn't sufficient; `.phase` stays set for exactly that ingest window).

---

### `POST /api/reanalyze`

Re-runs the analysis pipeline for an existing MD5 directory. The original uploaded file is preserved; the previous analysis outputs (`eve.json`, `events.db`, etc.) are removed and regenerated.

**Request Body:**
```json
{"md5": "<hash>"}
```

Only `md5` is read from the request body - the response's `phase` is determined automatically from what's actually in the analysis's directory (`network` if a PCAP is found, `logs` for a log file, `email` for an email message, otherwise `files`), not accepted as client input.

**Response:**
```json
{"status": "processing", "md5": "<hash>", "phase": "network"}
```

**Errors:** `400` for invalid MD5 or unsafe path. `404` if the analysis doesn't exist or contains no analyzable file. `409` if analysis is already in progress. `500` if Suricata fails to start (the failure reason from the analysis's `.error` file, e.g. Suricata missing or a permissions problem - distinguished from the `409` case by whether `.error` was written).

---

### `POST /api/delete-analysis`

Deletes a single historical analysis (removes the entire MD5 directory).

**Request Body:**
```json
{"md5": "<hash>"}
```

**Response:**
```json
{"success": true}
```

**Errors:** `400` for invalid MD5 or unsafe path. `404` if analysis not found.

---

### `POST /api/rename-analysis`

Sets a custom display name for an analysis, overwriting `name.txt`. Only changes what's displayed (header, previous-analyses list) - the real originally-uploaded filename is unaffected, preserved separately in `.meta`'s `original` field.

**Request Body:**
```json
{"md5": "<hash>", "name": "<new display name>"}
```

The name is trimmed, has embedded newlines collapsed to spaces, and is capped at 255 characters.

**Response:**
```json
{"success": true, "name": "<new display name>"}
```

**Errors:** `400` for invalid MD5, unsafe path, or an empty/whitespace-only name. `404` if analysis not found.

---

### `POST /api/analysis-notes`

Sets (or clears) freeform investigation notes for an analysis, overwriting `notes.txt`. Unlike `/api/rename-analysis`, embedded newlines are preserved verbatim (multi-line notes are the point), and an empty submission is a valid way to clear notes rather than an error.

**Request Body:**
```json
{"md5": "<hash>", "notes": "<notes text>"}
```

The notes are trimmed and capped at 10,000 characters. An empty (or whitespace-only) value deletes `notes.txt` if present.

**Response:**
```json
{"success": true, "notes": "<notes text>"}
```

**Errors:** `400` for invalid MD5, unsafe path, or non-string notes. `404` if analysis not found.

---

### `POST /api/row-note`

Sets (or clears) a freeform note on one row of the `events` or `sigma_alerts`
table - the row-scoped counterpart to `POST /api/analysis-notes` above (a
short annotation on one specific alert/event, not the whole analysis). Same
clear-on-empty convention.

**Request Body:**
```json
{"md5": "<hash>", "table": "events", "rowId": 42, "note": "<note text>"}
```

`table` must be `"events"` or `"sigma_alerts"`. `rowId` must be an integer
(not a boolean - Python's `bool` is a subclass of `int`, so this is checked
explicitly). The note is trimmed and capped at 500 characters
(`MAX_ROW_NOTE_LENGTH`, distinct from `MAX_NOTES_LENGTH`'s 10,000 for
whole-analysis notes). An empty (or whitespace-only) value clears the note.

**Response:**
```json
{"success": true, "note": "<note text>"}
```

**Errors:** `400` for invalid MD5, unsafe path, invalid `table`, invalid
`rowId`, or non-string `note`. `404` if analysis not found.

Row-level notes are lost on `POST /api/reanalyze` (it rebuilds `events.db`
from scratch) - unlike whole-analysis notes (`notes.txt`), which reanalyze
never touches. This is intentional, not a bug.

---

### `POST /api/acknowledge-alert`

Acknowledges or un-acknowledges one row of the `events` or `sigma_alerts`
table - the single-row counterpart to `POST /api/acknowledge-alerts-bulk`
below. Acknowledging removes the row from every other endpoint's default
results immediately (it's excluded server-side, not just hidden client-side)
- see the `acknowledged` param on `GET /api/events`/`GET /api/count`/
`GET /api/sigma-alerts`/`GET /api/sigma-count` above, which is the only way
to see acknowledged rows again.

**Request Body:**
```json
{"md5": "<hash>", "table": "events", "rowId": 42, "acknowledged": true}
```

`table` must be `"events"` or `"sigma_alerts"`. `rowId` must be an integer
(not a boolean). `acknowledged` defaults to `true` if omitted; set it to
`false` to un-acknowledge.

**Response:**
```json
{"success": true, "acknowledged": true}
```

**Errors:** `400` for invalid MD5, unsafe path, invalid `table`, invalid
`rowId`, or non-boolean `acknowledged`. `404` if analysis not found.

Acknowledged state is scoped to the current analysis only and, like
row-level notes, is lost on `POST /api/reanalyze`.

---

### `POST /api/acknowledge-alerts-bulk`

Acknowledges every id in `rowIds` in one call - the "all instances of this
alert" bulk path (the matching id set is computed client-side from
whatever's already loaded, not by a server-side signature/rule lookup).
No bulk un-acknowledge counterpart - undoing is always one row at a time,
via `POST /api/acknowledge-alert` from within the Acknowledged Alerts tab.

**Request Body:**
```json
{"md5": "<hash>", "table": "events", "rowIds": [42, 43, 44]}
```

`table` must be `"events"` or `"sigma_alerts"`. `rowIds` must be a
non-empty array of integers (not booleans), capped at `MAX_QUERY_LIMIT`
(100,000 by default - see `GET /api/limits`).

**Response:**
```json
{"success": true, "count": 3}
```

**Errors:** `400` for invalid MD5, unsafe path, invalid `table`, or invalid
`rowIds` (wrong type, empty, non-integer/boolean entries, or too many).
`404` if analysis not found.

---

### `POST /api/delete-all-analyses`

Deletes all historical analyses (every MD5-shaped directory under the data root). Non-analysis directories and files are left untouched.

**Request Body:** `{}` - the content is ignored, but it must be sent as a JSON object with `Content-Type: application/json` (`415` otherwise), like every other JSON POST.

**Response:**
```json
{"success": true, "deleted": 5}
```

**Errors:** `500` if every analysis directory fails to delete.

---

### `POST /api/csp-report`

Sink for Content-Security-Policy violation reports - every response's CSP names it as its `report-uri`, so browsers POST here when they block something. Accepts any `Content-Type` (browsers send `application/csp-report`), reads at most 64 KB, and logs each distinct violation (by directive, blocked URI, source file and line) once to the server's console. The one violation the bundled CyberChef causes on every load - `frame-src`, from its loading animation - is expected and not logged.

**Response:** `204`, no body - even for a malformed report. A missing, invalid or over-64 KB `Content-Length` gets `400`.

---

## Error Codes

| Code | Meaning |
|---|---|
| `400` | Invalid input (bad IP, port, MD5, URL, path traversal), or an upload over the size limit |
| `403` | Untrusted `Host` header, or a cross-site POST - see [Request Requirements](#request-requirements) |
| `404` | Resource not found (no file, no analysis, no packets) |
| `405` | `HEAD` request |
| `409` | Conflict - analysis already in progress for this MD5 |
| `413` | Too large to return in full (a carved stream, stream payload or extracted file) or to download (`/api/load-url`) |
| `415` | A JSON POST without `Content-Type: application/json` |
| `500` | Internal server error (no stack traces or server paths leaked) |
| `507` | Not enough disk space available on the server for this upload |
