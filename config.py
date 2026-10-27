"""Application-wide configuration constants for SO-CRATES.

All tunable numeric values (size limits, timeouts, thresholds) are centralized
here so they can be adjusted for different deployments without scattering edits
across the codebase.
"""

# Size limits
# MAX_UPLOAD_SIZE is the hard ceiling enforced server-side (see
# storage.py's resolve_upload_size_limit) - any client-requested override,
# including the user-configurable frontend setting, is always clamped to
# this value. DEFAULT_UPLOAD_SIZE is what's used when no override is sent
# (preserves the old fixed ceiling for any caller that doesn't opt in).
MAX_UPLOAD_SIZE = 5000 * 1024 * 1024       # 5000 MB
DEFAULT_UPLOAD_SIZE = 1000 * 1024 * 1024   # 1000 MB
MAX_EVE_SIZE = 5000 * 1024 * 1024          # 5000 MB
MAX_REQUEST_BODY_SIZE = 1024 * 1024        # 1 MB
MAX_TRANSCRIPT_SIZE = 100000               # characters
DISK_SPACE_SAFETY_MARGIN = 100 * 1024 * 1024  # 100 MB buffer kept free on disk-space checks

# Query / display limits
# MAX_QUERY_LIMIT is the hard ceiling enforced server-side (see
# socrates.py's _parse_pagination) - any client-requested `limit=`,
# including the user-configurable frontend setting, is always clamped to
# this value regardless of what the client asked for.
MAX_QUERY_LIMIT = 100000
MAX_TRANSCRIPT_LINES = 500
MAX_HEXDUMP_PACKETS = 500

# Timeouts (seconds)
STREAM_TIMEOUT_SECONDS = 60
URL_DOWNLOAD_TIMEOUT = 30
URL_DOWNLOAD_MAX_SECONDS = 3600            # a whole download (URL_DOWNLOAD_TIMEOUT is per read, which a trickle never trips)
SQLITE_TIMEOUT_SECONDS = 30
FILE_COMMAND_TIMEOUT = 10
RULES_DOWNLOAD_TIMEOUT = 60
YARA_SCAN_TIMEOUT = 300
SURICATA_UPDATE_TIMEOUT = 60
SURICATA_SOURCE_RECONCILE_TIMEOUT = 30      # per enable-source/disable-source subprocess call
SURICATA_RUN_TIMEOUT = 300                 # 5 minutes max for a single PCAP
SIGMA_RUN_TIMEOUT = 300                    # 5 minutes max for Zircolite log analysis
SHARK_RUN_TIMEOUT = 1800                   # 30 minutes max for one tshark run - it runs in the background at low priority, after Suricata
STALE_TMP_SECONDS = 2 * 3600               # what a dead server left in /tmp is removed at startup once this old (storage.cleanup_stale_tmp) - well past the longest anything there lives, a tshark run's folder (SHARK_RUN_TIMEOUT, plus the 10 minutes the build gets after it)

# Sigma / Zircolite
ZIRCOLITE_VERSION = '3.7.1'
SIGMA_RULES_SUBDIR = 'sigma-rules'

# Rules freshness
# Zircolite-Rules-v2 and Emerging Threats Open both ship (roughly) daily;
# YARA Forge ships weekly. A single shared threshold can't match all
# three cadences at once, and this is tuned toward catching the two daily
# feeds falling behind promptly rather than toward YARA Forge's slower
# one - this was 7 days (a "wait for a whole missed YARA Forge release"
# ceiling) until reconsidered, since that let Sigma/Suricata coverage
# silently drift for most of a week (6+ missed daily releases) before
# anyone was told, which was judged worse than occasionally flagging
# YARA a few days before its own release cadence would strictly warrant.
# It's the single source of truth for "how old is too old", read by:
#   - get_suricata_rules_info()/get_yara_rules_info()/get_sigma_rules_info()
#     ('stale' field), which drives both static/socrates.js's opt-in
#     checkForStaleRules() notification and the Rules modal's own
#     amber-date warning (isRulesetStale()/formatDateSpan(), which read it
#     via /api/rules-info's staleThresholdHours rather than hardcoding
#     their own separate threshold - the two used to disagree, 24h vs a
#     30-day frontend-only constant, until they were unified here).
# Note: is_file_stale(rules_file, RULES_MAX_AGE_HOURS) is also still
# computed inside setup_yara_rules()/setup_sigma_rules() to decide whether
# to attempt an actual network refresh, but as of the network-consent
# changes described in AGENTS.md's "Detection Rule Freshness" section,
# every current caller passes either force=True (the value doesn't matter,
# force short-circuits it) or network_allowed=False (the download branch
# is unreachable either way) - so that particular check is presently dead
# code, kept only because a future caller with network_allowed=True,
# force=False could reactivate it.
RULES_MAX_AGE_HOURS = 2 * 24  # 2 days

# Uploads
UPLOAD_TMP_SUBDIR = 'upload-tmp'

# Search / analysis limits
MAX_SEARCH_TERM_LENGTH = 200               # characters
MAX_DISPLAY_NAME_LENGTH = 255               # characters - user-renamed analysis display name
MAX_NOTES_LENGTH = 10000                    # characters - user-entered analysis notes
MAX_ROW_NOTE_LENGTH = 500                   # characters - row-scoped counterpart to MAX_NOTES_LENGTH, a short annotation not a second full notes field
HASH_CHUNK_SIZE = 65536                    # bytes for incremental hashing
MAX_STRINGS_READ_SIZE = 2 * 1024 * 1024    # 2 MB cap for string extraction
MAX_ZIP_MEMBERS = 100                      # files per uploaded ZIP - each member becomes its own analysis (and pcaps each spawn a Suricata process), so an unbounded count is a fork-bomb vector
MAX_STREAM_TEXT_OUTPUT = 4 * 1024 * 1024   # 4 MB cap on raw tshark/tcpdump text read for transcripts/hexdumps - the response is trimmed to MAX_TRANSCRIPT_* far below this; without a read cap a huge stream buffers fully in RAM first
MAX_STREAM_DOWNLOAD_SIZE = 200 * 1024 * 1024  # 200 MB cap on a carved-stream pcap download; larger streams get a 413 rather than a partial (corrupt) file
MAX_TRANSCRIPT_CARVE_SIZE = 16 * 1024 * 1024  # 16 MB cap on the flow carved for an ASCII transcript - it's held in memory, and written to /tmp (often RAM), and the transcript shows no more than MAX_TRANSCRIPT_LINES/MAX_TRANSCRIPT_SIZE anyway; a longer flow is read up to the cut and marked truncated
MAX_ENTROPY_READ_SIZE = 10 * 1024 * 1024   # 10 MB cap for entropy calculation
MAX_RAW_STREAM_SIZE = 10 * 1024 * 1024     # 10 MB cap on /api/raw-stream's exact payload bytes - it feeds the browser (CyberChef), which gets sluggish well before MAX_STREAM_DOWNLOAD_SIZE; larger payloads get a 413, never a truncated one
MAX_EXTRACTED_FILE_SIZE = 25 * 1024 * 1024  # 25 MB cap on /api/extracted-file, for the same reason

# Email (.eml) analysis - see email_analyzer.py. These bound the memory,
# event count and nesting a crafted message can produce; what they cut off
# is reported as a warning on the email.
MAX_EMAIL_ATTACHMENTS = 100                # attachments decoded and analyzed per message (nested forwards included)
MAX_EMAIL_LINKS = 1000                     # link events per message
MAX_EMAIL_DEPTH = 5                        # levels of forwarded messages (message/rfc822 parts) parsed
MAX_EMAIL_MESSAGES = 50                    # forwarded messages parsed per upload, at any depth
MAX_EMAIL_SIZE = 100 * 1024 * 1024         # bigger .eml files are analyzed as plain files - parsing holds the message and its decoded attachments in memory
MAX_EMAIL_BODY_CHARS = 65536               # characters of body text kept in the email event

# tshark (shark_analyzer.py) - a run's memory grows with a capture's
# packet count (its connections, really), not its size: tshark's own and
# the build's flow table together, ~1.1 KB per packet measured - 2.9 GB
# for the 2.27 million packets of a 209 MB capture, 3.9 GB for 3.53
# million. A run whose processes together pass SHARK_MAX_MEMORY_BYTES is
# stopped, and only captures up to SHARK_BACKGROUND_MAX_PACKETS are
# analyzed without being asked - bigger ones run when the user requests
# them (and may hit the memory limit). 3 million keeps a run that starts
# on its own about 0.7 GB under the limit.
SHARK_MAX_MEMORY_BYTES = 4 * 1024 ** 3
SHARK_BACKGROUND_MAX_PACKETS = 3_000_000
# ... and only up to this size when the packets can't be counted (no capinfos)
SHARK_BACKGROUND_MAX_BYTES = 250 * 1024 * 1024
SHARK_MEMORY_CHECK_SECONDS = 0.5

# Thresholds
STALE_THRESHOLD_SECONDS = 600              # 10 minutes
