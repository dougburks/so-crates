"""Application-wide configuration constants for SO-CRATES.

All tunable numeric values (size limits, timeouts, thresholds) are centralized
here so they can be adjusted for different deployments without scattering edits
across the codebase.
"""

# Size limits
# MAX_UPLOAD_SIZE is the hard ceiling enforced server-side (see
# socrates.py's _resolve_upload_size_limit) - any client-requested override,
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
SQLITE_TIMEOUT_SECONDS = 30
FILE_COMMAND_TIMEOUT = 10
RULES_DOWNLOAD_TIMEOUT = 60
YARA_SCAN_TIMEOUT = 300
SURICATA_UPDATE_TIMEOUT = 60
SURICATA_SOURCE_RECONCILE_TIMEOUT = 30      # per enable-source/disable-source subprocess call
SURICATA_RUN_TIMEOUT = 300                 # 5 minutes max for a single PCAP
SIGMA_RUN_TIMEOUT = 300                    # 5 minutes max for Zircolite log analysis

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
MAX_ENTROPY_READ_SIZE = 10 * 1024 * 1024   # 10 MB cap for entropy calculation

# Thresholds
STALE_THRESHOLD_SECONDS = 600              # 10 minutes
