# Release Notes

## 4.2.0

### Security hardening

The HTTP layer no longer trusts its network position. DNS-name `Host`
headers other than localhost are rejected to block DNS rebinding (IP
literals still work; set the new `ALLOWED_HOSTS` environment variable
for reverse-proxy/hostname deployments), cross-site POSTs are rejected
via `Origin`/`Sec-Fetch-Site`, and JSON endpoints require
`Content-Type: application/json` - together blocking CSRF against a
local instance. Also fixed: an encoded path-traversal read through
`/static/`, an SSRF bypass via a hostname resolving to `0.0.0.0`, and
unbounded server-side caches. Analyzer artifact filenames are reserved
so an upload can't spoof or clobber results, uploaded ZIPs are capped at
100 members, stream carving no longer buffers unbounded output in
memory, and both compose files now publish `127.0.0.1:8000:8000` by
default (the LAN-wide form is left as a comment).

### Strict Content Security Policy

`script-src` no longer allows inline script: every inline handler
attribute was converted to delegated event listeners and the theme
bootstrap moved to its own file, so an escaping bug in HTML rendering
would now produce inert text instead of executing. The policy's
`report-uri` logs any future violation server-side.

### DNS Heuristics fixes

The DNS Heuristics card no longer shows a count carried over from a
previously viewed analysis (whose tab then said "No suspicious DNS
activity detected"), and no longer goes missing until a page reload
when an analysis is opened while still processing. Two false-positive
classes are gone: deep-but-ordinary subdomain chains (entropy is now
scored per label) and long hyphenated word-mashup labels (the tunneling
check now requires a low vowel ratio, like the DGA check). The
exclusion list gained the missing Akamai suffixes and common OS/vendor
domains (Microsoft, Google, Apple, Mozilla, etc.) - DGA and tunneling
require an attacker-controlled domain, which those are not.

### UX and accessibility

Oversized uploads are caught before uploading, with a message naming
the limit and pointing at Settings. The bulk-acknowledge truncation
warning no longer auto-dismisses, toasts last 3.5s, the analysis-timeout
message notes the analysis may still finish in the background, and the
truncation banner links to Settings. Sample cards and the drop zone are
keyboard-accessible, theme tiles preview on focus as well as hover, and
confirm dialogs manage focus properly. The Rules modal no longer eats
the first click after its 2-second poll rebuilds the modal body (seen as
"Revert to Default, then Update needs two clicks"), aggregation tables
page deterministically when values have tied counts, and the Security
Onion comparison modal fits a 1080p display without scrolling.

### Documentation and website

so-crates.org has a new landing page: hex-rain hero with the SO-CRATES
artwork, feature cards, the demo video and screenshot tour in
Linux-style window frames with lightbox zoom, and a theme chooser using
eight of the app's own palettes. The docs went through a full accuracy
audit against the code (API reference, configuration, installation,
architecture), Usage became a section with sub-pages, the Themes
gallery lazy-loads its screenshots, and credits now cover the
documentation site's dependencies and the artwork's provenance.

## 4.1.0

### DNS Heuristics

A new **DNS Heuristics** tab groups every DNS query in the capture by
registrable domain and flags the ones that look like DNS tunneling or DGA
(Domain Generation Algorithm) malware, sitting right before DNS Queries
whenever anything trips a flag. Five independent signals feed a 0-100
score: a high-entropy subdomain prefix under an otherwise ordinary parent
domain (the classic tunneling shape); a high-entropy, low-vowel-ratio
registrable domain itself (the DGA shape - vowel ratio, not entropy
alone, is what actually separates a random-looking-but-real word mashup
like `furtheringthemagic.com` from genuine DGA output, which lands at
nearly identical raw entropy); 15 or more distinct subdomains queried
under the same parent (fan-out, not just repeated lookups of the same
name); an unusually long query name or label; and TXT/NULL record types,
more associated with tunneling/exfil tooling than ordinary browsing.
Known CDN suffixes are allowlisted out before scoring to cut noise.
Clicking a flagged domain searches for it and jumps straight to DNS
Queries to see the underlying events. A collapsible "About DNS
Heuristics" info card explains the scoring up front, since this tab
behaves nothing like any other data-type tab - rows are aggregated
per-domain rather than raw events, and clicking one navigates away
rather than expanding a detail panel in place.

### Community ID correlation and TLS fingerprinting

Suricata's `community-id` output is now force-enabled on every analysis
(it ships off by default) - a single deterministic `community_id` field
on flow/alert records that lets SO-CRATES's output correlate against
Zeek and other community-id-aware tools without anyone needing to
discover the setting exists. A new **Correlate** entry in the pivot
menu puts that to use directly: click any field on a row that has a
community ID and Correlate searches for every other log across the
whole capture sharing that same flow, network protocol events and
alerts alike. It's suppressed when the clicked value already *is* the
community ID itself, since Hunt right above it already does the exact
same whole-analysis search in that case. JA3/JA3S/JA4 TLS
client/server fingerprinting is force-enabled the same way - Suricata
only computes these when an active rule's signature keyword happens to
require them, so without this the fields were silently absent from
`tls` events whenever none of the currently-enabled curated rule
sources referenced ja3/ja4. All three now show up as their own rows in
a TLS row's detail panel whenever present.

### Keyboard navigation refinements

Several real gaps surfaced through actual use of 4.0.0's keyboard
navigation, all fixed now. With a multi-row stat-card grid, Right/Down
tracking follows whichever card is actually under the keyboard ring
instead of always snapping back to the active tab's own column - Right
into a different column, then Down, now continues straight down that
column instead of jumping back to the original one. The filter bar's
chips and Clear All button are a single Left/Right-cycled horizontal
group now instead of separate Down/Up stops, so Down from a chip goes
straight to the data-type cards rather than stepping through Clear All
first. Opening a fresh analysis, applying a filter, or performing a
search now seeds keyboard focus on the resulting position (the default
tab's card, or the new filter chip) instead of requiring an extra,
wasted first arrow press to "arrive" there - a typed search's own chip
gets a visible ring immediately, matching how a deliberate action should
read, while a passive rebuild (an acknowledge action, a query-limit
change) seeds the same starting position invisibly. Clearing filters
returns focus to the first data-type card once none remain, or stays on
whatever chip is left after a partial clear. Log analysis and
binary/file analysis now get all of the above too - they'd never gotten
the same fresh-load seeding PCAP analysis had, and log analysis
specifically had its own separate bug where a stat card could end up
with no tab-active card at all whenever Sigma alerts were absent (the
common case), silently breaking Down/Up navigation on the grid entirely.

### Pivot menu: Include/Exclude/Only inside expanded rows

A field clicked inside an expanded row's detail panel now gets the same
Include/Exclude/Only menu a table-cell click on the identical
underlying data already did, for far more fields than before. Most
detail-panel labels are more descriptive prose than the terse column
header a table cell uses for the same field (DNS's "Query Name" vs. the
column "Query", HTTP's "User Agent" vs. "User-Agent", and a dozen more
like it across other event types) - a verified label-to-column mapping
now bridges the gap. Log analysis had its own, more pervasive version of
the same mismatch: every detail field is labeled with the raw underlying
JSON field name (e.g. "CommandLine"), not the human column label
("Command Line") table headers use - now converted automatically. A
Sigma alert's own "Matched Event" section goes further still, since none
of its fields (e.g. Computer) have a fixed column at all - filtering on
them now works via the same generic field lookup the underlying log
extraction logic already supported internally, without guessing which
fields are actually safe to allow through.

### Aggregation Tables: pagination, page size, and keyboard navigation

Aggregation Tables used to show only the top 10 values per column with no
way to see more. Each table now pages through its values with Prev/Next
controls instead of growing the page - so a table full of long,
variable-width values (a DNS query column, say) never reflows the surrounding
layout or shifts a Next button out from under your cursor as you click
through it. An "Items per page" selector (10/25/50/100) applies to every
table in the currently-open section at once and persists across
sessions, matching how theme/collapse-state preferences already do.
Pagination is keyboard-driven too: Left/Right jumps directly to a
different table instead of stepping through every row to reach it; Down
walks a table's own rows and, once it reaches the last one, its Prev/Next
stop, then continues into the next *visual row* of tables (not just the
next table in source order, which for a multi-column layout is usually a
same-row sibling reachable via Left/Right instead) or the Data Table if
there isn't one - Up retraces the same path in reverse, all the way back
out through the Data Table if you page past the top. Left/Right toggles
between Prev and Next once you've arrived at that stop, and Enter
activates whichever one is highlighted without losing keyboard focus
afterward.

### Fixed while preparing this release

- The command palette's "Open X"/"Go to Y" entries (Themes, Rules,
  Settings, Notes, every data-type tab, Search) were trimmed to just
  their target name, matching how every other entry already read -
  "Go to Search bar" in particular shortened to just "Search".
- A stray keyboard-selection ring could be left behind on a stat card
  after a plain mouse click switched to a different tab, since nothing
  previously cleared it outside the keyboard-driven navigation paths -
  now cleared as part of the click itself.
- Typing a theme's name into the command palette (e.g. `ethereal`)
  matched the theme by name but not by "theme" itself, since only the
  bare name was searchable text.

## 4.0.0

### Acknowledge alerts

A noisy analysis - the same benign Suricata or Sigma signature firing
hundreds of times - used to have no way to mark it "seen, not
interesting" short of scrolling past it forever. The pivot menu on any
Network Alert or Sigma Alert row now offers **Acknowledge this alert**
and **Acknowledge all instances of this alert**: acknowledging removes
the row from every view immediately (Network Alerts/Sigma Alerts, All
Events, the Sankey diagram, and every count), not just a dimmed row
still sitting in the list. A new **Acknowledged Alerts** stat-card tab
is the only place they still show, for review or undo via
**Un-acknowledge this alert** - grouped under separate Network Alerts
and Sigma Alerts sub-sections when both have acknowledged rows, or
displayed as a single sortable table (identical to that type's own tab)
when only one does. Un-acknowledging the last remaining row switches
back to Network Alerts automatically. Acknowledging is scoped to the
current analysis only and persists in that analysis's own database, the
same as a row note.

### Full keyboard navigation

Arrow keys now drive navigation across the whole app instead of just
scrolling the page. On the welcome screen, Left/Right moves between the
sample-file cards and Up/Down moves between rows in Previous Analyses; on
an analysis page, Left/Right switches stat-card tabs and Up/Down moves
through the visible data table's rows (including a binary/YARA analysis,
whose table renders with no `.section` wrapper around it, unlike every
pcap/log tab). Enter activates whatever's currently highlighted - opens a
sample, jumps to a previous analysis, or expands/collapses a table row,
the same as clicking it. Escape returns to the welcome screen from
anywhere, closing one thing at a time (a modal, the gear menu, a pivot
menu) before it ever leaves the current analysis.

The Themes modal gets its own arrow-key grid navigation: all four arrows
move a highlight through the tile grid and call the same live-preview
hover uses on every move, Up/Down jump by a real detected row (read back
from the grid's own `getComputedStyle`, not a hardcoded column count) so
they behave like Up/Down instead of Left/Right, and the first press
starts relative to whichever theme is currently active rather than always
restarting from a corner of the grid.

On an analysis page, keyboard reach now extends past the stat-card tabs
and data table: the Sankey Diagram and Aggregation Tables section headers
can be expanded/collapsed with Enter and stay selected afterward, so
collapsing one back down after looking at something inside it means
arrowing straight back to it rather than re-navigating from the top.
Up/Down can also move onto aggregation table values, filter bar chips,
and everything inside an expanded row's detail panel - Add Note, ASCII
Transcript, Hexdump, Download PCAP, Expand All/Collapse All, and
individual packets. Left/Right stays scoped to the stat-card tabs until
Up/Down is pressed at least once, at which point it becomes
context-sensitive to whichever section is currently selected instead -
cycling ASCII Transcript/Hexdump/Download PCAP as one group, or Expand
All/Collapse All as another, rather than always jumping stat-card tabs.
Escape now closes an open pivot menu without also leaving the whole
analysis, and arrow-key selection scrolling accounts for the fixed
header and footer instead of occasionally landing a selection underneath
one of them.

Since theme-cycling used to be bound to the `t` key - colliding with
typing several of the app's own theme cheat codes (`retro`, `digit` both
contain a `t`) - it moved first to the arrow keys, then to `<`/`>` once
arrow keys took on real in-app navigation duties instead.

### Command Palette

Typing any letter or digit outside a text field now opens a command
palette pre-filled with what was typed, replacing the old theme
cheat-code shortcuts entirely - keep typing to narrow the list, Up/Down
to highlight a candidate, Enter to commit it, Escape to cancel without
doing anything. A query matches anywhere in a candidate, not just its
very first word - typing `alerts` finds both Network Alerts and File
Alerts, `blue` finds every Fun theme with "Blue" in its name, and even a
bare mid-word fragment like `eme` finds Open Themes. A match at the very
start ranks above a word-boundary match, which ranks above a bare
mid-word match, so a short, precise query never gets buried under
mid-word noise. It matches every theme's own name (switching to it
directly, same as picking it
from the Themes modal), every data-type stat-card tab currently on
screen, and a long list of shortcuts that used to require the gear menu
or a page reload: `help`, `about`, `themes`, `rules`, `settings`,
`notes`, `delete`, `re-analyze`, `search`, `clear`, `sankey`,
`aggregation`, `advanced features`, `documentation`, `security onion`,
`github repo`, `pcap samples`, `log samples`, `binary samples`,
`upload`, `import`, `previous analyses`, `copy md5 hash to clipboard`,
and `rename analysis`. The Themes modal keeps its own separate, lighter
type-ahead - typing a theme's name there jumps the grid highlight
straight to it without opening the palette at all, the same native
`<select>`-style convention the grid's own arrow-key navigation already
uses.

### A cleaner main screen

Re-analyze and Delete moved off the welcome screen's Previous Analyses
list entirely, onto the analysis page header next to the existing Notes
icon - a row on the main screen now shows just its name and, when
present, a notes indicator. Delete All moved out of the welcome screen
too, into a new Danger Zone section in Settings, which fetches a live
count of previous analyses on every open rather than relying on a count
handed in from an already-rendered list. Hacker theme's delete-related
controls (the header delete icon, Delete All) no longer force themselves
green to avoid clashing with the theme's monochrome CRT look - now that
neither one sits inline in a scrolling list of other rows, they just use
the theme's own red danger color like every other danger control does.

### Every file in a ZIP gets analyzed, not just the first one

Uploading (or loading from a URL) a `.zip` containing more than one
supported file used to only ever analyze the first one found, silently
dropping the rest - a real gap for sites like
malware-traffic-analysis.net, which regularly ship ZIPs with two or more
pcaps for a single incident. Every supported file extracted from a ZIP
is now analyzed independently: each pcap gets its own network analysis,
and each log/binary file gets its own log or file analysis, all in
parallel. A byte-identical duplicate within the same ZIP is only
analyzed once. Loading the ZIP still opens straight into the first file
found, same as before, with a toast linking to Previous Analyses for
anything else that was also analyzed alongside it - and, for a file that
genuinely couldn't be analyzed (rather than one intentionally skipped),
a separate toast reporting how many were skipped and why.

### New ambient theme backgrounds, and a reshuffled theme list

Breadbin Blue and CGA both traded their earlier sprite/starfield
animations for a proper demoscene-style plasma field (four combined sine
waves sampled on a coarse grid) - CGA's is additionally quantized through
an ordered Bayer dither down to the real 4-color CGA palette, a
period-authentic technique for simulating more colors than the palette
actually has. Amber CRT's background now prints boot-log-style lines one
at a time at randomized intervals instead of smoothly scrolling, closer
to how a real terminal fills a screen. DOS Blue's Norton-Commander-style
dual file panes now scale their name lists to fill the full viewport
height instead of capping out partway down.

A new **MP3 Player** fun theme joins the lineup - brushed-metal chrome
grays, a soft LCD-green readout, a cyan bezel highlight, and a bouncing
spectrum-analyzer background (cheat code `mp3`). The Daylight theme was
removed (existing users on it fall back to White, close enough visually
to not need a migration prompt), and Sguil moved from Fun Themes to Light
Themes, keeping its `sguil` cheat code.

Stat cards, sample cards, the pivot menu, and modals all switched from a
2-corner (top-left/bottom-right) HUD bracket to a proper 4-corner one -
still just two pseudo-elements per element, but each now paints two
adjacent corners via a stack of background gradients instead of a single
border-based L. Keyboard-selected sample cards and theme tiles now get
the same corner-bracket glow/border feedback mouse hover already gave
them, including each fun theme's own neon-glow treatment. Amber CRT was
missing its own bracket glow entirely (every other neon theme had one) -
now consistent.

### Fixed while preparing this release

- **A crafted filename could silently defeat YARA scanning entirely.**
  Uploaded filenames were sanitized against path traversal but not
  control characters - a filename containing an embedded newline became
  the real on-disk filename, which YARA's `--scan-list` input (one path
  per line) then split into two bogus entries, neither the real file. The
  pipeline still reported a clean, completed scan. `sanitize_filename` now
  rejects control characters (0x00-0x1F, 0x7F).
- **A Suricata analysis could get stuck "in progress" forever.** The
  background watchdog thread only caught a timeout; any other failure
  (an `OSError` from `proc.wait()`, a problem inside the post-processing
  phase) left the `.phase` lock file in place with nothing to clear it,
  and `spawn_suricata()`'s own re-entry guard refuses to start a new run
  while that lock exists. Every failure path now clears the lock and
  records an error.
- Several `/api/*` routes (`/api/events`, `/api/sigma-alerts`,
  `/api/sigma-stats`) silently returned `200` with empty data for a
  malformed or missing `md5`, unlike every sibling route, which returns a
  clean `400` - now consistent. A handful of other routes had no
  exception handling around their database queries at all; a DB error
  there reset the connection instead of returning a JSON error like
  everywhere else already did.
- A corrupted/truncated `eve.json` line that was syntactically valid JSON
  but not an object (a bare number, string, or array) aborted ingestion
  of the whole analysis instead of just that one line.
- The recorded demo video's very first frame could be captured before
  the page had fully painted into the recording viewport - visible as a
  small sliver of real content in the corner of an otherwise flat grey
  frame, exactly the thumbnail X/LinkedIn/etc. auto-extract when the raw
  file is uploaded directly. Trimmed automatically now. A caption in the
  same recording also called the sample pcap "built-in," which it isn't -
  it's a one-click link to a pcap hosted on malware-traffic-analysis.net,
  not something bundled with the app.

## 3.2.0

### Per-row notes

A small note icon on each table row (Suricata alerts, DNS/HTTP/TLS/flow
events, Sigma alerts, file/YARA matches, imported log events) lets an
analyst attach a short annotation to that specific piece of evidence -
"false positive, known scanner", "escalated to IR ticket #4521" - separate
from the existing whole-analysis Notes field. The icon reuses the same
modal component as analysis-level notes, scoped to the clicked row instead.
Row-level notes are lost on reanalyze (which rebuilds the underlying database from
scratch) - intentional, and now surfaced explicitly: the reanalyze
confirmation dialog shows a bold "WARNING! You have one or more notes on a
table row and these will be destroyed" line and turns the Re-analyze button
red, but only when the analysis actually has row-level notes to lose.

### Pivot menu: right-click-style Include/Exclude/Only/Hunt on any value

Clicking a value in a data table row, an expanded row's detail panel, or an
aggregation table now opens a pivot menu instead of immediately filtering or
expanding - **Include** (broaden the current search to also match this
value), **Exclude** (narrow it to hide this value), **Only** (start a new
search scoped to just this value, clearing every other filter), and **Hunt**
(a full-text search for this value across every field, replacing the whole
search - the one action that also clears any active search/filters
entirely). Each of Include/Exclude/Only carries a color-coded
magnifying-glass icon (green/red/blue) and an explanatory hover tooltip spelling out
exactly what clicking it will do with the real column/value substituted in.

The menu also offers **Copy to Clipboard** and one-click lookups against
Google, VirusTotal, Shodan, AbuseIPDB, urlscan.io, and CyberChef, plus
**user-defined custom lookup sites** (added/edited/removed from Settings,
with a `{value}` URL template) - all persisted per-browser, with strict
http/https-only URL validation on custom entries so a malicious saved
template can't execute as `javascript:`/`data:` when opened.

Because a click on a pivotable cell no longer expands the row, the menu also
carries an **Expand Row** entry (relabeled **Collapse Row** once the row is
already open) as a discoverable way back to the old behavior - the row's
timestamp cell still expands directly on click, as before.

This replaced the aggregation table's old single-click-to-filter behavior
entirely - clicking a value there now opens the same menu rather than
applying a filter immediately.

### AI-generated rule summaries

Expanding a Suricata alert, Sigma alert, or YARA file match now shows an
**AI Summary** row right at the top of Alert Details/Sigma Rule/Rule - a
one-paragraph, plain-English explanation of what the rule actually detects,
fetched only on first expand and shown only if a summary actually comes
back. Unlike Playbook's investigation questions, there's no generic
fallback here: a summary for the wrong rule would be actively misleading,
so a miss just shows nothing. A single row can show more than one of these
(a file with multiple YARA matches gets one summary per match).

Same baked-in-only shape as Playbooks and for the same reason - summaries
are generated from Security Onion's `securityonion-resources` repository
(`generated-summaries-published` branch), gzip-compressed down to a few MB
total across all three detection engines, with no runtime refresh
mechanism. Manual installs get nothing by default, but can point
`AI_SUMMARIES_DIR` at their own locally-built index.

### Security Onion Playbooks

Expanding a Suricata or Sigma alert now shows a **Playbook** section (after
Alert Details/Sigma Rule, before Notes) with plain-English investigation
guidance for that specific detection rule, or the generic baseline
guidance if no rule-specific playbook exists. It's fetched only on first
expand and shown only if a playbook actually comes back, so an install
with nothing baked in shows no trace of the feature at all. The (sometimes long)
questions list can be collapsed back down independently, while the
playbook's name and description stay visible either way.

Playbook data is baked into the Docker/Podman image from Security Onion's
own Playbooks repository (~15MB of gzip-compressed, English-only guidance -
the Elasticsearch/Sigma-syntax queries each question also carries aren't
portable to this app's SQLite store and are dropped entirely). Manual
installs get nothing by default, but can point `PLAYBOOKS_DIR` at their own
locally-built index. No runtime refresh mechanism - this is deliberately
baked-in-only, unlike the Suricata/YARA/Sigma rulesets, since guidance text
changes far less often than daily threat rulesets.

### Suricata protocol-decode-alert noise

Fixed per-source `suricata-update` invocations not passing `--disable-conf`,
which let "Generic Protocol Command Decode" and similar protocol-anomaly
alerts leak into results even when those alerts were disabled via
`disable.conf`. A new opt-in
`show_protocol_decode_alerts` setting (Rules modal) makes this noise
explicitly opt-in rather than an accident of the fetch wiring. When
enabled, these alerts now get their own dedicated "Decoder Alerts" tab
(ordered right after Network Alerts/File Alerts, colored to match
Anomalies since it's closely related - if not identical - signal) instead
of diluting Network Alerts. Same columns and detail view as a regular
alert, just without a Playbook section (there's no investigation guidance
for something that isn't a real detection).

### Smaller fixes and UI polish

- A reanalyze icon next to the notes icon in the analysis header re-runs
  the pipeline without leaving the page.
- Fixed an intermittent "Loading Sankey diagram..." that never resolved -
  the diagram now tracks its own fetch generation independently of the rest
  of the page, closing a bug class that had been patched piecemeal twice
  before for other unrelated actions.
- Stat cards now always show just the filtered count (e.g. `229,378`), not
  the old `229,378 / 229,831` form that could overflow a card's border on a
  large analysis; a data type that a search/filter reduces to zero is dropped
  from the grid entirely instead of shown as disabled.
- The test-suite/dev-server port-8000 collision is gone for good - JSDOM
  tests now run against an isolated fake origin instead of the app's real
  port, so `python3 socrates.py` no longer needs to be stopped before
  running tests.

### Fixed while preparing this release

- **The Docker/Podman image would not have started** - `playbook_lookup.py`
  was missing from the final stage's `COPY` line despite being imported
  unconditionally by `socrates.py`. The existing test meant to catch
  exactly this class of bug (a module added but never wired into the image)
  didn't, because it only checked whether the filename appeared *anywhere*
  in the Dockerfile, and `playbook_lookup.py` happened to already be named
  in three unrelated comments - the test now checks the actual `COPY`
  instruction's argument list specifically.
- The screenshot and demo-recording scripts (`scripts/capture_screenshots.py`,
  `scripts/record_demo.py`) predated the pivot menu and were clicking table
  rows and aggregation values directly, which now opens the pivot menu
  instead of expanding/filtering. Both scripts were updated to target the
  timestamp cell and the menu's Only/Include actions respectively.
- A double-escaping bug in the File Info detail panel's EXIF Metadata
  section could render a value containing `&`/`<`/`>`/`"` as garbled,
  doubly-escaped HTML entities.

## 3.1.0

### Rename an analysis, add notes, and click-to-copy the MD5

Clicking the filename in the analysis header now turns it into an
editable field - Enter or clicking away saves the new display name
(`POST /api/rename-analysis`), Escape cancels. Renaming only changes
what's displayed (header, Previous Analyses list); the real
originally-uploaded filename stays intact in `.meta`'s `original` field.
Fixed a real bug found while building this: reopening a renamed analysis
from the Previous Analyses list reverted the header back to the
*original* filename - `loadAnalysis()` was unconditionally overwriting
the already-correct, rename-aware display name with `.meta.extracted`
(the upload-time filename, which a rename never touches), a leftover
override that turned out to be entirely redundant even before renaming
existed, since `name.txt` and `.meta.extracted` always start identical
at upload time anyway. The filename is truncated with an ellipsis when
it's too long to fit - hovering it shows the full filename via a native
tooltip.

A new Notes field lets an analyst attach freeform investigation context
to an analysis ("suspected GuLoader, C2 at x.top", "false positive,
benign updater") - separate from rename, which only relabels the
analysis rather than annotating it. A small icon next to the MD5/date in
the analysis header opens a Notes modal (textarea, live character count,
explicit Save/Cancel - not autosave, since a modal already has an
obvious commit action); the icon itself is muted when there are no notes
and accent-colored once there are, so an analyst can tell at a glance
without opening it. Notes are stored as a plain-text `notes.txt` per
analysis (mirroring `name.txt`'s convention) and saved via a new
`POST /api/analysis-notes` - unlike rename, multi-line text is preserved
verbatim (not collapsed to a single line) and an empty submission is a
valid, intentional way to clear notes rather than a rejected empty name.

The Previous Analyses list also shows this same icon on any row that has
notes, so an analyst doesn't have to open every analysis just to check -
and clicking it jumps straight to that analysis and opens its Notes
modal in one step, rather than just the normal overview.

Two small bugs were caught and fixed while building this: the notes
button initially had no dedicated CSS rule and fell back to the
browser's default white button, which looked out of place next to the
dark-styled reanalyze/delete buttons beside it - now matches
`.previous-analysis-reanalyze`'s background/color treatment, including
its per-theme overrides. And any open modal (Notes included) used to
stay open if you navigated back to the Welcome screen via the
"SO-CRATES" logo - most confusing for Notes specifically, since it's
tied to the specific analysis you just left. `showWelcome()` now closes
every modal via a `closeAllModals()` helper shared with the existing
Escape-key handler.

Clicking the MD5 hash next to it copies it to the clipboard, with a
toast confirming success - or a clear error if `navigator.clipboard`
isn't available, which happens on any real HTTP (non-HTTPS) origin other
than the browser's `localhost`/`127.0.0.1` loopback exception (a common
way to reach a container's published port from another machine on the
same LAN).

Since the display name is now user-editable, two different analyses
could end up renamed to the same thing with nothing to tell them apart
in the Previous Analyses list. Each row's hover tooltip now shows the
sample's own date range instead of its MD5 - an analyst is far more
likely to recognize "when" than an MD5 fragment, and the MD5 is still
reachable via the row's href/status-bar URL, so showing it in the
tooltip too was redundant. Keeping the date range in the tooltip rather
than an inline span next to the name keeps the row itself uncluttered:
duplicates stay distinguishable on hover without restricting what
anything can be renamed to. `GET /api/analyses` now includes a
`date_range` field per analysis for this (`{"min": ..., "max": ...}`,
both `null` for an analysis still mid-processing with no `events.db`
yet); the tooltip falls back to the MD5 in that case.

### Rules modal: on-demand updates, sources, staleness, and readability

Suricata/YARA/Sigma rule updates no longer block server startup. A new
"Rules" entry in the gear menu opens a modal showing each ruleset's current
rule count and last-updated time, with an independent "Update" button per
ruleset plus "Update All". Startup now only does the fast local bootstrap
(no network) and prints a message pointing users at the new Rules modal
instead of the old startup rule-check.

While an update runs, a small spinner and an elapsed-time counter (`Updating…
45s`) show it's actively working, instead of the raw update log dumping
straight into the modal - that log (Suricata's `suricata-update` run in
particular can be dozens of lines) read as noisy for what's meant to be a
simple progress indicator. The actual log is still there for anyone who
wants it: a "View Log" toggle reveals it on demand, both while an update is
running and after it finishes, and "Hide Log" collapses it again without
losing the underlying output (still fetched via the same polling
`/api/rule-update-status` calls either way). Once an update finishes, a green checkmark
or red X appears next to that ruleset's Update button reflecting whether it
succeeded - a persistent complement to the existing completion toast, which
is easy to miss if you're not looking right when it fires. The icon only
appears after an update has actually run this session (never on first load,
before anything's been triggered), so it can't be mistaken for a stale
success/failure from a prior visit.

A manually-installed (non-Docker/Podman) deployment starts with zero
rules configured for all three engines - unlike the container image,
which bakes them all in and copies them into place before the server
ever accepts a request. Nothing breaks without rules (every analyzer
degrades gracefully - Suricata still parses full flow/protocol data with
just no alerts; YARA/Sigma attempt an on-demand background download on
the first real upload if internet is available), but there was
previously no indication to a new manual-install user that anything was
missing. A one-time sticky toast now appears on first load if
`/api/rules-info` shows no rules for all three engines, with an "Open
Rules" link straight to the Rules modal.

**Fixed a real report from this exact scenario**: the five "not
available"/"using cached" progress messages across all three engines
said "No internet access detected" unconditionally in their `else`
branch - which is reached both when a reachability check genuinely
failed *and* when `network_allowed=False` (server startup, which never
checks reachability at all by design, so it can't block on a slow or
unreachable mirror). A user on a machine with real internet access saw
this at every startup and reasonably suspected a bug. Each message now
distinguishes the two cases: "no internet access" is only ever printed
when a reachability check actually ran and failed; the startup
(never-checked) case instead prints a short, consistent
`WARNING! No <ruleset> rules found` for whichever ruleset(s) are
missing. These warnings state a fact, not an instruction - the startup
banner's existing "Tip! ... click the menu in the upper-right corner
and then select Rules." line (always printed, not just when something's
missing, since it's equally useful for a container install whose
baked-in rules might just be outdated) is what tells the user what to
do about it.

Each ruleset section now names and links to its actual upstream source -
Suricata to [Emerging Threats Open](https://rules.emergingthreats.net/),
YARA to [YARA Forge](https://github.com/YARAHQ/yara-forge), Sigma to
[SigmaHQ](https://github.com/SigmaHQ/sigma) - the same three projects
already listed in [Credits](credits.md), so an analyst can see what
they're actually pulling in before clicking Update.

Each ruleset's "updated" date is now colored with the warning color once
it's more than 30 days old (or was never successfully updated) - an
analyst previously had to notice and mentally calculate staleness from a
plain date string; now it's visible at a glance across all four dates
(Suricata, YARA, Sigma Windows, Sigma Linux).

- The modal now grows up to 1550px / 95% of viewport width and 92% of
  viewport height (up from a fixed 900px), and each ruleset's log box no
  longer has its own small fixed height - it sizes to its content, so the
  modal itself is the only scrollable region instead of three separate,
  cramped inner scrollbars. On a large enough screen, a full
  `suricata-update` run is visible with no scrollbars at all.
- Log lines now wrap instead of forcing a horizontal scrollbar on long
  lines (e.g. `suricata-update`'s "Writing rules to ..." summary line).
- Sections are now ordered YARA, Sigma, Suricata (shortest output to
  longest) instead of Suricata first, so the two quick rule-count
  summaries are visible without scrolling past Suricata's much longer,
  variable-length update log.

Startup itself is now quieter too: it no longer prints "No internet
access detected - using baked-in Suricata rules" or "Baked-in rules
copied successfully" - since startup never touches the network by
design, neither message reflected an actual check and was just
noise every time. The old "Rule updates are now managed from the web
interface..." line is now a friendlier tip:
"Tip! To check for rule updates, click the menu in the upper-right
corner and then select Rules."

### YARA Forge / Sigma rule freshness

`setup_yara_rules()`/`setup_sigma_rules()` previously used a cached rules
file forever once downloaded or copied from the Docker image, with no
freshness check - a long-lived install's rules could silently drift
arbitrarily far behind YARA Forge's weekly and Zircolite-Rules-v2's daily
upstream releases. Both now refresh a cached copy in place if it's older
than 24 hours and the network is reachable, falling back to the
still-usable stale copy on any refresh failure rather than losing rules
entirely. The three potentially-stale sources (YARA, Sigma Windows, Sigma
Linux) share a single reachability probe instead of each blocking through
its own timeout, so a slow/unreachable network adds at most ~5s to
startup instead of ~15s.

Also fixed while touching the download path: `_download_yara_forge_rules`
and `_download_rule_file` used to write straight into the destination
file, which would have corrupted an already-good cached copy if a refresh
failed partway through. Both now write to a temp file and rename
atomically into place.

### Other UI fixes

- All modals now dismiss via Escape or a backdrop click, not just their
  close button.
- The Help modal links to https://so-crates.org.
- The welcome tip mentioning the max upload size now links "Settings"
  directly to the Settings modal instead of just naming it in plain
  text.

### About modal and manual update checks

A new "About" entry in the gear menu opens a modal with the current
version, tagline, a "Made with ♥ by defenders for defenders - Sponsored by
Security Onion Solutions, LLC" line, and Documentation/GitHub links. The
"Check GitHub for newer releases" checkbox and its manual "Check Now"
button (added alongside the existing opt-in automatic check, not
replacing it) moved here from Settings. The footer's "SO-CRATES" link now
opens this modal instead of navigating to GitHub (the "Update available"
badge still links directly to the GitHub release).

### Smaller Docker image

The Docker image is roughly 130MB smaller, from three fixes found by
inspecting `podman history` and the actual contents of the Zircolite git
clone:

- The venv copied in from the builder stage (`COPY --from=zircolite-builder
  ... /usr/local/lib/zircolite-venv`) was followed by a separate `chown -R`
  to give the app user ownership. On an overlay filesystem, a `chown -R`
  over a directory copied in from another stage forces a full copy-up of
  every file just to change ownership metadata - doubling that layer's
  size. Fixed by using `COPY --chown=1000:1000` directly instead.
- The Zircolite git clone was copied into the final image wholesale, but
  `sigma_analyzer.py` only ever uses `zircolite.py`, the `zircolite/`
  package, and `config/config.yaml` from it - the clone's own bundled
  `rules/` (unused; SO-CRATES bakes in its own Sigma rules separately),
  `gui/`, `pics/`, `tests/`, `docs/`, and `templates/` directories were
  pure dead weight. Pruned in the builder stage before the final `COPY`,
  shrinking that copy from ~53MB to under 1MB.
- The `unzip` package is now only needed at build time (to extract the
  YARA Forge release archive) - the app itself parses ZIP uploads with
  Python's own `zipfile` module - so it's no longer installed in the
  final image.

Also fixed: the Dockerfile's `COPY` line for top-level `.py` modules was
missing `ohmydebn_colors.py`, which made the container fail at import time.
The regression test that's meant to catch
this (`test_dockerfile_copies_socrates_files`) used its own
hand-maintained file list that had the same gap - it now dynamically
checks every `.py` file actually in the repo root against the Dockerfile
instead.

### Theme renames and additions

- **C64 → Breadbin Blue**, **MS-DOS Blue → DOS Blue**, **Windows XP → Luna
  Blue** - both the display label and the underlying registry key/cheat
  code changed (`c64`→`breadbin-blue`/`bread`, `msdos`→`dos-blue`/`dos`,
  `winxp`→`luna-blue`/`luna`), to move away from specific product/console
  branding.
- Two new Fun themes: **Digital Frontier** (a Tron-inspired look, cheat
  code `digit`) and **Retro Handheld** (a Game Boy-inspired 4-shade green
  look, cheat code `retro`) - named generically for the same reason.

### Themes modal UI cleanup

- The "Sync theme to OhMyDebn theme" toggle moves to the top of the Themes modal
  and hides the manual picker while enabled, since OhMyDebn owns the
  theme while sync is on.
- Removed the active-theme checkmark from the theme tile grid - the
  border-color/bold-text highlight already marks the active tile, so the
  checkmark (and the empty placeholder space reserved for it on every
  other tile) was redundant visual noise.

### OhMyDebn theme sync

A new opt-in "Sync theme to OhMyDebn theme" setting (off by default, in the Themes
modal) lets SO-CRATES follow OhMyDebn desktop theme switches automatically.
A `GET /api/theme` endpoint reads the active theme's name and color
palette from a single `OHMYDEBN_THEME_DIR` environment variable (unset
outside an OhMyDebn/podman launch, so this is a no-op for every other
deployment), by convention at `<OHMYDEBN_THEME_DIR>/current/theme.name`
and `<OHMYDEBN_THEME_DIR>/current/theme/`, and the frontend polls it once
a second while the tab is visible.

- A theme name that matches one of SO-CRATES's built-in themes is applied
  directly, with a toast: "Changed SO-CRATES theme to `<name>` to match
  OhMyDebn".
- For a custom or Aether-generated theme with no built-in match, a full
  theme (~25 CSS custom properties) is instead synthesized at runtime from
  the theme's raw color palette, with a toast: "Generated color palette
  from OhMyDebn theme `<name>`". Three source formats are supported, tried
  in order against real installed themes until one works: the native
  `colors.toml`'s numbered `color0`-`color15` ANSI-slot scheme; the same
  file's alternate semantic-named scheme (`red`/`blue`/`bright_red`/
  `muted`/..., used by at least one of OhMyDebn's own bundled themes); and
  `alacritty.toml` (standard `[colors.primary]`/`[colors.normal]`/
  `[colors.bright]` tables), including its `0xrrggbb` hex variant and
  themes that omit `[colors.bright]` entirely (falls back to `[colors.normal]`
  per color). Every derived text/accent color (`--text-muted`,
  `--tag-*-text`, `--badge-*-text`, `--accent`) is nudged as needed to meet
  a real WCAG 3:1 contrast ratio against the derived background, so a
  low-contrast source palette can't make labels/headings unreadable.
  Verified against all themes bundled with a real OhMyDebn installation.
- If neither a known theme nor a usable palette is available, sync
  disables itself and SO-CRATES reverts to Midnight, with a sticky toast
  explaining why (click, or its "Open Themes" link, to dismiss).

### Reliability and security fixes

- **Critical: JPEGs (and other file types) misclassified as PE
  executables.** `exif_analyzer.py`'s category detection ran a loose
  substring check (`'pe' in file_type.lower()`) before its more reliable
  MIME-type checks - `"JPEG".lower()` contains the substring `"pe"` (from
  "j-**pe**-g"), so every JPEG silently lost its image-specific EXIF
  fields to the executable-metadata branch instead. Reordered so the
  reliable MIME-type checks run first.
- **Critical: baked-in Suricata rules silently overwrote a previously
  fetched, better ruleset on every single restart.** The no-live-update
  branch of `setup_suricata_config()` checked for the baked-in rules copy
  *before* checking whether rules already existed on disk - and since
  every server startup calls this with `network_allowed=False`
  unconditionally, a real Docker/Podman deployment with a persistent
  `/data` volume would have its live-updated `suricata.rules` reverted
  back to the generic baked-in snapshot on every restart, with no
  progress message logged. Fixed by checking existing on-disk rules
  first, matching the priority order already used by the (correct)
  update-failure fallback a few lines away.
- **FTS5 search index could drift from `file_metadata.json`.** The file
  metadata merge path relied on a stale comment claiming FTS5's
  external-content table auto-updates on a plain `UPDATE` of the content
  table - it doesn't. Fixed with an explicit
  `INSERT INTO events_fts(events_fts, rowid, json_data) VALUES('delete',
  ...)` plus re-insert.
- **Suricata rule updates now fall back to baked-in/existing rules if
  `suricata-update` itself fails**, not just when the initial internet
  reachability probe fails - a proxy blocking the real rule mirrors, a
  cert error, or a full disk could previously leave Suricata with no
  rules at all despite "internet access" having been detected.
- **`_run_ruleset_update()`'s error reporting was silently broken.** Its
  `except` branch logged a failed update to the progress log but never
  set `_rule_update_state[name]['error']` - always `None` - so the
  frontend's error-vs-success toast (`status[name].error ? '... update
  error: ...' : '... rules updated'`) could never actually show a
  failure: a ruleset update that raised still reported success, giving an
  analyst false confidence that their rules were current.
- **`setup_yara_rules()`'s refresh-failure fallback only caught
  `(OSError, urllib.error.URLError)`**, but the download helper can also
  raise `zipfile.BadZipFile` (a truncated, rate-limited, or HTML-error
  response that isn't actually a zip) or `KeyError` (if the expected
  member is ever renamed upstream) - neither is an `OSError` subclass, so
  both escaped the fallback entirely and turned a routine "check for
  updates" refresh into a whole-file-analysis failure despite a perfectly
  good cached copy sitting on disk. Both exceptions are now caught too.
- **`get_sigma_rules_info()`'s docstring promises it never raises**, but
  it opened its cached rules file in plain text mode with no `errors`
  handling - unlike its YARA/Suricata siblings, which both use
  `errors='ignore'`. Invalid bytes in a corrupted cached file raised
  `UnicodeDecodeError` instead of the documented graceful fallback,
  breaking the entire Rules-info panel (Suricata and YARA included) for
  a problem in just one ruleset's file. Fixed to match its siblings.
- **`_fetch_url_safely()`'s redirect-following path read a redirect
  response's body with a bare, unbounded `resp.read()`**, unlike the
  200-response path, which streams in bounded chunks and aborts once the
  configured max size is exceeded. Since this function fetches
  attacker/analyst-supplied URLs, a malicious or compromised server could
  pair a redirect with an arbitrarily large or slow-trickling body and
  exhaust memory before `Location` was ever read. Now bounded the same
  way as the 200 path.
- A ZIP upload containing more than one supported file only ever
  analyzes the first one found; the count of skipped files is now
  surfaced as a toast instead of being silent data loss the user has no
  way to notice.
- A YARA match's `file_path` field was silently truncated for any scanned
  filename containing a space (e.g. a user-uploaded `My Invoice.pdf`) -
  the CLI output parser took the last whitespace-delimited token as the
  path, which only ever worked because rule names never contain
  whitespace while arbitrary uploaded filenames can. Currently harmless
  in practice (the SHA256 used elsewhere is always independently
  recomputed from the file's bytes, and nothing reads this field back
  out of the database), but a real landmine for the next caller that
  does. Fixed by resolving each match's path against the exact set of
  paths passed to `--scan-list` (which the app always already knows)
  instead of a naive split, falling back to the old behavior only if
  nothing in that known set matches.
- Multiple frontend `fetch()` call sites built URLs by interpolating the
  current file's MD5 directly into a query string without
  `encodeURIComponent` - swept all of them (previously only
  `buildStreamUrl()`/`buildSearchQuery()` encoded correctly).
- Clicking a column header inside an Aggregation Tables mini-panel
  (e.g. the "Count"/"Value" headers) silently re-sorted the unrelated
  main data table underneath it, with zero visual feedback in the panel
  itself - `.agg-table th` had `cursor: pointer` copy-pasted from the
  real sortable table's header style, so the app's own delegated
  click-to-sort handler (which only skips headers with `cursor: default`)
  treated it as sortable. Fixed by giving aggregation-table headers
  `cursor: default`.
- `_validate_stream_params` now returns its HTTP status code explicitly
  instead of callers guessing 400 vs. 404 by substring-matching the
  error message text.
- `_non_artifact_files()` (the display-name fallback used when `name.txt`
  is missing) and `handle_post_reanalyze()`'s file-selection logic used
  to be two separately hand-rolled, drifted implementations of "the real
  uploaded file in this analysis directory, minus pipeline artifacts" -
  the former blanket-excluded any `.txt`/`.json`/`.db`-suffixed filename
  by extension, so a legitimately-uploaded standalone file with one of
  those extensions could never be found as a display-name fallback, even
  though reanalyze's own separate listing (extension-agnostic, exact
  artifact names only) happily found and reanalyzed that exact same
  file. Consolidated into one shared helper so the two can no longer
  silently disagree.
- `is_host_reachable()` never closed the socket it opened to test
  reachability - masked by CPython's refcounting GC, but a real resource
  leak (and the source of `ResourceWarning: unclosed <socket.socket...>`
  noise seen in test runs). Now uses a `with` block.
- Removed dead code: the `reachable_check` parameter on
  `setup_yara_rules`/`setup_sigma_rules`, the `_check_reachable()` helper
  duplicated in both `yara_analyzer.py` and `sigma_analyzer.py`, and
  `validators.make_reachability_checker()` - all unused after an earlier
  refactor moved rule updates to independent per-ruleset background
  threads.
- A handful of docs pages had drifted from the current source: a stale
  "seven test files" list in the architecture docs (now ten, with the
  three newest ones added), a reversed description of Zircolite's
  PATH-vs-bundled-copy lookup priority, a stale "auto-cloned on first
  run" claim about Zircolite that hasn't been true since it started being
  baked into the Docker image, a missing `filesSkipped` field in the
  `/api/upload` response docs, and an incorrect description of
  `POST /api/check-status`'s readiness check (it's the same check for
  every file type, not a PCAP-vs-other distinction). The security docs
  now also mention the non-root container user and startup's
  zero-network-calls guarantee. `AGENTS.md`'s hardcoded theme list/count
  (last accurate at 25 themes) was replaced with a pointer to the real
  `THEMES` registry, which now has 32.

## 3.0.0

### Suricata upgraded to 8.0.6

SO-CRATES now installs Suricata from Debian's `trixie-backports` repo
(8.0.6) instead of the base `trixie` repo's 7.0.10, along with
`suricata-update` 1.3.8 (fixes a real security issue - arbitrary file write
via path traversal in rule archive extraction, OISF redmine #8633). This
applies to both the Dockerfile and bare-metal installs.

**Critical fix that came with the upgrade:** Suricata 8 silently changed DNS
logging to a new default format - `dns.rrname`/`dns.rrtype`, read directly
by every DNS column in the UI, no longer exist at the top level at all (the
same data moved to `dns.queries[0]`). This broke the `dns` tab completely
(Query/Type went blank) - one of the highest-volume, most-viewed event types in the
app. Fixed with a fallback that keeps working for previously-stored
analyses from Suricata 7 too.

### New and fixed protocol support

- **enip** and **ntp** now produce real events - Suricata 7.0.10 detected
  both correctly but had no eve-log output module for either, so nothing
  ever reached the UI regardless of config. Both work now that Suricata 8
  ships the loggers.
- **websocket, pop3, mdns, ldap** - full column, filtering, and aggregation
  support for these protocols, new in Suricata 8.
- **arp** - decode-layer logging support added, but kept **off by default**
  (Suricata's own stance: "many events can be logged"). A live test across
  35 sample captures showed ARP at up to 12% of events in a realistic
  multi-host capture. Set the `ENABLE_ARP_LOGGING` environment variable to
  opt in.
- 18 previously-enabled-but-unsupported Suricata protocols gained full
  column/aggregation support for the first time (previously falling back to
  a generic 6-column view): quic, dhcp, ftp_data, smb, ssh, krb5, sip, snmp,
  mqtt, http2, dcerpc, rdp, tftp, ike, nfs, rfb, bittorrent_dht, smtp - plus
  `ftp` and `anomaly`, which predated this work but had the same gap.
- Fixed real data-shape bugs found while verifying against real traffic:
    - `quic.ja3`/`ja3s` are objects (`{hash, string}`), not plain strings -
      previously rendered as the literal text `[object Object]`.
    - `rfb.client_protocol_version`/`server_protocol_version` are `{major,
      minor}` objects, and `security_type` is nested under `authentication`,
      not top-level.
    - `anomaly.message` was read in three separate places (a field that has
      never existed in Suricata's eve.json) - the real field is
      `anomaly.event`.
    - HTTP/2 traffic (including cleartext h2c) is always logged by Suricata
      under `event_type: "http"`, never a separate `"http2"` type - removed
      dead code that assumed otherwise; real HTTP/2 traffic already renders
      correctly under the existing `http` tab.
- Fixed a Suricata config-generation bug: re-running setup on an
  already-provisioned install could silently stop adding any newly-added
  protocol to eve-log output, once earlier protocols had already been
  inserted.

### Performance & scalability

- Aggregation tables and the Sankey diagram are now computed server-side
  (`GET /api/aggregation-data`, `GET /api/sankey-data`) via SQL `GROUP BY`,
  scaling with the query instead of the full dataset size, with unfiltered
  results cached per-analysis.
- Uploads are now parsed as a stream instead of buffered in memory - peak
  memory no longer scales with upload size. Leftover temp files from an
  upload interrupted by a server crash are now swept on the next startup.
- Upload size limit raised from a fixed 1,000 MB to a user-configurable
  ceiling (up to 5,000 MB hard max) via Settings; a disk-space check now
  runs before accepting an upload.
- Query result limit raised from 5,000 to a user-configurable ceiling (up
  to 100,000 hard max) via Settings.

### UI

- 20 new themes (25 total, up from 5), grouped into Dark Themes, Light
  Themes, and Fun Themes sections in the gear menu, each with its own
  favicon. Three of the new Fun themes stand out:
    - **CGA** - classic 4-color CGA Palette 1 High-Intensity look (black
      background, cyan/magenta/white)
    - **C64** - Commodore 64 blue-on-blue aesthetic, using the real
      Pepto/VICE C64 16-color palette (blue background, light-blue
      border/text/accent, including the header's "SO-CRATES" logo), for a
      deliberately flat, monochrome resting look, with a distinct cyan
      `--interactive-highlight` for hover/focus/active borders so those
      states are still visible
    - **Vaporwave** - a modern, non-retro counterpart to the other three:
      dark purple/navy background with hot-pink accents and
      cyan/mint/pastel-yellow highlights, evoking the 2010s+ vaporwave
      internet aesthetic rather than nostalgia for old hardware
- The active theme is now marked with a checkmark in the gear menu.
- Each Fun theme (C64, CGA, Hacker, Sguil, Vaporwave) now has its own typed
  cheat code - type it anywhere outside a text field to switch instantly. See
  [Themes](themes.md) for the codes.
- The gear menu's Fun Themes section now appears after Light Themes
  instead of between Dark and Light (`THEME_GROUP_ORDER` in
  `static/socrates.js` is now `['dark', 'light', 'fun']`); the `t` hotkey
  cycle follows the same updated order.
- CGA's header/footer text (the "SO-CRATES" logo, tagline, filename, and
  date/MD5 metadata) is now the CGA magenta accent instead of black/dark
  teal, matching the rest of the CGA palette more closely.
- **Sguil's expanded data-table rows had mismatched field backgrounds**:
  when a light-blue zebra-striped row (`nth-of-type(4n+3)`) was expanded,
  each field's *value* box stayed stark white instead of matching the
  light-blue row, looking like a patchwork of mismatched boxes. `.detail-value`
  now follows the row's light-blue background in that case; `.detail-label`
  intentionally keeps its own light-cyan background on every row.

### Documentation

- Docs now live on a real site (MkDocs Material, deployed to GitHub Pages)
  instead of a single growing README plus a handful of unlinked `docs/*.md`
  files. `README.md` is now a short landing page (tagline, a screenshot,
  and links out to the docs site); everything else - installation
  (Docker/Podman/OhMyDebn/Manual), usage, themes, configuration, security,
  architecture, the API reference, and the filtering design doc - is now
  properly cross-linked, searchable, and navigable instead of split across
  files with no shared nav.
- The Themes page shows a real screenshot of every one of the 25 themes,
  grouped under Dark/Light/Fun headings, click-to-zoom.
- Added `scripts/capture_screenshots.py` to regenerate every docs screenshot
  in one run against the app's own built-in sample pcap - no local fixture
  or hardcoded analysis needed.
- Added a recorded demo video (`scripts/record_demo.py`, Playwright) to the
  Home page, walking through a sample analysis end-to-end: upload, each
  data tab, All Events, Aggregation Tables filtering, drill-down, ASCII
  Transcript, and Hexdump. Published as an H.264/AAC MP4 (re-encoded from
  Playwright's raw WebM capture) rather than WebM directly, since MP4 is
  universally browser-supported and is also the format required to upload
  the same clip directly to X/Instagram/LinkedIn/Facebook.
- The Architecture page is now split into focused subpages (Overview, Data
  Storage, Database, Event Types, UI, Security Model, Test Coverage)
  instead of one long page, matching Installation's existing
  Overview/Docker/Podman/OhMyDebn/Manual split.
- Went through every docs page and verified its claims directly against
  current source rather than trusting what the docs already said - fixed
  real drift in the API reference (missing endpoint, wrong response
  shapes, a fictional error code), the security page, the architecture
  page, and several others (stale file-layout diagrams, wrong config
  defaults, stale test/column counts).

### Other fixes

- **CGA theme's borders read as dark green instead of cyan**: every
  border/panel-outline in the app was driven by `--bg-hover`, which also
  doubles as the hover-state background fill. CGA's `--bg-hover` (`#004040`)
  had equal green/blue channels at low brightness - green dominates human
  luminance perception far more than blue, so the color skewed
  green-looking despite being a "pure cyan" hue numerically. Fixed properly
  by splitting borders into their own `--border-color` variable, distinct
  from `--bg-hover`: CGA's `--border-color` is now the real CGA light-cyan
  RGBI value (`#55ffff`, verified by sampling pixel colors from an actual
  CGA Palette 1 High-Intensity game screenshot), while `--bg-hover` stays a
  muted `#008080` teal so hover-state fills don't get uncomfortably bright
  behind white text. Every other theme sets both variables to the same
  value they always rendered as, so this is a no-visible-change refactor
  for the other 22 themes.
- **CGA header/footer now use bright light cyan instead of near-black**: the
  dark `--bg-secondary` background shared with every panel/card was making
  the header and footer blend into the rest of the black-on-teal UI in a
  way that read poorly. CGA's `.app-header`/`.footer` now use the real CGA
  light-cyan background (`#55ffff`) directly, with `--text-bright`/
  `--text-muted` switched to dark colors scoped to that same rule for
  legibility. The gear dropdown menu (a child of the header in the DOM, but
  rendered on its own dark panel) resets those two variables back to their
  normal light values so its own text doesn't inherit the header's dark
  override.
- **Dead CSS custom properties removed**: `--accent-rgb` and
  `--filter-bar-bg` were defined identically in all 23 theme blocks but
  never referenced anywhere via `var(--name)` in CSS/JS/HTML. Removed, with
  a test (`test_dead_theme_vars_removed`) to keep them from quietly coming
  back. (`--border-color` was briefly removed alongside these for the same
  reason, then reintroduced with the real purpose described above.)
- **Upload disk-space check used the wrong number**: `/api/upload`'s
  upfront disk-space check was sized against the raw `Content-Length` of
  the request, not the resolved upload-size ceiling (`effective_max`) - a
  compressed upload (e.g. a ZIP) can have a `Content-Length` far smaller
  than what it's allowed to expand to, so the check could pass even when
  there wasn't really enough room. `/api/load-url` already checked against
  `effective_max`; `/api/upload` now does too.
- **Load-from-URL password gap**: `/api/load-url` only ever tried the
  MTA-style dated password (`infected_YYYYMMDD`) when a URL's path matched
  `/YYYY/MM/DD/` on `malware-traffic-analysis.net` - any other password
  attempt was skipped entirely, unlike `/api/upload`, which always tries
  the plain `infected` password regardless of source. `/api/load-url` now
  always tries `infected` too (cheap, harmless even when it doesn't apply),
  trying the MTA dated variant first when the URL matches.
- Fun-theme cheat codes shorter than 5 characters (e.g. `cga`) only ever
  matched in the first few keystrokes after page load, since the
  keystroke buffer they were checked against stays a fixed 5 characters
  once filled and the check used `===` instead of `.endsWith()`. Fixed
  for all three codes (`cga`, `31337`, `sguil`).
- The Welcome modal's help text had a hardcoded `Maximum file size is
  1000MB.` string that never reflected reality once upload size became
  user-configurable (see Performance & scalability, above) - a user who'd
  raised their own ceiling in Settings still saw the stale default with no
  indication it was adjustable. Now computed from the user's actual
  effective limit each time the modal opens.
- `extractAllValue()`'s `'Command'`/`'Message'` column overrides were stale
  and actively wrong - `Command` ignored pgsql/enip/pop3's own real command
  fields in the "All Events" view, and `Message` read the same
  never-existed `anomaly.message` field. Both removed in favor of the
  already-correct per-protocol handling.
- Fixed the equivalent `anomaly.message` bug in the event detail side panel.
- `docs/FILTERING.md`'s "Column Overlap" reference table, which had grown
  stale over many protocol additions, now points at the actual source of
  truth (`getColumnsForType()`) instead of duplicating an ever-drifting list.
- **Podman Compose deployment bug**: `docker-compose.podman.yml`'s
  `user: "${UID}:${GID}"` silently resolved to an empty `user: ":"` when
  following the README's exact instructions, since bash doesn't export
  `$UID`/`$GID` by default - this forced the container to run as root
  instead of the current user, defeating the whole point of the
  `userns_mode: keep-id` volume-permission mapping. Confirmed by actually
  building and running the image. README now instructs users to write a
  `.env` file instead of relying on a shell export, since `podman compose` reads that
  automatically from any terminal, including for a later `down`/`restart`.
