# AGENTS.md

This file contains agent-focused guidance for maintaining SO-CRATES.

## Updating Vendored Dependencies

SO-CRATES bundles D3 and d3-sankey in `static/` so the application works offline and builds remain deterministic.

### D3

To update to the latest version:

```bash
curl -sL "https://unpkg.com/d3@7/dist/d3.min.js" -o static/d3.min.js
curl -sL "https://unpkg.com/d3-sankey@0.12/dist/d3-sankey.min.js" -o static/d3-sankey.min.js
```

After updating, verify the files load correctly and run the test suite:

```bash
python3 -m unittest discover -v
```

If the copyright year changed, update `static/LICENSE` accordingly.

Check for D3 releases at https://github.com/d3/d3/releases.
Recommended cadence: every 6–12 months, or immediately if a security CVE is announced.

## Backend Architecture

SO-CRATES's backend is split into domain modules. Do not add new logic directly to `socrates.py` - place it in the appropriate module:

| Module | Add here if... |
|---|---|
| `validators.py` | Input validation and the small, focused I/O it depends on (no HTTP framework code). IP/port checks, filename sanitization, URL/SSRF safety (including DNS resolution via `resolve_safe_ips` and TCP reachability via `is_host_reachable`), PCAP magic bytes, ZIP slip prevention, file staleness checks. |
| `suricata_analyzer.py` | Anything related to Suricata lifecycle: config setup, rule downloads, spawning subprocesses, processing locks, file extraction. |
| `yara_analyzer.py` | YARA scanning: executable checks, rules download/setup, scanning extracted files, parsing output. |
| `sigma_analyzer.py` | Sigma rule conversion/execution via Zircolite, importing log events into the events DB. Querying `sigma_alerts` back out is `db.py`'s job, not this module's. |
| `file_analyzer.py` | Lightweight file metadata extraction (`file`-command magic/MIME type, Shannon entropy, printable strings). No hashing here - MD5/SHA256 are computed in `socrates.py`/`yara_analyzer.py`. |
| `exif_analyzer.py` | EXIF metadata extraction for image/media files. |
| `ohmydebn_colors.py` | Deriving a full theme (CSS custom properties) from an OhMyDebn/Aether color palette (`colors.toml`/`alacritty.toml`) for the Themes modal's OhMyDebn sync toggle. Pure functions, no I/O. |
| `playbook_lookup.py` | Security Onion Playbooks lookup - reading the baked-in gzip-compressed indexes (`BAKED_IN_PLAYBOOKS_DIR`/`PLAYBOOKS_DIR`), exact-rule/engine-fallback resolution, in-process caching. No fetch/refresh logic - see "Detection Rule Freshness" below for why. |
| `ai_summary_lookup.py` | AI-generated per-rule summary lookup - same baked-in gzip-compressed-index/in-process-caching shape as `playbook_lookup.py` (`AI_SUMMARIES_DIR`), but exact-match only, no engine-wide fallback, and covers `nids`/`sigma`/`yara` (one more type than Playbooks). No fetch/refresh logic - see "Detection Rule Freshness" below. |
| `db.py` | SQLite schema changes, new query functions, index optimization, bulk loading logic. |
| `models.py` | New Suricata event field extraction helpers (parsing JSON fields into typed values). |
| `config.py` | Application-wide constants: size limits, timeouts, thresholds. Adjust here for different deployments. |
| `socrates.py` | Only HTTP handler methods, request/response formatting, and thin orchestration that calls other modules. |

### Handler Conventions

- Use `_send_json(data)` for all JSON responses, `_send_error(code, message)` for errors.
- Extract shared endpoint logic into helper methods on `Handler` (e.g., `_validate_stream_params`).
- Keep `do_GET` and `do_POST` as thin dispatchers via `GET_ROUTES` / `POST_ROUTES` class attributes.

### Frontend Structure

The frontend is split into three files under `static/`:

| File | Content |
|---|---|
| `socrates.html` | HTML shell (one minimal inline theme-restore script in `<head>` to prevent FOUC; otherwise no inline CSS/JS) |
| `static/socrates.css` | All styles |
| `static/socrates.js` | All JavaScript |

`socrates.html` references them via `<link rel="stylesheet" href="static/socrates.css">` and `<script src="static/socrates.js"></script>`.

When updating styles or frontend logic, edit the appropriate split file. Keep `socrates.html` free of inline `<style>` blocks. The single inline `<script>` in `<head>` restores the user's theme before the first paint; keep it minimal and fault-tolerant.

### Theming Conventions

SO-CRATES supports themes via CSS custom properties. The full, current list (name, group, and a short description of each) is the `THEMES` registry in `static/socrates.js` and [Themes](docs/themes.md) - don't duplicate that list here, it goes stale the same way any full list does (see `docs/filtering.md`'s "Column Overlap" note for the same reasoning). As of this writing there are 35: 20 Dark, 5 Light, 10 Fun.

- **Use CSS variables** (`var(--bg-primary)`, `var(--text-primary)`, `var(--accent)`, etc.) instead of hardcoded hex values for all structural/theme colors.
- **Add theme overrides** in the appropriate `[data-theme="<key>"]` block (the theme's registry key in `static/socrates.js`'s `THEMES` object) when a default dark color lacks contrast or does not match the theme's aesthetic.
- **Preserve hardcoded colors** only for functional/data-driven elements (event type colors, severity colors, ASCII transcript direction colors) that must stay consistent across themes.
- **Don't define a variable in every theme block "for completeness" without a real consumer.** `--accent-rgb` and `--filter-bar-bg` were defined identically in all 23 theme blocks but never referenced via `var(--name)` anywhere in CSS/JS/HTML - removed as dead CSS (`test_dead_theme_vars_removed` locks this in). If you add a new per-theme variable, grep for `var(--your-name` before considering it done.
- **`--bg-hover` and `--border-color` are deliberately separate variables.** `--bg-hover` is for hover-state background *fills* (table row hover, button hover); `--border-color` is for border/outline *decorations* (panel borders, header/footer dividers, input borders). Most themes set both to the same value since a muted color works fine for both roles, but don't assume they must match - CGA sets `--border-color` to a bright cyan (`#55ffff`, the real CGA light-cyan RGBI value) while keeping `--bg-hover` a much more muted teal (`#008080`), since a hover *fill* that bright would hurt text contrast but a 1px *border* reads fine at full brightness. `test_border_color_split_from_bg_hover` enforces that every theme defines both and that border declarations reference `var(--border-color)`, not `var(--bg-hover)`.
- **A theme can override structural colors per-selector, not just per-variable, when a single shared variable can't express the look.** CGA's header/footer use `background: #55ffff` (bright light cyan) directly on `[data-theme="cga"] .app-header, [data-theme="cga"] .footer`, rather than repointing `--bg-secondary` (which every other panel/card also uses and would go bright cyan too), and override `--text-bright`/`--text-muted` scoped to the same selector for legibility against the new background. See `test_cga_header_footer_light_cyan`. **If you add an override like this, only reset the same variables on an element that is an actual DOM descendant of the overridden selector and that actually reads those variables** - CSS custom properties cascade strictly through DOM nesting, not visual/menu grouping, so a modal or panel that merely *opens from* the header (e.g. `#themesModal`, a top-level sibling in the DOM, not a child of `.app-header`) never inherits the override in the first place and needs no reset. A `#themesModal` reset rule existed here for exactly this non-reason - it silently duplicated the theme's own root values - and was removed once `test_cga_header_footer_light_cyan` was checked against the current markup and found to be a no-op.
- **`--interactive-highlight` is an optional per-theme override for hover/focus/active border feedback.** Every hover/focus/active border rule (`.app-header-filename-input:focus`, `.stat-card:hover`, `.stat-card.tab-active`, `.pagination-page-input:focus`, `.settings-number-input:focus`, `.notes-textarea:focus`, `.settings-text-input:focus`, `.drop-zone-active`, `.view-tab.active`, `.search-input:focus`, `.sample-card:hover`, `.theme-tile:hover`, `.app-logo-text:focus-visible`, `.stat-card.keyboard-selected`, `.sample-card.keyboard-selected`, `.previous-analysis-row.keyboard-selected`, `tr[data-id].keyboard-selected`, `.theme-tile.keyboard-selected`, `.section-toggle-bar.keyboard-selected`, `.agg-row[data-agg-pivot].keyboard-selected`, `.pivot-menu-item.keyboard-selected`, `.filter-chip.keyboard-selected`, `.filter-clear-all.keyboard-selected`, `.stream-btn.keyboard-selected`, `.view-tab.keyboard-selected`, `.row-note-edit-link.keyboard-selected`, `.packet-header.keyboard-selected`, `.packet-control-btn.keyboard-selected`, `.detail-value-pivot.keyboard-selected`, `.autocomplete-item.keyboard-selected`, `.agg-page-btn.keyboard-selected`) reads `var(--interactive-highlight, var(--accent))` - a CSS fallback, so themes that don't define `--interactive-highlight` get exactly the old behavior (`--accent`) with zero risk. A theme needs this when its `--accent` is intentionally identical to `--border-color`/`--text-primary` (a deliberate flat, monochrome look) - without a separate highlight color, hovering/focusing would produce no visible change at all. Breadbin Blue (the original case, formerly named C64), Luna Blue, and DOS Blue all define this for exactly that reason, each to a distinct color from their own palette rather than a jarring color swap. If you add a new theme where `--accent` intentionally matches `--border-color`, check whether it needs `--interactive-highlight` too.
- **Use `currentColor`** for inline SVG icons so they inherit the surrounding text color and adapt automatically.
- **Avoid emojis** for UI icons when possible - use inline SVGs instead, since emojis render as full-color system glyphs that ignore CSS `color` and may be invisible in one theme.

Theme selection is not in the gear menu itself - the gear icon menu in the upper-right corner (`renderGearMenu()`) is just five static items (Help, Settings, Themes, Rules, About), with no divider and no theme buttons. Clicking **Themes** opens a separate Themes modal whose grid (`renderThemesModalGrid()`) groups tiles into the **Dark Themes** section (alphabetical: Catppuccin … Vantablack), then **Light Themes** (alphabetical: Catppuccin Latte … White), then **Fun Themes** (alphabetical: Amber CRT … Vaporwave) - this order is `THEME_GROUP_ORDER = ['dark', 'light', 'fun']` in `static/socrates.js`, with tiles alphabetical by label within each group (`THEME_MENU_ORDER`). The `toggleTheme()` hotkey cycle follows this same `THEME_MENU_ORDER`. Each tile carries `data-theme-option="<key>"`; the currently applied theme's tile gets the `theme-active` class (accent-colored border + bold text - not a checkmark) plus `aria-current="true"`, kept in sync by `updateThemeMenu()`, which runs from `setTheme()`, `applyCustomTheme()` (OhMyDebn sync), `showThemesModal()`, `init()`, and after every `renderGearMenu()` re-render. Hovering a tile does **not** call `updateThemeMenu()` or repaint the real page - `previewTheme()` only updates an isolated `<iframe>` preview panel (`themePreviewFrame`) inside the modal, deliberately scoped that way to avoid a WCAG 2.3.1 flash-risk from hovering rapidly across ~35 tiles; only clicking a tile (`commitTheme()` → `setTheme()`) applies the theme for real. The user's choice is persisted to `localStorage` as `socrates-theme` and restored on page load to prevent a flash of unstyled content.

To add a new theme:

1. Add it to the `THEMES` registry in `static/socrates.js` with the correct `group` (`'dark'`, `'fun'`, or `'light'`). `setTheme()`, `previewTheme()`, the `toggleTheme()` hotkey cycle, and the Themes modal's tile grid (`renderThemesModalGrid()`) are all generated automatically from the registry (grouped and alphabetical by label within each group) - there is nothing to add in `socrates.html`; its `<div id="themesModalBody">` starts empty and is filled entirely by `renderThemesModalGrid()`. (`renderGearMenu()`, the gear dropdown itself, is unrelated - it's a static 5-item list (Help, Settings, Themes, Rules, About), not driven by the registry.)
2. Add a `[data-theme="your-name"]` CSS override block in `static/socrates.css`.
3. If the theme needs a custom favicon, add `static/favicon-your-name.svg` - `updateFavicon()` resolves per-theme favicons by naming convention (the `dark` and `light` themes use the plain `static/favicon.svg`).
4. Add any theme-specific runtime behavior (e.g. background effects) and gate it on `getCurrentTheme()`.
5. Add it to the `THEMES` list in `scripts/capture_screenshots.py` (a separate hardcoded list, not derived from the registry) and re-run the script to generate its Themes-page screenshot - see the Release Checklist below.
6. Nothing else to wire up for the command palette - `AUTOCOMPLETE_COMMANDS` in `static/socrates.js` generates a typed-autocomplete entry for every theme straight from the `THEMES` registry (matched against the theme's own `label`, lowercased), so step 1 alone already makes the new theme reachable by typing its name outside a text field.

## Detection Rule Freshness

Suricata/YARA/Sigma rule refreshes only ever happen two ways: fully local (startup, `network_allowed=False` - cached/baked-in only, no reachability check) or fully explicit (Rules modal → `force=True`, an actual click is the consent). **Analysis itself must never trigger a network rule refresh as a side effect of scanning a file** - `_analyze_standalone_file`'s `setup_yara_rules(DATA_DIR, network_allowed=False)` call and `run_sigma_pipeline`'s `setup_sigma_rules(data_dir, network_allowed=False)` call both deliberately pass `network_allowed=False` for this reason. This used to not be the case - YARA/Sigma rules were silently refreshed over the network mid-analysis if `config.RULES_MAX_AGE_HOURS` had elapsed, no consent asked - until unprompted outbound connections were judged the worse tradeoff for a security-focused tool than occasionally analyzing with rules a bit older than that window. (Suricata never had this auto-refresh-on-analysis behavior in the first place - see `suricata_analyzer.py`'s lack of any `is_file_stale`/staleness concept; it either updates unconditionally when `network_allowed=True` or not at all.)

**Security Onion Playbooks are baked-in only, with no runtime refresh
mechanism at all** - unlike Suricata/YARA/Sigma above, there is no
`setup_playbooks()`, no `network_allowed`/`force` parameters, and no Rules
modal entry for them. `playbook_lookup.py`'s `get_playbook()` only ever
reads the two `.json.gz` indexes baked into the image by the Dockerfile's
`resources-builder` stage. This is deliberate, not an oversight: playbook
guidance text (plain-English "questions to ask" per detection rule)
changes far less often than daily-cadence threat rulesets, so the
staleness/consent machinery this section exists to describe isn't worth
building for it yet. If that changes, it should follow the same
`network_allowed=False`-at-startup / explicit-click-to-refresh shape
described here, not a new pattern.

**AI-generated rule summaries follow the identical baked-in-only shape, for
the same reason** - `ai_summary_lookup.py`'s `get_ai_summary()` only ever
reads the `.json.gz` indexes the same `resources-builder` stage bakes from a
different upstream repo/branch (`securityonion-resources`'s
`generated-summaries-published` branch) into `/usr/share/ai-summaries`. No
`setup_ai_summaries()`, no refresh path, no Rules modal entry - same
rationale as Playbooks above, and any future staleness/consent machinery
should follow the same pattern already described here rather than inventing
a third one.

`config.RULES_MAX_AGE_HOURS` (currently 2 days, `2 * 24` - tuned toward Sigma's/Suricata's roughly-daily release cadence rather than YARA Forge's slower weekly one, since a single shared threshold can't match all three) is the server-side default for "how old is too old" - see its comment in `config.py` for the full breakdown, including that its original job (gating an actual auto-refresh inside `setup_yara_rules()`/`setup_sigma_rules()`) is presently dead code given every current caller passes `force=True` or `network_allowed=False`. It's exposed to the frontend via `/api/rules-info`'s `staleThresholdHours` field, but the *effective* threshold actually used everywhere in the frontend goes through one more step: `_resolveStaleThresholdHours(serverHours)` returns the user's per-browser override (`getUserStaleThresholdDays()`, from the `socrates_staleThresholdDays` localStorage key and the number input next to the Rules modal's checkbox - same `localStorage`-preference-over-a-server-default pattern as `getUserQueryLimit()`/`getUserMaxUploadSizeMB()` in Settings, except there's no client-side fallback constant here, so an unset/invalid override resolves to `null` and falls through to the server value) if one is set, otherwise the server's `staleThresholdHours` unchanged. Both real consumers go through this same resolver, so they can't independently drift the way they did before being unified:

- **The Rules modal's own date-color warning** (`isRulesetStale()`/`formatDateSpan()` in `static/socrates.js`) - colors a ruleset's "updated" date amber once it's older than the resolved threshold. `renderRulesModalBody()` computes `const t = _resolveStaleThresholdHours(info.staleThresholdHours);` once and passes it to every `formatDateSpan()` call.
- **`checkForStaleRules()`** - opt-in via the `socrates_checkForStaleRules` localStorage key, same default-off mechanics as the `socrates_checkForUpdates` app-version checker, but with no manual "check now" trigger - the Rules modal already shows the same staleness live via `isRulesetStale()`'s amber-date warning, so a separate on-demand button was redundant and was removed. The checkbox (and the day-count input next to it) live in the Rules modal, not About, since they're rules-level settings rather than app-level ones, and are initialized in `showRulesModal()`/`refreshRulesModal()`, not `showAboutModal()`. Fires on every `showWelcomeUI()` view (not just once at `init()`, so it also catches a mid-session return to Welcome). `_staleRulesetLabels(rulesInfo, thresholdHours)` computes staleness itself from each ruleset's raw `updated` epoch via `isRulesetStale()` - the same function the date-color warning uses - rather than trusting `/api/rules-info`'s server-precomputed `stale` field, since the server has no way to already know about a client-side override. (That `stale` field, added to `get_suricata_rules_info()`/`get_yara_rules_info()`/`get_sigma_rules_info()`'s return dicts via `is_file_stale(rules_file, config.RULES_MAX_AGE_HOURS)`, still reflects the server's own default threshold and remains part of the API contract for any consumer that doesn't care about the client override - the frontend just no longer relies on it for this decision.)
- The day-count `<input>` (`#staleThresholdDaysInput`) is static HTML, not part of `#rulesModalBody`'s poll-regenerated template (`refreshRulesModal()` replaces that wholesale every 2s) - it's updated separately each poll via a direct `.value =` assignment, guarded by `document.activeElement !== daysInput` so a poll tick never yanks back a value the user is mid-typing (same class of guard as the log-scroll-position preservation for `.rule-update-log`).
- The Rules modal is a fixed normal width (`#rulesModal .modal-content { max-width: 900px; ... }`, matching every other modal). It used to widen while Suricata's log was expanded, back when that log streamed `suricata-update`'s full internal output; `_fetch_single_source()` now reports one concise line per source instead (see its docstring), so `.rule-update-log`'s existing `white-space: pre-wrap` handles it at normal width and the widen-on-expand mechanism was removed.

There's also **`checkForMissingRules()`** (`static/socrates.js`) - unconditional, not opt-in, no threshold involved at all. Fires once at `init()` when a ruleset has never been downloaded (`count === null` for every ruleset), which is important enough to always show once since it means detections will be completely empty. It's mutually exclusive with `checkForStaleRules()` by construction - a ruleset only reaches `isRulesetStale()` in `_staleRulesetLabels()` once its `updated` is non-`null` - so the two never compete for the same toast (`showToast()` only ever shows one at a time).

## Docs Site Maintenance

User-facing documentation lives on the MkDocs Material site built from `docs/*.md` (config in `mkdocs.yml`, deployed by `.github/workflows/docs.yml`). When adding, removing, or renaming a docs page, update `mkdocs.yml`'s `nav:` list to match - pages not listed there still build but won't appear in the site navigation. `README.md` itself stays a short landing page (tagline, screenshots, links out to the docs site) and should not grow a Table of Contents again; new content belongs in `docs/`, not README.

Preview changes locally before pushing: `pip install -r requirements-docs.txt && mkdocs serve` (use `mkdocs serve -a 127.0.0.1:8001` if SO-CRATES' own server is already running on its default port 8000). Run `mkdocs build --strict` to catch broken internal links - this fails the build the same way the deploy workflow does.

## Release Checklist

Before cutting a release:

1. Update `docs/release-notes.md` (the single source of truth - `README.md`
   links directly to it, there's no separate root-level stub) and bump the
   version in `socrates.py`'s `VERSION` constant / `docs/api.md`'s
   `/api/version` example if it changed. Do this *before* building the
   container in the next step - `VERSION` is baked into the image at build
   time, so bumping it after would leave the built image (and every
   screenshot/video captured from it) reporting the old version.
2. **Build the container image and use it for screenshot/video generation.**
   From the repo root, prefer `podman build -t so-crates:local -f Dockerfile .`
   when `podman` is on PATH; fall back to the equivalent `docker build -t
   so-crates:local -f Dockerfile .` otherwise. Run it (`podman run -d --rm
   -p <port>:8000 so-crates:local`) - `/data` is a Dockerfile `VOLUME` with
   no bind-mount given, so podman/docker creates a fresh anonymous volume
   for it automatically, giving a genuinely clean installation (no
   Previous Analyses clutter) with none of local dev's gaps: real baked-in
   Suricata/YARA/Sigma rules and, critically, real Playbook/AI Summary
   content (`PLAYBOOKS_DIR`/`AI_SUMMARIES_DIR` are baked into the image
   from the `resources-builder` stage - a bare local checkout has neither,
   which silently skips the Playbook screenshot below with a warning
   instead of capturing it). Confirm it started cleanly (`podman logs
   <container>`, look for "Baked-in rules copied successfully") and that
   `GET /api/version` reports the version you just bumped to, before using
   it for the next two steps.
3. **Regenerate the demo video first** - before screenshots, not after (see
   why at the end of this step). Run `python3 -m playwright install ffmpeg`
   (one-time; Playwright's video muxing needs its own bundled ffmpeg,
   separate from any system ffmpeg) then `python3 scripts/record_demo.py
   --base-url http://127.0.0.1:<port>/socrates.html` against the container
   from step 2. This re-records the workflow end-to-end (sample pcap → each
   data type → All Events → Aggregation Tables filtering → drill-down →
   ASCII Transcript → Hexdump) and publishes `docs/videos/demo.mp4` (silent,
   H.264 video only - Playwright's page recording has no audio source, so
   there is no audio track to re-encode) and `docs/videos/demo-poster.jpg`
   (a still frame grabbed from the same raw capture, used as the `<video
   poster>` so the embed doesn't show a blank white square before
   playback), both re-encoded/extracted via a system `ffmpeg` binary from
   Playwright's raw WebM capture - MP4 is used rather than WebM since it's
   universally browser-supported and is also the format required to upload
   the same clip directly to X/Instagram/LinkedIn/Facebook. `demo.mp4`'s
   encode trims a fraction of a second (`MP4_TRIM_START_SECONDS`) off the
   very start, since Playwright's raw recording's first frame can be
   captured before the page has fully painted into the configured viewport -
   left untrimmed, that showed up as the thumbnail X/LinkedIn/etc.
   auto-extract when someone uploads `demo.mp4` directly (small upper-left
   region of real content against an otherwise flat grey frame). The video
   is embedded on the Home page just above Screenshots. If `ffmpeg` isn't on
   PATH, it falls back to publishing the raw `docs/videos/demo.webm` instead
   with a warning - see the script's module docstring. Re-run whenever the
   recorded workflow's on-screen text/labels change (e.g. a renamed button
   or tab) even if nothing else about the release does - the captions are
   hardcoded to match specific UI strings and will look wrong (or the script
   will fail to find an element) if those drift.

   **Must run before `capture_screenshots.py`, on a container/volume
   neither script has touched yet - confirmed by hitting this for real, not
   theoretical.** `record_demo.py`'s captions are keyed to exact strings
   from the sample's own analysis (e.g. a specific aggregation-row value);
   running `capture_screenshots.py` against the same container first (its
   own "Sample pcap file" click triggers the identical analysis) left that
   value's own locator un-findable within `record_demo.py`'s wait window
   once run second - `Locator.scroll_into_view_if_needed: Timeout 30000ms
   exceeded` on an `.agg-row` lookup, even though the exact same analysis
   completed successfully and the value genuinely was in the data. The
   reverse order (video against an untouched container, then screenshots
   after) worked without issue. If you must re-run either script a second
   time for any reason, remove and recreate the container first rather than
   reusing one either script has already driven a real analysis against.
4. **Regenerate screenshots.** Run `pip install -r requirements-screenshots.txt
   && python3 scripts/capture_screenshots.py --base-url
   http://127.0.0.1:<port>/socrates.html` against the same container, now
   that step 3's video is done with it. This refreshes all 7
   `docs/images/so-crates-*.png` (Home page) and all 35
   `docs/images/themes/*.png` (Themes page) against the app's own default
   sample pcap (`DEFAULT_SAMPLE_URL` in `static/socrates.js` - a one-click
   convenience link to an external pcap on malware-traffic-analysis.net, not
   something bundled with the app) - no local fixture or hardcoded MD5
   needed. Run this on every release, not just when the UI visibly changes -
   stale screenshots (e.g. showing an old default value in the Welcome
   modal) are easy to miss otherwise. If a new theme was added since the
   last release, make sure it was also added to the separate hardcoded
   `THEMES` list in `scripts/capture_screenshots.py` (see step 5 under "To
   add a new theme" above) - it is not derived from the registry, so a
   theme missing from it silently produces no screenshot rather than an
   error. This is also the run that captures `so-crates-playbook.png` -
   local dev has neither `PLAYBOOKS_DIR` nor `AI_SUMMARIES_DIR` baked in, so
   it silently skips that one screenshot with a warning instead of
   capturing it; the container has both, so confirm the script's own output
   says "captured playbook", not a "no playbook available" warning.

   Stop and remove this container (`podman rm -f <container>`) once both
   captures succeed - it's served its purpose; step 9 builds and
   smoke-tests a fresh one at the very end as the final pre-push gate.
5. **Review the diff** of the regenerated PNGs (`git diff --stat docs/images/`)
   before committing - a near-identical diff for every file usually means
   nothing meaningful changed; a few files changing more than the rest is
   worth a manual look to confirm it's an intended UI change, not a bug.
6. **Go through each page of the docs - including `AGENTS.md` and
   `README.md`, not just the MkDocs site under `docs/*.md` - and make sure
   it is accurate.** Don't just proofread - verify claims (endpoint shapes,
   config defaults, file layouts, dependency lists, test counts) directly
   against the current source (`socrates.py`, `db.py`, `validators.py`,
   `config.py`, `Dockerfile`, `socrates.html`, `static/socrates.js`,
   `tests/*.py`), not against what the docs already say or what a prior
   release looked like. Docs drift silently as the app changes underneath
   them, and even a hardcoded *count* standing in for a full list (event
   types, columns, tests) goes stale the same way a full list would - see
   `docs/filtering.md`'s "Per-type columns are not enumerated here" note.
   **A claim about UI structure or behavior - which element renders what,
   what order things appear in, what runs in response to what - is not
   verified by confirming the data it's built from still exists.** Checking
   that a registry, constant, or list mentioned in the claim is still
   present only confirms the *ingredient*; the claim is about the
   *assembly* - which function actually consumes that data and what it
   currently does with it. Open and read the named function(s) themselves.
   A behavioral claim can go stale (a preview moved to an isolated iframe,
   an indicator changed from a checkmark to a border, a list moved from one
   container to another) even while every constant the old prose pointed to
   is untouched. Re-run `mkdocs build --strict` after each fix.

   **This only catches claims that are wrong - it does not catch a feature
   that's simply absent from user-facing docs.** A new feature can ship
   with `docs/release-notes.md` and the technical `docs/architecture/*.md`
   pages updated while `docs/usage.md` (the actual how-to-use-the-app guide)
   never gets a new section at all - there's no false claim there to catch
   by verifying accuracy, just a silent gap. This happened for real: the
   pivot menu, per-row notes, Security Onion Playbooks, and Decoder Alerts
   all shipped without a single mention in `docs/usage.md`, caught only
   because someone asked directly. So: for every user-facing feature added
   or changed since the last release (check `docs/release-notes.md`'s
   latest section for the list), explicitly confirm `docs/usage.md`
   describes it - not just that everything already in `docs/usage.md` is
   still true.
7. **Review all source and docs** for spelling errors, grammar issues, logic
   issues, security issues, orphaned code, and code that needs refactoring.
   Cover the whole tree, not just what changed since the last release -
   issues introduced several releases back are just as worth catching. Fix
   what's clearly correct to fix; for anything that implies a design
   decision (e.g. removing a function with no caller vs. wiring it up),
   flag it and confirm before acting rather than guessing.
8. Run the full test suite (`python3 -m unittest discover -v`) and
   `mkdocs build --strict` before pushing. `tests/jsdom_helper.py` sets
   `JSDOM_TEST_ORIGIN` (`http://localhost:19999`) as the JSDOM page origin -
   deliberately not the app's real dev-server port (8000), so a manually-running
   `python3 socrates.py` no longer needs to be stopped before running tests.
   With `resources: 'usable'`, JSDOM genuinely fetches `<script src="static/socrates.js">`
   (and the d3 files) over real network I/O rather than only via the
   harness's own intentional `window.eval(jsContent)` - if something were
   ever actually listening on `JSDOM_TEST_ORIGIN`'s port, that fetch would
   succeed and `socrates.js` would execute a *second* time inside the
   test's window, re-running `init()` and resetting shared top-level `var`
   state (e.g. `currentFileName`) mid-test for whichever tests are slow
   enough to still be running when that extra network round-trip resolves -
   `TestRenameAnalysis` was the class most likely to trip on it back when
   this pointed at port 8000. If a full run ever reports a handful of
   failures you can't otherwise explain, check for a listener on
   `JSDOM_TEST_ORIGIN`'s port before assuming a real regression. This run
   can legitimately take 10+ minutes for the full suite (2000+ tests across
   every `tests/test_*.py` module) - give it a generous timeout rather than
   killing it early and mistaking a still-running suite for a hang.
9. **Build the container image locally and smoke-test it, one more time.**
   Same command as step 2, but this is a distinct pass, not a rerun of
   that one - it validates the *final* code state (post docs/source-review
   fixes from steps 6-8), and its purpose is different: catching a build
   that fails to execute, not generating assets. The test suite's
   Dockerfile checks are all static string/regex matching against its text -
   they cannot catch a build that actually fails to execute, and this is not
   hypothetical: two separate real CI failures (a missing `ca-certificates`
   package breaking `git clone` with "Problem with the SSL CA cert", and a
   missing `suricata-update update-sources` call breaking `enable-source`
   for any curated rule source not in suricata-update's own bundled index)
   both went straight through every existing checklist step undetected and
   were only caught by an actual build. Neither required a Dockerfile edit
   to trigger, either - a base image refresh alone can silently break a
   build with no local diff to review, so run this every release, not just
   when the Dockerfile changed. After a successful build, run it
   (`podman run -d -p <port>:8000 <tag>`) and confirm: the container starts
   and logs "Baked-in rules copied successfully", `GET /api/version`
   responds with the version you bumped to, `GET /api/rules-info` shows the
   expected baked-in Suricata source count, and `/usr/share/playbooks/` has
   both `.json.gz` indexes (`podman exec <container> ls /usr/share/playbooks/
   /usr/share/suricata/rules-available/`). Clean up the test container and
   image afterward (`podman rm -f`/`podman rmi`) rather than leaving it
   alongside the deployment's real image.
10. **Remove any stray `tmp*` directories or files** left in the project root
    (e.g. `tmp-********` dirs) - the pattern is gitignored, so they won't
    show up in `git status`, but they're debris from agent sandboxes and
    are easy to miss with `find . -maxdepth 1 -iname 'tmp*'`. (The old
    `tmp*.js` offenders no longer occur: `tests/jsdom_helper.py` writes its
    per-test driver scripts to the system temp directory now, precisely so
    a hard-killed test run can't strand them in the repo root.)
