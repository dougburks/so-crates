# UI

Four files:

| File | Content |
|---|---|
| `socrates.html` | HTML shell (repo root) - no inline CSS or JS |
| `static/theme-boot.js` | Restores the saved theme before first paint |
| `static/socrates.css` | All styles |
| `static/socrates.js` | All JavaScript |

`socrates.html` loads them via `<script src>` and `<link>` tags - `theme-boot.js` parser-blocking in `<head>`, so the theme applies before anything draws. D3 and d3-sankey are vendored in `static/` for offline use; CyberChef is baked into the container image and served at `/cyberchef/` (see [Architecture](index.md)).

## UI States

```
Welcome Screen (no analysis loaded)
  ├── Sample PCAP/log/binary/email cards (built in - load-builtin-sample → POST /api/load-sample)
  ├── URL input + file upload
  └── Previous analyses list

Analysis View (analysis loaded)
  ├── App header (SO-CRATES logo/home link, file name, MD5, date range, notes/reanalyze/delete icons, gear menu)
  ├── Search bar
  ├── File Info card (binary-file analyses only)
  ├── Filter Bar (active search and filters as removable chips)
  ├── Stats Grid (clickable event-type cards, shows the filtered count alone when a filter is active - see `buildStats()` in filtering.md)
  ├── Sankey Diagram (collapsible section - Source IP → Dest IP → Dest Port, reflects current filters)
  ├── Aggregation Tables (collapsible section - frequency counts per column)
  └── Data Table (the selected tab's rows; a row expands into its detail panel)
```

## JavaScript Architecture

**Global state:**
```js
let allEvents = [];          // Loaded for "All Events" tab
let eventTypes = [];         // available types for current analysis
var currentMd5 = '';         // current analysis MD5 (var, not let - see below)
var currentFileName = '';    // display name (var, not let - see below)
var currentNotes = '';       // per-analysis freeform notes (var, not let - see below)
var currentFilters = {};     // {columnName: value | {include, exclude}} — global, flat (var, not let - see below)
let currentSearch = [];      // server-side full-text search terms (array)
let baseEventStats = {};     // unfiltered per-type totals (baseline for the tab set)
var advancedMode = false;    // advanced toggle state (var, not let - see below)
let tabDataCache = {};       // cached event data per type
```

`currentMd5`/`currentFileName`/`currentNotes`/`currentFilters`/`advancedMode` (and a couple of others, e.g. `truncatedTypes`) are deliberately declared with `var` rather than `let`/`const` - the JSDOM test harness (`tests/jsdom_helper.py`) assigns/reads them via separate `window.eval()` invocations, and only `var`/function declarations attach to the actual global object persistently across those separate evaluations.

**Key function groups:**

| Group | Functions | Purpose |
|---|---|---|
| Navigation | `showWelcome()`, `loadAnalysis()`, `showTab()`, `showWelcomeUI()`, `showAnalysisUI()` | Screen/tab switching |
| Keyboard Navigation | `navigateStatTabs()`, `activeColumnStatCards()`, `navigateSampleCards()`, `navigateVertical()`, `seedVerticalNavSelectionIfStale()`, `navigateFilterBarItems()`, `focusNewestFilterChip()`, `focusFilterBarOrFirstCard()`, `navigateThemeTiles()`, `activateKeyboardSelection()`, `isNavigableKeyContext()` | Arrow-key/Enter navigation (see [Usage](../usage/keyboard-and-menus.md#keyboard-shortcuts)) |
| Command Palette | `AUTOCOMPLETE_COMMANDS`, `openAutocompleteModal()`, `filterAutocomplete()`, `autocompleteMatchesQuery()`, `autocompleteMatchScore()`, `activateAutocompleteSelection()` | Type-anywhere command list (see [Usage](../usage/keyboard-and-menus.md#command-palette)) |
| Data Loading | `loadTabData()`, `loadFromUrl()`, `uploadPcap()`, `checkStatus()` | Fetch data from API |
| Rendering | `buildStats()`, `buildSections()`, `buildSection()`, `buildAllEvents()`, `buildRowForEvent()`, `updateSankeyDiagram()` | Build HTML |
| Aggregation | `buildAggregationTablesCore()`, `buildAggregationTables()`, `buildAggregationTablesAll()`, `buildAggregationsSection()`, `buildAggregationsSectionAll()` | Frequency grids |
| Search | `performSearch()`, `clearSearchTerm()`, `refreshAnalysisData()` | Full-text search via server |
| Filtering | `applyFilters()`, `clearFilter()`, `clearAllFilters()`, `getFilteredEvents()`, `getSankeyEvents()`, `refreshCurrentView()` | Column filter management |
| Streams | `downloadPcap()`, `loadAsciiTranscript()`, `loadHexdumpData()`, `switchStreamView()`, `togglePacket()`, `toggleRow()` | Stream analysis |
| Modals | `closeAllModals()`, `showNotesModal()`, `closeNotesModal()`, `saveAnalysisNotes()`, `openAnalysisNotesFromList()`, `showRulesModal()`, `closeRulesModal()`, `triggerRulesetUpdate()`, `isRulesetStale()` | Notes editing and Rules-modal management, shared modal cleanup |
| Utilities | `escapeHtml()`, `formatEvent()`, `extractValue()`, `extractAllValue()`, `getColumnsForType()`, `clearAnalysisContainers()` | Helpers |

## Column System

Each event type has its own column set. The "All Events" view uses a unified column set.

**Shared columns (every network event type):** Time, Protocol, Source IP, Source Port, Dest IP, Dest Port. Log events and Sigma alerts have their own, data-dependent columns instead, and an email analysis's tabs (Emails, Links, File Info, File Alerts) have networkless ones (`EMAIL_MODE_COLUMNS`) and no All Events view.

**Per-type columns:** e.g. Alert/Category/Severity (alerts), Query/Type (DNS), Method/Host/URL/Status (HTTP). Every event type on the [Event Types](event-types.md) page has its own set - 30+ types by now - defined in `getColumnsForType()` (`static/socrates.js`), which is the source of truth; this doc intentionally doesn't enumerate all of them; a full list here would just drift out of sync with every new protocol added (the same problem already found and fixed once in `filtering.md`'s old "Column Overlap" table).

**All-events columns:** Type (event type), Detail (type-specific summary)

## Filtering Design

Filters are **global** - `currentFilters` is one flat object keyed by column name, whose value is either an exact-match string or an `{include, exclude}` list pair. `matchesCurrentFilters()` applies every active filter to every tab: a filter on a column the current tab doesn't have compares against an empty value, so it excludes those rows rather than being skipped - a DNS `Query` filter matches no HTTP events, so the HTTP card drops out of the stats grid (`buildStats()` omits zero-count types).

See [filtering.md](../filtering.md) for full details.
