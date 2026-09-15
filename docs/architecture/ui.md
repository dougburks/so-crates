# UI

Three files:

| File | Content |
|---|---|
| `socrates.html` | HTML shell (repo root) |
| `static/socrates.css` | All styles |
| `static/socrates.js` | All JavaScript |

`socrates.html` loads the CSS and JS via `<link>` and `<script src>` tags. D3 and d3-sankey are vendored in `static/` for offline use.

## UI States

```
Welcome Screen (no analysis loaded)
  ├── URL input + file upload
  └── Previous analyses list

Analysis View (analysis loaded)
  ├── Header (back button, name, path, date range)
  ├── Visualizations bar (Diagram toggle, Aggregation toggle)
  ├── Filter Bar (active search and filters as removable chips)
  ├── Stats Grid (clickable event-type cards, shows the filtered count alone when a filter is active - see `buildStats()` in filtering.md)
  ├── Sankey Diagram (diagram mode — Source IP → Dest IP → Dest Port, reflects current filters)
  ├── Aggregations (frequency counts per column)
  └── Data Sections (tabbed tables)
```

## JavaScript Architecture

**Global state:**
```js
let allEvents = [];          // Loaded for "All Events" tab
let eventTypes = [];         // available types for current analysis
var currentMd5 = '';         // current analysis MD5 (var, not let - see below)
var currentFileName = '';    // display name (var, not let - see below)
var currentNotes = '';       // per-analysis freeform notes (var, not let - see below)
var currentFilters = {};     // {columnName: value} — global, flat (var, not let - see below)
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

**Shared columns (all types):** Time, Protocol, Source IP, Source Port, Dest IP, Dest Port

**Per-type columns:** e.g. Alert/Category/Severity (alerts), Query/Type (DNS), Method/Host/URL/Status (HTTP). Every event type on the [Event Types](event-types.md) page has its own set - 30+ types by now - defined in `getColumnsForType()` (`static/socrates.js`), which is the source of truth; this doc intentionally doesn't enumerate all of them; a full list here would just drift out of sync with every new protocol added (the same problem already found and fixed once in `filtering.md`'s old "Column Overlap" table).

**All-events columns:** Type (event type), Detail (type-specific summary)

## Filtering Design

Filters are **global** - `currentFilters` is a flat `{columnName: value}` object. When switching tabs, filters for columns that don't exist in the new view are silently skipped (the column lookup returns `-1` and the filter is ignored).

See [filtering.md](../filtering.md) for full details.
