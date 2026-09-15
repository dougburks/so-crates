# Filtering Architecture

## Design

`currentFilters` is a **flat object** mapping column names to a per-column
filter spec. The spec is polymorphic - a plain string means "exact match"
(the original shape, still written by `applyFilters()` when a Sankey
diagram link/node is clicked), or an `{include: [...], exclude: [...]}`
object (written by the pivot menu's Include/Exclude/Only actions -
`includeFilterValue()`/`excludeFilterValue()`/`onlyFilterValue()` - when a
table row cell or aggregation-table value is clicked):

```js
let currentFilters = {};
// Example: { "Dest Port": "80", "Source IP": { "include": ["10.0.0.1"], "exclude": [] } }
```

`matchesCurrentFilters(e, extractFn)` is the one place that reads both
shapes - a string entry requires an exact match; an object entry ORs
`include` (empty include means "no restriction") and excludes anything in
`exclude`. Different columns always AND together regardless of shape.

Filters are **global** - they apply across all tabs (Alert, DNS, HTTP, All Events, etc.). When a filter is set on one tab, it persists when switching to another tab.

Search (`currentSearch`) is a separate server-side full-text filter using SQLite FTS5. It is an **array of terms** - typing `tcp 80` creates two chips `[🔍 "tcp" ×] [🔍 "80" ×]`. Each chip is independently removable. Quoted phrases like `"GET /login"` become a single chip. Search terms AND together on the backend. Search complements column filters: you can search for `192.168.1.1` and then further narrow with aggregation filters. Search is cleared when loading a new PCAP or when clicking **Clear All**.

## Scalable Fetch vs. Full-Batch Fallback

With no column filter active, the table, aggregations, and Sankey diagram all use lightweight, unbounded server-side queries - `fetchEventsPage()` (SQL `LIMIT`/`OFFSET`, always exactly `CONFIG.TABLE_PAGE_SIZE` rows per page), `fetchAggregationData()`, and `fetchSankeyData()` (both server-side `GROUP BY` over the full matching set). None of these are bounded by the query-limit setting described below - they work the same regardless of dataset size.

The moment a column filter is applied (`applyFilters()`, or any of the pivot menu's Include/Exclude/Only actions, all of which write into `currentFilters`), everything falls back to full-batch client-side mode: `canUseScalableFetch()`, `canUseServerAggregation()`, and `canUseServerSankey()` all check `Object.keys(currentFilters).length === 0` and become `false`. This is because arbitrary column-value filtering has no server-side `WHERE`-clause equivalent - only search (`q=`) and `type=` are implemented server-side. `applyFilters()` then calls `ensureCappedBatch(eventType)`, which fetches up to `getUserQueryLimit()` raw rows (default 75,000, user-adjustable up to the server ceiling `MAX_QUERY_LIMIT` = 100,000 - see `GET /api/limits` in [api.md](api.md)) into `tabDataCache`/`allEvents`. From there, filtering, sorting, table pagination, and aggregation (for `log`/`sigmaalert`/`binary`/`mqtt`/`ldap`, which have no server-side aggregation at all) all happen in JS over that in-memory array.

`log`/`sigmaalert`/`binary`/`mqtt`/`ldap` event types always need the full batch for their aggregation view regardless of filters, since their columns are dynamic/data-dependent or (for `binary`) have no scalable path at all - see `needsFullBatch()`.

If the true match count exceeds what was fetched, `ensureCappedBatch()` marks the type in `truncatedTypes`, and `isCurrentTabTruncated()` drives a visible warning in the filter bar - filtered/aggregated results are never silently incomplete without an indicator, but they can still be a partial view of a very large, heavily-filtered dataset.

## Key Functions

| Function | Role |
|---|---|
| `performSearch()` | Splits `searchInput` into terms, pushes to `currentSearch` array, clears input, refreshes data |
| `clearSearchTerm(index)` | Removes single term at index from `currentSearch`, refreshes data |
| `applyFilters(sectionId, filters)` | Sets `currentFilters[f.column] = f.value` for each `{column, value}` pair, rebuilds table + agg grid + stats + sankey - the only remaining caller that passes filter pairs is a Sankey link/node click (Include/Exclude/Only reuse it with an empty list for the rebuild) |
| `matchesCurrentFilters(e, extractFn)` | Returns whether one event matches every active column filter, handling both the string and `{include, exclude}` shapes |
| `ensureFilterSpec(column)` | Normalizes `currentFilters[column]` to the `{include, exclude}` shape, upgrading a pre-existing plain-string entry rather than clobbering it |
| `includeFilterValue(sectionId, column, value)` | Pivot menu "Include" - broadens `column` to also match `value` (OR'd with whatever it already allows); every other column untouched |
| `excludeFilterValue(sectionId, column, value)` | Pivot menu "Exclude" - narrows `column` to also deny `value`; every other column untouched |
| `onlyFilterValue(sectionId, column, value)` | Pivot menu "Only" - resets every other filter so `column = value` is the sole active filter; leaves `currentSearch` untouched |
| `huntFilterValue(value)` | Pivot menu "Hunt" - replaces `currentSearch` with just this one term and clears `currentFilters` entirely (a full reset, unlike Only) |
| `clearFilter(columnName)` | Deletes `currentFilters[columnName]` outright (both shapes), rebuilds |
| `clearFilterValue(column, kind, value)` | Removes one value from a column's `include`/`exclude` list, deleting the column's entry entirely once both lists are empty; leaves any other value on that column alone |
| `clearAllFilters()` | Clears **both** `currentSearch` and `currentFilters`, refreshes data from server |
| `getFilteredEvents(sectionId, events, eventType)` | Returns events matching all active column filters |
| `buildSection(eventType, events)` | Builds the main data table, applies `currentFilters` internally |
| `buildAggregationsSection(eventType, events)` | Builds agg grid; **expects pre-filtered events** |
| `buildAllEvents()` | Builds "All Events" table, applies `currentFilters` internally |
| `buildAggregationsSectionAll()` | Builds agg grid for "All Events"; applies `currentFilters` internally |
| `updateFilterBarVisibility()` | Shows/hides the filter bar when search or filters exist |
| `buildStats(filteredStats)` | Rebuilds stats cards - always shows the filtered count alone (comma-formatted), never "filtered / total"; a data type with a filtered count of zero is dropped from the grid entirely rather than shown disabled |
| `canUseScalableFetch()` / `canUseServerAggregation(eventType)` / `canUseServerSankey(eventType)` | `true` when no column filter is active (and, for scalable fetch, no client-only sort) - gates server-side pagination/aggregation/Sankey vs. the full-batch fallback |
| `ensureCappedBatch(eventType)` | Fetches up to `getUserQueryLimit()` raw rows into `tabDataCache`/`allEvents`; no-op if already cached |
| `needsFullBatch(eventType)` | `true` when the aggregation view (Aggregation toggle ON) can't use its server-side fetch (log/sigmaalert/binary/mqtt/ldap, or any type once a column filter is active), or when the Sankey diagram (Diagram toggle ON) can't (a column filter is active) |
| `getUserQueryLimit()` | Reads/validates the user's configured full-batch row cap from `localStorage`, falling back to `CONFIG.DEFAULT_QUERY_LIMIT` |
| `computeFilteredStats()` | Counts events by type from the filtered subset |
| `getSankeyEvents()` | Returns filtered events for the currently visible tab for the Sankey diagram |
| `refreshCurrentView()` | Rebuilds the current tab's table, aggregations, stats, filter bar, and Sankey diagram |
| `updateSankeyDiagram()` | Rebuilds the Sankey diagram using events from `getSankeyEvents()` |

## Data Flow

- `buildSection` / `buildAllEvents` apply `currentFilters` internally
- Filter bar is rendered by `updateFilterBarVisibility()` into `#filterBarContainer`
- `buildAggregationsSection` expects **pre-filtered events** from the caller
- `loadTabData` must call `getFilteredEvents()` before passing data to `buildAggregationsSection`
- `buildAggregationsSectionAll` applies `currentFilters` internally (exception to the pre-filtered rule)

## Column Overlap

Per-event-type columns differ from "All Events" columns:

| Shared columns | Per-type only | All-events only |
|---|---|---|
| Time, Protocol, Source IP, Source Port, Dest IP, Dest Port | Everything else `getColumnsForType()` returns per event type - see below | Type (event type itself, e.g. `"DNS"`/`"ANOMALY"`), Detail |

**Per-type columns are not enumerated here, including their count.** Every
event type has its own real per-type columns (`getColumnsForType()` in
`static/socrates.js`) - e.g. Alert/Category/Severity for `alert`, Query/Type
for `dns`, JA3/JA3S for `quic`, Opcode/Fin/Payload for `websocket`,
Operation/Message ID/Result Code for `ldap`. A prior version of this doc
tried to keep a hardcoded copy of that list here (and later, just a
hardcoded event-type/column *count* as a compromise); both went stale the
same way, every time a new event type was added - even the count needed
updating far more often than anyone remembered to. Treat `getColumnsForType()`
as the only source of truth for what columns exist per type, including how
many there are - don't re-add a number here either.

Two columns mean something **different** depending on context, and that
distinction genuinely belongs in this doc (it's the one thing a fresh read
of `getColumnsForType()` won't tell you by itself):
- **`Type`**: on a per-type tab it's protocol-specific (a DNS/mdns record
  type, dnp3's own `type` field, anomaly's `type` field, ...). In "All
  Events" it means the event_type itself, uppercased (e.g. `"HTTP"`).
  `extractAllValue()` special-cases `'Type'` for exactly this reason.
- **`Detail`**: only exists in "All Events" - a one-line, event-specific
  summary (e.g. the DNS query name, the alert signature, the ldap
  operation). Each event type's Detail rendering lives in `extractValue()`'s
  shared `'Detail'` case.

When filtering, both `extractValue()` and `extractAllValue()` handle every
per-type column. `extractAllValue()` delegates everything except `'Type'`
straight to `extractValue()`, so it automatically supports the full,
current set of per-type columns without needing its own copy of the list -
this is also why a filter set on one tab (e.g., Alert on the Alerts tab)
correctly matches events when switching to "All Events". Only truly
unknown columns return `''`.

**REGRESSION, fixed:** `extractAllValue()` used to also special-case
`'Command'` (hardcoded to `e.ftp?.command`, which went stale the moment
pgsql/enip/pop3 gained their own real command fields - it silently returned
`''` for all three in the "All Events" view) and `'Message'` (read
`e.anomaly?.message`, a field that has never existed in Suricata's eve.json
anomaly schema - the real field is `event`, and no column has been labeled
`'Message'` since anomaly gained real columns). Both overrides were removed;
`extractValue()`'s own per-protocol handling was already correct.

## Known Gotchas

### 1. `currentFilters` must stay flat
Nesting it as `{sectionId: {columnName: value}}` causes filters to disappear when switching tabs because each tab creates a new empty section entry. Tests enforce this:
- `test_currentFilters_is_flat_object_not_nested`
- `test_all_filtering_functions_use_global_currentFilters`

### 2. `buildAggregationsSection` expects pre-filtered events
When calling `buildAggregationsSection(eventType, events)` in aggregation mode, `events` must already be filtered through `getFilteredEvents()`. Passing raw events will show incorrect aggregation counts. Tests enforce this:
- `test_loadTabData_filters_agg_tables_in_advanced_mode_cached`
- `test_loadTabData_filters_agg_tables_in_advanced_mode_fresh`

### 3. Aggregation toggle must filter before building agg tables
When the user toggles Aggregation ON, the handler must call `getFilteredEvents()` before `buildAggregationsSection()`. See the `advancedToggle` change listener.

### 4. onclick quoting
Never use `JSON.stringify()` inside `onclick` attributes - it produces double-quoted strings that break inside double-quoted HTML attributes. Use single-quoted template expressions with escaped internal single quotes. Tests enforce this:
- `test_no_json_stringify_in_clear_filter_onclick`
- `test_clear_filter_uses_single_quoted_args`
- `test_agg_row_onclick_has_escaped_quotes`
- `test_no_bare_json_stringify_in_onclick_templates`

Note: the pivot menu (Include/Exclude/Only/Hunt, and the row-cell/
aggregation-row click handlers that open it) doesn't build `onclick`
attribute strings at all - it's wired via `addEventListener` closures over
the real column/value instead, specifically to sidestep this whole class of
escaping bug for values that can be arbitrary attacker-influenced content
(a log field, an HTTP header, etc). See `showPivotMenu()`'s own comment.

## Running Tests

```bash
python3 -m unittest discover tests -v
```

All tests must pass. The filtering-related tests are in:

- `TestFilterOnclickQuoting` (4 tests)
- `TestAdvancedModeFilterBar` (32 tests)
- `TestSearchUI` (30 tests)
