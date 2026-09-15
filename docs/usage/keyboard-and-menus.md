# Keyboard & Menus

## Keyboard Shortcuts

Arrow keys navigate rather than scroll the page, and adapt to what's on screen:

- **Left/Right** - on the welcome screen, moves between the sample-file cards; on an analysis page, switches between stat-card tabs, or between Aggregation Tables (or, once on a table's Prev/Next stop, toggles between the two) when the keyboard highlight is inside that section
- **Up/Down** - on the welcome screen, moves between rows in Previous Analyses; on an analysis page, moves between rows in the visible data table. Inside the Aggregation Tables section, Down walks a table's own rows and then its Prev/Next stop before continuing into the next visual row of tables (or the Data Table if there isn't one) - Up retraces the same path in reverse
- **Enter** - activates whatever's currently highlighted (opens a sample or previous analysis, or expands/collapses a table row) - the same as clicking it
- **Escape** - closes whatever's open (a modal, the gear menu, a pivot menu) one level at a time, then returns to the welcome screen once nothing else is open
- **`<` / `>`** - cycles through themes backward/forward; see [Themes](../themes.md)

When the [Themes](../themes.md) modal is open, all four arrow keys instead move a highlight through the theme grid (Left/Right by one tile, Up/Down by a full row) and live-preview whichever tile is highlighted, the same as hovering it with the mouse - Enter applies it. Typing a theme's name jumps the highlight straight to it (native `<select>`-style type-ahead, not the command palette below - it stays closed the whole time).

### Command Palette

Typing any letter or digit outside a text field opens a command palette, pre-filled with what you typed. Keep typing to narrow the list, Up/Down to highlight a candidate, Enter to commit it (or Escape to cancel without doing anything). A query matches anywhere in a candidate, not just its very first word - typing `alerts` finds both **Network Alerts** and **File Alerts**, `blue` finds every Fun theme with "Blue" in its name, and even a bare mid-word fragment like `eme` finds **Themes**. Results that match at the very start rank above word-boundary matches, which rank above a bare mid-word match, so a short, precise query never gets buried. It matches:

- Any theme's own name (e.g. `gruvbox`, `cga`, `breadbin blue`) - switches to it directly, the same as picking it from the [Themes](../themes.md) modal
- Any data-type stat-card tab currently on screen (e.g. `dns`, `http`, `all events`) - switches to that tab, the same as clicking it
- `help`, `about`, `themes`, `rules`, or `settings` - opens the corresponding modal from the [Gear Menu](#gear-menu) below
- `advanced features` - opens the Security Onion feature-comparison modal
- `documentation`, `security onion`, `github repo`, `pcap samples`, `log samples`, or `binary samples` - opens the corresponding external site in a new tab
- `upload`, `import`, or `previous analyses` (analysis page only) - all three return to the welcome screen, where all three actions live
- `copy md5 hash to clipboard` (analysis page only) - copies the current analysis's MD5, same as clicking it in the header
- `rename analysis` (analysis page only) - starts renaming the current analysis, same as clicking its filename in the header
- `notes` (analysis page only) - opens the Notes modal for the current analysis
- `delete` (analysis page only) - opens the delete-confirmation modal for the current analysis (still requires confirming there before anything is actually deleted)
- `re-analyze` (analysis page only) - opens the reanalyze confirmation modal for the current analysis
- `search` (analysis page only) - focuses the search bar instead of opening a modal
- `clear` (analysis page only) - clears all active search terms/filters, same as the filter bar's own Clear All button
- `sankey` (analysis page only) - collapses or expands the Sankey Diagram section
- `aggregation` (analysis page only) - collapses or expands the Aggregation Tables section

## Gear Menu

The gear icon in the upper-right corner opens a menu with five entries:

- **Help** - the welcome/help modal, including a link to this documentation site
- **Settings** - upload size, query result limit, custom lookup sites, and a Danger Zone section to permanently delete every previous analysis at once (with a live count of how many exist)
- **Themes** - browse and apply themes; see [Themes](../themes.md)
- **Rules** - check the current rule count and last-updated time for Suricata, YARA, and Sigma, and trigger an update for one ruleset (or all three) with live progress. Rule updates are not run automatically at startup - this modal is the only way to refresh them after the initial install. The Suricata section also has a "Show protocol-anomaly noise alerts" toggle (off by default) for Suricata's own built-in decoder alerts (e.g. excessive retransmissions) - see [Decoder Alerts](exploring-results.md#navigate-results)
- **About** - current version, links to this documentation site and the GitHub repo, and an opt-in "Check GitHub for newer releases" setting with a manual "Check Now" button
