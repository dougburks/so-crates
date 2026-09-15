        function escapeHtml(str) {
            if (str == null) return '';
            return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }

        // escapeJsString (JS-string-then-HTML escaping for values embedded
        // in inline handler attributes) is gone: no generated HTML carries
        // inline on*= handlers anymore (CSP: script-src without
        // 'unsafe-inline'). Dynamic values now ride in data-* attributes -
        // escapeHtml'd scalars, or percent-encoded JSON for structured
        // payloads (see pivotDataAttrsHtml) - decoded by the delegated
        // listeners at the bottom of this file.

        // Shared by loadAnalysis() (the analysis header) and showWelcome()
        // (the Previous Analyses list) so both render a sample's own event
        // date range identically. Returns '' if neither bound is known
        // (e.g. an analysis still mid-processing, with no events.db yet).
        function formatDateRange(dateRange) {
            const min = dateRange && dateRange.min;
            const max = dateRange && dateRange.max;
            if (!min && !max) return '';
            return min && min === max
                ? min.slice(0, 19)
                : `${min?.slice(0, 19) || ''} to ${max?.slice(0, 19) || ''}`;
        }

        function safeStorageGet(storage, key) {
            try { return storage.getItem(key); } catch (e) { return null; }
        }
        function safeStorageSet(storage, key, value) {
            try { storage.setItem(key, value); } catch (e) { /* ignore */ }
        }
        function safeStorageRemove(storage, key) {
            try { storage.removeItem(key); } catch (e) { /* ignore */ }
        }

        // Reads and validates the user's persisted max-query-limit preference.
        // Re-validates on every call (not just at write time) since a
        // devtools-edited localStorage value bypasses saveSettings() entirely;
        // the server independently clamps this again regardless (defense in depth).
        function getUserQueryLimit() {
            const raw = safeStorageGet(localStorage, 'socrates_maxQueryLimit');
            const n = parseInt(raw, 10);
            if (isNaN(n) || n < 1000 || n > 500000) return CONFIG.DEFAULT_QUERY_LIMIT;
            return n;
        }

        function getUserMaxUploadSizeMB() {
            const raw = safeStorageGet(localStorage, 'socrates_maxUploadSizeMB');
            const n = parseInt(raw, 10);
            if (isNaN(n) || n < 100 || n > 20000) return CONFIG.DEFAULT_UPLOAD_SIZE_MB;
            return n;
        }

        // Unlike getUserQueryLimit()/getUserMaxUploadSizeMB(), there's no
        // client-side default constant to fall back to here - the real
        // default is the server's config.RULES_MAX_AGE_HOURS, fetched
        // dynamically via /api/rules-info's staleThresholdHours. Returns
        // null (not a fallback number) when unset/invalid, so callers can
        // tell "no override, use the server's value" apart from "override
        // to N days" - see _resolveStaleThresholdHours().
        function getUserStaleThresholdDays() {
            const raw = safeStorageGet(localStorage, 'socrates_staleThresholdDays');
            const n = parseInt(raw, 10);
            if (isNaN(n) || n < 1 || n > 365) return null;
            return n;
        }

        // Single place both isRulesetStale() consumers (the Rules modal's
        // date-color warning and checkForStaleRules()'s notification) go
        // through to resolve "how old is too old" - keeps them agreeing
        // the same way unifying on staleThresholdHours did originally (see
        // AGENTS.md's Detection Rule Freshness section), now that either
        // one can also be overridden by the user's per-browser preference.
        function _resolveStaleThresholdHours(serverHours) {
            const days = getUserStaleThresholdDays();
            return days !== null ? days * 24 : serverHours;
        }

        function sortEventTypes(types) {
            // Network Alerts, File Alerts, Decoder Alerts, Anomalies (in
            // that order) take priority over everything else, which then
            // falls back to alphabetical below. sigmaalert/log never
            // coexist with alert/filealerts/protocol_decode/anomaly (log
            // mode vs pcap mode are mutually exclusive), so their relative
            // priority to each other is preserved from before without
            // affecting the pcap-mode ordering above.
            const order = { alert: 0, filealerts: 1, protocol_decode: 2, anomaly: 3, sigmaalert: 4, log: 5 };
            return [...types].sort((a, b) => {
                const ai = order[a] ?? 99;
                const bi = order[b] ?? 99;
                if (ai !== bi) return ai - bi;
                return a.localeCompare(b);
            });
        }

        const THEMES = {
            dark: { label: 'Midnight', group: 'dark' },
            sguil: { label: 'Sguil', group: 'light' },
            hacker: { label: 'Hacker', group: 'fun' },
            cga: { label: 'CGA', group: 'fun' },
            'breadbin-blue': { label: 'Breadbin Blue', group: 'fun' },
            vaporwave: { label: 'Vaporwave', group: 'fun' },
            'digital-frontier': { label: 'Digital Frontier', group: 'fun' },
            'retro-handheld': { label: 'Retro Handheld', group: 'fun' },
            'matte-black': { label: 'Matte Black', group: 'dark' },
            'tokyo-night': { label: 'Tokyo Night', group: 'dark' },
            'retro-82': { label: 'Retro 82', group: 'dark' },
            'ethereal': { label: 'Ethereal', group: 'dark' },
            'lumon': { label: 'Lumon', group: 'dark' },
            'catppuccin': { label: 'Catppuccin', group: 'dark' },
            'ohmydebn': { label: 'OhMyDebn', group: 'dark' },
            'catppuccin-latte': { label: 'Catppuccin Latte', group: 'light' },
            'flexoki-light': { label: 'Flexoki Light', group: 'light' },
            'everforest': { label: 'Everforest', group: 'dark' },
            'gruvbox': { label: 'Gruvbox', group: 'dark' },
            'hackerman': { label: 'Hackerman', group: 'dark' },
            'kanagawa': { label: 'Kanagawa', group: 'dark' },
            'miasma': { label: 'Miasma', group: 'dark' },
            'nord': { label: 'Nord', group: 'dark' },
            'osaka-jade': { label: 'Osaka Jade', group: 'dark' },
            'ristretto': { label: 'Ristretto', group: 'dark' },
            'rose-pine': { label: 'Rose Pine', group: 'light' },
            'vantablack': { label: 'Vantablack', group: 'dark' },
            'white': { label: 'White', group: 'light' },
            'luna-blue': { label: 'Luna Blue', group: 'fun' },
            'amber': { label: 'Amber CRT', group: 'fun' },
            'dos-blue': { label: 'DOS Blue', group: 'fun' },
            'dracula': { label: 'Dracula', group: 'dark' },
            'solarized-dark': { label: 'Solarized Dark', group: 'dark' },
            'monokai': { label: 'Monokai', group: 'dark' },
            'mp3-player': { label: 'MP3 Player', group: 'fun' },
        };

        const THEME_GROUP_LABELS = { dark: 'Dark Themes', fun: 'Fun Themes', light: 'Light Themes' };
        const THEME_GROUP_ORDER = ['dark', 'light', 'fun'];

        // Menu/hotkey cycle order: group by section (Dark, Light, Fun),
        // alphabetical by label within each section.
        const THEME_MENU_ORDER = THEME_GROUP_ORDER.flatMap(group =>
            Object.keys(THEMES)
                .filter(k => THEMES[k].group === group)
                .sort((a, b) => THEMES[a].label.localeCompare(THEMES[b].label))
        );

        function getCurrentTheme() {
            return document.documentElement.getAttribute('data-theme') || 'dark';
        }

        let menuBaseTheme = null;

        // data-theme marker for a theme synthesized at runtime from an
        // OhMyDebn/Aether palette (see applyCustomTheme()) rather than one
        // of THEMES's hand-built CSS blocks. Not itself a THEMES key - never
        // manually selectable, only ever reached via OhMyDebn sync.
        const OHMYDEBN_CUSTOM_THEME = 'ohmydebn-custom';

        // Full set of CSS custom properties a synthesized theme sets inline
        // via applyCustomTheme() - kept in one place so setTheme() can clear
        // them all when switching back to a real, CSS-block-backed theme.
        const CUSTOM_THEME_CSS_VARS = [
            '--accent', '--help-icon-color', '--accent-hover',
            '--bg-primary', '--bg-secondary', '--bg-tertiary', '--bg-hover', '--bg-hover-light',
            '--border-color', '--bg-drop-active', '--badge-bg-neutral',
            '--text-primary', '--text-bright', '--text-muted',
            '--tag-gray-text', '--tag-red-text', '--badge-danger-text',
            '--tag-green-text', '--badge-success-text', '--badge-warning-text',
            '--tag-blue-text', '--tag-purple-text', '--tag-orange-text',
            '--danger-bg', '--modal-backdrop',
        ];

        function setTheme(themeName) {
            const valid = Object.prototype.hasOwnProperty.call(THEMES, themeName);
            if (!valid) return;
            const html = document.documentElement;
            // Clear any inline properties left over from a previously
            // synthesized OhMyDebn custom theme, so they don't linger on
            // top of this real theme's CSS block.
            CUSTOM_THEME_CSS_VARS.forEach(function(name) { html.style.removeProperty(name); });
            if (themeName === 'dark') {
                html.removeAttribute('data-theme');
            } else {
                html.setAttribute('data-theme', themeName);
            }
            safeStorageSet(localStorage, 'socrates-theme', themeName);
            updateThemeMenu();
            updateFunThemeClass();
            updateAllAmbientThemes();
            updateFavicon();
            // If the themes modal is open, treat this as the new baseline so
            // a later close/revert does not undo the change, and keep the
            // preview iframe in sync - otherwise changing the theme some
            // other way while the modal is open (the 't' hotkey, a cheat
            // code) would leave the preview showing a stale theme while the
            // real page and the grid's checkmark have already moved on.
            const themesModal = document.getElementById('themesModal');
            if (themesModal && themesModal.classList.contains('active')) {
                menuBaseTheme = themeName;
                previewTheme(themeName);
            }
        }

        // Applies a theme synthesized server-side from an OhMyDebn/Aether
        // palette (see /api/theme's customColors, derived by
        // ohmydebn_colors.py) for a theme THEMES has no CSS block for.
        // Deliberately does not persist to localStorage['socrates-theme']:
        // the inline properties this sets only exist in this page's live
        // DOM, so restoring the marker on next load with no colors behind
        // it yet (before the sync poll's first tick resolves) would be
        // worse than the brief default-theme flash of just not persisting
        // it at all - only ever reachable via sync anyway, never manually.
        function applyCustomTheme(colors) {
            const html = document.documentElement;
            html.setAttribute('data-theme', OHMYDEBN_CUSTOM_THEME);
            Object.keys(colors).forEach(function(name) {
                html.style.setProperty(name, colors[name]);
            });
            updateThemeMenu();
            updateFunThemeClass();
            updateAllAmbientThemes();
            updateFavicon();
        }

        // Real app markup/classes (.app-header, .stats-grid, .stat-card)
        // reusing the real stylesheet, rendered in an isolated iframe
        // document so previewing a theme never touches the real page's
        // document.documentElement. Loaded once via srcdoc (relative URLs
        // in srcdoc resolve against the parent document's URL, so
        // static/socrates.css resolves the same way it does for the real
        // page) and then just has its data-theme attribute toggled per
        // hover - cheap, and avoids booting a second full copy of the app
        // (which loading the real socrates.html in an iframe would mean:
        // re-running init(), restarting the OhMyDebn theme-sync poll, etc.
        // just for a hover preview).
        const THEME_PREVIEW_SRCDOC = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<link rel="stylesheet" href="static/socrates.css">
<style>
  html, body { overflow: hidden; }
  .app-header { position: static; border-bottom: none; }
  .preview-container { padding: 12px 14px; }
  .preview-stats-grid { grid-template-columns: repeat(3, 1fr); margin-bottom: 0; }
</style>
</head>
<body>
  <div class="app-header">
    <div class="app-header-left">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle;">
        <circle cx="11" cy="11" r="8"></circle>
        <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
      </svg>
      <span class="app-logo-text" style="color: var(--text-bright); font-weight: 700;">SO-CRATES</span>
      <span class="app-header-filename">sample.pcap</span>
    </div>
  </div>
  <div class="preview-container">
    <div class="stats-grid preview-stats-grid">
      <div class="stat-card tab-active">
        <div class="stat-number">128</div>
        <div class="stat-label">Alerts</div>
      </div>
      <div class="stat-card">
        <div class="stat-number">4,502</div>
        <div class="stat-label">Flows</div>
      </div>
      <div class="stat-card">
        <div class="stat-number">37</div>
        <div class="stat-label">DNS</div>
      </div>
    </div>
  </div>
</body>
</html>`;

        let themePreviewFrameReady = false;

        // Only ever touches the isolated preview iframe's own document,
        // never the real page's document.documentElement. Hovering across a
        // packed grid of ~26 tiles with no debounce would otherwise mean a
        // full-page, high-contrast recolor on every mouseenter - exactly
        // the large-area rapid-flash pattern WCAG 2.3.1 (Three Flashes or
        // Below Threshold) exists to prevent. Scoping the change to this
        // small, separate document keeps it well under that "large area"
        // threshold regardless of how fast the cursor moves. commitTheme()
        // (click) is the only path that still changes the real theme.
        function previewTheme(themeName) {
            const valid = Object.prototype.hasOwnProperty.call(THEMES, themeName);
            if (!valid) return;
            const frame = document.getElementById('themePreviewFrame');
            const frameDoc = frame && frame.contentDocument;
            if (frameDoc && frameDoc.documentElement) {
                frameDoc.documentElement.setAttribute('data-theme', themeName);
            }
            updatePreviewingLabel(themeName);
        }

        // "Previewing <name>" always shows, confirming what the preview
        // panel currently displays (hover target, or the resting/baseline
        // theme once nothing is hovered). Any theme's name can be typed
        // into the command palette (see AUTOCOMPLETE_COMMANDS) to jump to
        // it directly, so there's no separate per-theme code to show here
        // any more.
        function updatePreviewingLabel(themeName) {
            const label = document.getElementById('themePreviewingLabel');
            if (!label) return;
            label.textContent = THEMES[themeName].label;
        }

        function revertTheme() {
            if (menuBaseTheme !== null) {
                previewTheme(menuBaseTheme);
            }
        }

        // Applies the theme for real (unlike previewTheme(), which only
        // touches the isolated preview iframe) but deliberately does not
        // close the themes modal - lets someone click through several
        // themes in a row, actually seeing the real app repaint each time,
        // without reopening the picker. Each click is still a single,
        // deliberate user-initiated action (not a rapid/incidental trigger
        // like hover), so this doesn't reintroduce the flash-risk pattern
        // previewTheme() was built to avoid. Escape/the close button/
        // backdrop click remain the ways to actually close the modal.
        function commitTheme(themeName) {
            setTheme(themeName);
        }

        // Polls /api/theme (populated from OHMYDEBN_THEME_DIR server-side,
        // e.g. when launched via ohmydebn-socrates-run) and, if the user
        // has opted in, applies
        // whatever theme OhMyDebn last switched to. Off by default so a
        // background desktop-theme change never repaints an open analysis
        // session without the user asking for it. The server only loosely
        // validates the theme name, so setTheme() -- which rejects anything
        // not in THEMES -- remains the real gate for that path; customColors
        // (see applyCustomTheme()) is validated server-side instead.
        let themeSyncInterval = null;

        // Track what was last actually applied via sync, independently of
        // each other and of the DOM's data-theme attribute. A synthesized
        // custom theme always stamps the same OHMYDEBN_CUSTOM_THEME marker
        // regardless of which palette is behind it, so comparing against
        // getCurrentTheme() can't tell "same colors, don't reapply" from
        // "different colors, need reapply" - only a fingerprint of the
        // colors themselves can. The two files driving these (theme name
        // vs. colors.toml) are independent and not guaranteed to change in
        // lockstep, so the customColors branch below is checked on its own
        // and never gated on data.theme being present/valid.
        let lastSyncedThemeName = null;
        let lastSyncedColorsFingerprint = null;

        async function pollOhmydebnTheme() {
            if (document.hidden) return;
            if (safeStorageGet(localStorage, 'socrates_syncThemeWithOS') !== 'true') return;
            try {
                const resp = await fetch('/api/theme');
                if (!resp.ok) return;
                const data = await resp.json();
                const knownTheme = data.theme && Object.prototype.hasOwnProperty.call(THEMES, data.theme);
                if (knownTheme) {
                    if (data.theme !== lastSyncedThemeName) {
                        setTheme(data.theme);
                        showToast('Changed SO-CRATES theme to ' + THEMES[data.theme].label + ' to match OhMyDebn');
                        lastSyncedThemeName = data.theme;
                        lastSyncedColorsFingerprint = null;
                    }
                } else if (data.customColors) {
                    const fingerprint = JSON.stringify(data.customColors);
                    if (fingerprint !== lastSyncedColorsFingerprint) {
                        applyCustomTheme(data.customColors);
                        showToast(data.theme
                            ? 'Generated color palette from OhMyDebn theme ' + data.theme
                            : 'Generated a color palette from OhMyDebn');
                        lastSyncedColorsFingerprint = fingerprint;
                        lastSyncedThemeName = null;
                    }
                } else if (data.theme && data.theme !== lastSyncedThemeName) {
                    // A theme name was reported, but it's neither a known
                    // THEMES key nor backed by a usable palette. Leaving
                    // sync on would just repeat this same no-op every poll
                    // with no visible sign anything is wrong, so turn sync
                    // off and fall back to Midnight instead of silently
                    // ignoring it forever.
                    safeStorageSet(localStorage, 'socrates_syncThemeWithOS', 'false');
                    const syncCheckbox = document.getElementById('syncThemeWithOS');
                    if (syncCheckbox) syncCheckbox.checked = false;
                    updateThemePickerVisibility();
                    setTheme('dark');
                    showToast('OhMyDebn reported an unknown theme - sync disabled and reverted to Midnight.', {
                        sticky: true,
                        actionLabel: 'Open Themes',
                        onAction: function() { showThemesModal(); }
                    });
                    lastSyncedThemeName = data.theme;
                }
            } catch (e) {
                // Ignore -- next poll will retry.
            }
        }

        function startThemeSync() {
            if (themeSyncInterval) return;
            pollOhmydebnTheme();
            themeSyncInterval = setInterval(pollOhmydebnTheme, 1000);
        }

        function toggleTheme() {
            const order = THEME_MENU_ORDER;
            const current = getCurrentTheme();
            const nextIndex = (order.indexOf(current) + 1) % order.length;
            const nextTheme = order[nextIndex];
            setTheme(nextTheme);
            showToast('Switched to ' + THEMES[nextTheme].label + ' theme');
        }

        function toggleThemeReverse() {
            const order = THEME_MENU_ORDER;
            const current = getCurrentTheme();
            const prevIndex = (order.indexOf(current) - 1 + order.length) % order.length;
            const prevTheme = order[prevIndex];
            setTheme(prevTheme);
            showToast('Switched to ' + THEMES[prevTheme].label + ' theme');
        }

        function updateThemeMenu() {
            // Mark the menu item for the currently applied theme. Tracks
            // hover previews too (setTheme/previewTheme both call this), so
            // the checkmark always matches what is on screen.
            const current = getCurrentTheme();
            const items = document.querySelectorAll('[data-theme-option]');
            items.forEach(function(item) {
                const isActive = item.getAttribute('data-theme-option') === current;
                item.classList.toggle('theme-active', isActive);
                if (isActive) {
                    item.setAttribute('aria-current', 'true');
                } else {
                    item.removeAttribute('aria-current');
                }
            });
        }

        const GEAR_ICON_SVG = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.17 15a1.65 1.65 0 0 0-1.51-1H2a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.17 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.17a1.65 1.65 0 0 0 1-1.51V2a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>`;

        function renderGearMenu() {
            return `
                <div class="app-header-menu">
                    <button class="app-header-menu-btn" data-action="toggle-menu" title="Menu" id="appHeaderMenuBtn">
                        ${GEAR_ICON_SVG}
                    </button>
                    <div class="app-header-menu-dropdown" id="appHeaderMenuDropdown">
                        <button class="app-header-menu-item" data-action="menu-help">
                            <span><svg class="theme-icon-help" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></span>
                            <span>Help</span>
                        </button>
                        <button class="app-header-menu-item" data-action="menu-settings">
                            <span><svg class="theme-icon-help" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.17 15a1.65 1.65 0 0 0-1.51-1H2a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.17 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.17a1.65 1.65 0 0 0 1-1.51V2a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg></span>
                            <span>Settings</span>
                        </button>
                        <button class="app-header-menu-item" data-action="menu-themes">
                            <span><svg class="theme-icon-help" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="13.5" cy="6.5" r=".5" fill="currentColor"/><circle cx="17.5" cy="10.5" r=".5" fill="currentColor"/><circle cx="8.5" cy="7.5" r=".5" fill="currentColor"/><circle cx="6.5" cy="12.5" r=".5" fill="currentColor"/><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.688 0-.437-.18-.835-.437-1.125-.29-.289-.438-.652-.438-1.125a1.64 1.64 0 0 1 1.668-1.668h1.996c3.051 0 5.555-2.503 5.555-5.554C21.965 6.012 17.461 2 12 2z"></path></svg></span>
                            <span>Themes</span>
                        </button>
                        <button class="app-header-menu-item" data-action="menu-rules">
                            <span><svg class="theme-icon-help" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg></span>
                            <span>Rules</span>
                        </button>
                        <button class="app-header-menu-item" data-action="menu-about">
                            <span><svg class="theme-icon-help" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg></span>
                            <span>About</span>
                        </button>
                    </div>
                </div>`;
        }

        function renderThemesModalGrid() {
            let html = '';
            for (const group of THEME_GROUP_ORDER) {
                html += `<div class="app-header-menu-header">${THEME_GROUP_LABELS[group]}</div><div class="theme-tile-grid">`;
                for (const key of THEME_MENU_ORDER.filter(k => THEMES[k].group === group)) {
                    // Hover/focus preview and click-to-commit are delegated
                    // (see the theme-tile mouseover/mouseout/focusin/focusout
                    // listeners and the 'commit-theme' STATIC_ACTIONS entry
                    // near the end of this file), keyed off the same
                    // data-theme-option attribute the keyboard nav already
                    // uses - no inline on*= handlers (CSP: script-src
                    // without 'unsafe-inline' blocks them).
                    html += `
                        <button class="theme-tile" data-theme-option="${key}" data-action="commit-theme">
                            <span>${THEMES[key].label}</span>
                        </button>`;
                }
                html += `</div>`;
            }
            return html;
        }

        // Subtle code-rain background for Hacker theme.
        let codeRainCtx = null;
        let codeRainCols = [];
        let codeRainFontSize = 14;
        let codeRainAnimationId = null;
        let codeRainLastDraw = 0;
        const codeRainChars = '0123456789ABCDEFｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ';

        function resizeCodeRain() {
            const canvas = document.getElementById('codeRain');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            if (!ctx) return;
            codeRainCtx = ctx;
            const dpr = window.devicePixelRatio || 1;
            canvas.width = window.innerWidth * dpr;
            canvas.height = window.innerHeight * dpr;
            codeRainCtx.scale(dpr, dpr);
            codeRainFontSize = Math.max(12, Math.min(16, Math.floor(window.innerWidth / 120)));
            codeRainCtx.font = codeRainFontSize + 'px monospace';
            const colCount = Math.ceil(window.innerWidth / (codeRainFontSize * 1.6));
            codeRainCols = [];
            for (let i = 0; i < colCount; i++) {
                codeRainCols.push(Math.random() * -window.innerHeight);
            }
        }

        function drawCodeRain(timestamp) {
            const canvas = document.getElementById('codeRain');
            if (!canvas || getCurrentTheme() !== 'hacker') return;
            if (!codeRainCtx) resizeCodeRain();
            if (!codeRainCtx) return;

            const dt = timestamp - codeRainLastDraw;
            if (dt < 50) {
                codeRainAnimationId = requestAnimationFrame(drawCodeRain);
                return;
            }
            codeRainLastDraw = timestamp;

            const width = window.innerWidth;
            const height = window.innerHeight;
            codeRainCtx.fillStyle = 'rgba(0, 0, 0, 0.08)';
            codeRainCtx.fillRect(0, 0, width, height);

            for (let i = 0; i < codeRainCols.length; i++) {
                const char = codeRainChars[Math.floor(Math.random() * codeRainChars.length)];
                const x = i * codeRainFontSize * 1.6;
                const y = codeRainCols[i];
                if (y > 0 && y < height + codeRainFontSize) {
                    const fade = Math.min(1, y / height + 0.3);
                    codeRainCtx.fillStyle = 'rgba(0, 255, 65, ' + (0.35 + fade * 0.65) + ')';
                    codeRainCtx.fillText(char, x, y);
                }
                codeRainCols[i] += codeRainFontSize * 0.6;
                if (y > height && Math.random() > 0.975) {
                    codeRainCols[i] = Math.random() * -codeRainFontSize * 10;
                }
            }

            codeRainAnimationId = requestAnimationFrame(drawCodeRain);
        }

        function startCodeRain() {
            if (codeRainAnimationId) return;
            resizeCodeRain();
            if (!codeRainCtx) return;
            codeRainLastDraw = performance.now();
            codeRainAnimationId = requestAnimationFrame(drawCodeRain);
        }

        function stopCodeRain() {
            if (codeRainAnimationId) {
                cancelAnimationFrame(codeRainAnimationId);
                codeRainAnimationId = null;
            }
            const canvas = document.getElementById('codeRain');
            if (canvas && codeRainCtx) {
                codeRainCtx.clearRect(0, 0, canvas.width, canvas.height);
            }
        }

        function updateCodeRain() {
            if (getCurrentTheme() === 'hacker') {
                startCodeRain();
            } else {
                stopCodeRain();
            }
        }

        // Subtle falling-tetromino background for Retro Handheld theme -
        // same fixed-canvas/rAF technique as the code rain above, on its
        // own separate #blockRain canvas (see .block-rain-canvas's CSS
        // comment for why a second canvas rather than a shared,
        // theme-branching one). No rotation, stacking, or collision -
        // just axis-aligned tetromino shapes drifting straight down and
        // respawning once off-screen, the same ambient-texture role rain
        // plays for Hacker.
        let blockRainCtx = null;
        let blockRainPieces = [];
        const fallingBlockSize = 16;
        let blockRainAnimationId = null;
        let blockRainLastDraw = 0;
        const FALLING_BLOCK_SHAPES = [
            [[0, 0], [1, 0], [2, 0], [3, 0]], // I
            [[0, 0], [1, 0], [0, 1], [1, 1]], // O
            [[1, 0], [0, 1], [1, 1], [2, 1]], // T
            [[1, 0], [2, 0], [0, 1], [1, 1]], // S
            [[0, 0], [1, 0], [1, 1], [2, 1]], // Z
            [[0, 0], [0, 1], [1, 1], [2, 1]], // J
            [[2, 0], [0, 1], [1, 1], [2, 1]]  // L
        ];
        // The theme's own darkest palette shades (see [data-theme=
        // "retro-handheld"]'s --text-primary/--accent/--text-muted) -
        // reads as the real 4-shade Game Boy LCD palette rather than an
        // arbitrary green, and needs no separate light/dark handling
        // since this canvas only ever renders for this one theme.
        const BLOCK_RAIN_COLORS = ['#0f380f', '#1f5c1f', '#306230'];

        function makeFallingBlock(width) {
            const cols = Math.max(1, Math.floor(width / fallingBlockSize) - 4);
            return {
                shape: FALLING_BLOCK_SHAPES[Math.floor(Math.random() * FALLING_BLOCK_SHAPES.length)],
                col: Math.floor(Math.random() * cols),
                y: Math.random() * -window.innerHeight,
                speed: 3 + Math.random() * 3,
                color: BLOCK_RAIN_COLORS[Math.floor(Math.random() * BLOCK_RAIN_COLORS.length)]
            };
        }

        function resizeBlockRain() {
            const canvas = document.getElementById('blockRain');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            if (!ctx) return;
            blockRainCtx = ctx;
            const dpr = window.devicePixelRatio || 1;
            canvas.width = window.innerWidth * dpr;
            canvas.height = window.innerHeight * dpr;
            blockRainCtx.scale(dpr, dpr);
            const pieceCount = Math.max(14, Math.ceil(window.innerWidth / 90));
            blockRainPieces = [];
            for (let i = 0; i < pieceCount; i++) {
                blockRainPieces.push(makeFallingBlock(window.innerWidth));
            }
        }

        function drawBlockRain(timestamp) {
            const canvas = document.getElementById('blockRain');
            if (!canvas || getCurrentTheme() !== 'retro-handheld') return;
            if (!blockRainCtx) resizeBlockRain();
            if (!blockRainCtx) return;

            const dt = timestamp - blockRainLastDraw;
            if (dt < 50) {
                blockRainAnimationId = requestAnimationFrame(drawBlockRain);
                return;
            }
            blockRainLastDraw = timestamp;

            const width = window.innerWidth;
            const height = window.innerHeight;
            // Fades the previous frame's blocks out against the theme's
            // own light background color (--bg-primary: #9bbc0f) rather
            // than black, which the code rain above clears with - that
            // theme's page is dark so a black fade is invisible; this
            // one's page is pale yellow-green, so fading to black would
            // paint a visible dark smear behind every piece instead of a
            // clean fade. Higher alpha than code rain's 0.08 (which
            // suits sparse, thin text glyphs) - these are solid blocks,
            // so the same low alpha left a long, still-fairly-opaque
            // smear behind each one that was genuinely hard to tell from
            // the actual piece. This clears each old frame in 2-3 draws
            // instead of a dozen+, leaving just a short Game-Boy-LCD-
            // ghosting hint rather than a confusing trail.
            blockRainCtx.fillStyle = 'rgba(155, 188, 15, 0.35)';
            blockRainCtx.fillRect(0, 0, width, height);

            for (const piece of blockRainPieces) {
                blockRainCtx.fillStyle = piece.color;
                for (const block of piece.shape) {
                    const x = (piece.col + block[0]) * fallingBlockSize;
                    const y = piece.y + block[1] * fallingBlockSize;
                    if (y > -fallingBlockSize && y < height) {
                        blockRainCtx.fillRect(x + 1, y + 1, fallingBlockSize - 2, fallingBlockSize - 2);
                    }
                }
                piece.y += piece.speed;
                if (piece.y > height) {
                    Object.assign(piece, makeFallingBlock(width));
                }
            }

            blockRainAnimationId = requestAnimationFrame(drawBlockRain);
        }

        function startBlockRain() {
            if (blockRainAnimationId) return;
            resizeBlockRain();
            if (!blockRainCtx) return;
            blockRainLastDraw = performance.now();
            blockRainAnimationId = requestAnimationFrame(drawBlockRain);
        }

        function stopBlockRain() {
            if (blockRainAnimationId) {
                cancelAnimationFrame(blockRainAnimationId);
                blockRainAnimationId = null;
            }
            const canvas = document.getElementById('blockRain');
            if (canvas && blockRainCtx) {
                blockRainCtx.clearRect(0, 0, canvas.width, canvas.height);
            }
        }

        function updateBlockRain() {
            if (getCurrentTheme() === 'retro-handheld') {
                startBlockRain();
            } else {
                stopBlockRain();
            }
        }

        // Synthwave grid-horizon ambient background for Vaporwave - on
        // its own #vaporwaveGrid canvas, same fixed/behind-everything
        // positioning as the two effects above, but a single static
        // draw rather than a continuous rAF loop (tried animated first,
        // then made static - see git history). A composed scene like
        // this (converging grid + a sun sitting on the horizon) needs to
        // be recognizable even glimpsed only in the thin slivers of page
        // not covered by real content - continuous motion in those
        // small, disconnected slivers read as flicker rather than a
        // coherent "flying over the grid" feel, and a still image both
        // avoids that and costs nothing once drawn (no ongoing rAF work,
        // no timers). Only redrawn on theme activation and window
        // resize - resizeVaporwaveGrid() itself does the (re)draw, so it
        // stays the single place both "wire up the canvas" and "put
        // pixels on it" happen, the same function the window resize
        // listener already calls.
        let vaporwaveCtx = null;
        const VAPORWAVE_H_LINE_COUNT = 24;
        const VAPORWAVE_V_LINE_COUNT = 16;

        function drawVaporwaveGrid() {
            if (!vaporwaveCtx) return;
            const width = window.innerWidth;
            const height = window.innerHeight;
            const horizonY = height * 0.58;
            const centerX = width / 2;
            vaporwaveCtx.clearRect(0, 0, width, height);

            // Sun sitting exactly on the horizon - clipping to its upper
            // half (rather than drawing a full circle) is what makes it
            // read as "sitting on" rather than "floating above" the
            // horizon. A few horizontal bands are cut out of the lower
            // portion (the classic retro sun stripes) via clearRect,
            // which - on a low-opacity overlay canvas like this one -
            // correctly reveals whatever real page content is
            // underneath, the same way the rest of the canvas's
            // transparent background already does.
            const sunRadius = Math.min(width, height) * 0.14;
            vaporwaveCtx.save();
            vaporwaveCtx.beginPath();
            vaporwaveCtx.rect(centerX - sunRadius, horizonY - sunRadius, sunRadius * 2, sunRadius);
            vaporwaveCtx.clip();
            const sunGradient = vaporwaveCtx.createRadialGradient(centerX, horizonY, 0, centerX, horizonY, sunRadius);
            sunGradient.addColorStop(0, 'rgba(255, 113, 206, 1)');
            sunGradient.addColorStop(1, 'rgba(255, 113, 206, 0)');
            vaporwaveCtx.fillStyle = sunGradient;
            vaporwaveCtx.beginPath();
            vaporwaveCtx.arc(centerX, horizonY, sunRadius, 0, Math.PI * 2);
            vaporwaveCtx.fill();
            for (let band = 0; band < 4; band++) {
                const bandY = horizonY - sunRadius * (0.08 + band * 0.09);
                vaporwaveCtx.clearRect(centerX - sunRadius, bandY, sunRadius * 2, sunRadius * 0.035);
            }
            vaporwaveCtx.restore();

            // Converging verticals, evenly spaced along the bottom edge
            // and spreading past the viewport's left/right edges so the
            // grid still fills the corners.
            vaporwaveCtx.strokeStyle = 'rgba(1, 205, 254, 0.65)';
            vaporwaveCtx.lineWidth = 1;
            for (let i = 0; i < VAPORWAVE_V_LINE_COUNT; i++) {
                const spread = (i / (VAPORWAVE_V_LINE_COUNT - 1) - 0.5) * width * 1.6;
                vaporwaveCtx.beginPath();
                vaporwaveCtx.moveTo(centerX, horizonY);
                vaporwaveCtx.lineTo(centerX + spread, height);
                vaporwaveCtx.stroke();
            }

            // Horizontal lines at fixed, evenly-spaced depths - t eases
            // with t*t so they bunch up near the horizon and spread
            // apart near the bottom, the standard cheap trick for
            // perspective depth without real 3D projection math. No
            // longer incremented over time (see this function's own
            // comment above for why) - each line just sits at its own
            // fixed t forever.
            for (let i = 0; i < VAPORWAVE_H_LINE_COUNT; i++) {
                const t = i / VAPORWAVE_H_LINE_COUNT;
                const y = horizonY + (height - horizonY) * t * t;
                const alpha = 0.25 + 0.6 * t;
                vaporwaveCtx.strokeStyle = `rgba(1, 205, 254, ${alpha})`;
                vaporwaveCtx.beginPath();
                vaporwaveCtx.moveTo(0, y);
                vaporwaveCtx.lineTo(width, y);
                vaporwaveCtx.stroke();
            }
        }

        function resizeVaporwaveGrid() {
            const canvas = document.getElementById('vaporwaveGrid');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            if (!ctx) return;
            vaporwaveCtx = ctx;
            const dpr = window.devicePixelRatio || 1;
            canvas.width = window.innerWidth * dpr;
            canvas.height = window.innerHeight * dpr;
            vaporwaveCtx.scale(dpr, dpr);
            if (getCurrentTheme() === 'vaporwave') drawVaporwaveGrid();
        }

        function startVaporwaveGrid() {
            resizeVaporwaveGrid();
        }

        function stopVaporwaveGrid() {
            const canvas = document.getElementById('vaporwaveGrid');
            if (canvas && vaporwaveCtx) {
                vaporwaveCtx.clearRect(0, 0, canvas.width, canvas.height);
            }
        }

        function updateVaporwaveGrid() {
            if (getCurrentTheme() === 'vaporwave') {
                startVaporwaveGrid();
            } else {
                stopVaporwaveGrid();
            }
        }

        // Norton Commander dual-pane ambient background for DOS Blue - on
        // its own #dosDefrag canvas (id/class kept from the earlier
        // defrag/prompt/QBasic-dialog effects this replaced, to avoid an
        // unrelated HTML/CSS rename). One bordered file-list pane in each
        // side margin (the app's own central content column already
        // occupies the middle, so a real side-by-side dual pane wouldn't
        // fit in either margin alone). Row count is computed from the
        // available margin height on each resize (not a fixed count) so
        // the panes stretch to fill most of the margin - real Norton
        // Commander panes span nearly the full screen, unlike a QBasic
        // dialog box, which is inherently compact and would look wrong
        // stretched that tall. Each pane's yellow selection bar steps
        // down the list on its own timer - a mostly-static composed scene
        // plus one small moving element per pane, same recipe as Luna
        // Blue's clouds.
        let dosDefragCtx = null;
        let dosDefragAnimationId = null;
        let dosDefragLastDraw = 0;
        let ncLeftFiles = [];
        let ncRightFiles = [];
        let ncLeftHighlight = 0;
        let ncRightHighlight = 0;
        let ncLeftNextMove = 0;
        let ncRightNextMove = 0;
        let ncVisibleRows = 10;
        const NC_FILES_LEFT = [
            'AUTOEXEC.BAT', 'CONFIG.SYS', 'COMMAND.COM', 'IO.SYS', 'MSDOS.SYS',
            'WIN386.SWP', 'HIMEM.SYS', 'EMM386.EXE', 'MOUSE.COM', 'DOSKEY.COM',
            'EDIT.COM', 'QBASIC.EXE', 'FORMAT.COM', 'FDISK.EXE', 'SCANDISK.EXE',
            'DEFRAG.EXE', 'SHARE.EXE', 'SMARTDRV.EXE', 'ANSI.SYS', 'XCOPY.EXE',
            'SYSTEM.INI', 'WIN.INI', 'PROTOCOL.INI', 'NET.CFG', 'STARTUP.CMD',
            'DBLSPACE.BIN', 'DRVSPACE.BIN', 'RAMDRIVE.SYS', 'SETVER.EXE', 'APPEND.EXE',
            'ATTRIB.EXE', 'LABEL.EXE', 'SYS.COM', 'TREE.COM', 'SORT.EXE',
            'FIND.EXE', 'MORE.COM', 'PRINT.EXE', 'RECOVER.EXE', 'RESTORE.EXE'
        ];
        const NC_FILES_RIGHT = [
            'README.TXT', 'SETUP.EXE', 'GAME.EXE', 'SAVE001.DAT', 'SAVE002.DAT',
            'MANUAL.TXT', 'SOUND.DRV', 'VGA.DRV', 'CONFIG.CFG', 'HISCORE.DAT',
            'LEVEL1.DAT', 'PATCH.EXE', 'INSTALL.EXE', 'SOUND.CFG', 'JOYSTICK.CFG',
            'INTRO.DAT', 'CREDITS.TXT', 'MUSIC.DAT', 'SPRITES.DAT', 'LEVEL2.DAT',
            'DEMO.EXE', 'TUTORIAL.DAT', 'OPTIONS.CFG', 'KEYS.CFG', 'FONTS.DAT',
            'PALETTE.DAT', 'MAP01.DAT', 'MAP02.DAT', 'ENEMY.DAT', 'WEAPONS.DAT',
            'TEXTURE.DAT', 'AUDIO.DAT', 'VOICE.DAT', 'ENDING.DAT', 'BACKUP.DAT',
            'TEMP.DAT', 'CACHE.DAT', 'LOG.TXT', 'ERROR.LOG', 'STATS.DAT'
        ];
        const NC_ROW_HEIGHT = 18;
        const NC_PANE_WIDTH = 180;
        const NC_PANE_Y = 100;
        const NC_BOTTOM_CLEARANCE = 90;

        // Cycles through fresh shuffles of the pool rather than capping at
        // the pool's own length - a pane taller than the pool (a large
        // monitor's margin can easily need 40+ rows) still fills
        // completely instead of leaving blank space below a short list,
        // at the cost of eventually repeating names further down.
        function makeNcFileList(pool) {
            let names = [];
            while (names.length < ncVisibleRows) {
                names = names.concat([...pool].sort(() => Math.random() - 0.5));
            }
            names = names.slice(0, ncVisibleRows);
            return names.map(name => ({ name, size: 128 + Math.floor(Math.random() * 98000) }));
        }

        function drawNcPane(ctx, x, y, title, files, highlightRow) {
            const width = NC_PANE_WIDTH;
            const height = NC_ROW_HEIGHT * (1 + files.length);

            ctx.lineWidth = 1;
            ctx.strokeStyle = '#55FFFF';
            ctx.strokeRect(x, y, width, height);

            ctx.fillStyle = '#55FFFF';
            ctx.fillRect(x, y, width, NC_ROW_HEIGHT);
            ctx.fillStyle = '#0000AA';
            ctx.font = 'bold 12px "Courier New", monospace';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText(title, x + width / 2, y + NC_ROW_HEIGHT / 2 + 1);

            ctx.font = '12px "Courier New", monospace';
            files.forEach((file, i) => {
                const rowY = y + NC_ROW_HEIGHT * (1 + i);
                if (i === highlightRow) {
                    ctx.fillStyle = '#FFFF55';
                    ctx.fillRect(x + 1, rowY, width - 2, NC_ROW_HEIGHT);
                    ctx.fillStyle = '#0000AA';
                } else {
                    ctx.fillStyle = '#FFFFFF';
                }
                ctx.textAlign = 'left';
                ctx.fillText(file.name, x + 8, rowY + NC_ROW_HEIGHT / 2 + 1);
                ctx.textAlign = 'right';
                ctx.fillText(String(file.size), x + width - 8, rowY + NC_ROW_HEIGHT / 2 + 1);
            });
            ctx.textAlign = 'left';
            ctx.textBaseline = 'alphabetic';
        }

        function drawDosDefrag(timestamp) {
            const canvas = document.getElementById('dosDefrag');
            if (!canvas || getCurrentTheme() !== 'dos-blue') return;
            if (!dosDefragCtx) resizeDosDefrag();
            if (!dosDefragCtx) return;

            const dt = timestamp - dosDefragLastDraw;
            if (dt < 50) {
                dosDefragAnimationId = requestAnimationFrame(drawDosDefrag);
                return;
            }
            dosDefragLastDraw = timestamp;

            if (timestamp >= ncLeftNextMove) {
                ncLeftHighlight = (ncLeftHighlight + 1) % ncLeftFiles.length;
                ncLeftNextMove = timestamp + 1200 + Math.random() * 700;
            }
            if (timestamp >= ncRightNextMove) {
                ncRightHighlight = (ncRightHighlight + 1) % ncRightFiles.length;
                ncRightNextMove = timestamp + 1200 + Math.random() * 700;
            }

            const width = window.innerWidth;
            const height = window.innerHeight;
            dosDefragCtx.clearRect(0, 0, width, height);

            drawNcPane(dosDefragCtx, 20, NC_PANE_Y, 'C:\\DOS', ncLeftFiles, ncLeftHighlight);
            drawNcPane(dosDefragCtx, width - NC_PANE_WIDTH - 20, NC_PANE_Y, 'A:\\DATA', ncRightFiles, ncRightHighlight);

            dosDefragAnimationId = requestAnimationFrame(drawDosDefrag);
        }

        function resizeDosDefrag() {
            const canvas = document.getElementById('dosDefrag');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            if (!ctx) return;
            dosDefragCtx = ctx;
            const dpr = window.devicePixelRatio || 1;
            canvas.width = window.innerWidth * dpr;
            canvas.height = window.innerHeight * dpr;
            dosDefragCtx.scale(dpr, dpr);

            const availableHeight = window.innerHeight - NC_PANE_Y - NC_BOTTOM_CLEARANCE;
            ncVisibleRows = Math.max(5, Math.floor(availableHeight / NC_ROW_HEIGHT) - 1);
            ncLeftFiles = makeNcFileList(NC_FILES_LEFT);
            ncRightFiles = makeNcFileList(NC_FILES_RIGHT);
            ncLeftHighlight = 0;
            ncRightHighlight = 0;
        }

        function startDosDefrag() {
            if (dosDefragAnimationId) return;
            resizeDosDefrag();
            if (!dosDefragCtx) return;
            dosDefragLastDraw = performance.now();
            ncLeftNextMove = dosDefragLastDraw + 1200;
            ncRightNextMove = dosDefragLastDraw + 1200;
            dosDefragAnimationId = requestAnimationFrame(drawDosDefrag);
        }

        function stopDosDefrag() {
            if (dosDefragAnimationId) {
                cancelAnimationFrame(dosDefragAnimationId);
                dosDefragAnimationId = null;
            }
            const canvas = document.getElementById('dosDefrag');
            if (canvas && dosDefragCtx) {
                dosDefragCtx.clearRect(0, 0, canvas.width, canvas.height);
            }
        }

        function updateDosDefrag() {
            if (getCurrentTheme() === 'dos-blue') {
                startDosDefrag();
            } else {
                stopDosDefrag();
            }
        }

        // Dithered plasma ambient background for CGA - on its own
        // #cgaStarfield canvas (id/class kept from the earlier
        // twinkling-starfield effect this replaced, to avoid an unrelated
        // HTML/CSS rename). The same flowing sine-wave plasma field as
        // Breadbin Blue's, but quantized down to CGA's real 4-color
        // high-intensity palette (black/cyan/magenta/white) through an
        // ordered Bayer dither pattern - the actual period technique CGA
        // software used to fake more colors/shades than the hardware
        // could really display. Small dither cells (not Breadbin's larger
        // ones) to read as properly blocky/low-res CGA pixels.
        let cgaStarfieldCtx = null;
        const CGA_DITHER_COLORS = ['#000000', '#55ffff', '#ff55ff', '#ffffff'];
        const CGA_DITHER_MATRIX = [
            [0, 8, 2, 10],
            [12, 4, 14, 6],
            [3, 11, 1, 9],
            [15, 7, 13, 5]
        ];
        const CGA_DITHER_CELL = 4;
        let cgaStarfieldAnimationId = null;
        let cgaStarfieldLastDraw = 0;

        function drawCgaStarfield(timestamp) {
            const canvas = document.getElementById('cgaStarfield');
            if (!canvas || getCurrentTheme() !== 'cga') return;
            if (!cgaStarfieldCtx) resizeCgaStarfield();
            if (!cgaStarfieldCtx) return;

            const dt = timestamp - cgaStarfieldLastDraw;
            if (dt < 50) {
                cgaStarfieldAnimationId = requestAnimationFrame(drawCgaStarfield);
                return;
            }
            cgaStarfieldLastDraw = timestamp;

            const width = window.innerWidth;
            const height = window.innerHeight;
            const t = timestamp * 0.0006;
            for (let y = 0; y < height; y += CGA_DITHER_CELL) {
                for (let x = 0; x < width; x += CGA_DITHER_CELL) {
                    const value = Math.sin(x * 0.03 + t)
                        + Math.sin(y * 0.035 + t * 1.2)
                        + Math.sin((x + y) * 0.02 + t * 0.8)
                        + Math.sin(Math.sqrt(x * x + y * y) * 0.025 - t * 1.4);
                    const normalized = (value + 4) / 8;
                    const scaled = normalized * CGA_DITHER_COLORS.length;
                    const level = Math.floor(scaled);
                    const frac = scaled - level;
                    const dx = (x / CGA_DITHER_CELL) % 4;
                    const dy = (y / CGA_DITHER_CELL) % 4;
                    const threshold = CGA_DITHER_MATRIX[dy][dx] / 16;
                    const ditheredLevel = frac > threshold ? level + 1 : level;
                    const clamped = Math.max(0, Math.min(CGA_DITHER_COLORS.length - 1, ditheredLevel));
                    cgaStarfieldCtx.fillStyle = CGA_DITHER_COLORS[clamped];
                    cgaStarfieldCtx.fillRect(x, y, CGA_DITHER_CELL, CGA_DITHER_CELL);
                }
            }

            cgaStarfieldAnimationId = requestAnimationFrame(drawCgaStarfield);
        }

        function resizeCgaStarfield() {
            const canvas = document.getElementById('cgaStarfield');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            if (!ctx) return;
            cgaStarfieldCtx = ctx;
            const dpr = window.devicePixelRatio || 1;
            canvas.width = window.innerWidth * dpr;
            canvas.height = window.innerHeight * dpr;
            cgaStarfieldCtx.scale(dpr, dpr);
        }

        function startCgaStarfield() {
            if (cgaStarfieldAnimationId) return;
            resizeCgaStarfield();
            if (!cgaStarfieldCtx) return;
            cgaStarfieldLastDraw = performance.now();
            cgaStarfieldAnimationId = requestAnimationFrame(drawCgaStarfield);
        }

        function stopCgaStarfield() {
            if (cgaStarfieldAnimationId) {
                cancelAnimationFrame(cgaStarfieldAnimationId);
                cgaStarfieldAnimationId = null;
            }
            const canvas = document.getElementById('cgaStarfield');
            if (canvas && cgaStarfieldCtx) {
                cgaStarfieldCtx.clearRect(0, 0, canvas.width, canvas.height);
            }
        }

        function updateCgaStarfield() {
            if (getCurrentTheme() === 'cga') {
                startCgaStarfield();
            } else {
                stopCgaStarfield();
            }
        }

        // Classic demoscene plasma field for Breadbin Blue - on the same
        // #breadbinSprites canvas (id/class kept from the earlier
        // blinking-sprite effect this replaced, to avoid an unrelated
        // HTML/CSS rename). Four combined sine waves sampled on a coarse
        // grid (not per-pixel - far too much trig for 60fps) and mapped
        // through a lookup table built from the theme's own palette, so
        // it's cheap to redraw in full every tick. Unlike the sprite
        // field or the raster-bars/scrolltext combo tried before it, this
        // is a soft continuous field with no hard edges, so it doesn't
        // need to dodge the header/footer/panels the way those did - it
        // just runs across the whole canvas at low opacity and reads
        // fine wherever it happens to peek through.
        let breadbinSpriteCtx = null;
        let breadbinSpriteAnimationId = null;
        let breadbinSpriteLastDraw = 0;
        let breadbinPlasmaPalette = null;
        const BREADBIN_SPRITE_COLORS = ['#7869C4', '#67B6BD', '#94E089', '#BFCE72', '#d19a5a', '#B86962', '#ffffff'];
        const BREADBIN_PLASMA_CELL = 10;

        function breadbinHexToRgb(hex) {
            const n = parseInt(hex.slice(1), 16);
            return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
        }

        function makeBreadbinPlasmaPalette() {
            const stops = BREADBIN_SPRITE_COLORS.map(breadbinHexToRgb);
            const palette = new Array(256);
            for (let i = 0; i < 256; i++) {
                const t = (i / 256) * stops.length;
                const idx = Math.floor(t) % stops.length;
                const nextIdx = (idx + 1) % stops.length;
                const frac = t - Math.floor(t);
                const a = stops[idx], b = stops[nextIdx];
                const r = Math.round(a[0] + (b[0] - a[0]) * frac);
                const g = Math.round(a[1] + (b[1] - a[1]) * frac);
                const bl = Math.round(a[2] + (b[2] - a[2]) * frac);
                palette[i] = `rgb(${r},${g},${bl})`;
            }
            return palette;
        }

        function drawBreadbinSprites(timestamp) {
            const canvas = document.getElementById('breadbinSprites');
            if (!canvas || getCurrentTheme() !== 'breadbin-blue') return;
            if (!breadbinSpriteCtx) resizeBreadbinSprites();
            if (!breadbinSpriteCtx) return;

            const dt = timestamp - breadbinSpriteLastDraw;
            if (dt < 60) {
                breadbinSpriteAnimationId = requestAnimationFrame(drawBreadbinSprites);
                return;
            }
            breadbinSpriteLastDraw = timestamp;

            const width = window.innerWidth;
            const height = window.innerHeight;
            const t = timestamp * 0.0006;
            for (let y = 0; y < height; y += BREADBIN_PLASMA_CELL) {
                for (let x = 0; x < width; x += BREADBIN_PLASMA_CELL) {
                    const value = Math.sin(x * 0.02 + t)
                        + Math.sin(y * 0.025 + t * 1.3)
                        + Math.sin((x + y) * 0.015 + t * 0.7)
                        + Math.sin(Math.sqrt(x * x + y * y) * 0.02 - t * 1.5);
                    const normalized = Math.floor(((value + 4) / 8) * 255) & 255;
                    breadbinSpriteCtx.fillStyle = breadbinPlasmaPalette[normalized];
                    breadbinSpriteCtx.fillRect(x, y, BREADBIN_PLASMA_CELL, BREADBIN_PLASMA_CELL);
                }
            }

            breadbinSpriteAnimationId = requestAnimationFrame(drawBreadbinSprites);
        }

        function resizeBreadbinSprites() {
            const canvas = document.getElementById('breadbinSprites');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            if (!ctx) return;
            breadbinSpriteCtx = ctx;
            const dpr = window.devicePixelRatio || 1;
            canvas.width = window.innerWidth * dpr;
            canvas.height = window.innerHeight * dpr;
            breadbinSpriteCtx.scale(dpr, dpr);
            if (!breadbinPlasmaPalette) breadbinPlasmaPalette = makeBreadbinPlasmaPalette();
        }

        function startBreadbinSprites() {
            if (breadbinSpriteAnimationId) return;
            resizeBreadbinSprites();
            if (!breadbinSpriteCtx) return;
            breadbinSpriteLastDraw = performance.now();
            breadbinSpriteAnimationId = requestAnimationFrame(drawBreadbinSprites);
        }

        function stopBreadbinSprites() {
            if (breadbinSpriteAnimationId) {
                cancelAnimationFrame(breadbinSpriteAnimationId);
                breadbinSpriteAnimationId = null;
            }
            const canvas = document.getElementById('breadbinSprites');
            if (canvas && breadbinSpriteCtx) {
                breadbinSpriteCtx.clearRect(0, 0, canvas.width, canvas.height);
            }
        }

        function updateBreadbinSprites() {
            if (getCurrentTheme() === 'breadbin-blue') {
                startBreadbinSprites();
            } else {
                stopBreadbinSprites();
            }
        }

        let digitalFrontierCtx = null;
        let dfStreaks = [];
        let dfAnimationId = null;
        let dfLastDraw = 0;
        let dfLastSpawn = 0;
        let dfNextSpawnDelay = 0;
        const DF_STREAK_COLORS = ['#00d9ff', '#00d9ff', '#00d9ff', '#ff9d4d'];
        const DF_STREAK_DURATION = 2200;
        const DF_STREAK_TRAIL_LENGTH = 220;
        const DF_MAX_STREAKS = 3;

        function makeDigitalFrontierStreak(width, height, timestamp) {
            const axis = Math.random() < 0.5 ? 'h' : 'v';
            return {
                axis,
                cross: axis === 'h' ? Math.random() * height : Math.random() * width,
                start: timestamp,
                duration: DF_STREAK_DURATION * (0.8 + Math.random() * 0.5),
                color: DF_STREAK_COLORS[Math.floor(Math.random() * DF_STREAK_COLORS.length)]
            };
        }

        function drawDigitalFrontier(timestamp) {
            const canvas = document.getElementById('digitalFrontierStreaks');
            if (!canvas || getCurrentTheme() !== 'digital-frontier') return;
            if (!digitalFrontierCtx) resizeDigitalFrontier();
            if (!digitalFrontierCtx) return;

            const dt = timestamp - dfLastDraw;
            if (dt < 50) {
                dfAnimationId = requestAnimationFrame(drawDigitalFrontier);
                return;
            }
            dfLastDraw = timestamp;

            const width = window.innerWidth;
            const height = window.innerHeight;
            digitalFrontierCtx.clearRect(0, 0, width, height);

            if (timestamp - dfLastSpawn > dfNextSpawnDelay && dfStreaks.length < DF_MAX_STREAKS) {
                dfStreaks.push(makeDigitalFrontierStreak(width, height, timestamp));
                dfLastSpawn = timestamp;
                dfNextSpawnDelay = 1500 + Math.random() * 2500;
            }
            dfStreaks = dfStreaks.filter(s => timestamp - s.start < s.duration);

            for (const streak of dfStreaks) {
                const t = (timestamp - streak.start) / streak.duration;
                const travel = streak.axis === 'h' ? width : height;
                const headPos = t * (travel + DF_STREAK_TRAIL_LENGTH) - DF_STREAK_TRAIL_LENGTH;
                const tailPos = headPos - DF_STREAK_TRAIL_LENGTH;
                if (headPos < 0 || tailPos > travel) continue;

                const x1 = streak.axis === 'h' ? Math.max(0, tailPos) : streak.cross;
                const y1 = streak.axis === 'h' ? streak.cross : Math.max(0, tailPos);
                const x2 = streak.axis === 'h' ? Math.min(width, headPos) : streak.cross;
                const y2 = streak.axis === 'h' ? streak.cross : Math.min(height, headPos);

                const grad = streak.axis === 'h'
                    ? digitalFrontierCtx.createLinearGradient(tailPos, streak.cross, headPos, streak.cross)
                    : digitalFrontierCtx.createLinearGradient(streak.cross, tailPos, streak.cross, headPos);
                grad.addColorStop(0, 'rgba(0, 0, 0, 0)');
                grad.addColorStop(1, streak.color);

                digitalFrontierCtx.strokeStyle = grad;
                digitalFrontierCtx.lineWidth = 2;
                digitalFrontierCtx.shadowColor = streak.color;
                digitalFrontierCtx.shadowBlur = 8;
                digitalFrontierCtx.beginPath();
                digitalFrontierCtx.moveTo(x1, y1);
                digitalFrontierCtx.lineTo(x2, y2);
                digitalFrontierCtx.stroke();
            }
            digitalFrontierCtx.shadowBlur = 0;

            dfAnimationId = requestAnimationFrame(drawDigitalFrontier);
        }

        function resizeDigitalFrontier() {
            const canvas = document.getElementById('digitalFrontierStreaks');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            if (!ctx) return;
            digitalFrontierCtx = ctx;
            const dpr = window.devicePixelRatio || 1;
            canvas.width = window.innerWidth * dpr;
            canvas.height = window.innerHeight * dpr;
            digitalFrontierCtx.scale(dpr, dpr);
            dfStreaks = [];
        }

        function startDigitalFrontier() {
            if (dfAnimationId) return;
            resizeDigitalFrontier();
            if (!digitalFrontierCtx) return;
            dfLastDraw = performance.now();
            dfLastSpawn = dfLastDraw;
            dfNextSpawnDelay = 400 + Math.random() * 800;
            dfAnimationId = requestAnimationFrame(drawDigitalFrontier);
        }

        function stopDigitalFrontier() {
            if (dfAnimationId) {
                cancelAnimationFrame(dfAnimationId);
                dfAnimationId = null;
            }
            const canvas = document.getElementById('digitalFrontierStreaks');
            if (canvas && digitalFrontierCtx) {
                digitalFrontierCtx.clearRect(0, 0, canvas.width, canvas.height);
            }
            dfStreaks = [];
        }

        function updateDigitalFrontier() {
            if (getCurrentTheme() === 'digital-frontier') {
                startDigitalFrontier();
            } else {
                stopDigitalFrontier();
            }
        }

        // "Bliss" homage for Luna Blue - the rolling-hill-under-blue-sky
        // scene, a nod to Windows XP's default wallpaper (its Luna visual
        // style is this theme's namesake). Mostly a static composed
        // scene like Vaporwave's horizon, plus a handful of clouds
        // drifting slowly across the sky - the one animated element,
        // small and diffuse like the other continuously-animated themes.
        let lunaBlissCtx = null;
        let lunaClouds = [];
        let lunaBlissAnimationId = null;
        let lunaBlissLastDraw = 0;
        const LUNA_CLOUD_COUNT = 5;

        function makeLunaClouds(width, height) {
            const clouds = new Array(LUNA_CLOUD_COUNT);
            for (let i = 0; i < LUNA_CLOUD_COUNT; i++) {
                clouds[i] = {
                    x: Math.random() * width,
                    y: height * (0.08 + Math.random() * 0.4),
                    scale: 0.6 + Math.random() * 0.9,
                    speed: 4 + Math.random() * 10,
                    alpha: 0.55 + Math.random() * 0.35
                };
            }
            return clouds;
        }

        function drawLunaCloud(ctx, cloud) {
            const { x, y, scale, alpha } = cloud;
            ctx.globalAlpha = alpha;
            ctx.fillStyle = '#ffffff';
            ctx.beginPath();
            ctx.ellipse(x, y, 40 * scale, 16 * scale, 0, 0, Math.PI * 2);
            ctx.ellipse(x - 30 * scale, y + 6 * scale, 26 * scale, 14 * scale, 0, 0, Math.PI * 2);
            ctx.ellipse(x + 32 * scale, y + 5 * scale, 28 * scale, 15 * scale, 0, 0, Math.PI * 2);
            ctx.ellipse(x - 10 * scale, y - 10 * scale, 24 * scale, 16 * scale, 0, 0, Math.PI * 2);
            ctx.ellipse(x + 14 * scale, y - 8 * scale, 22 * scale, 14 * scale, 0, 0, Math.PI * 2);
            ctx.fill();
        }

        function drawLunaBliss(timestamp) {
            const canvas = document.getElementById('lunaBliss');
            if (!canvas || getCurrentTheme() !== 'luna-blue') return;
            if (!lunaBlissCtx) resizeLunaBliss();
            if (!lunaBlissCtx) return;

            const dt = timestamp - lunaBlissLastDraw;
            if (dt < 50) {
                lunaBlissAnimationId = requestAnimationFrame(drawLunaBliss);
                return;
            }
            const elapsedSeconds = dt / 1000;
            lunaBlissLastDraw = timestamp;

            const width = window.innerWidth;
            const height = window.innerHeight;
            const horizonY = height * 0.8;

            const sky = lunaBlissCtx.createLinearGradient(0, 0, 0, horizonY);
            sky.addColorStop(0, '#173F8C');
            sky.addColorStop(0.55, '#5C93EE');
            sky.addColorStop(1, '#DCEFFF');
            lunaBlissCtx.globalAlpha = 1;
            lunaBlissCtx.fillStyle = sky;
            lunaBlissCtx.fillRect(0, 0, width, height);

            for (const cloud of lunaClouds) {
                cloud.x += cloud.speed * elapsedSeconds;
                const cloudWidth = 90 * cloud.scale;
                if (cloud.x - cloudWidth > width) {
                    cloud.x = -cloudWidth;
                    cloud.y = height * (0.08 + Math.random() * 0.4);
                }
                drawLunaCloud(lunaBlissCtx, cloud);
            }
            lunaBlissCtx.globalAlpha = 1;

            const hill = lunaBlissCtx.createLinearGradient(0, horizonY - height * 0.12, 0, height);
            hill.addColorStop(0, '#8ED43C');
            hill.addColorStop(1, '#3F8A12');
            lunaBlissCtx.fillStyle = hill;
            lunaBlissCtx.beginPath();
            lunaBlissCtx.moveTo(0, horizonY);
            lunaBlissCtx.bezierCurveTo(width * 0.22, horizonY - height * 0.12, width * 0.38, horizonY + height * 0.05, width * 0.58, horizonY - height * 0.03);
            lunaBlissCtx.bezierCurveTo(width * 0.78, horizonY - height * 0.1, width * 0.9, horizonY + height * 0.03, width, horizonY - height * 0.02);
            lunaBlissCtx.lineTo(width, height);
            lunaBlissCtx.lineTo(0, height);
            lunaBlissCtx.closePath();
            lunaBlissCtx.fill();

            lunaBlissAnimationId = requestAnimationFrame(drawLunaBliss);
        }

        function resizeLunaBliss() {
            const canvas = document.getElementById('lunaBliss');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            if (!ctx) return;
            lunaBlissCtx = ctx;
            const dpr = window.devicePixelRatio || 1;
            canvas.width = window.innerWidth * dpr;
            canvas.height = window.innerHeight * dpr;
            lunaBlissCtx.scale(dpr, dpr);
            lunaClouds = makeLunaClouds(window.innerWidth, window.innerHeight);
        }

        function startLunaBliss() {
            if (lunaBlissAnimationId) return;
            resizeLunaBliss();
            if (!lunaBlissCtx) return;
            lunaBlissLastDraw = performance.now();
            lunaBlissAnimationId = requestAnimationFrame(drawLunaBliss);
        }

        function stopLunaBliss() {
            if (lunaBlissAnimationId) {
                cancelAnimationFrame(lunaBlissAnimationId);
                lunaBlissAnimationId = null;
            }
            const canvas = document.getElementById('lunaBliss');
            if (canvas && lunaBlissCtx) {
                lunaBlissCtx.clearRect(0, 0, canvas.width, canvas.height);
            }
        }

        function updateLunaBliss() {
            if (getCurrentTheme() === 'luna-blue') {
                startLunaBliss();
            } else {
                stopLunaBliss();
            }
        }

        // Boot-log ambient background for Amber - lines of fake
        // kernel/system boot messages printed one at a time, like a real
        // terminal rather than a smooth-scrolling ticker: each new line
        // appears at a randomized interval (sometimes in rapid
        // succession, sometimes with a short pause, like a real boot
        // sequence moving through fast and slow steps), snapping the
        // existing lines up by one row rather than continuously scrolling
        // pixel-by-pixel. Brightness fades toward the top (bottom =
        // newest = full opacity) to mimic CRT phosphor persistence.
        let amberBootLogCtx = null;
        let amberLogLines = [];
        let amberVisibleRows = 0;
        let amberNextLineTime = 0;
        let amberBootLogAnimationId = null;
        let amberBootLogLastDraw = 0;
        const AMBER_LINE_HEIGHT = 16;
        const AMBER_BOOT_LOG_MESSAGES = [
            '[  OK  ] Initializing memory subsystem...',
            '[  OK  ] Mounting /dev/sda1 on /...',
            '[  OK  ] Loading kernel modules...',
            '[  OK  ] Starting network interface eth0...',
            '[  OK  ] Detecting hardware devices...',
            '[  OK  ] Starting system logger...',
            '[  OK  ] Checking filesystem integrity...',
            '[  OK  ] Loading device drivers...',
            '[  OK  ] Starting cron daemon...',
            '[  OK  ] Initializing swap space...',
            '[ WARN ] Clock skew detected, adjusting...',
            '[  OK  ] Starting SSH daemon...',
            '[  OK  ] Bringing up loopback interface...',
            '[  OK  ] Calibrating delay loop...',
            '[  OK  ] Starting local services...',
            'Kernel command line: root=/dev/sda1 ro quiet',
            'CPU0: base frequency 100MHz, cache 512KB',
            'Total memory: 640K conventional, 15360K extended'
        ];

        function drawAmberBootLog(timestamp) {
            const canvas = document.getElementById('amberBootLog');
            if (!canvas || getCurrentTheme() !== 'amber') return;
            if (!amberBootLogCtx) resizeAmberBootLog();
            if (!amberBootLogCtx) return;

            const dt = timestamp - amberBootLogLastDraw;
            if (dt < 50) {
                amberBootLogAnimationId = requestAnimationFrame(drawAmberBootLog);
                return;
            }
            amberBootLogLastDraw = timestamp;

            if (timestamp >= amberNextLineTime) {
                amberLogLines.push(AMBER_BOOT_LOG_MESSAGES[Math.floor(Math.random() * AMBER_BOOT_LOG_MESSAGES.length)]);
                if (amberLogLines.length > amberVisibleRows) {
                    amberLogLines.shift();
                }
                amberNextLineTime = timestamp + 60 + Math.random() * 640;
            }

            const width = window.innerWidth;
            const height = window.innerHeight;
            amberBootLogCtx.clearRect(0, 0, width, height);
            for (let i = 0; i < amberLogLines.length; i++) {
                const y = i * AMBER_LINE_HEIGHT;
                const fadeT = Math.max(0, Math.min(1, y / height));
                amberBootLogCtx.globalAlpha = 0.25 + 0.55 * fadeT;
                amberBootLogCtx.fillStyle = '#FFB000';
                amberBootLogCtx.fillText(amberLogLines[i], 16, y);
            }
            amberBootLogCtx.globalAlpha = 1;

            amberBootLogAnimationId = requestAnimationFrame(drawAmberBootLog);
        }

        function resizeAmberBootLog() {
            const canvas = document.getElementById('amberBootLog');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            if (!ctx) return;
            amberBootLogCtx = ctx;
            const dpr = window.devicePixelRatio || 1;
            canvas.width = window.innerWidth * dpr;
            canvas.height = window.innerHeight * dpr;
            amberBootLogCtx.scale(dpr, dpr);
            amberBootLogCtx.font = '13px "Courier New", monospace';
            amberVisibleRows = Math.ceil(window.innerHeight / AMBER_LINE_HEIGHT);
            amberLogLines = [];
            amberNextLineTime = 0;
        }

        function startAmberBootLog() {
            if (amberBootLogAnimationId) return;
            resizeAmberBootLog();
            if (!amberBootLogCtx) return;
            amberBootLogLastDraw = performance.now();
            amberBootLogAnimationId = requestAnimationFrame(drawAmberBootLog);
        }

        function stopAmberBootLog() {
            if (amberBootLogAnimationId) {
                cancelAnimationFrame(amberBootLogAnimationId);
                amberBootLogAnimationId = null;
            }
            const canvas = document.getElementById('amberBootLog');
            if (canvas && amberBootLogCtx) {
                amberBootLogCtx.clearRect(0, 0, canvas.width, canvas.height);
            }
        }

        function updateAmberBootLog() {
            if (getCurrentTheme() === 'amber') {
                startAmberBootLog();
            } else {
                stopAmberBootLog();
            }
        }

        // Bouncing spectrum-analyzer ambient background for MP3 Player -
        // the single most recognizable visual signature of that late-90s/
        // early-2000s skinnable media-player era. A row of bars along the
        // bottom of the viewport, each easing toward a new random target
        // height on its own timer (no real audio behind it), colored
        // bottom-to-top in the classic green-yellow-orange-red EQ gradient,
        // with a small bright "peak-hold" cap that rises with its bar and
        // falls back slowly - the authentic touch real hardware/software
        // equalizers had.
        let mp3VisualizerCtx = null;
        let mp3Bars = [];
        let mp3VisualizerAnimationId = null;
        let mp3VisualizerLastDraw = 0;
        let mp3MaxBarHeight = 0;
        const MP3_BAR_WIDTH = 6;
        const MP3_BAR_GAP = 3;

        function makeMp3Bars(width) {
            const barSlot = MP3_BAR_WIDTH + MP3_BAR_GAP;
            const count = Math.max(12, Math.floor(width / barSlot));
            const bars = new Array(count);
            for (let i = 0; i < count; i++) {
                bars[i] = {
                    height: Math.random() * mp3MaxBarHeight,
                    target: Math.random() * mp3MaxBarHeight,
                    nextChange: performance.now() + 150 + Math.random() * 350,
                    peak: 0
                };
            }
            return bars;
        }

        function drawMp3Visualizer(timestamp) {
            const canvas = document.getElementById('mp3Visualizer');
            if (!canvas || getCurrentTheme() !== 'mp3-player') return;
            if (!mp3VisualizerCtx) resizeMp3Visualizer();
            if (!mp3VisualizerCtx) return;

            const dt = timestamp - mp3VisualizerLastDraw;
            if (dt < 50) {
                mp3VisualizerAnimationId = requestAnimationFrame(drawMp3Visualizer);
                return;
            }
            mp3VisualizerLastDraw = timestamp;

            const width = window.innerWidth;
            const height = window.innerHeight;
            const baseline = height;
            mp3VisualizerCtx.clearRect(0, 0, width, height);

            // One gradient reused for every bar - a pure vertical gradient's
            // color at any point only depends on y, so it's identical for
            // every bar regardless of its x position.
            const grad = mp3VisualizerCtx.createLinearGradient(0, baseline, 0, baseline - mp3MaxBarHeight);
            grad.addColorStop(0, '#3DDC5A');
            grad.addColorStop(0.55, '#E8E24A');
            grad.addColorStop(0.8, '#F2A73B');
            grad.addColorStop(1, '#F24B4B');
            mp3VisualizerCtx.fillStyle = grad;

            const barSlot = MP3_BAR_WIDTH + MP3_BAR_GAP;
            for (let i = 0; i < mp3Bars.length; i++) {
                const bar = mp3Bars[i];
                if (timestamp >= bar.nextChange) {
                    bar.target = Math.random() * mp3MaxBarHeight;
                    bar.nextChange = timestamp + 150 + Math.random() * 350;
                }
                bar.height += (bar.target - bar.height) * 0.25;
                if (bar.height > bar.peak) {
                    bar.peak = bar.height;
                } else {
                    bar.peak -= mp3MaxBarHeight * 0.02;
                    if (bar.peak < bar.height) bar.peak = bar.height;
                }

                const x = i * barSlot;
                const barHeight = Math.max(2, bar.height);
                mp3VisualizerCtx.fillStyle = grad;
                mp3VisualizerCtx.fillRect(x, baseline - barHeight, MP3_BAR_WIDTH, barHeight);

                mp3VisualizerCtx.fillStyle = '#ffffff';
                mp3VisualizerCtx.fillRect(x, baseline - bar.peak - 2, MP3_BAR_WIDTH, 2);
            }

            mp3VisualizerAnimationId = requestAnimationFrame(drawMp3Visualizer);
        }

        function resizeMp3Visualizer() {
            const canvas = document.getElementById('mp3Visualizer');
            if (!canvas) return;
            const ctx = canvas.getContext('2d');
            if (!ctx) return;
            mp3VisualizerCtx = ctx;
            const dpr = window.devicePixelRatio || 1;
            canvas.width = window.innerWidth * dpr;
            canvas.height = window.innerHeight * dpr;
            mp3VisualizerCtx.scale(dpr, dpr);
            mp3MaxBarHeight = Math.min(220, window.innerHeight * 0.28);
            mp3Bars = makeMp3Bars(window.innerWidth);
        }

        function startMp3Visualizer() {
            if (mp3VisualizerAnimationId) return;
            resizeMp3Visualizer();
            if (!mp3VisualizerCtx) return;
            mp3VisualizerLastDraw = performance.now();
            mp3VisualizerAnimationId = requestAnimationFrame(drawMp3Visualizer);
        }

        function stopMp3Visualizer() {
            if (mp3VisualizerAnimationId) {
                cancelAnimationFrame(mp3VisualizerAnimationId);
                mp3VisualizerAnimationId = null;
            }
            const canvas = document.getElementById('mp3Visualizer');
            if (canvas && mp3VisualizerCtx) {
                mp3VisualizerCtx.clearRect(0, 0, canvas.width, canvas.height);
            }
        }

        function updateMp3Visualizer() {
            if (getCurrentTheme() === 'mp3-player') {
                startMp3Visualizer();
            } else {
                stopMp3Visualizer();
            }
        }

        function updateFavicon() {
            const link = document.getElementById('faviconLink');
            if (!link) return;
            const theme = getCurrentTheme();
            // Every theme except dark has a matching
            // static/favicon-<theme>.svg; dark uses the plain one.
            // The synthesized OhMyDebn custom theme has no favicon of its
            // own (colors vary per palette) - reuse the hand-built
            // "OhMyDebn" theme's favicon as the closest branding match.
            if (theme === OHMYDEBN_CUSTOM_THEME) {
                link.href = 'static/favicon-ohmydebn.svg';
                return;
            }
            link.href = (theme === 'dark')
                ? 'static/favicon.svg'
                : `static/favicon-${theme}.svg`;
        }

        // Single source of truth for "every ambient theme background
        // effect" - setTheme()/applyCustomTheme()/init() all need to
        // re-evaluate every effect's on/off state on every theme change
        // (each updater itself checks getCurrentTheme() and starts/stops
        // accordingly), and the resize/visibilitychange listeners just
        // below need to reach every effect too. Adding a new ambient
        // theme now only means adding one entry to each of these three
        // arrays, rather than a new call in 4+ separate places.
        const AMBIENT_THEME_RESIZERS = [resizeCodeRain, resizeBlockRain, resizeVaporwaveGrid, resizeDosDefrag, resizeCgaStarfield, resizeBreadbinSprites, resizeDigitalFrontier, resizeLunaBliss, resizeAmberBootLog, resizeMp3Visualizer];
        const AMBIENT_THEME_UPDATERS = [updateCodeRain, updateBlockRain, updateVaporwaveGrid, updateDosDefrag, updateCgaStarfield, updateBreadbinSprites, updateDigitalFrontier, updateLunaBliss, updateAmberBootLog, updateMp3Visualizer];
        const AMBIENT_THEME_STOPPERS = [stopCodeRain, stopBlockRain, stopVaporwaveGrid, stopDosDefrag, stopCgaStarfield, stopBreadbinSprites, stopDigitalFrontier, stopLunaBliss, stopAmberBootLog, stopMp3Visualizer];

        function updateAllAmbientThemes() {
            AMBIENT_THEME_UPDATERS.forEach(fn => fn());
        }

        function stopAllAmbientThemes() {
            AMBIENT_THEME_STOPPERS.forEach(fn => fn());
        }

        AMBIENT_THEME_RESIZERS.forEach(fn => window.addEventListener('resize', fn));
        document.addEventListener('visibilitychange', function() {
            if (document.hidden) {
                stopAllAmbientThemes();
            } else {
                updateAllAmbientThemes();
            }
        });

        function toggleMenu() {
            const dropdown = document.getElementById('appHeaderMenuDropdown');
            if (!dropdown) return;
            dropdown.classList.toggle('active');
        }

        function closeMenu() {
            const dropdown = document.getElementById('appHeaderMenuDropdown');
            if (dropdown) dropdown.classList.remove('active');
        }

        function showThemesModal() {
            closeOtherMenuModals('themesModal');
            document.getElementById('themesModalBody').innerHTML = renderThemesModalGrid();
            updateThemeMenu();
            // getCurrentTheme() can be the synthesized OHMYDEBN_CUSTOM_THEME
            // marker (reachable if sync was on, applied a custom palette,
            // then got turned off - the picker becomes visible again while
            // that marker is still the applied theme). previewTheme()/
            // revertTheme() both gate on the theme being a real THEMES key,
            // so a marker baseline would silently no-op every hover/revert
            // in this modal - fall back to 'dark' instead.
            const currentTheme = getCurrentTheme();
            menuBaseTheme = Object.prototype.hasOwnProperty.call(THEMES, currentTheme) ? currentTheme : 'dark';
            document.getElementById('syncThemeWithOS').checked = safeStorageGet(localStorage, 'socrates_syncThemeWithOS') === 'true';
            // Hidden by default - only shown if OHMYDEBN_THEME_DIR is set
            // server-side AND its theme.name is currently readable, so this never shows a
            // control that can't do anything (e.g. not launched via
            // ohmydebn-socrates-run). Never blocks the modal on this check
            // (mirrors showSettingsModal()'s /api/limits fetch) - defaults
            // to hidden on any fetch failure too, since "can't confirm it
            // works" should fail closed, not show a maybe-broken toggle.
            const syncContainer = document.getElementById('syncThemeWithOSContainer');
            syncContainer.style.display = 'none';
            updateThemePickerVisibility();
            fetch('/api/theme-sync-available').then(r => r.json()).then(data => {
                syncContainer.style.display = data.available ? 'block' : 'none';
                updateThemePickerVisibility();
            }).catch(() => {});
            const frame = document.getElementById('themePreviewFrame');
            if (!themePreviewFrameReady) {
                frame.addEventListener('load', function() {
                    themePreviewFrameReady = true;
                    previewTheme(menuBaseTheme);
                }, { once: true });
                frame.srcdoc = THEME_PREVIEW_SRCDOC;
            } else {
                previewTheme(menuBaseTheme);
            }
            document.getElementById('themesModal').classList.add('active');
        }

        function closeThemesModal() {
            document.getElementById('themesModal').classList.remove('active');
            revertTheme();
            menuBaseTheme = null;
            themeTileNavSelection = null;
        }

        // Backdrop-click helper: closes exactly when the click landed on
        // the backdrop div itself (not a child element), i.e. when
        // target === currentTarget. The static modals now route backdrop
        // clicks through the delegated 'backdrop' STATIC_ACTIONS entry
        // instead (same target check), but this helper's logic is still
        // the reference implementation the tests exercise directly.
        function handleModalBackdropClick(event, closeFn) {
            if (event.target === event.currentTarget) closeFn();
        }

        // Applies immediately on toggle, unlike the numeric Settings
        // fields which need a "Save" click - the themes modal has no save
        // step for anything else (theme clicks apply instantly too), so a
        // deferred-until-Save toggle here would be an inconsistent trap
        // (easy to check the box, forget to save, and have it silently not
        // take effect).
        function handleSyncThemeWithOSChange(checkbox) {
            safeStorageSet(localStorage, 'socrates_syncThemeWithOS', String(checkbox.checked));
            if (checkbox.checked) {
                // Re-enabling sync must reassert OhMyDebn's theme even if it
                // hasn't changed since sync was last on - otherwise a theme
                // picked manually while sync was off (now possible again
                // since the picker is visible when sync is disabled) would
                // stay applied indefinitely, since pollOhmydebnTheme()'s
                // dedup check would see the same theme/colors as last time
                // and treat it as "nothing to do."
                lastSyncedThemeName = null;
                lastSyncedColorsFingerprint = null;
                pollOhmydebnTheme();
            }
            updateThemePickerVisibility();
        }

        // While sync is on, OhMyDebn owns the theme - any tile the user
        // clicks here would just get stomped by the next poll (at most a
        // second later), so the picker is hidden rather than left clickable
        // and quietly ineffective. Gated on syncContainer's own visibility
        // (not just the checkbox) so a stale "checked" value from
        // localStorage can't hide the picker on a machine where the sync
        // feature isn't even available server-side.
        function updateThemePickerVisibility() {
            const syncContainer = document.getElementById('syncThemeWithOSContainer');
            const syncAvailable = syncContainer.style.display !== 'none';
            const enabled = syncAvailable && document.getElementById('syncThemeWithOS').checked;
            document.getElementById('themePickerControls').style.display = enabled ? 'none' : '';
            document.getElementById('themeSyncActiveNotice').style.display = enabled ? 'block' : 'none';
        }

        // Shared by the opt-in automatic check (silent) and the manual
        // "Check Now" button (which reports the result via toast) - hits
        // /api/version-check and flips on the footer badge if an update is
        // available. Returns the parsed {currentVersion, latestVersion,
        // updateAvailable} on success, or null on any failure (network
        // error, non-2xx, bad JSON) - the endpoint itself can't distinguish
        // "checked, no update" from "the check failed", so neither can this.
        async function _fetchAndApplyVersionCheck() {
            try {
                const resp = await fetch('/api/version-check');
                if (!resp.ok) return null;
                const data = await resp.json();
                const badge = document.getElementById('footerUpdateBadge');
                if (badge && data.updateAvailable) {
                    badge.style.display = 'inline';
                }
                return data;
            } catch (e) {
                return null;
            }
        }

        // Opt-in only (checked before ever fetching, same as
        // pollOhmydebnTheme()) - a stale app version doesn't silently
        // degrade the correctness of the current analysis, so there's no
        // harm in requiring explicit consent rather than checking
        // automatically. One-shot per page load (called once from init()),
        // not polled - the running app version can't change while the tab
        // is open. (Detection rule freshness is a different story - see
        // checkForStaleRules() below, which used to be unconditional for
        // exactly that "silently degrades correctness" reason, until
        // network-without-consent was judged the worse tradeoff.)
        async function checkForAppUpdate() {
            if (safeStorageGet(localStorage, 'socrates_checkForUpdates') !== 'true') return;
            await _fetchAndApplyVersionCheck();
        }

        // Manual "Check Now" button in the About modal - bypasses the
        // opt-in gate (an explicit click IS the consent) and, unlike the
        // silent automatic check, always reports the result via toast so
        // clicking the button visibly does something even when there's
        // nothing new.
        async function checkForAppUpdateNow() {
            const data = await _fetchAndApplyVersionCheck();
            if (!data) {
                showToast('Could not check for updates - try again later');
            } else if (data.updateAvailable) {
                showToast('Update available: v' + data.latestVersion);
            } else {
                showToast("You're on the latest version");
            }
        }

        function handleCheckForUpdatesChange(checkbox) {
            safeStorageSet(localStorage, 'socrates_checkForUpdates', String(checkbox.checked));
            if (checkbox.checked) checkForAppUpdate();
        }

        function _joinWithAnd(items) {
            if (items.length <= 2) return items.join(' and ');
            return items.slice(0, -1).join(', ') + ', and ' + items[items.length - 1];
        }

        // Maps /api/rules-info's shape ({suricata: {...}, yara: {...},
        // sigma: {windows: {...}, linux: {...}}}) to the ruleset family
        // labels that are currently stale, matching the Rules modal's own
        // three update buttons (Suricata/YARA/Sigma - "update Sigma"
        // refreshes both its windows and linux rulesets together, so
        // either being stale counts as "Sigma" is stale here). Computes
        // staleness itself via isRulesetStale(updated, thresholdHours) -
        // the same function/threshold the Rules modal's date-color warning
        // uses - rather than trusting the server's precomputed 'stale'
        // field, since thresholdHours may be the user's per-browser
        // override (_resolveStaleThresholdHours()), which the server has
        // no way to have already applied. A ruleset with no 'updated' at
        // all (never downloaded, not merely old) is deliberately not
        // included - that's checkForMissingRules()'s job (unconditional,
        // fires when every ruleset is null), not this one's. The two stay
        // mutually exclusive by construction: a ruleset only reaches
        // isRulesetStale() here once 'updated' is non-null, so they never
        // compete to show a toast for the same ruleset at the same time.
        function _staleRulesetLabels(rulesInfo, thresholdHours) {
            const isStale = (entry) => !!(entry && entry.updated && isRulesetStale(entry.updated, thresholdHours));
            const stale = [];
            if (isStale(rulesInfo.suricata)) stale.push('Suricata');
            if (isStale(rulesInfo.yara)) stale.push('YARA');
            const sigma = rulesInfo.sigma || {};
            if (isStale(sigma.windows) || isStale(sigma.linux)) stale.push('Sigma');
            return stale;
        }

        // Opt-in only, same mechanics as checkForAppUpdate() - but for a
        // different reason. Analyzing with stale detection rules DOES
        // silently degrade the correctness of the results (missed
        // detections), which used to be the argument for refreshing
        // YARA/Sigma rules over the network automatically, no consent
        // asked, whenever a file was analyzed (see setup_yara_rules()/
        // setup_sigma_rules()'s network_allowed=False call sites in
        // socrates.py/sigma_analyzer.py, and AGENTS.md). That traded one
        // problem for a worse one for a security-focused tool: unprompted
        // outbound connections. This notification is the replacement -
        // opt-in, and purely a local file-age check (stat'ing rules files
        // via /api/rules-info, no outbound network access regardless of
        // the opt-in setting - that setting is for notification-noise
        // consent, not network consent), fired once per welcome-screen
        // view (called from showWelcomeUI()) to catch the analyst before
        // they start an analysis rather than interrupt one already
        // running. No separate manual "check now" trigger - the Rules
        // modal already shows the same staleness live via its own
        // amber-date warning (isRulesetStale()/formatDateSpan()), so a
        // second, redundant on-demand check added nothing.
        async function checkForStaleRules() {
            if (safeStorageGet(localStorage, 'socrates_checkForStaleRules') !== 'true') return;
            let stale;
            try {
                const resp = await fetch('/api/rules-info');
                if (!resp.ok) return;
                const info = await resp.json();
                stale = _staleRulesetLabels(info, _resolveStaleThresholdHours(info.staleThresholdHours));
            } catch (e) {
                return;
            }
            if (stale.length) {
                showToast(
                    _joinWithAnd(stale) + ' rules are stale. Update via the Rules menu before analyzing.',
                    { sticky: true, actionLabel: 'Open Rules', onAction: showRulesModal }
                );
            }
        }

        function handleCheckForStaleRulesChange(checkbox) {
            safeStorageSet(localStorage, 'socrates_checkForStaleRules', String(checkbox.checked));
            if (checkbox.checked) checkForStaleRules();
        }

        // Applies immediately on change (unlike Settings modal's numeric
        // fields, which batch behind an explicit Save) - matches the
        // checkbox right next to it, which also applies on change. An
        // empty/invalid/out-of-range value clears the override (falls
        // back to the server's default) rather than clamping to the
        // nearest boundary, so deleting the number is how a user resets
        // to default. Re-renders #rulesModalBody immediately from the
        // cached lastRulesInfo/lastRulesStatus (same pattern as
        // toggleRuleLog()) so the amber-date warnings above reflect the
        // new threshold right away, not just on the next 2s poll tick.
        function handleStaleThresholdDaysChange(input) {
            const n = parseInt(input.value, 10);
            if (isNaN(n) || n < 1 || n > 365) {
                safeStorageRemove(localStorage, 'socrates_staleThresholdDays');
            } else {
                safeStorageSet(localStorage, 'socrates_staleThresholdDays', String(n));
            }
            reRenderRulesModalFromCache();
        }

        document.addEventListener('click', function(e) {
            const menu = document.querySelector('.app-header-menu');
            if (menu && !menu.contains(e.target)) {
                closeMenu();
            }
        });

        const COLORS = {
            EVENT: {
                alert: '#ff6b6b',
                anomaly: '#ff9800',
                dns: '#66bb6a',
                dnp3: '#26c6da',
                filealerts: '#e91e63',
                fileinfo: '#9c27b0',
                flow: '#bc8cff',
                ftp: '#00bcd4',
                http: '#ffa726',
                log: '#b0b0b0',
                modbus: '#ab47bc',
                pgsql: '#ff7043',
                protocol_decode: '#ff9800',
                sigmaalert: '#ff6b6b',
                stats: '#9e9e9e',
                tls: '#58a6ff',
                connection: '#8b949e',
            },
            SEVERITY: {
                1: '#ff6b6b',
                2: '#ffa726',
                3: '#ffca28',
                4: '#66bb6a',
                default: '#8b949e',
            },
        };

        // Value->color maps for the dot indicator used on categorical table columns
        // (Protocol, HTTP Method, DNS Type, TLS Version). Falls back to --text-muted
        // for values not explicitly mapped, so new/unusual values still render sanely.
        const DOT_COLORS = {
            // Chosen to avoid the Type column's colors (TLS/Flow/HTTP already
            // use blue/purple/orange) so the two columns never show identical
            // dots in the same row - see the widest gaps in Type's hue wheel.
            PROTO: { TCP: '#a8d94f', UDP: '#4fd9a0', ICMP: '#4f52d9' },
            HTTP_METHOD: {
                GET: '#58a6ff', POST: '#66bb6a', PUT: '#ffa726', DELETE: '#ff6b6b',
                PATCH: '#bc8cff', HEAD: '#8b949e', OPTIONS: '#8b949e', CONNECT: '#8b949e',
            },
            DNS_TYPE: {
                A: '#58a6ff', AAAA: '#58a6ff', CNAME: '#26c6da', MX: '#ffa726',
                NS: '#bc8cff', TXT: '#66bb6a', PTR: '#ff79c6', SOA: '#ab47bc', SRV: '#00bcd4',
            },
            SIGMA_SEVERITY: {
                critical: 'var(--badge-danger-text)',
                high: '#ff7043',
                medium: 'var(--badge-warning-text)',
                low: '#ffca28',
                informational: 'var(--accent)',
            },
        };

        function valueDotSpan(color) {
            return `<span class="value-dot" style="background:${color || 'var(--text-muted)'}"></span>`;
        }

        function tlsVersionColor(version) {
            if (!version) return null;
            if (version.includes('1.3')) return '#66bb6a';
            if (version.includes('1.2')) return '#58a6ff';
            if (version.includes('1.1')) return '#ffa726';
            if (version.includes('1.0')) return '#ff6b6b';
            if (version.toUpperCase().includes('SSL')) return '#ff6b6b';
            return null;
        }
        const CONFIG = {
            DEFAULT_QUERY_LIMIT: 75000,
            DEFAULT_UPLOAD_SIZE_MB: 1000,
            MAX_POLLING_ATTEMPTS: 120,
            POLLING_INTERVAL_MS: 1000,
            TLS_ISSUER_MAX_LENGTH: 30,
            TLS_SUBJECT_MAX_LENGTH: 40,
            USER_AGENT_MAX_LENGTH: 50,
            AGGREGATION_TOP_N: 10,
            SEARCH_DEBOUNCE_MS: 300,
            SANKEY_BOTTOM_MARGIN: 60,
            SANKEY_MAX_NODES_PER_COLUMN: 50,
            TABLE_PAGE_SIZE: 100,
        };
        // Page size for every Aggregation Table's Prev/Next pagination
        // (matches Security Onion's own aggregation-table UX) - user-
        // adjustable via the "Items per page" selector (changeAggPageSize),
        // persisted across sessions the same way theme/collapse-state
        // preferences already are. db.py's AGGREGATION_TOP_N is only the
        // fallback default the server uses if a request omits page_size
        // entirely; the actual page size for every real request is always
        // whatever this is set to.
        const AGG_PAGE_SIZE_OPTIONS = [10, 25, 50, 100];
        const AGG_PAGE_SIZE_STORAGE_KEY = 'socrates_aggPageSize';
        // var (not let/const) like every other piece of mutable top-level
        // state in this file (hiddenAggregations, aggPage, currentMd5,
        // advancedMode, ...) - only var/function declarations attach to the
        // real global object, so a jsdom test's own separate indirect-eval
        // invocation (see tests/jsdom_helper.py, window["eval"]) can
        // actually see and mutate it; a let here would be invisible outside
        // whichever indirect eval originally loaded this file.
        var AGG_PAGE_SIZE = (() => {
            const stored = parseInt(safeStorageGet(localStorage, AGG_PAGE_SIZE_STORAGE_KEY), 10);
            return AGG_PAGE_SIZE_OPTIONS.includes(stored) ? stored : CONFIG.AGGREGATION_TOP_N;
        })();
        const DEFAULT_SAMPLE_URL = 'https://www.malware-traffic-analysis.net/2026/02/03/2026-02-03-GuLoader-for-AgentTesla-style-infection-with-FTP-data-exfil.pcap.zip';
        const SAMPLE_LOG_URL = 'https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/refs/heads/master/Defense%20Evasion/apt10_jjs_sideloading_prochollowing_persist_as_service_sysmon_1_7_8_13.evtx';
        const SAMPLE_BINARY_URL = 'https://secure.eicar.org/eicar.com';

        // Named constants above (not inline string literals in the sample
        // cards below) so the tooltip's domain is always derived from the
        // same URL the click actually fetches, rather than a second,
        // separately-typed copy that could silently drift from it.
        function _sampleCardTitle(url) {
            try {
                return 'Downloads from ' + new URL(url).hostname;
            } catch (e) {
                return '';
            }
        }
        const FILE_ICON_SVG = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 4px;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>';
        const REFRESH_ICON_SVG = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle;"><polyline points="23 4 23 10 17 10"></polyline><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path></svg>';
        const DELETE_ICON_SVG = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle;"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>';
        const FOLDER_ICON_SVG = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 4px;"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>';
        const FOLDER_OPEN_ICON_SVG = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle;"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path><polyline points="2 13 6 9 10 13"></polyline></svg>';
        const DOWN_ARROW_ICON_SVG = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 4px;"><line x1="12" y1="5" x2="12" y2="19"></line><polyline points="19 12 12 19 5 12"></polyline></svg>';
        const CHECKMARK_ICON_SVG = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle;"><polyline points="20 6 9 17 4 12"></polyline></svg>';
        const X_ICON_SVG = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle;"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>';
        const LIGHTBULB_ICON_SVG = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 4px;"><path d="M9 18h6"/><path d="M10 22h4"/><path d="M12 2a7 7 0 0 0-7 7c0 2.5 1.5 4.5 3 6h8c1.5-1.5 3-3.5 3-6a7 7 0 0 0-7-7z"/></svg>';
        const SEARCH_ICON_SVG = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 4px;"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>';
        const COPY_ICON_SVG = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 4px;"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';
        const PLUS_ICON_SVG = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 4px;"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>';
        const CALENDAR_ICON_SVG = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 4px;"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>';
        const NOTES_ICON_SVG = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle;"><path d="M14 3v4a1 1 0 0 0 1 1h4"></path><path d="M17 21H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h7l5 5v11a2 2 0 0 1-2 2z"></path><line x1="9" y1="9" x2="10" y2="9"></line><line x1="9" y1="13" x2="15" y2="13"></line><line x1="9" y1="17" x2="15" y2="17"></line></svg>';
        const EXPAND_ICON_SVG = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 4px;"><polyline points="15 3 21 3 21 9"></polyline><polyline points="9 21 3 21 3 15"></polyline><line x1="21" y1="3" x2="14" y2="10"></line><line x1="3" y1="21" x2="10" y2="14"></line></svg>';
        const LINK_ICON_SVG = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 4px;"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>';
        const NOTES_MAX_LENGTH = 10000;
        const ROW_NOTE_MAX_LENGTH = 500; // mirrors config.MAX_ROW_NOTE_LENGTH
        function getWelcomeHelpContent() { return `
            <p style="color: var(--text-muted); font-size: 0.95rem;">
                <span style="color: var(--help-icon-color);">${LIGHTBULB_ICON_SVG}</span> Maximum file size is ${getUserMaxUploadSizeMB().toLocaleString()} MB (adjustable in <a href="#" data-action="show-settings-modal" style="color: var(--accent); text-decoration: underline; font-weight: 600;">Settings</a>).
            </p>
            <p style="color: var(--text-muted); font-size: 0.95rem; margin-top: 15px;">
                <span style="color: var(--help-icon-color);">${LIGHTBULB_ICON_SVG}</span> Processing may take a few minutes depending on the size of the file.
            </p>
            <p style="color: var(--text-muted); font-size: 0.95rem; margin-top: 15px;">
                <span style="color: var(--help-icon-color);">${LIGHTBULB_ICON_SVG}</span> File types supported:
            </p>
            <table style="width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.9rem; color: var(--text-primary);">
                <thead>
                    <tr style="border-bottom: 1px solid var(--border-color);">
                        <th style="text-align: left; padding: 8px 12px; color: var(--text-muted); font-weight: 600; width: 18%;">File Type</th>
                        <th style="text-align: left; padding: 8px 12px; color: var(--text-muted); font-weight: 600; width: 40%;">File Extensions</th>
                        <th style="text-align: left; padding: 8px 12px; color: var(--text-muted); font-weight: 600; width: 18%;">Engine</th>
                        <th style="text-align: left; padding: 8px 12px; color: var(--text-muted); font-weight: 600; width: 24%;">Ruleset</th>
                    </tr>
                </thead>
                <tbody>
                    <tr style="border-bottom: 1px solid var(--bg-tertiary);">
                        <td style="padding: 8px 12px;"><strong style="color: var(--accent);">Packet Capture</strong></td>
                        <td style="padding: 8px 12px;">.pcap, .pcapng, .cap, .trace</td>
                        <td style="padding: 8px 12px;">Suricata</td>
                        <td style="padding: 8px 12px;"><a href="#" data-action="show-rules-modal" data-arg="expand-sources" style="color: var(--accent); text-decoration: underline; font-weight: 600;">Multiple Rulesets</a></td>
                    </tr>
                    <tr style="border-bottom: 1px solid var(--bg-tertiary);">
                        <td style="padding: 8px 12px;"><strong style="color: var(--accent);">Logs</strong></td>
                        <td style="padding: 8px 12px;">.evtx, .json, .jsonl, .csv, .xml, .log</td>
                        <td style="padding: 8px 12px;">Zircolite</td>
                        <td style="padding: 8px 12px;"><a href="#" data-action="show-rules-modal" style="color: var(--accent); text-decoration: underline; font-weight: 600;">SigmaHQ</a></td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 12px;"><strong style="color: var(--accent);">Binary / Other</strong></td>
                        <td style="padding: 8px 12px;">.exe, .dll, .elf, .pdf, etc.</td>
                        <td style="padding: 8px 12px;">YARA</td>
                        <td style="padding: 8px 12px;"><a href="#" data-action="show-rules-modal" style="color: var(--accent); text-decoration: underline; font-weight: 600;">YARA Forge</a></td>
                    </tr>
                </tbody>
            </table>
            <p style="color: var(--text-muted); font-size: 0.85rem; margin-top: 8px; margin-bottom: 0;">
                Any of the above file types can be uploaded inside a .zip archive - every supported file found is extracted and analyzed as its own independent analysis.
            </p>
            <p style="color: var(--text-muted); font-size: 0.95rem; margin-top: 15px;">
                <span style="color: var(--help-icon-color);">${LIGHTBULB_ICON_SVG}</span> Want more fun? Try one of our Fun <a href="#" data-action="show-themes-modal" style="color: var(--accent); text-decoration: underline; font-weight: 600;">themes</a>!
            </p>
        `; }
        // Full feature comparison, opened via showSecurityOnionModal() -
        // the footer's own teaser (#footerCenterTeaser, set in
        // showWelcomeUI()) only links to this rather than showing it
        // directly, so it doesn't push a long table onto every visit to
        // the welcome screen.
        const SECURITY_ONION_COMPARISON_HTML = `
                <div style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 10px; text-align: center;">SO-CRATES provides basic analysis of imported files. Need more advanced functionality?<br>Take a look at the full <a href="https://securityonion.net/software" target="_blank" rel="noopener noreferrer" style="color: var(--accent); text-decoration: none; font-weight: 600;">Security Onion</a> platform available in a free Community Edition!<br>If you need enterprise features, consider upgrading to <a href="https://securityonion.com/pro" target="_blank" rel="noopener noreferrer" style="color: var(--accent); text-decoration: none; font-weight: 600;">Security Onion Pro</a>!</div>
                <table class="feature-table" style="width: 100%; border-collapse: collapse; margin-top: 15px;">
                    <thead>
                        <tr style="border-bottom: 1px solid var(--border-color);">
                            <th style="text-align: left; padding: 10px; color: var(--text-muted); font-size: 0.8rem; text-transform: none; cursor: default;">Feature</th>
                            <th style="text-align: center; padding: 10px; color: var(--text-bright); font-size: 0.8rem; text-transform: none; cursor: default;">SO-CRATES</th>
                            <th style="text-align: center; padding: 10px; color: var(--text-bright); font-size: 0.8rem; text-transform: none; cursor: default;">Security Onion</th>
                            <th style="text-align: center; padding: 10px; color: var(--text-bright); font-size: 0.8rem; text-transform: none; cursor: default;">Security Onion Pro</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr style="border-bottom: 1px solid var(--border-color);">
                            <td style="padding: 8px 10px; color: var(--text-primary); font-size: 0.85rem;">Import Files</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid var(--border-color);">
                            <td style="padding: 8px 10px; color: var(--text-primary); font-size: 0.85rem;">Investigate Alerts and Metadata</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid var(--border-color);">
                            <td style="padding: 8px 10px; color: var(--text-primary); font-size: 0.85rem;">Airgap / Offline Deployment</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid var(--border-color);">
                            <td style="padding: 8px 10px; color: var(--text-primary); font-size: 0.85rem;">Analyze Live Traffic</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid var(--border-color);">
                            <td style="padding: 8px 10px; color: var(--text-primary); font-size: 0.85rem;">Production Deployments</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid var(--border-color);">
                            <td style="padding: 8px 10px; color: var(--text-primary); font-size: 0.85rem;">Distributed Deployments</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid var(--border-color);">
                            <td style="padding: 8px 10px; color: var(--text-primary); font-size: 0.85rem;">Endpoint Visibility</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid var(--border-color);">
                            <td style="padding: 8px 10px; color: var(--text-primary); font-size: 0.85rem;">Log Management</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid var(--border-color);">
                            <td style="padding: 8px 10px; color: var(--text-primary); font-size: 0.85rem;">Case Management</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 10px; color: var(--text-primary); font-size: 0.85rem;">Guided Analysis</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 10px; color: var(--text-primary); font-size: 0.85rem;">Onion AI Assistant</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 10px; color: var(--text-primary); font-size: 0.85rem;">Open ID Connect (OIDC)</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 10px; color: var(--text-primary); font-size: 0.85rem;">FIPS</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 10px; color: var(--text-primary); font-size: 0.85rem;">STIG Compliance for the OS</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 10px; color: var(--text-primary); font-size: 0.85rem;">Connect API</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 10px; color: var(--text-primary); font-size: 0.85rem;">External Notifications</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 10px; color: var(--text-primary); font-size: 0.85rem;">Manager of Managers (MoM)</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 10px; color: var(--text-primary); font-size: 0.85rem;">MCP Server</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--bg-hover-light);">-</td>
                            <td style="text-align: center; padding: 8px 10px; color: var(--badge-success-text);">${CHECKMARK_ICON_SVG}</td>
                        </tr>
                    </tbody>
                </table>
                <div style="margin-top: 15px; display: flex; flex-wrap: wrap; gap: 10px; justify-content: center; font-size: 0.85rem;">
                    <a href="https://securityonion.net/software" target="_blank" rel="noopener noreferrer" style="color: var(--accent); text-decoration: none;">Security Onion</a>
                    <span style="color: var(--bg-hover);">|</span>
                    <a href="http://securityonion.net/docs/about" target="_blank" rel="noopener noreferrer" style="color: var(--accent); text-decoration: none;">Security Onion Documentation</a>
                    <span style="color: var(--bg-hover);">|</span>
                    <a href="https://securityonion.com/pro" target="_blank" rel="noopener noreferrer" style="color: var(--accent); text-decoration: none;">Security Onion Pro</a>
                    <span style="color: var(--bg-hover);">|</span>
                    <a href="http://securityonion.net/docs/security-onion-pro" target="_blank" rel="noopener noreferrer" style="color: var(--accent); text-decoration: none;">Security Onion Pro Documentation</a>
                </div>
        `;
        let lastSampleUrl = DEFAULT_SAMPLE_URL;
        function yaraTagBadgeHtml(tag) {
            const t = (tag || '').toUpperCase();
            let color;
            if (['RANSOMWARE','TROJAN','BACKDOOR','MALWARE','BOTNET'].includes(t)) {
                color = 'var(--tag-red-text)';
            } else if (['STORMBAMBOO','CHARMINGKITTEN','TURLA','LAZARUS','PLATINUM','HATMAN','CHARMINGCYPRESS','INKYPINE','INKYSQUID','EVILBAMBOO','TRANSPARENTJASMINE','UTA0040','WHEELEDASH'].includes(t)) {
                color = 'var(--tag-purple-text)';
            } else if (t.startsWith('CVE_')) {
                color = 'var(--tag-orange-text)';
            } else if (['FILE','MEMORY','SCRIPT','LOG'].includes(t)) {
                color = 'var(--tag-blue-text)';
            } else if (['INFO','UTILITY','HIGHVOL'].includes(t)) {
                color = 'var(--tag-gray-text)';
            } else {
                color = 'var(--tag-green-text)';
            }
            return `<span style="margin-right:12px;white-space:nowrap;display:inline-block;">${valueDotSpan(color)}${escapeHtml(tag)}</span>`;
        }

        function buildStreamUrl(endpoint, src, sport, dst, dport) {
            const md5Param = currentMd5 ? `&md5=${encodeURIComponent(currentMd5)}` : '';
            return `/api/${endpoint}?src=${encodeURIComponent(src)}&sport=${encodeURIComponent(sport)}&dst=${encodeURIComponent(dst)}&dport=${encodeURIComponent(dport)}${md5Param}`;
        }

        // Serialized currentSearch terms for API query strings ('&q=a&q=b'), or ''.
        function buildSearchQuery() {
            return currentSearch.length > 0 ? currentSearch.map(t => '&q=' + encodeURIComponent(t)).join('') : '';
        }

        // Classify a filename as 'pcap', 'log', or 'binary' by extension.
        function detectFileType(name) {
            if (name && /\.(pcap|pcapng|cap|trace)$/i.test(name)) return 'pcap';
            if (name && /\.(evtx|json|jsonl|csv|xml|log)$/i.test(name)) return 'log';
            return 'binary';
        }

        function showTab(sectionId, el) {
            // Both a direct mouse click and navigateStatTabs()'s own
            // cards[nextIndex].click() funnel through here - a mouse click
            // is the explicit "I want Left/Right to mean data type again"
            // signal (see leftRightSwitchesStatTabs's own comment), and
            // resetting it when navigateStatTabs() itself triggers this is
            // a harmless no-op (it can only have run while already true).
            leftRightSwitchesStatTabs = true;
            document.querySelectorAll('.section').forEach(s => s.classList.add('section-hidden'));
            document.getElementById(sectionId).classList.remove('section-hidden');
            document.querySelectorAll('.stat-card').forEach(c => c.classList.remove('tab-active'));
            if (el) {
                el.classList.add('tab-active');
                // A plain mouse click on a different card than whatever's
                // currently keyboard-selected (a Left/Right preview, or a
                // prior Down/Up landing) leaves that ring stuck on a now-
                // unrelated card, since nothing else clears it on this
                // path - navigateStatTabs()'s own cards[nextIndex].click()
                // always targets the SAME card it just rang, so this is a
                // no-op there. activeColumnStatCards() trusts
                // verticalNavSelection as the current column's reference
                // card (see its own comment), so leaving a stray ring
                // uncleared would point Down/Up at the wrong column after
                // a real tab change like this one.
                document.querySelectorAll('.stat-card.keyboard-selected').forEach(card => {
                    if (card !== el) {
                        card.classList.remove('keyboard-selected');
                        if (verticalNavSelection === card) verticalNavSelection = null;
                    }
                });
            }

            const eventType = sectionId.replace('section-', '');
            loadTabData(eventType, el);
        }
        
        let tabDataCache = {};

        // Populated by buildAcknowledgedAlertsSection() and read back by
        // renderAcknowledgedAlertsGroups() - separate from tabDataCache
        // since the Acknowledged Alerts tab's own fetches use
        // acknowledged_only=true, a fundamentally different query from
        // every other tab's (which all exclude acknowledged rows by
        // default).
        let acknowledgedAlertsCache = { alert: [], sigmaalert: [] };

        async function loadTabData(eventType, activeCard) {
            resetPagination();
            const sectionId = `section-${eventType}`;
            const sectionEl = document.getElementById(sectionId);

            if (activeCard) {
                activeCard.classList.add('tab-active');
            } else {
                // Every real stat card carries data-section="section-x"
                // (see buildStats' own template, dispatched via the
                // 'show-tab' STATIC_ACTIONS entry) - matched via dataset
                // rather than parsing a handler attribute string.
                document.querySelectorAll('.stat-card').forEach(card => {
                    if (card.dataset.section === 'section-' + eventType) {
                        card.classList.add('tab-active');
                    }
                });
            }

            // #sankeyPanel/#aggregations are single, page-level panels
            // shared across every tab (not per-section - see
            // socrates.html). #sankeyPanel is toggled visible once for the
            // whole PCAP-mode session (see the analysis-load code that
            // sets sankeyPanel.style.display = '') rather than per tab
            // switch, and #aggregations is only ever touched by the
            // generic branches below when advancedMode is true (see
            // buildAggregationsSection's call sites) - with advancedMode
            // false, nothing downstream ever rewrites it at all. Both are
            // defaulted back to normal here, before any of the branches
            // below, so none of them need to remember to do it - only the
            // dns_heuristics branch turns them off, for the one tab whose
            // data (aggregated per-domain heuristic scores, not raw flow
            // events) doesn't fit either model. Without resetting
            // #aggregations here too, leaving dns_heuristics with
            // advancedMode off left even the collapsed "▸ Aggregation
            // Tables" bar permanently missing, not just its expanded
            // content. Every other branch either doesn't touch these
            // (acknowledged - a pre-existing gap, not addressed here) or
            // overwrites their content itself (updateSankeyDiagram(),
            // buildAggregationsSection()).
            const sankeyPanel = document.getElementById('sankeyPanel');
            if (sankeyPanel && !isLogAnalysisMode) sankeyPanel.style.display = '';
            const aggContainer = document.getElementById('aggregations');
            if (aggContainer) aggContainer.innerHTML = AGG_COLLAPSED_HTML;

            if (eventType === 'acknowledged') {
                await buildAcknowledgedAlertsSection();
                updateFilterBarVisibility();
                return;
            }

            if (eventType === 'dns_heuristics') {
                if (sankeyPanel) sankeyPanel.style.display = 'none';
                if (aggContainer) aggContainer.innerHTML = '';
                if (sectionEl) await buildDnsHeuristicsSection();
                updateFilterBarVisibility();
                return;
            }

            if (eventType === 'all') {
                if (canUseScalableFetch()) {
                    if (needsFullBatch('all')) await ensureCappedBatch('all');
                    if (sectionEl) await buildAllEvents();
                    if (sectionEl && advancedMode) await buildAggregationsSectionAll();
                    updateFilterBarVisibility();
                    await updateSankeyDiagram();
                    return;
                }
                try {
                    await ensureCappedBatch('all');
                } catch(e) {
                    console.error('Failed to load all events:', e);
                }
                if (sectionEl) buildAllEvents();
                if (sectionEl && advancedMode) await buildAggregationsSectionAll();
                updateFilterBarVisibility();
                await updateSankeyDiagram();
                return;
            }

            if (isLogAnalysisMode && eventType === 'log') {
                // Lazily hydrate tabDataCache['log'] on first visit to this
                // tab - no-op if already cached (same helper every other
                // eventType uses).
                await ensureCappedBatch('log');
                const events = tabDataCache['log'] || [];
                const filtered = getFilteredLogEvents(events);
                if (sectionEl) buildLogSectionContent(sectionId, filtered);
                if (advancedMode) buildLogAggregations(filtered, sectionId);
                updateFilterBarVisibility();
                return;
            }

            if (isLogAnalysisMode && eventType === 'sigmaalert') {
                if (canUseScalableFetch()) {
                    if (advancedMode) await ensureCappedBatch('sigmaalert');
                    if (sectionEl) await buildSigmaAlertSectionContent(sectionId, null);
                    if (advancedMode) buildSigmaAlertAggregations(getFilteredSigmaAlerts(tabDataCache['sigmaalert'] || []), sectionId);
                    updateFilterBarVisibility();
                    return;
                }
                try {
                    await ensureCappedBatch('sigmaalert');
                } catch(e) {
                    console.error('Failed to load sigma alerts:', e);
                }
                const alerts = tabDataCache['sigmaalert'] || [];
                const filtered = getFilteredSigmaAlerts(alerts);
                if (sectionEl) buildSigmaAlertSectionContent(sectionId, filtered);
                if (advancedMode) buildSigmaAlertAggregations(filtered, sectionId);
                updateFilterBarVisibility();
                return;
            }

            if (canUseScalableFetch()) {
                if (needsFullBatch(eventType)) await ensureCappedBatch(eventType);
                if (sectionEl) await buildSection(eventType, tabDataCache[eventType] || []);
                if (advancedMode) await buildAggregationsSection(eventType, getFilteredEvents(sectionId, tabDataCache[eventType] || [], eventType));
                updateFilterBarVisibility();
                await updateSankeyDiagram();
                return;
            }

            if (tabDataCache[eventType]) {
                const filtered = getFilteredEvents(sectionId, tabDataCache[eventType], eventType);
                if (advancedMode && sectionEl) {
                    await buildAggregationsSection(eventType, filtered);
                    buildSection(eventType, tabDataCache[eventType]);
                } else if (sectionEl) {
                    buildSection(eventType, tabDataCache[eventType]);
                }
                updateFilterBarVisibility();
                await updateSankeyDiagram();
                return;
            }
            
            try {
                await ensureCappedBatch(eventType);
                const events = tabDataCache[eventType] || [];

                const filtered = getFilteredEvents(sectionId, events, eventType);
                if (advancedMode) {
                    if (sectionEl) {
                        await buildAggregationsSection(eventType, filtered);
                    }
                }
                if (sectionEl) buildSection(eventType, events);
                updateFilterBarVisibility();
                await updateSankeyDiagram();
            } catch(e) {
                console.error('Failed to load tab data:', e);
                if (sectionEl) {
                    sectionEl.innerHTML = `<div class="section-header">${escapeHtml(typeLabels[eventType] || eventType.toUpperCase())}</div><div class="loading">Error loading data</div>`;
                }
            }
        }
        
        // Row-cell pivot menu entry point, called first by toggleRow/
        // toggleLogRow/toggleSigmaRow so a click on a pivotable cell opens
        // Include/Exclude/Only instead of expanding the row. Returns true
        // if it opened the menu (caller must return without also
        // expanding), false if the click should fall through to the
        // normal expand/collapse behavior - clicked outside any <td>,
        // clicked a <td> from a different row (e.g. a bubbled click from
        // the detail-row below), or this cell has no pivot data (the
        // excluded Time column, or an empty value - see
        // pivotDataAttrsHtml). The note-icon <td> never reaches here at
        // all: its own onclick already calls stopPropagation (see
        // rowNoteIconHtml). Passes tr through to showPivotMenu so its
        // "Expand Row" entry (see there) has a way back to the
        // expand/collapse behavior this click just bypassed.
        function handleRowCellClick(tr, event) {
            if (!event) return false;
            const td = event.target.closest('td');
            if (!td || td.parentElement !== tr) return false;
            let pairs;
            try {
                pairs = JSON.parse(decodeURIComponent(tr.dataset.pivot || '[]'));
            } catch (e) {
                return false;
            }
            const cellIndex = Array.from(tr.children).indexOf(td);
            const pair = pairs[cellIndex];
            if (!pair) return false;
            // The menu created below survives this same click because the
            // document-level outside-click listener that closes pivot
            // menus is registered EARLIER than the data-action dispatcher
            // this runs from - it has already fired (closing any previous
            // menu) by the time showPivotMenu() runs, and never sees the
            // brand-new menu as "outside".
            event.stopPropagation();
            showPivotMenu(event, 'section-' + tr.dataset.eventType, pair[0], pair[1], false, tr, tr.dataset.communityId);
            return true;
        }

        // Tracks the single currently-open pivot menu (at most one at a
        // time, same as every other dropdown/modal in this app) so the
        // outside-click listener below and the main keydown handler's
        // Escape case (further down in the file) know what to close.
        let activePivotMenuEl = null;
        // Arrow-key selection within the open pivot menu (see
        // navigatePivotMenuItems() below) - separate from
        // verticalNavSelection since the menu is a transient overlay on
        // top of whatever row opened it, not part of the page's own
        // vertical list.
        let pivotMenuNavSelection = null;

        function closePivotMenu() {
            if (activePivotMenuEl) {
                activePivotMenuEl.remove();
                activePivotMenuEl = null;
            }
            pivotMenuNavSelection = null;
        }

        // Same always-registered-once, contains()-check pattern as the
        // gear menu's own outside-click listener above - the pivot menu is
        // append/remove'd from document.body per open rather than
        // toggling a persistent element's 'active' class, since unlike the
        // gear menu it has no fixed home in the DOM (it can open from any
        // row, in any table).
        document.addEventListener('click', function(e) {
            if (activePivotMenuEl && !activePivotMenuEl.contains(e.target)) {
                closePivotMenu();
            }
        });
        // Escape used to have its own dedicated listener here too, closing
        // the pivot menu the same way the outside-click listener above
        // does. Removed - it ran before the main keydown handler further
        // down the file (listeners fire in registration order), which
        // raced that handler's own hadSomethingOpen check: activePivotMenuEl
        // was already null by the time the main handler looked at it, so
        // Escape closed the pivot menu AND immediately fell through to
        // showWelcome() in the same keystroke. Folded into the main
        // handler's own Escape case instead, which closes it before
        // hadSomethingOpen would otherwise be computed too late to matter.

        // The columns list a detail-panel field's label is checked against
        // (see handleDetailValueClick) to decide whether it gets the full
        // Include/Exclude/Only/Hunt menu or the trimmed Hunt-only one -
        // mirrors pivotDataAttrsHtml's own per-eventType column source, but
        // as a standalone lookup (a detail value has no ready-made columns
        // array the way a table row's own render call does).
        function detailColumnsForEventType(eventType) {
            if (!eventType) return [];
            if (eventType === 'all') return ALL_EVENTS_COLUMNS;
            if (eventType === 'binary') return BINARY_YARA_COLUMNS;
            return getColumnsForType(eventType);
        }

        // Real user report: most detail-panel fields don't get the full
        // Include/Exclude/Only menu even though a table-cell click on the
        // very same underlying data does - because the detail panel's own
        // labels (htmlRowText's first argument, all over the render*Details
        // functions below) are more descriptive prose than the terse
        // column-header strings getColumnsForType() returns and
        // extract*Value()'s own column-keyed switches expect (e.g. DNS's
        // detail label 'Query Name' vs the column 'Query'; HTTP's 'User
        // Agent' vs 'User-Agent'). This maps each such label to its real
        // column, per event type, so those fields get the full menu too -
        // filtering on the mapped column name, not the prose label, since
        // that's what extract*Value()'s switch statements actually key on.
        // Deliberately NOT exhaustive: only includes a mapping once
        // verified against the matching extract*Value() case that both
        // read the exact same underlying field (see the mapping's own
        // construction notes) - a wrong guess here would produce a
        // full-looking menu whose Include/Exclude/Only silently filter on
        // the wrong data, which is worse than the current trimmed menu.
        // 'Timestamp' (used by every renderer via _formatEventCommon) is
        // deliberately excluded even though every event type's own 'Time'
        // column exists in getColumnsForType()'s array - extractValue()
        // has no matching 'Time' case (falls through to its log-analysis-
        // only default branch), so a table-cell click on the Time column
        // already offers a silently-nonfunctional Include/Exclude/Only;
        // mapping 'Timestamp' here would just reproduce that same existing
        // gap in a second place rather than close it.
        const DETAIL_LABEL_TO_COLUMN = {
            alert: { 'Signature': 'Alert' },
            protocol_decode: { 'Signature': 'Alert' },
            dns: { 'Query Name': 'Query', 'Query Type': 'Type' },
            http: { 'User Agent': 'User-Agent' },
            tls: { 'SNI': 'SNI / Host' },
            flow: { 'Pkts to Server': 'Pkts →', 'Pkts to Client': 'Pkts ←', 'Bytes to Server': 'Bytes →', 'Bytes to Client': 'Bytes ←' },
            filealerts: { 'Rule': 'Rule Name' },
            dnp3: { 'Source Address': 'Source Addr', 'Destination Address': 'Dest Addr', 'Application Function': 'Function' },
            pgsql: { 'Command Completed': 'Command', 'Data Rows': 'Rows', 'SSL Accepted': 'SSL' },
            sigmaalert: { 'Rule Title': 'Rule' },
        };

        // Delegated (not a per-value listener) since htmlRowText returns a
        // plain HTML string, not a DOM node addEventListener could attach
        // to directly - same reasoning as showPivotMenu's own closures
        // over inline handler-string embedding. Detail-panel fields have no
        // ready-made column context of their own (unlike a table row,
        // which already carries data-event-type - see pivotDataAttrsHtml),
        // so this resolves it from the detail-row's own preceding
        // collapsed row instead: every detail-row is rendered as the very
        // next sibling of the row it expands from (see e.g.
        // buildRowForEvent's own row + detail-row pairing).
        document.addEventListener('click', function(event) {
            const pivotEl = event.target.closest('[data-detail-pivot]');
            if (!pivotEl) return;
            let pair;
            try {
                pair = JSON.parse(decodeURIComponent(pivotEl.dataset.detailPivot));
            } catch (e) {
                return;
            }
            const [label, value, isDynamicField] = pair;
            const detailRow = pivotEl.closest('tr.detail-row');
            const collapsedRow = detailRow ? detailRow.previousElementSibling : null;
            const eventType = collapsedRow ? collapsedRow.dataset.eventType : null;
            const columns = detailColumnsForEventType(eventType);
            // A label already matching a real column (e.g. 'Source IP')
            // is used as-is. Log/Sigma Alert rows are a different case
            // entirely, not covered by DETAIL_LABEL_TO_COLUMN below: their
            // detail panel (formatLogEventDetail) labels values with the
            // RAW json_data field name (e.g. 'SourceIp', 'CommandLine'),
            // while getColumnsForType('log')'s own columns (via
            // discoverLogColumns) are the human LABEL for that same field
            // (e.g. 'Source IP') - _getLabelForField is the exact
            // conversion extractLogValue()/extractSigmaValue() themselves
            // already do in reverse, so this must mirror it to land on a
            // column those functions actually recognize. A harmless no-op
            // for every other event type's already-real labels, since
            // LOG_FIELD_LABELS has no matching key for any of them (real
            // user report: log analysis's own detail panel showed only
            // Hunt for the same reason the PCAP one originally did).
            const fieldLabel = _getLabelForField(label);
            // isDynamicField (see htmlRowText's own comment): a field like
            // 'Computer' rarely makes discoverLogColumns' own top-6 cut
            // (getColumnsForType('log')/('sigmaalert') never lists it), so
            // the columns.includes() checks above would always trim it -
            // yet extractLogValue()/extractSigmaValue()'s default case
            // resolves ANY json_data field generically, columns list or
            // not (real user report: many Matched Event fields on a sigma
            // alert, e.g. Computer, offered only Hunt for exactly this
            // reason). Takes priority over the alias map below since it's
            // a stronger signal - this field is verifiably a real,
            // generically-filterable json_data key, not a guess.
            const mappedColumn = columns.includes(label) ? label
                : columns.includes(fieldLabel) ? fieldLabel
                : isDynamicField ? fieldLabel
                : (eventType && DETAIL_LABEL_TO_COLUMN[eventType]?.[label]);
            const trimmed = !eventType || !mappedColumn;
            event.stopPropagation();
            showPivotMenu(event, eventType ? 'section-' + eventType : null, mappedColumn || label, value, trimmed, null, collapsedRow ? collapsedRow.dataset.communityId : null);
        });

        // Aggregation-table rows (see _renderAggTablesHtml) always carry a
        // real column - they're literally grouped by it - so this always
        // opens the full menu, unlike the detail-panel listener above.
        // Delegated for the same reason: _renderAggTablesHtml returns a
        // plain HTML string, and val is arbitrary field content.
        document.addEventListener('click', function(event) {
            const row = event.target.closest('tr.agg-row[data-agg-pivot]');
            if (!row) return;
            let triple;
            try {
                triple = JSON.parse(decodeURIComponent(row.dataset.aggPivot));
            } catch (e) {
                return;
            }
            const [sectionId, col, value] = triple;
            event.stopPropagation();
            showPivotMenu(event, sectionId, col, value, false);
        });

        // Include/Exclude/Only for one row-cell's value (see
        // handleRowCellClick). Built via direct DOM APIs and
        // addEventListener closures over the real col/value, not an
        // inline handler attribute string - col/value can be arbitrary
        // attacker-influenced content (a log field, an HTTP header, ...),
        // and closures sidestep the whole class of handler-string escaping
        // bugs (JSON.stringify-vs-double-quotes, unescaped single quotes)
        // this codebase's generated data-* attributes otherwise guard
        // against via escapeHtml/encodeURIComponent - see
        // TestFilterChipDataAttrs. Only the visible label text goes
        // through escapeHtml, same as any other rendered value.
        // Non-null only for a row that can be acknowledged (a Suricata
        // alert or a sigma_alerts row) - anything else (dns, http, a log
        // row, ...) gets no Acknowledge buttons in showPivotMenu() below.
        // rowId/identity are read straight off the <tr>'s own dataset
        // (baked in at render time by rowPrefixCells/buildSigmaAlertRow),
        // not looked up in tabDataCache - the default (no filter/sort)
        // view fetches each page through fetchEventsPage()'s own local
        // `items`, which never populates tabDataCache[eventType] at all
        // (see canUseScalableFetchForSort in buildSection), so a
        // tabDataCache-based lookup would silently find nothing for most
        // real page views. inAcknowledgedTab distinguishes "Acknowledge"
        // from "Un-acknowledge" - not a field on the row itself (every row
        // returned by the Acknowledged Alerts tab's own acknowledged_only
        // fetch is acknowledged by definition, so there'd be nothing to
        // check), just whether this particular pivot menu was opened from
        // within that tab's own section.
        function acknowledgeableRowInfo(expandRowEl) {
            if (!expandRowEl) return null;
            const eventType = expandRowEl.dataset.eventType;
            if (eventType !== 'alert' && eventType !== 'sigmaalert') return null;
            const table = eventType === 'sigmaalert' ? 'sigma_alerts' : 'events';
            const identity = expandRowEl.dataset.alertIdentity || null;
            const inAcknowledgedTab = !!expandRowEl.closest('#section-acknowledged');
            return { eventType, table, rowId: Number(expandRowEl.dataset.id), identity, inAcknowledgedTab };
        }

        // Single-row acknowledge/un-acknowledge and the "all instances"
        // bulk path both end here - refreshAnalysisData() (the same
        // resync clearAllFilters() already uses after a state change) is
        // what actually makes the row(s) disappear from view: it re-fetches
        // from the server, whose own queries now exclude (or, in the
        // Acknowledged Alerts tab, include-only) acknowledged rows - see
        // db.py's _build_where_conditions/_sigma_alert_where. No manual
        // DOM removal needed, and this keeps stat-card counts correct for
        // free instead of hand-updating them separately.
        async function setAlertAcknowledged(table, rowId, acknowledged) {
            await fetch('/api/acknowledge-alert', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ md5: currentMd5, table, rowId, acknowledged }),
            });
            await refreshAnalysisData();
        }

        // "All instances of this alert" - computed client-side from
        // whatever's already loaded (ensureCappedBatch first, so the match
        // set isn't limited to a partial page) rather than a server-side
        // signature_id/rule_id query, matching how every other bulk-ish
        // action in this app (Include/Exclude/Only) already works purely
        // off currently-loaded data.
        async function acknowledgeAllInstances(ackInfo) {
            if (!ackInfo.identity) {
                showToast('Could not determine this alert\'s identity');
                return;
            }
            await ensureCappedBatch(ackInfo.eventType);
            const pool = ackInfo.eventType === 'sigmaalert' ? (tabDataCache['sigmaalert'] || []) : (tabDataCache[ackInfo.eventType] || allEvents || []);
            const matchIds = pool
                .filter(e => String(ackInfo.eventType === 'sigmaalert' ? e.rule_id : (e.alert?.signature_id || e.alert?.signature)) === ackInfo.identity)
                .map(e => e.id);
            if (matchIds.length === 0) return;
            if (truncatedTypes.has(ackInfo.eventType)) {
                showToast('Only matches within the current query limit were acknowledged - some may remain', { sticky: true });
            }
            await fetch('/api/acknowledge-alerts-bulk', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ md5: currentMd5, table: ackInfo.table, rowIds: matchIds }),
            });
            await refreshAnalysisData();
        }

        // trimmed: true omits Include/Exclude/Only - for a value that has
        // no real filterable column behind it (most detail-panel fields,
        // see handleDetailValueClick), Include/Exclude/Only would have
        // nothing valid to filter on. Hunt/Copy/the lookup sites need no
        // column at all (just the raw value), so they're offered either way.
        // expandRowEl: the <tr> the click originated from (see
        // handleRowCellClick), or omitted for the aggregation-table and
        // detail-panel-value call sites - neither has a row of its own to
        // expand (an aggregation row has no detail-row sibling at all, and
        // a detail-panel value's row is already expanded, since that's the
        // only way its panel could be visible to click in). "Expand Row"
        // is only offered when expandRowEl actually has a collapsible
        // detail-row sibling.
        function showPivotMenu(event, sectionId, col, value, trimmed, expandRowEl, communityId) {
            closePivotMenu();
            const menu = document.createElement('div');
            menu.className = 'pivot-menu';
            menu.style.left = event.clientX + 'px';
            menu.style.top = event.clientY + 'px';
            const fullLabel = `${col}: ${value}`;
            const valueLabel = String(value).length > 60 ? String(value).slice(0, 60) + '…' : String(value);
            const expandDetailRow = expandRowEl ? expandRowEl.nextElementSibling : null;
            const canExpandRow = !!(expandDetailRow && expandDetailRow.classList.contains('detail-row'));
            // toggleDetailRow (wired below) always toggles either
            // direction - the label/tooltip just need to describe whatever
            // it's about to do next, based on the row's state right now.
            const rowIsExpanded = canExpandRow && expandDetailRow.classList.contains('visible');
            const expandRowLabel = rowIsExpanded ? 'Collapse Row' : 'Expand Row';
            const expandRowTitle = rowIsExpanded ? 'Hide full details for this row' : 'View full details for this row';
            const expandRowHtml = canExpandRow
                ? `<button type="button" class="pivot-menu-item" data-pivot-action="expand-row" title="${escapeHtml(expandRowTitle)}"><span class="pivot-menu-icon">${EXPAND_ICON_SVG}</span>${expandRowLabel}</button><div class="pivot-menu-divider"></div>`
                : '';
            // Acknowledge/Un-acknowledge - see acknowledgeableRowInfo()'s
            // own comment for why this is null for any non-alert row.
            const ackInfo = acknowledgeableRowInfo(expandRowEl);
            const ackHtml = !ackInfo ? '' : ackInfo.inAcknowledgedTab
                ? `<button type="button" class="pivot-menu-item" data-pivot-action="unacknowledge">Un-acknowledge this alert</button><div class="pivot-menu-divider"></div>`
                : `<button type="button" class="pivot-menu-item" data-pivot-action="acknowledge">Acknowledge this alert</button><button type="button" class="pivot-menu-item" data-pivot-action="acknowledge-all">Acknowledge all instances of this alert</button><div class="pivot-menu-divider"></div>`;
            // Only the magnifying glass icon is color-coded (via its own
            // wrapping span, not the button itself) - the button's own text
            // stays the normal menu-item color. Icon colors reuse the same
            // tag-red/green/blue trio already used for YARA tag badges
            // elsewhere, rather than adding new theme variables, and are
            // defined in every theme already so Include/Exclude/Only stay
            // distinguishable regardless of which theme is active. Hunt
            // gets no special tint - it's a different kind of action
            // (whole-analysis free-text search, not a field-scoped filter)
            // and Include/Exclude/Only's colors are deliberately not
            // implied to apply to it.
            // Lookup-site buttons are built from PIVOT_LOOKUP_SITES
            // (built-in) concatenated with getCustomLookupSites()
            // (user-added, see the Settings modal's own section) rather
            // than hand-written one per site, so adding another site is a
            // one-line data change, not another copy-pasted button +
            // listener pair. The combined array is also what the click
            // handler below indexes into, so a site's position here and
            // its data-pivot-lookup-index always agree.
            const allLookupSites = PIVOT_LOOKUP_SITES.concat(getCustomLookupSites());
            const lookupSitesHtml = allLookupSites.map((site, i) =>
                `<button type="button" class="pivot-menu-item" data-pivot-lookup-index="${i}"><span class="pivot-menu-icon">${SEARCH_ICON_SVG}</span>${escapeHtml(site.label)}</button>`
            ).join('');
            // Deliberately says "search" for all four, not "filter" for
            // Include/Exclude/Only and "search" only for Hunt - the two
            // mechanisms (currentFilters vs currentSearch) are an
            // implementation detail an analyst reading a tooltip has no
            // reason to care about; both narrow down what's shown, which
            // is the only thing worth explaining here.
            const includeTitle = `Include ${col}: ${value} in current search`;
            const excludeTitle = `Exclude ${col}: ${value} from current search results`;
            const onlyTitle = `Start a new search for ${col}: ${value}`;
            const huntTitle = `Start a new search for ${value} across all fields`;
            const filterButtonsHtml = trimmed ? '' : `
                <button type="button" class="pivot-menu-item" data-pivot-action="include" title="${escapeHtml(includeTitle)}"><span class="pivot-menu-icon pivot-menu-icon-include">${SEARCH_ICON_SVG}</span>Include</button>
                <button type="button" class="pivot-menu-item" data-pivot-action="exclude" title="${escapeHtml(excludeTitle)}"><span class="pivot-menu-icon pivot-menu-icon-exclude">${SEARCH_ICON_SVG}</span>Exclude</button>
                <button type="button" class="pivot-menu-item" data-pivot-action="only" title="${escapeHtml(onlyTitle)}"><span class="pivot-menu-icon pivot-menu-icon-only">${SEARCH_ICON_SVG}</span>Only</button>`;
            // Only offered when this row actually carries a community_id
            // (see the data-community-id attribute baked in by
            // rowPrefixCells/buildAllEventRow) - most rows do, but e.g.
            // stats/anomaly events don't. Suppressed when the clicked
            // value already IS the community_id (clicking the Community ID
            // field itself) since Hunt right above already does the exact
            // same whole-analysis search in that case - offering both
            // would just be two identical buttons.
            const correlateTitle = `Show all logs sharing this flow's Community ID (${communityId})`;
            const correlateHtml = (communityId && String(value) !== String(communityId))
                ? `<button type="button" class="pivot-menu-item" data-pivot-action="correlate" title="${escapeHtml(correlateTitle)}"><span class="pivot-menu-icon">${LINK_ICON_SVG}</span>Correlate</button>`
                : '';
            menu.innerHTML = `
                <div class="pivot-menu-label" title="${escapeHtml(fullLabel)}">${escapeHtml(col)}: ${escapeHtml(valueLabel)}</div>
                ${expandRowHtml}
                ${ackHtml}
                ${filterButtonsHtml}
                <button type="button" class="pivot-menu-item" data-pivot-action="hunt" title="${escapeHtml(huntTitle)}"><span class="pivot-menu-icon">${SEARCH_ICON_SVG}</span>Hunt</button>
                ${correlateHtml}
                <div class="pivot-menu-divider"></div>
                <button type="button" class="pivot-menu-item" data-pivot-action="copy"><span class="pivot-menu-icon">${COPY_ICON_SVG}</span>Copy to Clipboard</button>
                ${lookupSitesHtml}
                <button type="button" class="pivot-menu-item" data-pivot-action="add-custom-lookup"><span class="pivot-menu-icon">${PLUS_ICON_SVG}</span>Add Custom Lookup...</button>
            `;
            if (canExpandRow) {
                menu.querySelector('[data-pivot-action="expand-row"]').addEventListener('click', function() {
                    closePivotMenu();
                    toggleDetailRow(expandRowEl);
                });
            }
            if (ackInfo && ackInfo.inAcknowledgedTab) {
                menu.querySelector('[data-pivot-action="unacknowledge"]').addEventListener('click', function() {
                    closePivotMenu();
                    setAlertAcknowledged(ackInfo.table, ackInfo.rowId, false);
                });
            } else if (ackInfo) {
                menu.querySelector('[data-pivot-action="acknowledge"]').addEventListener('click', function() {
                    closePivotMenu();
                    setAlertAcknowledged(ackInfo.table, ackInfo.rowId, true);
                });
                menu.querySelector('[data-pivot-action="acknowledge-all"]').addEventListener('click', function() {
                    closePivotMenu();
                    acknowledgeAllInstances(ackInfo);
                });
            }
            if (!trimmed) {
                menu.querySelector('[data-pivot-action="include"]').addEventListener('click', function() {
                    closePivotMenu();
                    includeFilterValue(sectionId, col, value);
                });
                menu.querySelector('[data-pivot-action="exclude"]').addEventListener('click', function() {
                    closePivotMenu();
                    excludeFilterValue(sectionId, col, value);
                });
                menu.querySelector('[data-pivot-action="only"]').addEventListener('click', function() {
                    closePivotMenu();
                    onlyFilterValue(sectionId, col, value);
                });
            }
            menu.querySelector('[data-pivot-action="hunt"]').addEventListener('click', function() {
                closePivotMenu();
                huntFilterValue(value);
            });
            if (correlateHtml) {
                menu.querySelector('[data-pivot-action="correlate"]').addEventListener('click', function() {
                    closePivotMenu();
                    huntFilterValue(communityId);
                });
            }
            menu.querySelector('[data-pivot-action="copy"]').addEventListener('click', function() {
                closePivotMenu();
                copyValueToClipboard(value);
            });
            menu.querySelectorAll('[data-pivot-lookup-index]').forEach(function(btn) {
                const site = allLookupSites[Number(btn.dataset.pivotLookupIndex)];
                btn.addEventListener('click', function() {
                    closePivotMenu();
                    // PIVOT_LOOKUP_SITES' own entries carry a function
                    // (CyberChef's own base64 encoding, for one, can't be
                    // expressed as a plain string template); custom sites
                    // from getCustomLookupSites() are plain {value}-template
                    // strings instead (see applyCustomLookupUrlTemplate's
                    // own comment for why).
                    const url = typeof site.urlTemplate === 'function'
                        ? site.urlTemplate(value)
                        : applyCustomLookupUrlTemplate(site.urlTemplate, value);
                    window.open(url, '_blank', 'noopener,noreferrer');
                });
            });
            menu.querySelector('[data-pivot-action="add-custom-lookup"]').addEventListener('click', function() {
                closePivotMenu();
                showSettingsModal(true);
            });
            document.body.appendChild(menu);
            activePivotMenuEl = menu;

            // getBoundingClientRect() needs the menu already in the DOM to
            // measure its real rendered size - re-clamped here rather than
            // guessed up front, so it can't render off the right/bottom
            // edge of the viewport regardless of label length.
            const rect = menu.getBoundingClientRect();
            let left = event.clientX;
            let top = event.clientY;
            if (left + rect.width > window.innerWidth) left = Math.max(0, window.innerWidth - rect.width - 8);
            if (top + rect.height > window.innerHeight) top = Math.max(0, window.innerHeight - rect.height - 8);
            menu.style.left = left + 'px';
            menu.style.top = top + 'px';
        }

        function toggleRow(tr, event) {
            if (handleRowCellClick(tr, event)) return;
            toggleDetailRow(tr);
        }

        // Extracted from toggleRow so the pivot menu's "Expand Row" entry
        // (see showPivotMenu) can trigger the exact same expand/collapse
        // behavior directly, without going back through handleRowCellClick
        // - which would just reopen the pivot menu instead of expanding.
        function toggleDetailRow(tr) {
            const detailRow = tr.nextElementSibling;
            if (detailRow && detailRow.classList.contains('detail-row')) {
                const wasHidden = !detailRow.classList.contains('visible');
                tr.classList.toggle('expanded-row');
                detailRow.classList.toggle('visible');

                if (wasHidden) {
                    const asciiDiv = detailRow.querySelector('.stream-payload');
                    if (asciiDiv) {
                        const srcIp = asciiDiv.dataset.srcIp;
                        const srcPort = asciiDiv.dataset.srcPort;
                        const dstIp = asciiDiv.dataset.dstIp;
                        const dstPort = asciiDiv.dataset.dstPort;
                        const pre = asciiDiv.querySelector('.ascii-transcript');
                        if (pre && !pre.innerHTML) {
                            pre.innerHTML = '<div style="color:var(--text-muted);padding:10px 0;display:flex;align-items:center;gap:8px;"><span class="ascii-loading"></span>Loading ASCII transcript...</div>';
                            loadAsciiTranscript(srcIp, srcPort, dstIp, dstPort, pre);
                        }
                    }
                    loadPlaybookSectionIfPresent(detailRow);
                    loadAiSummaryPlaceholders(detailRow);
                }
            }
        }

        // playbook is {name, description, questions: [{question, context}]}.
        // Reuses htmlSection/htmlRowText/htmlRow so the section fits the
        // same label/value grid every other detail-panel section uses -
        // Name/Description go through htmlRowText so they're pivot-menu
        // clickable like any other detail value, same as everywhere else.
        function renderPlaybookSectionHtml(playbook) {
            let html = htmlSection('Playbook', 'var(--accent)');
            html += htmlRowText('Name', playbook.name);
            html += htmlRowText('Description', playbook.description);
            const questionsHtml = (playbook.questions || []).map((q, i) => {
                const contextHtml = q.context ? `<div class="playbook-question-context">${escapeHtml(q.context)}</div>` : '';
                return htmlRow(`Q${i + 1}`, `<div class="playbook-question-text">${escapeHtml(q.question || '')}</div>${contextHtml}`);
            }).join('');
            // Full-width, not a label/value row - there's no natural short
            // label for it. Doubles as the collapse/expand toggle for the
            // questions below (see togglePlaybookQuestions) - Name/
            // Description always stay visible either way, so an advanced
            // user can collapse just the (sometimes long) questions list to
            // reclaim vertical space between Alert Details/Rule and the
            // Payload section further down, without losing the section
            // entirely. Expanded by default - this is a "shrink it back
            // down" control, not a "click to reveal" gate.
            html += `<div class="playbook-questions-toggle" data-action="toggle-playbook-questions" style="grid-column: 1 / -1; color: var(--text-muted); margin-top: 4px; cursor: pointer; user-select: none;">▾ The following questions might help guide your investigation:</div>`;
            html += `<div class="playbook-questions" style="display: contents;">${questionsHtml}</div>`;
            return html;
        }

        // Purely local DOM state via the toggle element's own next sibling,
        // not a global flag like toggleDiagram()/toggleAggregations() use -
        // multiple rows can each have their own expanded Playbook section
        // open at once, unlike the single-instance Sankey/Aggregations
        // panels those two toggle. display:'contents' (not '') so the
        // questions keep participating in the section's own grid layout
        // when shown, matching how they were laid out before the toggle
        // existed.
        function togglePlaybookQuestions(toggleEl) {
            const content = toggleEl.nextElementSibling;
            const collapsed = content.style.display === 'none';
            content.style.display = collapsed ? 'contents' : 'none';
            toggleEl.textContent = (collapsed ? '▾' : '▸') + ' The following questions might help guide your investigation:';
        }

        // Fetches /api/playbook using the placeholder's own
        // data-detection-type/data-rule-id (see renderAlertDetails/
        // formatSigmaAlertDetail) and, if a playbook comes back, inserts a
        // "Playbook" section directly before the placeholder - which
        // itself stays display:none forever, so a null response (e.g. a
        // manual install with nothing baked in) leaves no trace at all.
        // Called from toggleDetailRow/toggleSigmaRow's own wasHidden
        // branch, mirroring loadAsciiTranscript's lazy-on-first-expand
        // shape. data-attempted guards against re-fetching on every
        // collapse/re-expand - once tried (successfully or not), never
        // tried again for this row.
        async function loadPlaybookSectionIfPresent(detailRow) {
            const placeholder = detailRow.querySelector('.playbook-section-placeholder');
            if (!placeholder || placeholder.dataset.attempted) return;
            placeholder.dataset.attempted = 'true';
            const detectionType = placeholder.dataset.detectionType;
            const ruleId = placeholder.dataset.ruleId;
            try {
                const resp = await fetch(`/api/playbook?type=${encodeURIComponent(detectionType)}&id=${encodeURIComponent(ruleId)}`);
                const data = await resp.json();
                if (data.playbook) {
                    placeholder.insertAdjacentHTML('beforebegin', renderPlaybookSectionHtml(data.playbook));
                }
            } catch (e) {
                // Quiet failure - no playbook shown is the correct outcome either way.
            }
        }

        // Fetches /api/ai-summary for every not-yet-attempted
        // .ai-summary-placeholder in detailRow and, for each one that comes
        // back with a summary, inserts an "AI Summary" row directly before
        // it - same lazy-on-first-expand shape as
        // loadPlaybookSectionIfPresent above, except a single detail row can
        // contain more than one placeholder (renderFileInfoDetails' File
        // Alerts list renders one per YARA match), so this queries for all
        // of them and fetches in parallel rather than assuming exactly one.
        async function loadAiSummaryPlaceholders(detailRow) {
            const placeholders = detailRow.querySelectorAll('.ai-summary-placeholder:not([data-attempted])');
            await Promise.all(Array.from(placeholders).map(async (placeholder) => {
                placeholder.dataset.attempted = 'true';
                const detectionType = placeholder.dataset.detectionType;
                const ruleId = placeholder.dataset.ruleId;
                try {
                    const resp = await fetch(`/api/ai-summary?type=${encodeURIComponent(detectionType)}&id=${encodeURIComponent(ruleId)}`);
                    const data = await resp.json();
                    if (data.summary) {
                        placeholder.insertAdjacentHTML('beforebegin', htmlRowText('AI Summary', data.summary));
                    }
                } catch (e) {
                    // Quiet failure - no summary shown is the correct outcome either way.
                }
            }));
        }

        async function loadAsciiTranscript(src, sport, dst, dport, pre) {
            const url = buildStreamUrl('ascii-stream', src, sport, dst, dport);
            try {
                const resp = await fetch(url);
                const text = await resp.text();
                
                // Try to parse as JSON (new format with direction)
                try {
                    const data = JSON.parse(text);
                    if (data.lines && data.lines.length > 0) {
                        let html = '';
                        let groupHtml = '';
                        let lastDirection = '';
                        // Appends the just-finished direction's group (with
                        // its colored left bar) to html and resets groupHtml
                        // for the next one - called both mid-loop (on a
                        // direction change) and once more after the loop for
                        // the final trailing group.
                        const flushGroup = () => {
                            const bar = `<span style="display:inline-block;width:3px;background:${lastDirection === 'src' ? '#ff6b6b' : '#58a6ff'};margin-right:8px;flex-shrink:0;"></span>`;
                            html += `<div style="display:flex;align-items:stretch;">${bar}<div style="flex:1;">${groupHtml}</div></div>`;
                            groupHtml = '';
                        };
                        for (const line of data.lines) {
                            const direction = line.direction;
                            if (direction !== lastDirection && groupHtml) {
                                flushGroup();
                            }
                            groupHtml += line.text.split('\n').map(t => `<div>${escapeHtml(t)}</div>`).join('');
                            lastDirection = direction;
                        }
                        if (groupHtml) {
                            flushGroup();
                        }
                        pre.innerHTML = html;
                        if (data.truncated) {
                            pre.innerHTML += '<div style="margin-top:10px;color:var(--text-muted);font-style:italic;">[Truncated - stream too large. Use Download PCAP to view full capture.]</div>';
                        }
                        return;
                    }
                } catch (jsonErr) {
                    // Not JSON or parse failed, continue to plain text
                }
                
                // Legacy plain text format (backward compatibility)
                pre.textContent = text || 'No payload data';
            } catch(err) {
                pre.textContent = 'Error loading transcript: ' + err.message;
            }
        }
        
        async function switchStreamView(view, src, sport, dst, dport, btn) {
            const wrapper = btn.closest('.stream-payload');
            const asciiEl = wrapper.querySelector('.ascii-transcript');
            const hexdumpEl = wrapper.querySelector('.hexdump-content');
            const tabs = wrapper.querySelectorAll('.view-tab');
            
            tabs.forEach(t => t.classList.remove('active'));
            btn.classList.add('active');
            
            if (view === 'hexdump') {
                asciiEl.style.display = 'none';
                hexdumpEl.style.display = '';
                if (hexdumpEl.dataset.loaded !== 'true') {
                    hexdumpEl.innerHTML = '<div style="color:var(--text-muted);padding:10px 0;"><span class="ascii-loading"></span>Loading hexdump...</div>';
                    await loadHexdumpData(src, sport, dst, dport, hexdumpEl);
                }
            } else {
                hexdumpEl.style.display = 'none';
                asciiEl.style.display = '';
            }
        }
        
        async function loadHexdumpData(src, sport, dst, dport, container) {
            const url = buildStreamUrl('hexdump-stream', src, sport, dst, dport);
            
            try {
                const resp = await fetch(url);
                const data = await resp.json();
                
                if (data.packets && data.packets.length > 0) {
                    let html = '<div class="packet-controls"><button class="packet-control-btn" data-action="expand-all-packets">Expand All</button><button class="packet-control-btn" data-action="collapse-all-packets">Collapse All</button></div>';
                    
                    // Packets always start collapsed - expandAllPackets()/
                    // collapseAllPackets()/togglePacket() (bound above and
                    // on each packet-header) are the only things that ever
                    // change this, by toggling the 'hidden' class directly
                    // on the DOM after render, not by re-rendering from
                    // per-packet state.
                    data.packets.forEach((pkt) => {
                        const dirParts = pkt.header.split(' > ');
                        const isSrc = dirParts.length >= 2 ? dirParts[0].includes(src) : pkt.header.indexOf(src) < pkt.header.indexOf(dst);
                        const dirClass = isSrc ? 'src-dir' : 'dst-dir';
                        html += `
                            <div class="packet-block ${dirClass}">
                                <div class="packet-header" data-action="toggle-packet">
                                    <span>▸</span><span>${escapeHtml(pkt.header)}</span>
                                </div>
                                <div class="packet-content hidden">
                                    <pre>${escapeHtml(pkt.lines.join('\n'))}</pre>
                                </div>
                            </div>
                        `;
                    });
                    
                    if (data.truncated) {
                        html += '<div style="margin-top:10px;color:var(--text-muted);font-style:italic;">[Truncated - stream too large. Use Download PCAP to view full capture.]</div>';
                    }
                    
                    container.innerHTML = html;
                    container.dataset.loaded = 'true';
                } else {
                    container.innerHTML = '<div style="color:var(--text-muted);">No packets found</div>';
                    container.dataset.loaded = 'true';
                }
            } catch(err) {
                container.innerHTML = 'Error loading hexdump: ' + escapeHtml(err.message);
            }
        }
        
        function togglePacket(headerEl) {
            const contentEl = headerEl.nextElementSibling;
            const arrowEl = headerEl.querySelector('span:first-child');
            const isHidden = contentEl.classList.contains('hidden');
            arrowEl.textContent = isHidden ? '▾' : '▸';
            contentEl.classList.toggle('hidden');
        }
        
        function expandAllPackets(container) {
            container.querySelectorAll('.packet-content').forEach(el => el.classList.remove('hidden'));
            container.querySelectorAll('.packet-header > span:first-child').forEach(el => el.textContent = '▾');
        }
        
        function collapseAllPackets(container) {
            container.querySelectorAll('.packet-content').forEach(el => el.classList.add('hidden'));
            container.querySelectorAll('.packet-header > span:first-child').forEach(el => el.textContent = '▸');
        }
        
        function htmlRow(label, innerHtml, className, style) {
            const valueCls = className ? `detail-value ${className}` : 'detail-value';
            const sty = style ? ` style="${style}"` : '';
            return `<span class="detail-label">${escapeHtml(label)}</span><span class="${valueCls}"${sty}>${innerHtml}</span>`;
        }
        
        // Wraps a non-empty value in its own clickable span (see
        // handleDetailValueClick) so the ~120 call sites that go through
        // this one shared helper all get the detail-panel pivot menu for
        // free, without each needing its own change. data-detail-pivot
        // carries [label, value] as percent-encoded JSON rather than an
        // inline handler string - same reasoning as pivotDataAttrsHtml's
        // own data-pivot attribute (a detail value can be arbitrary
        // attacker-influenced content, e.g. a log field or HTTP header).
        // An empty value has nothing meaningful to pivot on, so it's left
        // as plain (unwrapped) text, matching pivotDataAttrsHtml's own
        // choice to exclude empty values from the row-cell menu too.
        // dynamicField: true only for formatLogEventDetail's own two call
        // sites (the log/sigma alert "raw event fields" section) - those
        // labels are literal json_data keys (e.g. 'CommandLine'), not
        // members of any fixed column list the way every other event
        // type's detail fields are, but extractLogValue()/
        // extractSigmaValue()'s own default case already resolves ANY
        // such field generically (see the detail-panel click handler's
        // own comment for why that makes columns.includes() the wrong
        // gate here). Encoding it into the pivot payload itself - rather
        // than re-deriving "was this a dynamic field" from the label text
        // in the click handler - avoids guessing: a label that HAPPENS to
        // collide with something read genuinely doesn't need to worry
        // about it, since only these two call sites ever set it.
        function htmlRowText(label, text, className, style, dynamicField) {
            const value = String(text || '');
            if (!value) return htmlRow(label, '', className, style);
            const pivotPayload = dynamicField ? [label, value, true] : [label, value];
            const encoded = encodeURIComponent(JSON.stringify(pivotPayload));
            return htmlRow(label, `<span class="detail-value-pivot" data-detail-pivot="${encoded}">${escapeHtml(value)}</span>`, className, style);
        }

        function maybeLinkifyValue(value) {
            const s = String(value || '').trim();
            const lower = s.toLowerCase();
            if (lower.startsWith('http://') || lower.startsWith('https://')) {
                return `${escapeHtml(s)} <a href="${escapeHtml(s)}" target="_blank" rel="noopener noreferrer" style="color: var(--accent); text-decoration: none; margin-left: 4px; font-size: 0.8em;">↗</a>`;
            }
            return escapeHtml(s);
        }

        function htmlSection(title, color) {
            return `<span style="color: var(--text-muted); margin-top: 10px; grid-column: 1 / -1; border-bottom: 1px solid var(--border-color); padding-bottom: 5px; color: ${color};">${escapeHtml(title)}</span>`;
        }

        function renderMetadataRows(meta) {
            if (!meta || Object.keys(meta).length === 0) return '';
            let html = '';
            Object.entries(meta).forEach(([k, v]) => {
                html += htmlRow(k.charAt(0).toUpperCase() + k.slice(1), maybeLinkifyValue(v));
            });
            return html;
        }
        
        function _formatEventCommon(e) {
            const ts = (e.timestamp || '').slice(0, 19);
            let html = `<div style="display: grid; grid-template-columns: 120px minmax(0, 1fr); gap: 8px; font-size: 0.85rem; min-width: 0;">`;
            html += htmlRowText('Timestamp', ts);
            html += htmlRow('Event Type', `${valueDotSpan(COLORS.EVENT[e.event_type])}${escapeHtml(e.event_type || '')}`);
            if (e.proto) html += htmlRowText('Protocol', e.proto);
            if (e.flow_id) html += htmlRowText('Flow ID', e.flow_id);
            if (e.community_id) html += htmlRowText('Community ID', e.community_id, 'mono');
            if (e.pcap_cnt) html += htmlRowText('PCAP Count', e.pcap_cnt);
            if (e.src_ip || e.src_port || e.dest_ip || e.dest_port) {
                html += htmlSection('Connection', COLORS.EVENT.connection);
                if (e.src_ip) html += htmlRowText('Source IP', e.src_ip, 'mono');
                if (e.src_port) html += htmlRowText('Source Port', e.src_port, 'mono');
                if (e.dest_ip) html += htmlRowText('Dest IP', e.dest_ip, 'mono');
                if (e.dest_port) html += htmlRowText('Dest Port', e.dest_port, 'mono');
            }
            return html;
        }

        function _formatEventPayload(e) {
            if (!e.src_ip || !e.src_port || !e.dest_ip || !e.dest_port) return '';
            const srcIpHtml = escapeHtml(e.src_ip);
            const dstIpHtml = escapeHtml(e.dest_ip);
            // Ports are embedded raw in data attributes, so coerce to
            // integers to guarantee they are numeric.
            const srcPort = parseInt(e.src_port, 10) || 0;
            const dstPort = parseInt(e.dest_port, 10) || 0;
            // The wrapper's own data-src-ip/data-src-port/data-dst-ip/
            // data-dst-port attributes are the single source of the stream
            // endpoints - the 'switch-stream-view'/'download-stream-pcap'
            // STATIC_ACTIONS entries read them back via closest(), so the
            // buttons themselves only carry the view name.
            return `<div class="stream-payload" data-src-ip="${srcIpHtml}" data-src-port="${srcPort}" data-dst-ip="${dstIpHtml}" data-dst-port="${dstPort}" style="margin-top: 15px;"><div style="color: var(--text-muted); font-size: 0.85rem; border-bottom: 1px solid var(--border-color); padding-bottom: 5px; margin-bottom: 5px;">Payload</div><div style="display: flex; justify-content: flex-start; align-items: center; margin-bottom: 10px;"><div class="view-tabs"><button class="view-tab active" data-action="switch-stream-view" data-view="ascii">ASCII Transcript</button><button class="view-tab" data-action="switch-stream-view" data-view="hexdump">Hexdump</button></div><button class="stream-btn" data-action="download-stream-pcap" style="margin-left: 12px;">Download PCAP</button></div><div class="stream-view-container" style="background: var(--bg-primary); padding: 15px; border-radius: 8px; font-size: 0.8rem; margin: 0;"><div class="ascii-transcript" style="white-space: pre-wrap; overflow-wrap: break-word;"></div><div class="hexdump-content" style="display: none;"></div></div></div>`;
        }

        // Hidden anchor for an AI Summary field - see
        // loadAiSummaryPlaceholders. display:none means it takes no space
        // and shows nothing if the fetch it triggers on first expand comes
        // back with no summary (e.g. a manual install with nothing baked
        // in) - there's never an empty "AI Summary" row shown, only ever a
        // populated one or nothing at all. Unlike the single
        // playbook-section-placeholder per row, a detail row can contain
        // more than one of these (see renderFileInfoDetails' matches loop),
        // so loadAiSummaryPlaceholders queries for all of them, not just one.
        function aiSummaryPlaceholderHtml(detectionType, ruleId) {
            return `<span class="ai-summary-placeholder" data-detection-type="${escapeHtml(detectionType)}" data-rule-id="${escapeHtml(String(ruleId || ''))}" style="display:none;"></span>`;
        }

        // includeAiSummary defaults true (renderAlertDetails' real-alert
        // case) - renderProtocolDecodeDetails explicitly passes false, same
        // reasoning as why it never gets a playbook-section-placeholder
        // either: decoder-noise "alerts" aren't real detections, so neither
        // Playbook guidance nor an AI summary of "what this rule detects"
        // applies to them.
        function renderAlertFields(e, includeAiSummary) {
            let html = htmlRowText('Signature', e.alert?.signature);
            if (includeAiSummary !== false) {
                html += aiSummaryPlaceholderHtml('nids', e.alert?.signature_id);
            }
            html += htmlRowText('Category', e.alert?.category);
            html += htmlRowText('Severity', e.alert?.severity);
            html += htmlRowText('Action', e.alert?.action);
            html += htmlRowText('GID', e.alert?.gid);
            html += htmlRowText('SID', e.alert?.signature_id);
            html += htmlRowText('Ruleset', classifyRuleset(e.alert?.signature_id));
            html += htmlRow('Rule', escapeHtml(e.alert?.rule || ''), 'mono', 'white-space: pre-wrap; overflow-wrap: break-word; min-width: 0;');
            return html;
        }

        function renderAlertDetails(e) {
            let html = htmlSection('Alert Details', COLORS.EVENT.alert);
            html += renderAlertFields(e);
            // Hidden anchor for the Playbook section - see
            // loadPlaybookSectionIfPresent. display:none means it takes no
            // space and shows nothing if the fetch it triggers on first
            // expand comes back with no playbook (e.g. a manual install
            // with nothing baked in) - there's never an empty "Playbook"
            // heading shown, only ever a populated one or nothing at all.
            html += `<span class="playbook-section-placeholder" data-detection-type="nids" data-rule-id="${escapeHtml(String(e.alert?.signature_id || ''))}" style="display:none;"></span>`;
            return html;
        }

        function renderProtocolDecodeDetails(e) {
            // Suricata's own built-in protocol-command-decode alerts are
            // noise, not real detections (see create_sqlite_db's
            // reclassification in db.py) - same fields as Alert Details,
            // but deliberately no Playbook section and no AI summary
            // placeholder, since there's no investigation guidance (or
            // rule explanation) needed for "this isn't a threat."
            let html = htmlSection('Decoder Alert Details', COLORS.EVENT.protocol_decode);
            html += renderAlertFields(e, false);
            return html;
        }

        function renderDnsDetails(e) {
            let html = htmlSection('DNS Details', COLORS.EVENT.dns);
            html += htmlRowText('Type', e.dns?.type);
            // Suricata 8's new V3 DNS logging format moved rrname/rrtype off
            // the top level into queries[0] - see the 'Query'/'Type' cases
            // in extractValue for details. e.dns.answers[].rdata already
            // worked under both formats, unaffected.
            html += htmlRowText('Query Name', e.dns?.rrname || e.dns?.queries?.[0]?.rrname, 'mono');
            html += htmlRowText('Query Type', e.dns?.rrtype || e.dns?.queries?.[0]?.rrtype);
            if (e.dns?.answers) {
                html += htmlRowText('Answers', e.dns.answers.map(a => a.rdata).join(', '), 'mono');
            }
            return html;
        }

        function renderHttpDetails(e) {
            let html = htmlSection('HTTP Details', COLORS.EVENT.http);
            html += htmlRow('Method', `${valueDotSpan(DOT_COLORS.HTTP_METHOD[(e.http?.http_method || '').toUpperCase()])}${escapeHtml(e.http?.http_method || '')}`);
            html += htmlRowText('Host', e.http?.hostname, 'mono');
            html += htmlRowText('URL', e.http?.url, 'mono');
            html += htmlRowText('User Agent', e.http?.http_user_agent, '', 'word-break: break-all;');
            html += htmlRowText('Status', e.http?.status);
            html += htmlRowText('Content Type', e.http?.http_content_type);
            return html;
        }

        function renderTlsDetails(e) {
            let html = htmlSection('TLS Details', COLORS.EVENT.tls);
            html += htmlRowText('SNI', e.tls?.sni, 'mono');
            html += htmlRow('Version', `${valueDotSpan(tlsVersionColor(e.tls?.version))}${escapeHtml(e.tls?.version || '')}`);
            if (e.tls?.ja3?.hash) html += htmlRowText('JA3', e.tls.ja3.hash, 'mono');
            if (e.tls?.ja3s?.hash) html += htmlRowText('JA3S', e.tls.ja3s.hash, 'mono');
            if (e.tls?.ja4) html += htmlRowText('JA4', e.tls.ja4, 'mono');
            html += htmlRowText('Subject', e.tls?.subject, 'mono');
            html += htmlRowText('Issuer', e.tls?.issuerdn, 'mono');
            html += htmlRowText('Not Before', e.tls?.notbefore);
            html += htmlRowText('Not After', e.tls?.notafter);
            html += htmlRowText('Fingerprint', e.tls?.fingerprint, 'mono');
            return html;
        }

        function renderFlowDetails(e) {
            let html = htmlSection('Flow Details', COLORS.EVENT.flow);
            html += htmlRowText('State', e.flow?.state);
            html += htmlRowText('Age', `${e.flow?.age || ''} seconds`);
            html += htmlRowText('Pkts to Server', (e.flow?.pkts_toserver || 0).toLocaleString());
            html += htmlRowText('Pkts to Client', (e.flow?.pkts_toclient || 0).toLocaleString());
            html += htmlRowText('Bytes to Server', (e.flow?.bytes_toserver || 0).toLocaleString());
            html += htmlRowText('Bytes to Client', (e.flow?.bytes_toclient || 0).toLocaleString());
            html += htmlRowText('Alerted', e.flow?.alerted ? 'Yes' : 'No');
            return html;
        }

        function renderFtpDetails(e) {
            let html = htmlSection('FTP Details', COLORS.EVENT.ftp);
            html += htmlRowText('Command', e.ftp?.command);
            html += htmlRowText('Reply', e.ftp?.reply);
            html += htmlRowText('Data Channel', e.ftp?.data_channel?.active ? 'Active' : 'Passive');
            return html;
        }

        function renderAnomalyDetails(e) {
            let html = htmlSection('Anomaly Details', COLORS.EVENT.anomaly);
            // BUGFIX: was e.anomaly?.message, a field that has never existed
            // in Suricata's eve.json anomaly schema (real field is 'event',
            // e.g. "APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION") - same
            // root cause as the Detail-column fix elsewhere, missed here.
            html += htmlRowText('Event', e.anomaly?.event);
            html += htmlRowText('Type', e.anomaly?.type);
            html += htmlRowText('Layer', e.anomaly?.layer);
            html += htmlRowText('App Proto', e.anomaly?.app_proto);
            return html;
        }

        function renderModbusDetails(e) {
            const m = e.modbus || {};
            const req = m.request || {};
            const resp = m.response || {};
            let html = htmlSection('Modbus Details', COLORS.EVENT.modbus);
            html += htmlRowText('Transaction ID', m.id);

            html += htmlSection('Request', COLORS.EVENT.modbus);
            html += htmlRowText('Function', req.function_code);
            html += htmlRowText('Unit ID', req.unit_id);
            html += htmlRowText('Access Type', req.access_type);
            html += htmlRowText('Category', req.category);
            html += htmlRowText('Error Flags', req.error_flags);
            if (req.read) {
                html += htmlRowText('Read Address', req.read.address);
                html += htmlRowText('Read Quantity', req.read.quantity);
            }
            if (req.write) {
                html += htmlRowText('Write Address', req.write.address);
                html += htmlRowText('Write Data', req.write.data);
            }
            if (req.diagnostic) {
                html += htmlRowText('Diagnostic Code', req.diagnostic.code);
                html += htmlRowText('Diagnostic Data', req.diagnostic.data);
            }

            html += htmlSection('Response', COLORS.EVENT.modbus);
            html += htmlRowText('Function', resp.function_code);
            html += htmlRowText('Unit ID', resp.unit_id);
            html += htmlRowText('Access Type', resp.access_type);
            html += htmlRowText('Category', resp.category);
            html += htmlRowText('Error Flags', resp.error_flags);
            if (resp.read) {
                html += htmlRowText('Read Data', resp.read.data);
            }
            if (resp.diagnostic) {
                html += htmlRowText('Diagnostic Code', resp.diagnostic.code);
                html += htmlRowText('Diagnostic Data', resp.diagnostic.data);
            }
            if (resp.exception) {
                html += htmlRowText('Exception Code', resp.exception.code);
            }
            return html;
        }

        function renderDnp3Details(e) {
            const d = e.dnp3 || {};
            let html = htmlSection('DNP3 Details', COLORS.EVENT.dnp3);
            html += htmlRowText('Type', d.type);
            html += htmlRowText('Source Address', d.src);
            html += htmlRowText('Destination Address', d.dst);
            if (d.application) {
                html += htmlRowText('Application Function', d.application.function_code);
                html += htmlRowText('Complete', d.application.complete ? 'Yes' : 'No');
            }
            if (d.control) {
                html += htmlRowText('Control Function', d.control.function_code);
            }
            if (d.iin && d.iin.indicators && d.iin.indicators.length) {
                html += htmlRowText('IIN Indicators', d.iin.indicators.join(', '));
            }
            ['request', 'response'].forEach(dir => {
                const obj = d[dir];
                if (!obj) return;
                html += htmlSection(dir.charAt(0).toUpperCase() + dir.slice(1), COLORS.EVENT.dnp3);
                html += htmlRowText('Type', obj.type);
                html += htmlRowText('Source', obj.src);
                html += htmlRowText('Destination', obj.dst);
                if (obj.application) {
                    html += htmlRowText('Function', obj.application.function_code);
                    html += htmlRowText('Complete', obj.application.complete ? 'Yes' : 'No');
                }
            });
            return html;
        }

        function renderPgsqlDetails(e) {
            const p = e.pgsql || {};
            const req = p.request || {};
            const resp = p.response || {};
            let html = htmlSection('PostgreSQL Details', COLORS.EVENT.pgsql);
            html += htmlRowText('TX ID', p.tx_id);

            if (req.simple_query || req.message || req.protocol_version || req.startup_parameters || req.process_id !== undefined || req.sasl_authentication_mechanism) {
                html += htmlSection('Request', COLORS.EVENT.pgsql);
                html += htmlRowText('Query', req.simple_query);
                html += htmlRowText('Message', req.message);
                html += htmlRowText('Protocol Version', req.protocol_version);
                if (req.startup_parameters && req.startup_parameters.user) {
                    html += htmlRowText('User', req.startup_parameters.user);
                }
                html += htmlRowText('Process ID', req.process_id);
                html += htmlRowText('SASL Mechanism', req.sasl_authentication_mechanism);
            }

            if (resp.command_completed || resp.code || resp.message || resp.data_rows !== undefined || resp.ssl_accepted !== undefined) {
                html += htmlSection('Response', COLORS.EVENT.pgsql);
                html += htmlRowText('Command Completed', resp.command_completed);
                html += htmlRowText('Response Code', resp.code);
                html += htmlRowText('Response Message', resp.message);
                html += htmlRowText('Severity', resp.severity_non_localizable);
                html += htmlRowText('Data Rows', resp.data_rows);
                html += htmlRowText('Data Size', resp.data_size);
                if (resp.ssl_accepted !== undefined) {
                    html += htmlRowText('SSL Accepted', resp.ssl_accepted ? 'Yes' : 'No');
                }
                if (resp.file) {
                    html += htmlRowText('Error File', resp.file);
                    html += htmlRowText('Error Line', resp.line);
                    html += htmlRowText('Routine', resp.routine);
                }
            }
            return html;
        }

        function renderFileAlertDetails(e) {
            const fa = e.filealerts || {};
            let html = htmlRowText('Rule', fa.rule_name);
            html += aiSummaryPlaceholderHtml('yara', fa.rule_name);
            html += htmlRowText('SHA256', fa.sha256, 'mono');
            if (fa.author) {
                html += htmlRowText('Author', fa.author);
            }
            if (fa.tags && fa.tags.length > 0) {
                html += htmlRow('Tags', fa.tags.map(t => yaraTagBadgeHtml(t)).join(''));
            }
            html += renderMetadataRows(fa.meta);
            return html;
        }

        function renderFileInfoDetails(e) {
            let html = htmlSection('File Info', COLORS.EVENT.fileinfo);
            html += htmlRowText('Filename', e.fileinfo?.filename, 'mono');
            html += htmlRowText('Magic', e.fileinfo?.magic);
            html += htmlRowText('MD5', e.fileinfo?.md5, 'mono');
            html += htmlRowText('SHA1', e.fileinfo?.sha1, 'mono');
            html += htmlRowText('SHA256', e.fileinfo?.sha256, 'mono');
            html += htmlRowText('Size', `${(e.fileinfo?.size || 0).toLocaleString()} bytes`);

            const meta = e.fileinfo?.metadata || {};
            if (meta.file_type || meta.mime_type || meta.entropy !== undefined || (meta.strings && meta.strings.length)) {
                html += htmlSection('File Metadata', COLORS.EVENT.fileinfo);
                if (meta.file_type) html += htmlRowText('File Type', meta.file_type);
                if (meta.mime_type) html += htmlRowText('MIME Type', meta.mime_type);
                if (meta.entropy !== undefined) html += htmlRowText('Entropy', String(meta.entropy));
                if (meta.strings && meta.strings.length) {
                    html += htmlRowText('Top Strings', meta.strings.slice(0, 20).join(', '), '', 'word-break: break-all;');
                }
            }

            if (meta.exif && Object.keys(meta.exif).length) {
                html += htmlSection('Exif Metadata', COLORS.EVENT.fileinfo);
                Object.entries(meta.exif).forEach(([k, v]) => {
                    html += htmlRowText(k, v, '', 'word-break: break-all;');
                });
            }

            const fileSha = e.fileinfo?.sha256 || '';
            const matches = allEvents.filter(ev => ev.event_type === 'filealerts' && ev.filealerts?.sha256 === fileSha);
            html += htmlSection('File Alerts', COLORS.EVENT.filealerts);
            if (matches.length > 0) {
                matches.forEach(m => {
                    html += htmlRowText('Rule', m.filealerts?.rule_name);
                    html += aiSummaryPlaceholderHtml('yara', m.filealerts?.rule_name);
                    if (m.filealerts?.tags && m.filealerts.tags.length) {
                        html += htmlRowText('Tags', m.filealerts.tags.join(', '));
                    }
                });
            } else {
                html += `<span style="color: var(--bg-hover-light); grid-column: 1 / -1;">No YARA matches</span>`;
            }
            return html;
        }

        const EVENT_RENDERERS = {
            alert: renderAlertDetails,
            protocol_decode: renderProtocolDecodeDetails,
            dns: renderDnsDetails,
            dnp3: renderDnp3Details,
            http: renderHttpDetails,
            modbus: renderModbusDetails,
            pgsql: renderPgsqlDetails,
            tls: renderTlsDetails,
            flow: renderFlowDetails,
            ftp: renderFtpDetails,
            anomaly: renderAnomalyDetails,
            filealerts: renderFileAlertDetails,
            fileinfo: renderFileInfoDetails,
        };

        function formatEvent(e) {
            let html = _formatEventCommon(e);
            const renderer = EVENT_RENDERERS[e.event_type];
            if (renderer) {
                html += renderer(e);
            }
            html += rowNoteDetailHtml('events', e.id, e.row_note);
            html += `</div>`;
            html += _formatEventPayload(e);
            return html;
        }
        
        function downloadPcap(src, sport, dst, dport) {
            const url = buildStreamUrl('download-stream', src, sport, dst, dport);
            const a = document.createElement('a');
            a.href = url;
            a.download = `stream_${src}_${sport}_to_${dst}_${dport}.pcap`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        }
        
        
        document.addEventListener('click', function(e) {
            if (e.target.tagName === 'TH') {
                const th = e.target;
                // Skip THs inside a modal (e.g. the Help modal's file-types
                // table) - those clicks used to be blocked from reaching
                // this document-level listener by a stopPropagation()
                // handler on every .modal-content div; that shim is gone
                // (backdrop closing now checks event.target instead), so
                // keep modal tables non-sortable explicitly.
                if (th.closest('.modal-content')) return;
                // Skip if cursor is default (non-sortable table)
                if (window.getComputedStyle(th).cursor === 'default') return;
                const thead = th.closest('thead');
                if (!thead) return;
                const index = Array.from(thead.querySelectorAll('th')).indexOf(th);
                sortCurrentTable(index);
            }

            // Delegated handler for previous analyses buttons - Re-analyze/
            // Delete moved to the analysis page header (reanalyzeIconHtml()/
            // deleteIconHtml()), so notes is the only action left here.
            const btn = e.target.closest('#previousAnalysesList button[data-action]');
            if (btn) {
                const md5 = btn.dataset.md5;
                const action = btn.dataset.action;
                if (action === 'notes') {
                    openAnalysisNotesFromList(md5);
                }
            }
        });
        
        function showLoading(message) {
            document.getElementById('loadingText').textContent = message || 'Loading...';
            document.getElementById('loadingModal').classList.add('active');
        }
        
        function hideLoading() {
            document.getElementById('loadingModal').classList.remove('active');
        }

        function clearAnalysisContainers() {
            isLogAnalysisMode = false;
            document.body.classList.remove('file-analysis');
            const statsGrid = document.getElementById('statsGrid');
            if (statsGrid) {
                statsGrid.innerHTML = '';
                statsGrid.style.display = '';
            }
            document.getElementById('sankeyPanel').style.display = 'none';
            document.getElementById('sankeyPanel').innerHTML = '';
            document.getElementById('aggregations').innerHTML = '';
            document.getElementById('sections').innerHTML = '';
            document.getElementById('filterBarContainer').innerHTML = '';
            document.getElementById('filterBarContainer').style.display = 'none';
            document.querySelectorAll('.file-info-card').forEach(c => c.remove());
            const fileInfoContainer = document.getElementById('fileInfoContainer');
            if (fileInfoContainer) {
                fileInfoContainer.innerHTML = '';
                fileInfoContainer.style.display = 'none';
            }
        }

        function showWelcomeUI() {
            document.getElementById('mainHeader').style.display = 'none';
            document.getElementById('dataPanel').style.display = 'none';
            document.getElementById('searchBarContainer').style.display = 'none';
            document.getElementById('inputBoxes').style.display = 'block';
            document.getElementById('appHeaderFilename').innerHTML = '';
            // .app-header-tagline is absolutely positioned (see socrates.css)
            // to center in the header bar regardless of #appHeaderLeft's own
            // width - unlike the footer's teaser, #appHeaderMeta is shared
            // with analysis mode (file metadata next to the filename, set
            // elsewhere), so it can't just become a 3-column layout without
            // also centering that unrelated content away from the filename
            // it describes. This welcome-only tagline is scoped to its own
            // class instead, left untouched at the other #appHeaderMeta call site.
            document.getElementById('appHeaderMeta').innerHTML = '<a href="#" data-action="show-about-modal" class="app-header-tagline">Security Onion Containerized Rapid Analysis of Threats, Evil, and Sus</a>';
            document.getElementById('footerCenterTeaser').innerHTML = '<a href="#" data-action="show-security-onion-modal" class="footer-teaser-link">Need more advanced functionality?</a>';
            document.getElementById('appHeaderRight').innerHTML = renderGearMenu();
            updateThemeMenu();
            checkForStaleRules();
        }

        function shouldShowHelpModal() {
            if (safeStorageGet(localStorage, 'socrates_hideHelp') === 'true') return false;
            if (safeStorageGet(sessionStorage, 'socrates_helpShown') === 'true') return false;
            return true;
        }

        // Help/Settings/Themes are all full-viewport overlays sharing the
        // same .modal z-index, so if one is already open when another is
        // triggered (e.g. the gear menu is still reachable while the
        // Themes modal is showing), the newer one can render behind the
        // older one depending on DOM order rather than on top of it -
        // opening one visibly does nothing while the other is still
        // technically .active underneath. Closing any other open menu
        // modal before showing a new one keeps at most one active at a
        // time, which sidesteps the stacking ambiguity entirely. Guarded
        // per-modal (not an unconditional close-everything) because
        // closeHelpModal() has real side effects (persisting the "show
        // again" checkbox state) that must only fire if Help was actually
        // open.
        function closeOtherMenuModals(exceptId) {
            const closers = { helpModal: closeHelpModal, settingsModal: closeSettingsModal, themesModal: closeThemesModal, rulesModal: closeRulesModal, aboutModal: closeAboutModal, notesModal: closeNotesModal, securityOnionModal: closeSecurityOnionModal };
            Object.keys(closers).forEach(function(id) {
                if (id === exceptId) return;
                const modal = document.getElementById(id);
                if (modal && modal.classList.contains('active')) closers[id]();
            });
        }

        function showHelpModal() {
            closeOtherMenuModals('helpModal');
            const isWelcome = isWelcomeScreen();
            const modalTitle = document.getElementById('helpModalTitle');
            const modalBody = document.getElementById('helpModalBody');
            const checkboxContainer = document.getElementById('helpShowAgainContainer');
            const checkbox = document.getElementById('helpShowAgain');

            const helpModal = document.getElementById('helpModal');
            if (isWelcome) {
                modalTitle.innerHTML = 'Welcome to <a href="#" data-action="show-about-modal" style="color: var(--accent); text-decoration: underline;">SO-CRATES</a>!';
                modalBody.innerHTML = getWelcomeHelpContent();
                checkboxContainer.style.display = 'flex';
                checkbox.checked = safeStorageGet(localStorage, 'socrates_hideHelp') !== 'true';
                helpModal.classList.add('wide');
            } else {
                modalTitle.textContent = 'Analysis Help';
                const isLogFile = detectFileType(currentFileName) === 'log';
                const isFileOnly = document.body.classList.contains('file-analysis');
                let helpText;
                if (isLogFile) {
                    helpText = `<span style="color: var(--help-icon-color);">${LIGHTBULB_ICON_SVG}</span> Investigate Sigma Alerts and then review Log Events. Filter using the search bar or Aggregation Tables.`;
                } else if (isFileOnly) {
                    helpText = `<span style="color: var(--help-icon-color);">${LIGHTBULB_ICON_SVG}</span> Review the FILE INFO section for metadata and then the data table at the bottom for any matches found by the YARA rules.`;
                } else {
                    helpText = `<span style="color: var(--help-icon-color);">${LIGHTBULB_ICON_SVG}</span> Start by reviewing all alerts and then you can change to one of the other data types like DNS, HTTP, or TLS. Filter using the search bar, Sankey Diagram, or Aggregation Tables. When you find something interesting, you can drill into the row in the data table at the bottom. This will allow you to see the ASCII transcript and hexdump and optionally download the PCAP file for that stream.`;
                }
                modalBody.innerHTML = '<div style="color: var(--text-muted); font-size: 0.95rem; line-height: 1.6;">' + helpText + '</div>';
                checkboxContainer.style.display = 'none';
                helpModal.classList.remove('wide');
            }

            helpModal.classList.add('active');
        }

        function closeHelpModal() {
            document.getElementById('helpModal').classList.remove('active');
            const isWelcome = isWelcomeScreen();
            if (isWelcome) {
                safeStorageSet(sessionStorage, 'socrates_helpShown', 'true');
                if (!document.getElementById('helpShowAgain').checked) {
                    safeStorageSet(localStorage, 'socrates_hideHelp', 'true');
                } else {
                    safeStorageRemove(localStorage, 'socrates_hideHelp');
                }
            }
        }

        function handleHelpBackdropClick(event) {
            if (event.target === document.getElementById('helpModal')) {
                closeHelpModal();
            }
        }

        // Backing count for the Danger Zone's Delete All button
        // (openDeleteAllAnalyses(settingsAnalysisCount) in the HTML reads
        // this by name at click time, not by the value baked in at
        // render time, since the real count only arrives after an async
        // fetch - see showSettingsModal()'s own fetch below).
        let settingsAnalysisCount = 0;

        // focusCustomLookup: true opens the modal with focus already in the
        // Custom Lookup Sites add-form - reached from the pivot menu's own
        // "Add Custom Lookup..." entry, so the analyst lands ready to type
        // rather than having to find and click into the field themselves.
        // Mirrors showRulesModal(expandSuricataSources)'s own pattern for
        // the same reason.
        function showSettingsModal(focusCustomLookup) {
            closeOtherMenuModals('settingsModal');
            const input = document.getElementById('maxQueryLimitInput');
            const hint = document.getElementById('settingsHint');
            const errorEl = document.getElementById('settingsError');
            input.value = getUserQueryLimit();
            errorEl.style.display = 'none';
            hint.textContent = `Default: ${CONFIG.DEFAULT_QUERY_LIMIT.toLocaleString()}.`;

            const uploadInput = document.getElementById('maxUploadSizeInput');
            const uploadHint = document.getElementById('uploadSizeHint');
            const uploadErrorEl = document.getElementById('uploadSizeError');
            uploadInput.value = getUserMaxUploadSizeMB();
            uploadErrorEl.style.display = 'none';
            uploadHint.textContent = `Default: ${CONFIG.DEFAULT_UPLOAD_SIZE_MB.toLocaleString()} MB.`;

            // Never block the modal on this - fall back to showing just the
            // defaults if the server can't be reached (mirrors safeStorageGet's
            // "never throw, always degrade" approach).
            fetch('/api/limits').then(r => r.json()).then(data => {
                input.max = data.maxQueryLimit;
                hint.textContent = `Default: ${CONFIG.DEFAULT_QUERY_LIMIT.toLocaleString()}. Server maximum: ${data.maxQueryLimit.toLocaleString()}.`;
                const maxUploadMB = Math.round(data.maxUploadSize / (1024 * 1024));
                uploadInput.max = maxUploadMB;
                uploadHint.textContent = `Default: ${CONFIG.DEFAULT_UPLOAD_SIZE_MB.toLocaleString()} MB. Server maximum: ${maxUploadMB.toLocaleString()} MB.`;
            }).catch(() => {});
            renderCustomLookupSitesSection();
            renderSettingsDeleteAllSection();
            document.getElementById('settingsModal').classList.add('active');
            if (focusCustomLookup) {
                document.getElementById('customLookupNameInput').focus();
            }
        }

        // Delete All moved here from the welcome screen's Previous Analyses
        // list (a rare, irreversible bulk action fits a Settings "danger
        // zone" better than sitting next to the list it wipes out) - unlike
        // that list, Settings can be opened from anywhere, so the count
        // shown next to the button is fetched fresh on every open rather
        // than being handed in from an already-rendered list.
        function renderSettingsDeleteAllSection() {
            const hint = document.getElementById('settingsDeleteAllHint');
            const btn = document.getElementById('settingsDeleteAllBtn');
            hint.textContent = 'Loading...';
            btn.disabled = true;
            fetch('/api/analyses').then(r => r.json()).then(analyses => {
                settingsAnalysisCount = analyses.length;
                hint.textContent = settingsAnalysisCount > 0
                    ? `Permanently delete all ${settingsAnalysisCount.toLocaleString()} previous ${settingsAnalysisCount === 1 ? 'analysis' : 'analyses'}. This cannot be undone.`
                    : 'No previous analyses to delete.';
                btn.disabled = settingsAnalysisCount === 0;
            }).catch(() => {
                settingsAnalysisCount = 0;
                hint.textContent = 'Could not load previous analyses.';
                btn.disabled = true;
            });
        }

        // Re-rendered from scratch (not patched in place) on every open and
        // after every add/edit/delete - the list is short (capped at
        // MAX_CUSTOM_LOOKUP_SITES) so this is cheap, and it keeps the
        // add/edit form's own reset (resetCustomLookupForm) as the single
        // place that clears editingCustomLookupIndex, rather than needing
        // to reason about partial DOM updates.
        function renderCustomLookupSitesSection() {
            const sites = getCustomLookupSites();
            const listEl = document.getElementById('customLookupSitesList');
            listEl.innerHTML = sites.length === 0
                ? '<div style="color: var(--text-muted); font-size: 0.85rem; padding: 6px 0;">No custom lookup sites yet.</div>'
                : sites.map((site, i) => `
                    <div style="display: flex; justify-content: space-between; align-items: center; gap: 10px; padding: 6px 0; border-bottom: 1px solid var(--bg-hover); min-width: 0;">
                        <div style="min-width: 0; overflow: hidden;">
                            <div style="color: var(--text-primary); font-size: 0.9rem; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(site.label)}</div>
                            <div style="color: var(--text-muted); font-size: 0.8rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(site.urlTemplate)}">${escapeHtml(site.urlTemplate)}</div>
                        </div>
                        <div style="display: flex; gap: 10px; align-items: center; flex-shrink: 0;">
                            <button data-action="edit-custom-lookup-site" data-index="${i}" style="background: none; color: var(--accent); border: none; padding: 0; cursor: pointer; font-size: 0.8rem; text-decoration: underline;">Edit</button>
                            <button data-action="delete-custom-lookup-site" data-index="${i}" style="background: none; color: var(--badge-danger-text); border: none; padding: 0; cursor: pointer; display: flex;" title="Delete">${DELETE_ICON_SVG}</button>
                        </div>
                    </div>
                `).join('');
            resetCustomLookupForm();
        }

        function resetCustomLookupForm() {
            editingCustomLookupIndex = null;
            document.getElementById('customLookupNameInput').value = '';
            document.getElementById('customLookupUrlInput').value = '';
            document.getElementById('customLookupError').style.display = 'none';
            document.getElementById('customLookupSaveBtn').textContent = 'Add';
            document.getElementById('customLookupCancelBtn').style.display = 'none';
        }

        function startEditCustomLookupSite(index) {
            const site = getCustomLookupSites()[index];
            if (!site) return;
            editingCustomLookupIndex = index;
            document.getElementById('customLookupNameInput').value = site.label;
            document.getElementById('customLookupUrlInput').value = site.urlTemplate;
            document.getElementById('customLookupError').style.display = 'none';
            document.getElementById('customLookupSaveBtn').textContent = 'Save';
            document.getElementById('customLookupCancelBtn').style.display = 'inline-block';
        }

        function cancelEditCustomLookupSite() {
            resetCustomLookupForm();
        }

        function handleSaveCustomLookupSite() {
            const name = document.getElementById('customLookupNameInput').value;
            const url = document.getElementById('customLookupUrlInput').value;
            const result = saveCustomLookupSite(editingCustomLookupIndex, name, url);
            if (!result.valid) {
                const errorEl = document.getElementById('customLookupError');
                errorEl.textContent = result.error;
                errorEl.style.display = 'block';
                return;
            }
            renderCustomLookupSitesSection();
        }

        function handleDeleteCustomLookupSite(index) {
            deleteCustomLookupSite(index);
            renderCustomLookupSitesSection();
        }

        function closeSettingsModal() {
            document.getElementById('settingsModal').classList.remove('active');
        }

        function showAboutModal() {
            closeOtherMenuModals('aboutModal');
            document.getElementById('checkForUpdates').checked = safeStorageGet(localStorage, 'socrates_checkForUpdates') === 'true';
            fetch('/api/version').then(r => r.json()).then(data => {
                if (data.version) {
                    document.getElementById('aboutVersion').textContent = data.version;
                }
            }).catch(() => {});
            document.getElementById('aboutModal').classList.add('active');
        }

        function closeAboutModal() {
            document.getElementById('aboutModal').classList.remove('active');
        }

        // The full feature comparison (SECURITY_ONION_COMPARISON_HTML) is
        // set here rather than baked into the modal's static HTML skeleton
        // - it's plain content with no per-open state, but still needs a
        // JS-side constant since it embeds CHECKMARK_ICON_SVG.
        function showSecurityOnionModal() {
            closeOtherMenuModals('securityOnionModal');
            document.getElementById('securityOnionModalBody').innerHTML = SECURITY_ONION_COMPARISON_HTML;
            document.getElementById('securityOnionModal').classList.add('active');
        }

        function closeSecurityOnionModal() {
            document.getElementById('securityOnionModal').classList.remove('active');
        }

        // Validates and (if valid) persists a single numeric Settings field.
        // Returns 'saved' (persisted, nothing more to do), 'pending' (value
        // was above the server ceiling -- auto-corrected in the input and
        // needs a second Save click to confirm, nothing persisted yet), or
        // 'invalid' (below floor, nothing persisted, error shown).
        function _validateAndMaybeSaveNumberSetting(inputId, errorId, storageKey, floor, floorMessage, fallbackCeiling) {
            const input = document.getElementById(inputId);
            const errorEl = document.getElementById(errorId);
            const value = parseInt(input.value, 10);
            const serverMax = input.max ? parseInt(input.max, 10) : fallbackCeiling;

            if (isNaN(value) || value < floor) {
                errorEl.textContent = floorMessage;
                errorEl.style.display = 'block';
                return 'invalid';
            }
            if (value > serverMax) {
                input.value = serverMax;
                errorEl.textContent = `Clamped to the server maximum of ${serverMax.toLocaleString()}. Click Save again to confirm.`;
                errorEl.style.display = 'block';
                return 'pending';
            }
            errorEl.style.display = 'none';
            safeStorageSet(localStorage, storageKey, String(value));
            return 'saved';
        }

        async function saveSettings() {
            const queryLimitResult = _validateAndMaybeSaveNumberSetting(
                'maxQueryLimitInput', 'settingsError', 'socrates_maxQueryLimit',
                1000, 'Please enter a number of at least 1,000.', 500000
            );
            const uploadSizeResult = _validateAndMaybeSaveNumberSetting(
                'maxUploadSizeInput', 'uploadSizeError', 'socrates_maxUploadSizeMB',
                100, 'Please enter a number of at least 100.', 20000
            );

            // refreshAnalysisData() only matters for the query-limit field --
            // upload size has no bearing on already-loaded analysis data.
            if (queryLimitResult === 'saved') {
                if (currentMd5) {
                    const saveBtn = document.getElementById('settingsSaveBtn');
                    saveBtn.disabled = true;
                    try {
                        await refreshAnalysisData();
                    } finally {
                        saveBtn.disabled = false;
                    }
                }
            }

            if (queryLimitResult === 'saved' && uploadSizeResult === 'saved') {
                closeSettingsModal();
            }
        }

        function showAnalysisUI() {
            leftRightSwitchesStatTabs = true;
            document.getElementById('inputBoxes').style.display = 'none';
            document.getElementById('mainHeader').style.display = 'block';
            document.getElementById('dataPanel').style.display = '';
            document.getElementById('searchBarContainer').style.display = 'block';
            // Same footer teaser as the welcome screen (showWelcomeUI) -
            // kept consistent across both modes rather than swapping to a
            // "Need help?" prompt during analysis.
            document.getElementById('footerCenterTeaser').innerHTML = '<a href="#" data-action="show-security-onion-modal" class="footer-teaser-link">Need more advanced functionality?</a>';
        }

        async function showWelcome() {
            document.title = 'SO-CRATES - Welcome';
            closeAllModals();
            if (window.location.search.includes('file=') || window.location.search.includes('pcap=')) {
                history.replaceState({}, '', window.location.pathname);
            }
            clearAnalysisContainers();
            showWelcomeUI();
            if (shouldShowHelpModal()) {
                showHelpModal();
            }
            
            // Load previous analyses
            let previousHtml = '';
            try {
                const resp = await fetch('/api/analyses');
                const analyses = await resp.json();
                if (analyses.length > 0) {
                    previousHtml = analyses.map(a => {
                        // The MD5 is still reachable via the link's
                        // href/status-bar URL - showing it in the hover
                        // tooltip too would be redundant. An analyst is far
                        // more likely to recognize the sample's own date
                        // range at a glance than an MD5 fragment, so that's
                        // the tooltip instead; keeping it out of the row
                        // itself (rather than an inline span) keeps the row
                        // uncluttered.
                        const dateText = formatDateRange(a.date_range);
                        const rowTitle = dateText || a.md5;
                        // Bare presence signal (no content preview) - the row
                        // is already tight with name + date + action buttons,
                        // so this just answers "does this one have notes?"
                        // without an analyst having to open it to check. It's
                        // its own button (not nested in the name/date link)
                        // so clicking it can jump straight to that analysis's
                        // Notes modal instead of just the normal overview.
                        const notesButtonHtml = a.has_notes
                            ? `<button data-md5="${escapeHtml(a.md5)}" data-action="notes" class="previous-analysis-notes" style="border: none; cursor: pointer; font-size: 1rem; padding: 4px 10px; border-radius: 6px; margin-right: 4px;" title="View/edit notes">${NOTES_ICON_SVG}</button>`
                            : '';
                        return `<div class="previous-analysis-row" style="display: flex; align-items: center; padding: 8px 10px;">
                            <a href="?file=${escapeHtml(a.md5)}" data-action="load-analysis" data-md5="${escapeHtml(a.md5)}" style="color: var(--accent); text-decoration: none; flex: 1; display: flex; align-items: baseline; gap: 8px; overflow: hidden;" title="${escapeHtml(rowTitle)}">
                                <span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${FOLDER_ICON_SVG}${escapeHtml(a.name)}</span>
                            </a>
                            ${notesButtonHtml}
                        </div>`;
                    }).join('');
                } else {
                    previousHtml = '<span style="color: var(--bg-hover-light);">No previous analyses available</span>';
                }
            } catch(err) {
                console.error('Failed to load analyses:', err);
                previousHtml = '<span style="color: var(--bg-hover-light);">Error loading analyses</span>';
            }
            document.getElementById('inputBoxes').innerHTML = `
                <div style="max-width: 900px; margin: 0 auto;">
                    <div style="display: flex; flex-direction: column; gap: 20px; margin-bottom: 20px;">
                        <div style="background: var(--bg-secondary); padding: 20px; border-radius: 8px; border: 1px solid var(--border-color); width: 100%; box-sizing: border-box;">
                            <div style="color: var(--text-muted); font-size: 0.9rem; text-transform: uppercase; margin-bottom: 15px; font-weight: 600;">${DOWN_ARROW_ICON_SVG} Select a sample file, import a file from URL, or import a file from your local system</div>
                            <div style="display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 15px;">
                                <div class="sample-card" title="${_sampleCardTitle(DEFAULT_SAMPLE_URL)}" tabindex="0" role="button" aria-label="Analyze the sample PCAP file" data-action="load-sample-url" data-url="${escapeHtml(DEFAULT_SAMPLE_URL)}" data-key-activate="enter-space">
                                     <span class="sample-label">Sample PCAP file</span>
                                 </div>
                                <div class="sample-card" title="${_sampleCardTitle(SAMPLE_LOG_URL)}" tabindex="0" role="button" aria-label="Analyze the sample log file" data-action="load-sample-url" data-url="${escapeHtml(SAMPLE_LOG_URL)}" data-key-activate="enter-space">
                                    <span class="sample-label">Sample log file</span>
                                </div>
                                <div class="sample-card" title="${_sampleCardTitle(SAMPLE_BINARY_URL)}" tabindex="0" role="button" aria-label="Analyze the sample binary file" data-action="load-sample-url" data-url="${escapeHtml(SAMPLE_BINARY_URL)}" data-key-activate="enter-space">
                                    <span class="sample-label">Sample binary file</span>
                                </div>
                            </div>
                            <div style="display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 15px;">
                                <div style="flex: 1; text-align: center;">
                                    <a href="https://www.malware-traffic-analysis.net/" target="_blank" rel="noopener noreferrer" style="color: var(--accent); text-decoration: none; font-size: 0.85rem;">More PCAP samples ↗</a>
                                </div>
                                <div style="flex: 1; text-align: center;">
                                    <a href="https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES" target="_blank" rel="noopener noreferrer" style="color: var(--accent); text-decoration: none; font-size: 0.85rem;">More log samples ↗</a>
                                </div>
                                <div style="flex: 1; text-align: center;">
                                    <a href="https://www.eicar.org/" target="_blank" rel="noopener noreferrer" style="color: var(--accent); text-decoration: none; font-size: 0.85rem;">More binary samples ↗</a>
                                </div>
                            </div>
                            <div style="text-align: center; color: var(--text-muted); font-size: 0.9rem; font-weight: 600; text-transform: uppercase; margin-bottom: 15px;">— OR —</div>
                            <div style="display: flex; gap: 8px; margin-bottom: 15px;">
                                <input type="text" id="pcapUrl" value="${DEFAULT_SAMPLE_URL}" data-clear-on-focus data-enter-action="load-from-url" style="background: var(--bg-primary); color: var(--text-primary); border: 1px solid var(--border-color); padding: 8px 12px; border-radius: 4px; font-size: 0.95rem; flex: 1;">
                                <button data-action="load-from-url" style="background: var(--accent); color: var(--bg-primary); padding: 8px 20px; border-radius: 4px; cursor: pointer; font-weight: 600; font-size: 0.95rem; border: none;">Go</button>
                            </div>
                            <div style="text-align: center; color: var(--text-muted); font-size: 0.9rem; font-weight: 600; text-transform: uppercase; margin-bottom: 15px;">— OR —</div>
                            <input type="file" id="pcapUpload" data-change-action="upload-pcap" style="display: none;">
                            <div id="dropZone" tabindex="0" role="button" aria-label="Choose a file to upload, or drag and drop one here" style="background: var(--bg-primary); color: var(--accent); padding: 20px; border-radius: 4px; cursor: pointer; font-size: 0.95rem; border: 2px dashed var(--border-color); text-align: center; transition: border-color 0.2s, background 0.2s;"
                                 data-action="open-upload-picker" data-key-activate="enter-space">
                                 <div style="font-size: 1.5rem; margin-bottom: 8px;"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle;"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path><polyline points="2 13 6 9 10 13"></polyline></svg></div>
                                 <div>Choose file or drag and drop here</div>
                             </div>
                         </div>
                     </div>
                       <div class="previous-analyses-section" style="background: var(--bg-secondary); padding: 20px; border-radius: 8px; border: 1px solid var(--border-color);">
                           <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                               <div style="color: var(--text-muted); font-size: 0.9rem; text-transform: uppercase; font-weight: 600;">${FOLDER_OPEN_ICON_SVG} Previous Analyses</div>
                           </div>
                          <div id="previousAnalysesList">${previousHtml}</div>
                      </div>
                 </div>
             `;
            
            document.getElementById('pcapUrl').value = lastSampleUrl;
        }
        
        // Shared by the Escape handler and showWelcome() (leaving the
        // analysis view entirely should not leave a stale modal floating on
        // top of it - Notes is the sharpest case since it's tied to the
        // specific analysis being left, but none of these belong open once
        // there's no longer an analysis page under them).
        function closeAllModals() {
            closeMenu();
            closeHelpModal();
            closeThemesModal();
            closeSettingsModal();
            closeErrorModal();
            closeDeleteModal();
            closeDeleteAllModal();
            closeReanalyzeModal();
            closeRulesModal();
            closeAboutModal();
            closeNotesModal();
            closeSecurityOnionModal();
            closeAutocompleteModal();
        }

        // scrollIntoView({block:'nearest'}) alone isn't enough here - it
        // only reasons about the raw viewport, with no notion that
        // .app-header/.footer are position:fixed on top of it (not part of
        // the normal document flow it scrolls within), so an element can
        // land technically inside the viewport's bounds and still be
        // hidden underneath one of them. Runs the native call first
        // (handles horizontal/inline positioning and gets vertical mostly
        // right on its own), then corrects for whichever fixed bar is
        // still covering the element afterward, measured fresh since the
        // native call may have already moved it. A no-op scrollBy(0) when
        // nothing's occluded.
        function scrollKeyboardSelectionIntoView(el) {
            el.scrollIntoView({ block: 'nearest', inline: 'nearest' });
            const headerBottom = document.querySelector('.app-header')?.getBoundingClientRect().bottom ?? 0;
            const footerTop = document.querySelector('.footer')?.getBoundingClientRect().top ?? window.innerHeight;
            const rect = el.getBoundingClientRect();
            if (rect.top < headerBottom) {
                window.scrollBy(0, rect.top - headerBottom);
            } else if (rect.bottom > footerTop) {
                window.scrollBy(0, rect.bottom - footerTop);
            }
        }

        // Arrow-key navigation. Two different interaction models
        // depending on the cost of the underlying action: stat-card tabs
        // activate immediately on Left/Right (cheap, already-cached tab
        // switch, like a native tab strip) - sample buttons, previous-
        // analysis rows, and data-table rows only get a visual
        // "keyboard-selected" highlight on arrow, activating on Enter,
        // since their action is a real network fetch or an expand/
        // collapse that shouldn't fire just from moving past an item.
        let verticalNavSelection = null;
        let horizontalSampleNavIndex = -1;

        // Left/Right switches the data-type stat-card tab (navigateStatTabs)
        // only while this is true. True on a fresh analysis load (set in
        // showAnalysisUI()) and reset back to true by a direct stat-card
        // click (set in showTab(), which both a mouse click and
        // navigateStatTabs() itself funnel through) - flipped false the
        // moment the user presses Up/Down (navigateVertical()) to move into
        // the page's own content. Otherwise Left/Right deep in a long table
        // silently jumps to a different data type, which reads as a stray
        // keystroke wiping out whatever the user was looking at.
        let leftRightSwitchesStatTabs = true;

        // showAnalysisUI() only hides #inputBoxes (display: none) rather
        // than clearing its innerHTML, so the welcome screen's contents
        // (sample cards, previous-analysis rows) are still sitting in the
        // DOM - just invisible - while an analysis is open. Checking this
        // display style is the same "which view is actually showing" test
        // showWelcomeUI()/showAnalysisUI() themselves use, and is more
        // reliable than inferring the view from whether some list happens
        // to be non-empty.
        function isWelcomeScreen() {
            return document.getElementById('inputBoxes').style.display !== 'none';
        }

        // The interactive controls inside an expanded detail-row - one
        // combined query so they come back in real document order:
        // [data-detail-pivot] (every clickable field value - Timestamp,
        // Src/Dst IP, DNS Query, etc., see htmlRowText) is rendered first
        // by formatEvent(), before the Notes/Payload sections it appends
        // after (rowNoteDetailHtml() then _formatEventPayload()) - so the
        // note link precedes ASCII Transcript/Hexdump, which precede
        // Download PCAP.
        // .packet-control-btn (Expand All/Collapse All) and .packet-header
        // (one per packet) live inside .hexdump-content, which loadHexdumpData()
        // only ever populates after the Hexdump tab has actually been activated
        // once (see switchStreamView) - querying for them is always safe even
        // before that (they simply don't exist yet, contributing nothing), and
        // the offsetParent filter below (not this selector) is what keeps them
        // out of the list while the ASCII Transcript view is showing instead.
        const EXPANDED_ROW_ITEM_SELECTOR = '[data-detail-pivot], .row-note-edit-link, .view-tab, .stream-btn, .packet-control-btn, .packet-header';

        // Scoped to the currently visible primary section (excludes
        // .agg-section, mirroring buildStats()'s own "visible section"
        // lookup) so Up/Down only ever walks the one event/log table
        // actually on screen, not a hidden tab's rows or an aggregation
        // table. tr[data-id] alone (no :not(.detail-row) needed) already
        // excludes detail-rows - only primary rows carry that attribute.
        // Each row's own detail-row (its very next sibling - see
        // toggleDetailRow) is spliced in right after it via
        // EXPANDED_ROW_ITEM_SELECTOR, but only while that specific row is
        // expanded - multiple rows can be expanded independently, so this
        // is checked per row rather than assuming one page-wide expanded
        // state. A collapsed row (or one with nothing to add - not every
        // event type has a stream, and some have no note link either)
        // contributes nothing extra, so Down/Up behave exactly as before
        // for any row that's never had Enter pressed on it.
        function getVisibleDataTableRows() {
            const section = document.querySelector('.section:not(.section-hidden):not(.agg-section)');
            // A binary-only analysis has no stat-card tabs at all -
            // buildBinaryAnalysisView() renders its YARA-match table
            // directly into #sections with no .section wrapper around
            // it, unlike every pcap/log tab's own hidden-except-one
            // .section block. #sections only ever holds that one table
            // in this mode, so querying it directly is safe here (it
            // would incorrectly include every hidden tab's rows too if
            // done unconditionally in the normal pcap/log case above,
            // which is why this is a fallback, not the first check).
            const sectionsEl = document.getElementById('sections');
            const rows = section
                ? Array.from(section.querySelectorAll('tr[data-id]'))
                : (sectionsEl ? Array.from(sectionsEl.querySelectorAll('tr[data-id]')) : []);
            return rows.flatMap(row => {
                const detailRow = row.nextElementSibling;
                if (!detailRow || !detailRow.classList.contains('detail-row') || !detailRow.classList.contains('visible')) {
                    return [row];
                }
                // offsetParent !== null - not just querying at all - is what
                // actually excludes the packet-control-btn/packet-header items
                // while the ASCII Transcript view is showing instead of Hexdump
                // (switchStreamView() hides .hexdump-content via display:none,
                // which zeroes offsetParent for everything inside it). The
                // other three item types are always visible together whenever
                // the row itself is expanded, so this filter is a no-op for them.
                const items = Array.from(detailRow.querySelectorAll(EXPANDED_ROW_ITEM_SELECTOR))
                    .filter(el => el.offsetParent !== null);
                return [row, ...items];
            });
        }

        // The filter bar (search-term/filter-value chips, plus one
        // trailing Clear All button - see buildFilterBarHtml()) in DOM
        // order.
        function filterBarRowItems() {
            return Array.from(document.querySelectorAll('#filterBarContainer .filter-chip, #filterBarContainer .filter-clear-all'));
        }

        // Down/Up must treat the whole filter bar row as ONE stop (real
        // bug report: with several chips active, Down used to step
        // through each one individually before ever reaching the stat-
        // card grid below - "moving between an active filter chip and
        // Clear All should be Left/Right", not Down) - Left/Right is what
        // cycles within the row instead (see navigateFilterBarItems).
        // Contributes whichever item is currently selected if Left/Right
        // has already moved within the row (mirrors activeColumnStatCards'
        // own "follow the current ring" reference-picking, one level up),
        // else defaults to the first chip - so a fresh Down/Up always
        // lands on a predictable, visible entry point into the row.
        function filterBarRowAnchor() {
            const items = filterBarRowItems();
            if (items.length === 0) return [];
            const current = (verticalNavSelection && verticalNavSelection.isConnected && items.includes(verticalNavSelection))
                ? verticalNavSelection : items[0];
            return [current];
        }

        // Left/Right's own handling for the filter bar row, mirroring
        // navigateStreamControls()/navigatePacketControls()'s established
        // horizontal-group idiom one level up - only active while the
        // current selection is actually inside the row; Down/Up
        // (navigateVertical(), via filterBarRowAnchor() above) is what
        // moves out of it entirely.
        function currentFilterBarSelection() {
            if (!(verticalNavSelection && verticalNavSelection.isConnected && verticalNavSelection.offsetParent !== null)) return null;
            if (!(verticalNavSelection.classList.contains('filter-chip') || verticalNavSelection.classList.contains('filter-clear-all'))) return null;
            return verticalNavSelection;
        }

        function navigateFilterBarItems(direction) {
            const current = currentFilterBarSelection();
            if (!current) return false;
            const items = filterBarRowItems();
            if (items.length < 2) return false;
            const index = items.indexOf(current);
            moveStreamControlSelectionTo(items[(index + direction + items.length) % items.length]);
            return true;
        }

        // The Sankey/Aggregation toggle bars sit directly above the data
        // table in the DOM (#sankeyPanel, #aggregations, #sections in that
        // order - see socrates.html), so prepending them here extends the
        // same flat top-to-bottom list navigateVertical() already walks for
        // table rows, rather than introducing a separate selection track.
        // offsetParent !== null (instead of e.g. checking style.display
        // directly) catches every way a bar can be hidden - #sankeyPanel's
        // own inline display:none when cleared, and the CSS rule that
        // force-hides it in binary/file-analysis mode - without needing to
        // know which one applies. Each bar already has an onclick handler
        // (toggleDiagram()/toggleAggregations()), so no change is needed in
        // activateKeyboardSelection(): its existing generic
        // verticalNavSelection.click() fallback (used for data rows too)
        // already fires it.
        const TOGGLE_BAR_SELECTORS = {
            sankey: '#sankeyPanel > .section-toggle-bar',
            agg: '#aggregations .section-toggle-bar',
            dnsHeuristicsInfo: '#section-dns_heuristics .dns-heuristics-info-toggle',
        };

        // Groups the currently-visible aggregation tables into visual rows
        // by rendered top position - the flex-wrap agg-grid has no fixed
        // column count the way #statsGrid's CSS Grid does (read via
        // statsGridColumnCount()), so row membership can only come from
        // actual layout, not arithmetic. Real bug report: DOM order alone
        // (every table's rows back to back) makes Down from a table's last
        // row land on the very next table in DOM order - almost always the
        // sibling immediately to its right, same visual row - when the
        // expectation is "next VISUAL row of tables, or the Data Table if
        // this was the last row"; Left/Right (navigateAggTables) is what's
        // supposed to move sideways within a row, not Down.
        function aggTableRowGroups() {
            const tables = Array.from(document.querySelectorAll('#aggregations .agg-section')).filter(t => t.offsetParent !== null);
            const rows = [];
            for (const table of tables) {
                const top = table.offsetTop;
                let row = rows.find(r => Math.abs(r.top - top) < 4); // sub-pixel tolerance
                if (!row) { row = { top, tables: [] }; rows.push(row); }
                row.tables.push(table);
            }
            rows.sort((a, b) => a.top - b.top);
            return rows.map(r => r.tables);
        }

        // A table's own value rows (tr.agg-row[data-agg-pivot], see
        // _renderAggTablesHtml) plus its Prev/Next pagination row collapsed
        // to one stop, if it has one (mirrors filterBarRowAnchor's own
        // reasoning exactly) - contributes whichever button is already
        // selected if Left/Right has moved within it
        // (navigateAggPaginationButtons), else defaults to the first
        // non-disabled one (page 1 has no Prev - landing on it by default
        // would need an extra Left/Right press before Enter could do
        // anything).
        function aggTableOwnItems(table) {
            const rows = Array.from(table.querySelectorAll('tr.agg-row[data-agg-pivot]'));
            const pageButtons = Array.from(table.querySelectorAll('.agg-page-btn'));
            if (pageButtons.length === 0) return rows;
            const current = (verticalNavSelection && verticalNavSelection.isConnected && pageButtons.includes(verticalNavSelection))
                ? verticalNavSelection : (pageButtons.find(b => !b.disabled) || pageButtons[0]);
            return rows.concat([current]);
        }

        // Down/Up walks the reference table's own rows/pagination stop,
        // bridging to the first table of the next visual row once it runs
        // out (or the last table of the previous row, moving the other
        // direction) - recomputed fresh on every keypress from wherever
        // verticalNavSelection actually landed, so chaining across several
        // rows in a row (so to speak) falls out for free without needing
        // to pre-build the whole multi-row sequence in one call. Left/Right
        // jumps directly to a different table instead of stepping through
        // every intervening row (see navigateAggTables) - the same
        // "Down/Up walks the flat list, Left/Right jumps within/between
        // groups" split every other section here already uses. Collapsed
        // panels naturally contribute nothing since #aggregations then has
        // no .agg-section elements to find at all.
        function aggTableAndPaginationItems() {
            const rowGroups = aggTableRowGroups();
            if (rowGroups.length === 0) return [];
            let referenceTable = (verticalNavSelection && verticalNavSelection.isConnected)
                ? verticalNavSelection.closest('#aggregations .agg-section') : null;
            let rowIndex = referenceTable ? rowGroups.findIndex(row => row.includes(referenceTable)) : -1;
            if (rowIndex === -1) {
                // verticalNavSelection isn't currently inside the agg block
                // at all (a toggle bar/filter chip/stat card, a Data Table
                // row, or nothing selected yet) - which end of the block to
                // offer as the entry point depends on which side we're
                // approaching from. Real bug report: with 3+ rows, Up from
                // the Data Table always re-entered at row 0 regardless of
                // how many rows actually existed below it, since this used
                // to default to the first row unconditionally - only a Data
                // Table row means "arriving from below" (Up); every other
                // case (including the very first Down of a fresh page) means
                // "arriving from above" (Down), so the first row is still
                // the right default there.
                const fromBelow = verticalNavSelection && verticalNavSelection.isConnected
                    && getVisibleDataTableRows().includes(verticalNavSelection);
                rowIndex = fromBelow ? rowGroups.length - 1 : 0;
                referenceTable = rowGroups[rowIndex][0];
            }
            let items = aggTableOwnItems(referenceTable);
            const prevRow = rowGroups[rowIndex - 1];
            if (prevRow) items = aggTableOwnItems(prevRow[prevRow.length - 1]).concat(items);
            const nextRow = rowGroups[rowIndex + 1];
            if (nextRow) items = items.concat(aggTableOwnItems(nextRow[0]));
            return items;
        }

        function getVerticalNavItems() {
            // The filter bar (search-term/filter-value chips, plus Clear
            // All) is a single horizontal row - see filterBarRowAnchor()'s
            // own comment for why it contributes only ONE entry here
            // rather than one per chip.
            const filterBarItems = filterBarRowAnchor();
            const toggleBars = [
                document.querySelector(TOGGLE_BAR_SELECTORS.sankey),
                document.querySelector(TOGGLE_BAR_SELECTORS.agg),
                document.querySelector(TOGGLE_BAR_SELECTORS.dnsHeuristicsInfo),
            ];
            const aggRows = aggTableAndPaginationItems();
            // Positioned right after the filter chips, matching where
            // #statsGrid actually sits on the page (see socrates.html:
            // #filterBarContainer, #statsGrid, #sankeyPanel,
            // #aggregations, #dataPanel, in that order) - Down/Up walking
            // this list is meant to move "straight down the page", and
            // burying the stat-card grid at the very end (reachable only
            // after a full wraparound) put it out of that order entirely.
            // Includes every row in the active tab's own column (not just
            // the active card itself), so a multi-row grid's other rows
            // are ordinary stops along the same path rather than a
            // separate mechanism bolted onto one end of it - Down from
            // the last table row still wraps to this same block (now via
            // plain wraparound, landing on its first entry, the active
            // card, with no special-casing needed), and Up from the first
            // filter chip (or the active card, if there are no chips)
            // symmetrically retraces it in reverse for free.
            const gridRowCards = activeColumnStatCards();
            return filterBarItems.concat(gridRowCards, toggleBars, aggRows)
                .filter(el => el && el.offsetParent !== null)
                .concat(getVisibleDataTableRows());
        }

        // Left/Right's own handling once the current selection is actually
        // one of the two Prev/Next buttons (i.e. Down has already entered
        // the pagination stop aggTableAndPaginationItems() collapses to one
        // entry) - mirrors currentFilterBarSelection/navigateFilterBarItems
        // exactly. navigateAggTables (below) handles Left/Right for every
        // OTHER agg-area selection (an ordinary row, not yet on Prev/Next).
        function currentAggPaginationSelection() {
            if (!(verticalNavSelection && verticalNavSelection.isConnected && verticalNavSelection.offsetParent !== null)) return null;
            if (!verticalNavSelection.classList.contains('agg-page-btn')) return null;
            return verticalNavSelection;
        }

        function navigateAggPaginationButtons(direction) {
            const current = currentAggPaginationSelection();
            if (!current) return false;
            const table = current.closest('.agg-section');
            const buttons = table ? Array.from(table.querySelectorAll('.agg-page-btn')) : [];
            if (buttons.length < 2) return false;
            const index = buttons.indexOf(current);
            moveStreamControlSelectionTo(buttons[(index + direction + buttons.length) % buttons.length]);
            return true;
        }

        // Left/Right jumps straight to a different aggregation table
        // instead of stepping through every intervening row via Down - only
        // active while the current selection is actually inside one (an
        // agg-row or one of its Prev/Next buttons); Down/Up
        // (navigateVertical(), via aggTableAndPaginationItems() above) is
        // what walks within/between tables one row at a time. Lands on the
        // target table's first row (matching navigateStatTabs' own
        // "preview, don't require a second Down" landing behavior) - every
        // rendered table has at least one row (_renderOneAggTableHtml is
        // never called with zero entries), so a null first-row can't happen
        // in practice.
        function navigateAggTables(direction) {
            const current = (verticalNavSelection && verticalNavSelection.isConnected)
                ? verticalNavSelection.closest('#aggregations tr.agg-row, #aggregations .agg-page-btn')
                : null;
            if (!current) return false;
            const currentTable = current.closest('.agg-section');
            if (!currentTable) return false;
            const tables = Array.from(document.querySelectorAll('#aggregations .agg-section')).filter(t => t.offsetParent !== null);
            const index = tables.indexOf(currentTable);
            if (index === -1 || tables.length < 2) return false;
            const nextTable = tables[(index + direction + tables.length) % tables.length];
            const target = nextTable.querySelector('tr.agg-row[data-agg-pivot]');
            if (!target) return false;
            moveStreamControlSelectionTo(target);
            return true;
        }

        // Which toggle bar (if any) is the current keyboard selection,
        // tracked by kind rather than by relying on verticalNavSelection's
        // node reference alone - toggleDiagram()/toggleAggregations()
        // rebuild their panel's entire innerHTML (including the bar itself)
        // on every collapse/expand, which would otherwise silently drop the
        // selection each time. The MutationObservers below use this to
        // re-glue the selection onto whichever new bar element lands, so
        // Enter can immediately re-collapse a panel just expanded via Enter
        // without another arrow-key press.
        let verticalNavToggleBarKind = null;

        function reapplyToggleBarSelection() {
            if (!verticalNavToggleBarKind) return;
            const bar = document.querySelector(TOGGLE_BAR_SELECTORS[verticalNavToggleBarKind]);
            if (!bar) return;
            bar.classList.add('keyboard-selected');
            verticalNavSelection = bar;
        }
        // childList (not subtree) is enough for both: toggleDiagram()
        // always replaces #sankeyPanel's innerHTML directly, and
        // toggleAggregations() always replaces #aggregations' innerHTML
        // directly (the .agg-panel wrapper and everything in it), so the
        // bar's re-creation is always a direct-child mutation of one of
        // these two containers.
        new MutationObserver(reapplyToggleBarSelection).observe(document.getElementById('sankeyPanel'), { childList: true });
        new MutationObserver(reapplyToggleBarSelection).observe(document.getElementById('aggregations'), { childList: true });
        // #section-dns_heuristics (unlike #sankeyPanel/#aggregations,
        // static elements always present in socrates.html) doesn't exist
        // until buildSections() first creates it, so observing it
        // directly here at script-init time would call .observe(null,
        // ...) and throw. #sections is the stable, always-present
        // ancestor buildSections() renders every tab's section into -
        // subtree: true catches buildDnsHeuristicsSectionContent()'s own
        // container.innerHTML replacement several levels down (sections >
        // section-dns_heuristics > section-content > agg-panel > toggle
        // bar) without needing to re-attach a new observer on every visit
        // to this tab. reapplyToggleBarSelection() is a cheap no-op
        // whenever verticalNavToggleBarKind isn't currently set, so the
        // wider subtree scope firing on unrelated tab/pagination changes
        // elsewhere in #sections costs nothing in practice.
        new MutationObserver(reapplyToggleBarSelection).observe(document.getElementById('sections'), { childList: true, subtree: true });

        function navigateStatTabs(direction) {
            const cards = Array.from(document.querySelectorAll('#statsGrid .stat-card'));
            if (cards.length === 0) return false;
            // Continue from a live preview selection if one exists, not
            // necessarily .tab-active - repeated Left/Right (like Down/Up
            // below) only moves the preview ring one card at a time, so
            // each press must pick up from wherever the ring already is,
            // not restart from whatever's still really active underneath
            // it.
            let currentIndex = (verticalNavSelection && verticalNavSelection.isConnected && cards.includes(verticalNavSelection))
                ? cards.indexOf(verticalNavSelection) : -1;
            if (currentIndex === -1) {
                const activeIndex = cards.findIndex(c => c.classList.contains('tab-active'));
                currentIndex = activeIndex === -1 ? 0 : activeIndex;
            }
            const nextIndex = (currentIndex + direction + cards.length) % cards.length;
            // Preview only, same as Down/Up's own handling of the active
            // tab's grid column (see activeColumnStatCards) -
            // deliberately does NOT click()/activate the card. Left/Right
            // used to switch tabs immediately on every press; now every
            // arrow key uses the same preview-then-Enter-to-commit model
            // (mirroring navigateThemeTiles' own established idiom for
            // grid navigation), so a user browsing with arrow keys never
            // gets dropped onto a different tab's data mid-browse without
            // meaning to.
            cards.forEach(c => c.classList.remove('keyboard-selected'));
            verticalNavSelection = cards[nextIndex];
            verticalNavSelection.classList.add('keyboard-selected');
            scrollKeyboardSelectionIntoView(verticalNavSelection);
            return true;
        }

        // .stats-grid is a responsive CSS grid (repeat(auto-fit,
        // minmax(140px, 1fr))) with no fixed column count - mirrors
        // themeTileGridColumnCount()'s own technique of reading the
        // browser's already-resolved column list back via
        // getComputedStyle rather than trying to compute it by hand from
        // container width/card width.
        function statsGridColumnCount() {
            const grid = document.getElementById('statsGrid');
            if (!grid) return 1;
            const columns = getComputedStyle(grid).gridTemplateColumns.trim().split(/\s+/).filter(Boolean).length;
            return columns > 0 ? columns : 1;
        }

        // Every card in the CURRENT column, top to bottom - just
        // [referenceCard] for a single-row grid or when no reference card
        // is found. Used by getVerticalNavItems() to fold the stat-card
        // grid into the same flat Down/Up sequence as everything else
        // (filter chips, Sankey/Aggregation Tables, the data table) -
        // earlier this was a separate preemptive interceptor
        // (navigateStatTabsVertical) bolted onto one end of that
        // sequence, which produced asymmetric, surprising wrap behavior
        // (Up not retracing the same path Down took) and skipped the
        // grid entirely whenever filter chips were the first real item in
        // the list. Folding every row into the ordinary list at its real
        // page position (see getVerticalNavItems' own comment) fixes both
        // for free via the exact same wraparound logic every other item
        // here already uses, with no stat-card-specific case needed.
        //
        // The reference card is whichever stat card is currently ringed
        // (verticalNavSelection), not necessarily .tab-active - Left/
        // Right (navigateStatTabs) can preview a DIFFERENT column's card
        // without committing it, and Down/Up must continue straight down
        // *that* column (real bug report: previewing a card via Right and
        // then pressing Down landed back on the still-active tab's own
        // column instead, reading as Down having gone "left"). Falls back
        // to .tab-active only when nothing is currently ringed (e.g. right
        // after a tab switch, before any arrow key has been pressed) -
        // showTab() clears any stray ring left on a different card by a
        // plain mouse click (see its own comment), so verticalNavSelection
        // never drifts out of sync with reality once a real click commits
        // a different tab.
        function activeColumnStatCards() {
            const referenceCard = (verticalNavSelection && verticalNavSelection.isConnected && verticalNavSelection.classList.contains('stat-card'))
                ? verticalNavSelection
                : document.querySelector('.stat-card.tab-active');
            if (!referenceCard) return [];
            const cards = Array.from(document.querySelectorAll('#statsGrid .stat-card'));
            const columnCount = statsGridColumnCount();
            const referenceIndex = cards.indexOf(referenceCard);
            if (referenceIndex === -1) return [];
            const columnStart = referenceIndex % columnCount;
            const column = [];
            for (let i = columnStart; i < cards.length; i += columnCount) {
                column.push(cards[i]);
            }
            return column;
        }

        // True for the 3 controls that behave as one horizontal group within
        // an expanded row's Payload section (see navigateStreamControls/
        // navigateStreamControlsVertical below) - ASCII Transcript, Hexdump
        // (both .view-tab) and Download PCAP (.stream-btn). Excludes
        // .packet-control-btn (Expand All/Collapse All) deliberately - that
        // pair is its own separate group one level below this one, not part
        // of the row/tab strip.
        function isStreamControlGroupMember(el) {
            return !!el && (el.classList.contains('view-tab') || el.classList.contains('stream-btn'));
        }

        // offsetParent, not just isConnected - a stale selection left over
        // from a stat-card tab the user has since switched away from (mouse
        // click bypasses navigateVertical()'s own indexOf-based self-heal,
        // since neither this nor navigateStreamControlsVertical() goes
        // through getVerticalNavItems() at all) is still attached to the
        // document, just hidden via .section-hidden's display:none.
        function currentStreamControlSelection() {
            if (!(verticalNavSelection && verticalNavSelection.isConnected && verticalNavSelection.offsetParent !== null && isStreamControlGroupMember(verticalNavSelection))) return null;
            return verticalNavSelection;
        }

        function moveStreamControlSelectionTo(el) {
            verticalNavSelection.classList.remove('keyboard-selected');
            verticalNavSelection = el;
            verticalNavSelection.classList.add('keyboard-selected');
            scrollKeyboardSelectionIntoView(verticalNavSelection);
        }

        // Left/Right's other section-local behavior once
        // leftRightSwitchesStatTabs is false (see its own comment) - cycles
        // through all 3 stream controls (ASCII Transcript, Hexdump, Download
        // PCAP - .stream-payload's own DOM order) as one horizontal group.
        // Only the two view-tabs activate on arrival (tabs[nextIndex].click(),
        // same as navigateStatTabs() does for data-type tabs - a real
        // tab-strip, not preview-then-Enter) - Download PCAP deliberately
        // does NOT, since unlike switching a view it's a real side effect
        // (triggers an actual file download), and arrowing past a button
        // must never fire its action on its own (same reasoning as every
        // other Enter-to-activate item in this app - see verticalNavSelection's
        // own comment). keyboard-selected moves along regardless - .active
        // (which view) and .keyboard-selected (arrow-key cursor) are
        // independent (see the CSS comment on .view-tab.keyboard-selected),
        // so switching the active view here must also explicitly move the
        // cursor, unlike a plain click elsewhere which only ever changes .active.
        function navigateStreamControls(direction) {
            const current = currentStreamControlSelection();
            if (!current) return false;
            const wrapper = current.closest('.stream-payload');
            if (!wrapper) return false;
            const items = Array.from(wrapper.querySelectorAll('.view-tab, .stream-btn'));
            if (items.length < 2) return false;
            const index = items.indexOf(current);
            const next = items[(index + direction + items.length) % items.length];
            if (next.classList.contains('view-tab')) next.click();
            moveStreamControlSelectionTo(next);
            return true;
        }

        // Up/Down's other section-local behavior for the same 3-item group
        // navigateStreamControls() cycles with Left/Right - treats the whole
        // group as a single row in a small 2D layout (Add Note above, the
        // Expand All/Collapse All section below), so Up/Down jump straight
        // out of the row to one of those instead of stepping to a
        // neighboring control within it (which is what plain flat-list
        // navigateVertical() would otherwise do, landing on whichever
        // control happens to be next in DOM order). Checked ahead of
        // navigateVertical() in the keydown handler, same precedence as
        // navigatePivotMenuItems()/navigateThemeTiles(). Falls through
        // (returns false) to navigateVertical()'s normal flat-list stepping
        // whenever the jump target doesn't exist yet - Hexdump not activated
        // at least once means no .packet-control-btn to jump to for Down.
        function navigateStreamControlsVertical(direction) {
            const current = currentStreamControlSelection();
            if (!current) return false;
            let target;
            if (direction > 0) {
                target = current.closest('.stream-payload')?.querySelector('.packet-control-btn');
            } else {
                target = current.closest('.detail-row')?.querySelector('.row-note-edit-link');
            }
            if (!target || target.offsetParent === null) return false;
            moveStreamControlSelectionTo(target);
            return true;
        }

        // Left/Right's behavior for the Expand All/Collapse All pair - its
        // own separate 2-item horizontal group, not merged into
        // navigateStreamControls()'s group above (that group's Down jumps
        // INTO this one as a distinct row, so it can't also BE this one).
        // Neither button activates on arrival, unlike ASCII Transcript/
        // Hexdump in the group above - both are real state-mutating actions
        // (bulk-toggling every packet's visibility) rather than a passive
        // view switch, so this follows the same reasoning Download PCAP
        // does: arrowing past a button must never fire its action on its
        // own, only Enter does.
        function navigatePacketControls(direction) {
            if (!(verticalNavSelection && verticalNavSelection.isConnected && verticalNavSelection.offsetParent !== null && verticalNavSelection.classList.contains('packet-control-btn'))) return false;
            const wrapper = verticalNavSelection.closest('.packet-controls');
            if (!wrapper) return false;
            const items = Array.from(wrapper.querySelectorAll('.packet-control-btn'));
            if (items.length < 2) return false;
            const index = items.indexOf(verticalNavSelection);
            moveStreamControlSelectionTo(items[(index + direction + items.length) % items.length]);
            return true;
        }

        // Up/Down's other section-local behavior for the Expand All/Collapse
        // All pair - mirrors navigateStreamControlsVertical()'s own jump
        // logic, one level down: Up from either button jumps to Download
        // PCAP (its nearest DOM neighbor in the group above, same "jump to
        // the boundary neighbor" pattern navigateStreamControlsVertical()
        // uses for Add Note), Down jumps to the first packet regardless of
        // which of the two is currently selected. Both search from the
        // shared .stream-payload ancestor (not just .packet-controls, which
        // only wraps the two buttons themselves) since that's the closest
        // container holding .stream-btn/.packet-header too. Checked ahead
        // of navigateVertical() in the keydown handler, same precedence as
        // navigateStreamControlsVertical().
        function navigatePacketControlsVertical(direction) {
            if (!(verticalNavSelection && verticalNavSelection.isConnected && verticalNavSelection.offsetParent !== null && verticalNavSelection.classList.contains('packet-control-btn'))) return false;
            const wrapper = verticalNavSelection.closest('.stream-payload');
            if (!wrapper) return false;
            const target = direction > 0 ? wrapper.querySelector('.packet-header') : wrapper.querySelector('.stream-btn');
            if (!target || target.offsetParent === null) return false;
            moveStreamControlSelectionTo(target);
            return true;
        }

        function navigateSampleCards(direction) {
            // Guard on the view, not just DOM presence - same reasoning
            // as navigateVertical(): showAnalysisUI() only hides
            // #inputBoxes rather than clearing it, so the sample cards
            // are still sitting in the DOM (just invisible) while an
            // analysis is open.
            const isWelcome = isWelcomeScreen();
            if (!isWelcome) return false;
            const cards = Array.from(document.querySelectorAll('.sample-card'));
            if (cards.length === 0) return false;
            cards.forEach(c => c.classList.remove('keyboard-selected'));
            // Left/Right and Up/Down are two independent selection tracks
            // on the welcome screen - moving on one axis must clear the
            // other's highlight, or Enter can activate a stale selection
            // instead of whatever's actually highlighted.
            document.querySelectorAll('.previous-analysis-row.keyboard-selected').forEach(el => el.classList.remove('keyboard-selected'));
            verticalNavSelection = null;
            verticalNavToggleBarKind = null;
            if (horizontalSampleNavIndex === -1 || horizontalSampleNavIndex >= cards.length) {
                horizontalSampleNavIndex = direction > 0 ? 0 : cards.length - 1;
            } else {
                horizontalSampleNavIndex = (horizontalSampleNavIndex + direction + cards.length) % cards.length;
            }
            cards[horizontalSampleNavIndex].classList.add('keyboard-selected');
            scrollKeyboardSelectionIntoView(cards[horizontalSampleNavIndex]);
            return true;
        }

        // Which list applies is driven by which view is actually showing
        // (same #inputBoxes display check showWelcomeUI()/showAnalysisUI()
        // themselves use), not just by which list happens to be non-empty
        // - showAnalysisUI() only hides #inputBoxes, it doesn't clear its
        // innerHTML, so the previous-analysis rows are still sitting in
        // the DOM (just invisible) while an analysis is open, and a
        // presence-only check would keep finding those instead of ever
        // falling through to the data table.
        function navigateVertical(direction) {
            const isWelcome = isWelcomeScreen();
            const items = isWelcome
                ? Array.from(document.querySelectorAll('.previous-analysis-row'))
                : getVerticalNavItems();
            if (items.length === 0) return false;
            // See leftRightSwitchesStatTabs's own comment - any real Up/Down
            // move hands Left/Right over to whatever's now keyboard-selected
            // instead of the data-type tabs.
            leftRightSwitchesStatTabs = false;
            items.forEach(el => el.classList.remove('keyboard-selected'));
            if (isWelcome) {
                // See the matching note in navigateSampleCards(): clear the
                // other axis's stale highlight so Enter always activates
                // whatever's actually highlighted.
                document.querySelectorAll('.sample-card.keyboard-selected').forEach(el => el.classList.remove('keyboard-selected'));
                horizontalSampleNavIndex = -1;
            }
            // isConnected guards against a stale reference into a row set
            // that's since been replaced (tab switch, pagination, a
            // search/filter re-render) - self-heals by just starting a
            // fresh selection instead of erroring or selecting nothing.
            let index = (verticalNavSelection && verticalNavSelection.isConnected) ? items.indexOf(verticalNavSelection) : -1;
            if (index === -1) {
                index = direction > 0 ? 0 : items.length - 1;
            } else {
                index = (index + direction + items.length) % items.length;
            }
            verticalNavSelection = items[index];
            // Landing on one of the active tab's own stat cards (see
            // getVerticalNavItems'/activeColumnStatCards' own comments -
            // the whole grid column lives at its real page position in
            // this same list now, not bolted onto one end of it) - hand
            // control back to Left/Right immediately, overriding the
            // leftRightSwitchesStatTabs = false just set above, so a
            // different data type is reachable right away without
            // needing a second Up/Down press first.
            if (!isWelcome && verticalNavSelection.classList.contains('stat-card')) {
                leftRightSwitchesStatTabs = true;
            }
            verticalNavToggleBarKind = isWelcome ? null
                : verticalNavSelection.matches(TOGGLE_BAR_SELECTORS.sankey) ? 'sankey'
                : verticalNavSelection.matches(TOGGLE_BAR_SELECTORS.agg) ? 'agg'
                : verticalNavSelection.matches(TOGGLE_BAR_SELECTORS.dnsHeuristicsInfo) ? 'dnsHeuristicsInfo'
                : null;
            verticalNavSelection.classList.add('keyboard-selected');
            scrollKeyboardSelectionIntoView(verticalNavSelection);
            return true;
        }

        // Whenever a rebuild (opening an analysis, applying/clearing a
        // search or filter, acknowledging an alert, ...) replaces the DOM
        // node verticalNavSelection was pointing at, the very next arrow
        // press would otherwise hit navigateVertical()'s own "nothing
        // selected" fallback and land ON the new top-of-list item instead
        // of moving relative to it (real bug reports, several rounds:
        // this happened both right after opening an analysis - landing on
        // the default tab's own card - and after applying a search filter
        // - landing on the new chip - when in both cases that item should
        // already read as the current position, so the first press moves
        // past it). Called after every such rebuild completes; re-seeds
        // with no visible ring (a starting reference point, not something
        // the user asked to see highlighted) so the first real arrow
        // press behaves exactly as if the user had already arrowed onto
        // whatever's now first. Guarded on staleness (isConnected) so an
        // ACTUAL, still-valid selection elsewhere - a re-glued toggle bar,
        // a table row that survived the rebuild - is left untouched
        // rather than yanked back to the top.
        function seedVerticalNavSelectionIfStale() {
            if (verticalNavSelection && verticalNavSelection.isConnected) return;
            verticalNavSelection = getVerticalNavItems()[0] || null;
        }

        let themeTileNavSelection = null;

        // .theme-tile-grid uses a responsive auto-fill column count (see
        // its own CSS rule), so the number of tiles per row changes with
        // modal width rather than being a fixed constant - read back
        // whatever it actually resolved to via getComputedStyle so
        // Up/Down can jump by a real row instead of guessing a column
        // count. All 3 group grids (Dark/Light/Fun) share the same
        // container width, so they always resolve to the same column
        // count - reading the first one is enough. Falls back to 1 (Up/
        // Down behaves like Left/Right) if the grid can't be found for
        // any reason, rather than throwing.
        function themeTileGridColumnCount() {
            const grid = document.querySelector('.theme-tile-grid');
            if (!grid) return 1;
            const columns = getComputedStyle(grid).gridTemplateColumns.trim().split(/\s+/).filter(Boolean).length;
            return columns > 0 ? columns : 1;
        }

        // Themes modal tiles are laid out as a responsive CSS grid split
        // across 3 separate group grids (Dark/Light/Fun) - rather than
        // handle cross-grid column alignment explicitly, this treats
        // every tile across all 3 groups as one flat sequential list in
        // DOM order (matching every other arrow-nav list in this app) and
        // moves through it by 1 (Left/Right) or by a full row's width
        // (Up/Down, via themeTileGridColumnCount()) - close enough to true
        // 2D movement in practice, since group boundaries rarely land
        // exactly on a row boundary anyway. Each move calls previewTheme()
        // on the newly-selected tile, exactly mirroring onmouseenter's
        // live-preview behavior, so keyboard navigation feels like
        // hovering with the keyboard rather than a separate mechanism.
        function navigateThemeTiles(direction, vertical) {
            const themesModal = document.getElementById('themesModal');
            if (!themesModal || !themesModal.classList.contains('active')) return false;
            const tiles = Array.from(document.querySelectorAll('.theme-tile[data-theme-option]'));
            if (tiles.length === 0) return false;
            const step = direction * (vertical ? themeTileGridColumnCount() : 1);
            tiles.forEach(t => t.classList.remove('keyboard-selected'));
            let index = (themeTileNavSelection && themeTileNavSelection.isConnected) ? tiles.indexOf(themeTileNavSelection) : -1;
            if (index === -1) {
                // No keyboard selection yet (the very first arrow press
                // since the modal opened) - start from the currently
                // active theme (menuBaseTheme, set by showThemesModal())
                // rather than always jumping to the first/last tile in the
                // whole grid, so navigation continues from wherever the
                // user already is instead of restarting from a corner.
                // menuBaseTheme is always a valid THEMES key by the time
                // this can run (showThemesModal() falls back to 'dark' if
                // the applied theme isn't a real one, e.g. the synthesized
                // OhMyDebn custom-theme marker) - the -1 fallback below is
                // purely defensive.
                const currentIndex = tiles.findIndex(t => t.dataset.themeOption === menuBaseTheme);
                index = currentIndex === -1
                    ? (direction > 0 ? 0 : tiles.length - 1)
                    : (currentIndex + step + tiles.length) % tiles.length;
            } else {
                index = (index + step + tiles.length) % tiles.length;
            }
            themeTileNavSelection = tiles[index];
            themeTileNavSelection.classList.add('keyboard-selected');
            previewTheme(themeTileNavSelection.dataset.themeOption);
            themeTileNavSelection.scrollIntoView({ block: 'nearest' });
            return true;
        }

        let themeTileTypeaheadBuffer = '';
        let themeTileTypeaheadTimer = null;

        // Type-ahead select for the Themes modal grid, mirroring the
        // standard native <select>-element convention (type a name's start
        // to jump to it) rather than reusing the app's own separate
        // command-palette overlay (see AUTOCOMPLETE_COMMANDS) - the modal
        // is already a picker with live preview, so jumping the highlight
        // in place reads more naturally here than popping a second,
        // floating search box on top of the grid you're already looking
        // at. Matches against THEMES[key].label directly (not the tile's
        // own textContent) so it's exact regardless of whatever else a
        // tile happens to render. The buffer resets after a short pause
        // between keystrokes - same idea as native select typeahead -
        // rather than growing forever, so typing "ret" then pausing then
        // typing "amber" searches for "amber", not "retamber".
        function handleThemeTileTypeahead(e) {
            const themesModal = document.getElementById('themesModal');
            if (!themesModal || !themesModal.classList.contains('active')) return false;
            if (!(e.key.length === 1 && /[a-z0-9]/i.test(e.key))) return false;
            clearTimeout(themeTileTypeaheadTimer);
            themeTileTypeaheadBuffer += e.key.toLowerCase();
            themeTileTypeaheadTimer = setTimeout(() => { themeTileTypeaheadBuffer = ''; }, 800);
            const tiles = Array.from(document.querySelectorAll('.theme-tile[data-theme-option]'));
            const match = tiles.find(t => (THEMES[t.dataset.themeOption]?.label || '').toLowerCase().startsWith(themeTileTypeaheadBuffer));
            // Still consumes the keystroke (returns true, so the caller
            // calls e.preventDefault()) even with no match yet - e.g. right
            // after "z" alone, before the buffer resets - since a
            // keystroke that's part of an in-progress typeahead search
            // still isn't meant for anything else, whether or not it
            // happens to resolve to a tile.
            if (!match) return true;
            document.querySelectorAll('.theme-tile.keyboard-selected').forEach(t => t.classList.remove('keyboard-selected'));
            themeTileNavSelection = match;
            themeTileNavSelection.classList.add('keyboard-selected');
            previewTheme(themeTileNavSelection.dataset.themeOption);
            themeTileNavSelection.scrollIntoView({ block: 'nearest' });
            return true;
        }

        // Both pivot-triggering delegated click listeners (tr.agg-row
        // [data-agg-pivot] and [data-detail-pivot], see above
        // getVerticalNavItems()/EXPANDED_ROW_ITEM_SELECTOR) read
        // event.clientX/clientY to position the menu - a plain .click()
        // leaves those at 0 (the click() method's synthetic MouseEvent
        // always zeroes coordinate properties), which would pin the menu
        // to the viewport's top-left corner instead of opening next to
        // whatever triggered it. Building the event by hand anchors it to
        // the element's own bounding box instead, so a keyboard-opened
        // menu lands in the same place a mouse click on that element would
        // have. Generic over any pivot-triggering element, not just table
        // rows, despite the name's history - kept short rather than
        // renamed to something like openPivotMenuForElement().
        function openPivotMenuForRow(row) {
            const rect = row.getBoundingClientRect();
            row.dispatchEvent(new MouseEvent('click', {
                bubbles: true,
                cancelable: true,
                clientX: rect.left + 16,
                clientY: rect.top + rect.height / 2,
            }));
        }

        function activateKeyboardSelection() {
            // Even higher priority than the pivot menu below - the command
            // palette's own text input holds real DOM focus while it's
            // open, so there's nothing else Enter could plausibly mean.
            if (activateAutocompleteSelection()) {
                return true;
            }
            // Highest priority: an open pivot menu is a transient overlay
            // on top of everything else, so Enter should always act on its
            // own highlighted item first rather than falling through to
            // whatever's keyboard-selected on the page underneath it.
            if (pivotMenuNavSelection && pivotMenuNavSelection.isConnected && activePivotMenuEl && activePivotMenuEl.contains(pivotMenuNavSelection)) {
                pivotMenuNavSelection.click();
                return true;
            }
            if (themeTileNavSelection && themeTileNavSelection.isConnected && themeTileNavSelection.classList.contains('keyboard-selected')) {
                themeTileNavSelection.click();
                return true;
            }
            const isWelcome = isWelcomeScreen();
            const selectedSample = isWelcome ? document.querySelector('.sample-card.keyboard-selected') : null;
            if (selectedSample) {
                selectedSample.click();
                return true;
            }
            if (verticalNavSelection && verticalNavSelection.isConnected && verticalNavSelection.classList.contains('keyboard-selected')) {
                if (verticalNavSelection.classList.contains('previous-analysis-row')) {
                    const link = verticalNavSelection.querySelector('a[href]');
                    if (link) link.click();
                } else if (verticalNavSelection.matches('tr.agg-row[data-agg-pivot]') || verticalNavSelection.matches('[data-detail-pivot]')) {
                    openPivotMenuForRow(verticalNavSelection);
                } else if (verticalNavSelection.classList.contains('filter-chip')) {
                    // The chip itself carries no click action (see
                    // buildFilterBarHtml()) - only its nested
                    // .filter-chip-remove "x" does, so .click() on the chip
                    // directly would silently do nothing.
                    const removeBtn = verticalNavSelection.querySelector('.filter-chip-remove');
                    if (removeBtn) removeBtn.click();
                } else {
                    verticalNavSelection.click();
                }
                return true;
            }
            return false;
        }

        // Mirrors navigateVertical()/navigateThemeTiles()'s own flat-list
        // pattern, scoped to the open pivot menu's own buttons - Escape
        // (registered separately, see closePivotMenu()'s call site) still
        // closes the menu outright, this only handles cycling Up/Down
        // through what's inside it.
        function navigatePivotMenuItems(direction) {
            if (!activePivotMenuEl) return false;
            const items = Array.from(activePivotMenuEl.querySelectorAll('.pivot-menu-item'));
            if (items.length === 0) return false;
            items.forEach(el => el.classList.remove('keyboard-selected'));
            let index = (pivotMenuNavSelection && pivotMenuNavSelection.isConnected) ? items.indexOf(pivotMenuNavSelection) : -1;
            if (index === -1) {
                index = direction > 0 ? 0 : items.length - 1;
            } else {
                index = (index + direction + items.length) % items.length;
            }
            pivotMenuNavSelection = items[index];
            pivotMenuNavSelection.classList.add('keyboard-selected');
            pivotMenuNavSelection.scrollIntoView({ block: 'nearest' });
            return true;
        }

        // Shared guard for every single-key shortcut below ('?', '>'/'<',
        // arrow navigation, Enter-to-activate): only fire when no modifier
        // is held and the user isn't actively typing somewhere (a real
        // input/textarea, or - defensively, though nothing in this app
        // currently uses it - a contenteditable element). Centralizing
        // this means a future change to what counts as "typing" (e.g. a
        // new input type) only needs updating here instead of at every
        // call site.
        function isNavigableKeyContext(e) {
            return !e.ctrlKey && !e.altKey && !e.metaKey &&
                e.target.tagName !== 'INPUT' && e.target.tagName !== 'TEXTAREA' &&
                !e.target.isContentEditable;
        }

        // Single source of truth for every typed shortcut, all routed
        // through one live-filtered command palette (see
        // openAutocompleteModal() below). The 4 modal-openers are listed by
        // hand; every theme is generated straight from THEMES instead of
        // maintaining a separate hand-picked list of "cheat codes" for just
        // the Fun group - any theme (Dark/Light/Fun alike) is reachable by
        // typing its real displayed name now, so a new theme needs no
        // manual autocomplete wiring of its own, and there's no separate
        // short code to invent, document, and keep in sync. analysisOnly
        // mirrors the old "notes" code's own guard - showNotesModal() with
        // no args edits currentNotes via currentMd5, neither of which is
        // meaningful before an analysis is loaded, so it's filtered out of
        // the list entirely on the welcome screen rather than being offered
        // and then doing something odd.
        const AUTOCOMPLETE_COMMANDS = [
            { code: 'help', label: 'Help', action: () => { closeAutocompleteModal(); showHelpModal(); } },
            { code: 'about', label: 'About', action: () => { closeAutocompleteModal(); showAboutModal(); } },
            { code: 'advanced features', label: 'Advanced Features', action: () => { closeAutocompleteModal(); showSecurityOnionModal(); } },
            // External links - same window.open(url, '_blank', 'noopener,noreferrer')
            // convention already used elsewhere in this file (see the
            // detail-panel value linkifier), not a plain <a target="_blank">
            // since these commands have no anchor element of their own to
            // click.
            { code: 'documentation', label: 'Documentation', action: () => { closeAutocompleteModal(); window.open('https://so-crates.org', '_blank', 'noopener,noreferrer'); } },
            { code: 'security onion', label: 'Security Onion', action: () => { closeAutocompleteModal(); window.open('https://securityonion.net', '_blank', 'noopener,noreferrer'); } },
            { code: 'github repo', label: 'Github repo', action: () => { closeAutocompleteModal(); window.open('https://github.com/dougburks/so-crates', '_blank', 'noopener,noreferrer'); } },
            { code: 'pcap samples', label: 'PCAP samples', action: () => { closeAutocompleteModal(); window.open('https://malware-traffic-analysis.net', '_blank', 'noopener,noreferrer'); } },
            { code: 'log samples', label: 'Log samples', action: () => { closeAutocompleteModal(); window.open('https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES', '_blank', 'noopener,noreferrer'); } },
            { code: 'binary samples', label: 'Binary samples', action: () => { closeAutocompleteModal(); window.open('https://www.eicar.org/', '_blank', 'noopener,noreferrer'); } },
            { code: 'themes', label: 'Themes', action: () => { closeAutocompleteModal(); showThemesModal(); } },
            { code: 'rules', label: 'Rules', action: () => { closeAutocompleteModal(); showRulesModal(); } },
            { code: 'settings', label: 'Settings', action: () => { closeAutocompleteModal(); showSettingsModal(); } },
            { code: 'notes', label: 'Notes', analysisOnly: true, action: () => { closeAutocompleteModal(); showNotesModal(); } },
            // openDeleteAnalysis() only opens the confirmation modal (see
            // its own definition) - it still requires clicking Delete
            // there to actually delete anything, same "no action until the
            // user agrees" property as every other command here.
            { code: 'delete', label: 'Delete this analysis', analysisOnly: true, action: () => { closeAutocompleteModal(); openDeleteAnalysis(currentMd5, currentFileName); } },
            { code: 're-analyze', label: 'Re-analyze', analysisOnly: true, action: () => { closeAutocompleteModal(); openReanalyzeModal(currentMd5, currentFileName); } },
            // Focuses, doesn't open anything - #searchBarContainer is
            // display:none until showAnalysisUI() reveals it, so
            // analysisOnly keeps this out of the candidate list entirely on
            // the welcome screen rather than focusing a hidden input.
            { code: 'search', label: 'Search', analysisOnly: true, action: () => { closeAutocompleteModal(); document.getElementById('searchInput').focus(); } },
            { code: 'clear', label: 'Clear all search filters', analysisOnly: true, action: () => { closeAutocompleteModal(); clearAllFilters(); } },
            { code: 'sankey', label: 'Toggle Sankey Diagram section', analysisOnly: true, action: () => { closeAutocompleteModal(); toggleDiagram(); } },
            { code: 'aggregation', label: 'Toggle Aggregation Tables section', analysisOnly: true, action: () => { closeAutocompleteModal(); toggleAggregations(); } },
            // All three go to the same place (showWelcome()) - they're
            // different mental models for "I want to start something new"
            // (upload a file, import from a URL, revisit a past analysis),
            // not three different screens. analysisOnly here means the
            // opposite of what it means everywhere else in this list (hide
            // while already on the welcome screen these navigate to,
            // rather than hide while NOT on an analysis) - reused as-is
            // since the underlying need (hide when the destination is
            // where you already are) is the same shape either way.
            { code: 'upload', label: 'Upload', analysisOnly: true, action: () => { closeAutocompleteModal(); showWelcome(); } },
            { code: 'import', label: 'Import', analysisOnly: true, action: () => { closeAutocompleteModal(); showWelcome(); } },
            { code: 'previous analyses', label: 'Previous Analyses', analysisOnly: true, action: () => { closeAutocompleteModal(); showWelcome(); } },
            { code: 'copy md5 hash to clipboard', label: 'Copy MD5 hash to clipboard', analysisOnly: true, action: () => { closeAutocompleteModal(); copyMd5ToClipboard(currentMd5); } },
            { code: 'rename analysis', label: 'Rename Analysis', analysisOnly: true, action: () => { closeAutocompleteModal(); startRenameAnalysis(); } },
            ...Object.entries(THEMES).map(([key, theme]) => ({
                // 'theme' is appended to code (not just present in label)
                // so typing "theme" surfaces every individual theme-switch
                // command, not just the "Themes" modal-opener above -
                // autocompleteMatchesQuery/autocompleteMatchScore only
                // ever look at code, never label.
                code: `${theme.label.toLowerCase()} theme`,
                label: `${theme.label} theme`,
                action: () => { closeAutocompleteModal(); setTheme(key); showToast(`Switched to ${theme.label} theme.`); },
            })),
        ];

        // The commands currently rendered in #autocompleteResults (post-
        // filter), kept alongside the DOM so the click delegate/Enter
        // activation below can map an .autocomplete-item back to its
        // action without re-deriving the filter.
        let autocompleteMatches = [];
        let autocompleteNavSelection = null;

        function isAutocompleteModalActive() {
            return document.getElementById('autocompleteModal').classList.contains('active');
        }

        function closeAutocompleteModal() {
            document.getElementById('autocompleteModal').classList.remove('active');
            // Blur, not just hide - closing (Escape, backdrop click, or a
            // command committing) doesn't otherwise move focus off the
            // input, so it would still be document.activeElement even
            // while invisible. The very next bare-letter trigger keydown
            // would then see e.target as that INPUT and isNavigableKeyContext()
            // would (correctly, for a real focused input) refuse to treat
            // it as a trigger key - silently blocking the palette from ever
            // reopening until something else happened to move focus away first.
            const input = document.getElementById('autocompleteInput');
            input.blur();
            input.value = '';
            autocompleteMatches = [];
            autocompleteNavSelection = null;
        }

        // Only letters/digits - the codes are all-alphanumeric, and this
        // doubles as the trigger-key test (see the keydown handler below):
        // any bare letter/digit typed outside a text field, with nothing
        // else already open, opens the palette pre-seeded with that
        // character instead of silently starting an invisible buffer match.
        function isAutocompleteTriggerKey(e) {
            return e.key.length === 1 && /[a-z0-9]/i.test(e.key);
        }

        function openAutocompleteModal(firstChar) {
            document.getElementById('autocompleteModal').classList.add('active');
            const input = document.getElementById('autocompleteInput');
            input.value = firstChar;
            filterAutocomplete();
            input.focus();
        }

        // Data-type stat-card tabs (DNS, HTTP, All Events, ...) aren't a
        // fixed list like AUTOCOMPLETE_COMMANDS' other entries - which
        // tabs exist depends on what that particular analysis actually
        // contains, so this is read fresh from #statsGrid on every filter
        // pass instead of being baked into AUTOCOMPLETE_COMMANDS itself.
        // Naturally contributes nothing on the welcome screen, where
        // #statsGrid has no .stat-card children yet - no separate
        // analysisOnly flag needed the way the other analysis-only
        // commands have. Reuses the card's own real onclick (card.click(),
        // same as navigateStatTabs() does) rather than duplicating
        // showTab()'s section-id logic here.
        function getDataTypeAutocompleteCommands() {
            return Array.from(document.querySelectorAll('#statsGrid .stat-card')).map(card => {
                const label = card.querySelector('.stat-label').textContent;
                return {
                    code: label.toLowerCase(),
                    label: label,
                    action: () => { closeAutocompleteModal(); card.click(); },
                };
            });
        }

        // Matches a query anywhere a word starts, not just at the very
        // start of the whole code - "alerts" needs to find "network
        // alerts"/"file alerts" (query prefixes the label's 2nd word), not
        // just codes it's a prefix of outright. A bare substring anywhere
        // (e.g. "eme" inside "themes") also counts - autocompleteMatchScore
        // below ranks it lowest of the three, so a real prefix match never
        // gets buried under mid-word noise for a short query.
        function autocompleteMatchesQuery(code, query) {
            if (!query) return true;
            return code.includes(query);
        }

        // 2 = the whole code is a prefix match ("dns" -> "dns"), 1 = some
        // word within it is ("alerts" -> "network alerts", split on spaces
        // AND hyphens so e.g. "analyze" also finds "re-analyze"), 0 = only
        // a bare substring match ("eme" -> "themes"). Used purely for
        // result ordering, not filtering - autocompleteMatchesQuery already
        // decided this code is a match at all.
        function autocompleteMatchScore(code, query) {
            if (code.startsWith(query)) return 2;
            if (code.split(/[\s-]+/).some(word => word.startsWith(query))) return 1;
            return 0;
        }

        // oninput (not keydown) so Backspace/paste/selection-delete all
        // re-filter for free via the browser's own native text-editing,
        // rather than this needing to hand-track the query string itself.
        function filterAutocomplete() {
            const query = document.getElementById('autocompleteInput').value.trim().toLowerCase();
            const isWelcome = isWelcomeScreen();
            const allCommands = AUTOCOMPLETE_COMMANDS.concat(getDataTypeAutocompleteCommands());
            autocompleteMatches = allCommands
                .filter(c => autocompleteMatchesQuery(c.code, query) && (!c.analysisOnly || !isWelcome))
                .sort((a, b) => autocompleteMatchScore(b.code, query) - autocompleteMatchScore(a.code, query));
            autocompleteNavSelection = null;
            const resultsEl = document.getElementById('autocompleteResults');
            resultsEl.innerHTML = autocompleteMatches.length
                ? autocompleteMatches.map((c, i) => `<button type="button" class="autocomplete-item" data-autocomplete-index="${i}">${escapeHtml(c.label)}</button>`).join('')
                : '<div class="autocomplete-empty">No matches</div>';
        }

        // Scoped to #autocompleteResults itself, not delegated from document
        // like every other click-delegated list in this app (agg-row,
        // filter-chip, ...) - those live directly on the page or in a
        // fixed-position popup; this one is kept scoped so the palette's
        // own items stay wired even if a future .modal-content
        // stopPropagation shim ever comes back (one used to sit between
        // these buttons and any document-level listener).
        document.getElementById('autocompleteResults').addEventListener('click', function(e) {
            const item = e.target.closest('.autocomplete-item[data-autocomplete-index]');
            if (!item) return;
            const cmd = autocompleteMatches[Number(item.dataset.autocompleteIndex)];
            if (cmd) cmd.action();
        });

        // Mirrors navigateVertical()'s own flat-list pattern, scoped to the
        // open palette's own results - always returns true while the modal
        // is active (even with 0 matches) so Up/Down never falls through to
        // whatever's keyboard-selected on the page underneath it.
        function navigateAutocompleteItems(direction) {
            if (!isAutocompleteModalActive()) return false;
            const items = Array.from(document.querySelectorAll('#autocompleteResults .autocomplete-item'));
            if (items.length > 0) {
                items.forEach(el => el.classList.remove('keyboard-selected'));
                let index = (autocompleteNavSelection && autocompleteNavSelection.isConnected) ? items.indexOf(autocompleteNavSelection) : -1;
                index = index === -1 ? (direction > 0 ? 0 : items.length - 1) : (index + direction + items.length) % items.length;
                autocompleteNavSelection = items[index];
                autocompleteNavSelection.classList.add('keyboard-selected');
                autocompleteNavSelection.scrollIntoView({ block: 'nearest' });
            }
            return true;
        }

        // Enter with nothing yet arrow-selected still commits a single
        // remaining match (typing a unique prefix and hitting Enter,
        // without an extra arrow press first, is standard command-palette
        // behavior) - with 0 or 2+ still-ambiguous matches it does nothing,
        // keeping the "no action until the user agrees" property the whole
        // palette was built around.
        function activateAutocompleteSelection() {
            if (!isAutocompleteModalActive()) return false;
            if (autocompleteNavSelection && autocompleteNavSelection.isConnected) {
                autocompleteNavSelection.click();
            } else {
                const items = document.querySelectorAll('#autocompleteResults .autocomplete-item');
                if (items.length === 1) items[0].click();
            }
            return true;
        }
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                // Escape backs out one level at a time: close whatever's
                // open (a modal, the gear dropdown, a pivot menu) if
                // anything is, and only fall through to leaving the
                // analysis entirely (back to the welcome screen) once
                // there's nothing left to close - so a stray Escape while
                // closing a modal doesn't also yank the analysis out from
                // under it in the same keystroke. loadingModal is
                // deliberately excluded (closeAllModals() itself never
                // touches it either, to avoid abandoning an in-progress
                // analysis mid-load). Also skipped while typing (e.g.
                // cancelling the inline analysis-rename input, which has
                // its own Escape handler for that but doesn't
                // stopPropagation()) - Escape there should only cancel
                // the edit, not also abandon the whole analysis.
                const hadSomethingOpen = !!document.querySelector('.modal.active:not(#loadingModal)') ||
                    !!document.getElementById('appHeaderMenuDropdown')?.classList.contains('active') ||
                    !!activePivotMenuEl;
                closeAllModals();
                // closeAllModals() only closes .modal elements - the pivot
                // menu isn't one (it's append/remove'd from document.body
                // per open, see closePivotMenu()'s own comment), so it
                // needs its own explicit close call here. This used to live
                // in a separate keydown listener instead, registered
                // earlier in the file - which raced this one: on a single
                // Escape press, that listener always ran first and cleared
                // activePivotMenuEl before hadSomethingOpen could see it
                // was ever open, so this handler always computed
                // hadSomethingOpen === false and fell through to
                // showWelcome() - Escape closed the pivot menu AND kicked
                // back to the welcome screen in the same keystroke instead
                // of just closing the menu.
                closePivotMenu();
                const isTypingContext = e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable;
                if (!hadSomethingOpen && !isTypingContext) {
                    const isWelcome = isWelcomeScreen();
                    if (!isWelcome) {
                        showWelcome();
                    }
                }
            }
            if (e.key === '?' && isNavigableKeyContext(e)) {
                e.preventDefault();
                showHelpModal();
            }
            // '<'/'>' (not the 't' key formerly used here, and not arrow
            // keys either) - 't' collided with typing several of the
            // app's own theme cheat codes (e.g. "retro", "digit" both
            // contain a 't'), toggling the theme on every matching
            // keystroke while the cheat code was still being typed.
            // Arrow keys are reserved for real in-app navigation (stat
            // tabs, sample buttons, table rows), so this uses '<'/'>'
            // instead - reads naturally as previous/next (same
            // convention as media-player buttons) and collides with
            // neither.
            if (e.key === '>' && isNavigableKeyContext(e)) {
                e.preventDefault();
                toggleTheme();
            }
            if (e.key === '<' && isNavigableKeyContext(e)) {
                e.preventDefault();
                toggleThemeReverse();
            }
            // Left/Right no-op while the pivot menu is open rather than
            // falling through to stat-tab/sample-card navigation - the
            // menu is a single vertical list with nothing for Left/Right
            // to do, and letting them reach the page underneath would
            // switch tabs (rebuilding the very table the open menu's row
            // belongs to) while the menu is still sitting on screen.
            if (e.key === 'ArrowRight' && isNavigableKeyContext(e)) {
                if (!activePivotMenuEl && (navigateThemeTiles(1) || navigateStreamControls(1) || navigatePacketControls(1) || navigateFilterBarItems(1) || navigateAggPaginationButtons(1) || navigateAggTables(1) || (leftRightSwitchesStatTabs && navigateStatTabs(1)) || navigateSampleCards(1))) {
                    e.preventDefault();
                }
            }
            if (e.key === 'ArrowLeft' && isNavigableKeyContext(e)) {
                if (!activePivotMenuEl && (navigateThemeTiles(-1) || navigateStreamControls(-1) || navigatePacketControls(-1) || navigateFilterBarItems(-1) || navigateAggPaginationButtons(-1) || navigateAggTables(-1) || (leftRightSwitchesStatTabs && navigateStatTabs(-1)) || navigateSampleCards(-1))) {
                    e.preventDefault();
                }
            }
            // navigateAutocompleteItems()/isAutocompleteModalActive() checked
            // first, and with an extra "|| isAutocompleteModalActive()" on
            // the guard itself - the palette's own text input necessarily
            // has real DOM focus while it's open (unlike the pivot menu's
            // plain buttons), which isNavigableKeyContext() would otherwise
            // treat as "the user is typing, don't intercept arrows" and
            // block this whole block from running at all. navigatePivotMenuItems()
            // next for the same reason activateKeyboardSelection() checks
            // pivotMenuNavSelection first - an open menu is a transient
            // overlay, so Up/Down should drive it rather than the page
            // underneath while it's open. navigateStreamControlsVertical()/
            // navigatePacketControlsVertical() next, same precedence as
            // navigateStreamControls()/navigatePacketControls() above -
            // jump out of whichever horizontal group is selected before
            // falling through to navigateVertical()'s plain flat-list
            // stepping.
            if (e.key === 'ArrowDown' && (isNavigableKeyContext(e) || isAutocompleteModalActive())) {
                if (navigateAutocompleteItems(1) || navigatePivotMenuItems(1) || navigateThemeTiles(1, true) || navigateStreamControlsVertical(1) || navigatePacketControlsVertical(1) || navigateVertical(1)) {
                    e.preventDefault();
                }
            }
            if (e.key === 'ArrowUp' && (isNavigableKeyContext(e) || isAutocompleteModalActive())) {
                if (navigateAutocompleteItems(-1) || navigatePivotMenuItems(-1) || navigateThemeTiles(-1, true) || navigateStreamControlsVertical(-1) || navigatePacketControlsVertical(-1) || navigateVertical(-1)) {
                    e.preventDefault();
                }
            }
            if (e.key === 'Enter' && (isNavigableKeyContext(e) || isAutocompleteModalActive())) {
                if (activateKeyboardSelection()) {
                    e.preventDefault();
                }
            }
            // Type-ahead select for the Themes modal grid (see
            // handleThemeTileTypeahead() above) - checked ahead of the
            // command-palette trigger below purely for grouping (the
            // trigger's own !document.querySelector('.modal.active') guard
            // already excludes it whenever Themes is open regardless of
            // order).
            if (isNavigableKeyContext(e) && handleThemeTileTypeahead(e)) {
                e.preventDefault();
            }
            // Bare letter/digit trigger for the command palette (see
            // AUTOCOMPLETE_COMMANDS/openAutocompleteModal() above) - only
            // when nothing else is already open/focused, so it can't steal
            // a keystroke meant for a real text field, another modal, the
            // gear dropdown, or the pivot menu (all of which have their own
            // reasons to want every keystroke themselves).
            if (isNavigableKeyContext(e) && isAutocompleteTriggerKey(e) && !isAutocompleteModalActive() &&
                !document.querySelector('.modal.active') && !activePivotMenuEl &&
                !document.getElementById('appHeaderMenuDropdown')?.classList.contains('active')) {
                e.preventDefault();
                openAutocompleteModal(e.key.toLowerCase());
            }
        });

        // opts.sticky: skip the auto-dismiss timeout entirely - the toast
        // stays until the user clicks it. For messages that report an
        // unprompted, important state change (not the routine "Switched to
        // X theme" toasts), a fixed few-second timeout is a bad fit: the
        // user may not even be looking at the screen when it fires, and a
        // longer message needs more time to read than a short one -
        // rather than guess a duration, just wait for acknowledgement.
        // opts.actionLabel/opts.onAction: optional inline link shown after
        // the message; clicking it dismisses the toast and runs onAction.
        function showToast(message, opts) {
            opts = opts || {};
            document.querySelectorAll('.socrates-toast').forEach(t => t.remove());
            const toast = document.createElement('div');
            toast.className = 'socrates-toast';
            toast.style.cssText = 'position: fixed; bottom: 20px; right: 20px; background: var(--bg-secondary); color: var(--accent); border: 1px solid var(--accent); padding: 12px 20px; border-radius: 6px; font-family: inherit; z-index: 10000; box-shadow: 0 4px 12px rgba(0,0,0,0.3); transition: opacity 0.5s;';

            const text = document.createElement('span');
            text.textContent = message;
            toast.appendChild(text);

            function dismiss() {
                toast.style.opacity = '0';
                setTimeout(function() { toast.remove(); }, 500);
            }

            if (opts.actionLabel && opts.onAction) {
                const link = document.createElement('a');
                link.href = '#';
                link.textContent = opts.actionLabel;
                link.style.cssText = 'margin-left: 12px; color: var(--accent); text-decoration: underline; font-weight: 600;';
                link.onclick = function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    dismiss();
                    opts.onAction();
                };
                toast.appendChild(link);
            }

            document.body.appendChild(toast);

            if (opts.sticky) {
                toast.style.cursor = 'pointer';
                toast.addEventListener('click', dismiss);
            } else {
                setTimeout(dismiss, 3500);
            }
        }

        // Every file in a multi-file ZIP is analyzed (pcaps get network
        // analysis, everything else gets log/binary analysis - see
        // notifyIfAdditionalAnalyses below) - filesSkipped now only ever
        // means a file genuinely failed to process (unreadable, etc), not
        // a by-design drop. The server reports how many so a real failure
        // still isn't silent.
        function notifyIfFilesSkipped(result) {
            if (result && result.filesSkipped) {
                const plural = result.filesSkipped === 1 ? 'file' : 'files';
                showToast(`${result.filesSkipped} additional ${plural} in the ZIP could not be analyzed`, { sticky: true });
            }
        }

        // A multi-file ZIP's other files (beyond the primary one the user
        // is navigated into) are each analyzed as their own independent
        // analysis in the background - point the user at Recent Analyses
        // rather than leaving them to wonder where the results went.
        function notifyIfAdditionalAnalyses(result) {
            if (result && result.additionalMd5s && result.additionalMd5s.length) {
                const n = result.additionalMd5s.length;
                showToast(
                    `${n} additional file${n === 1 ? '' : 's'} found in the ZIP ${n === 1 ? 'is' : 'are'} also being analyzed`,
                    { sticky: true, actionLabel: 'View Recent Analyses', onAction: () => showWelcome() }
                );
            }
        }

        // A manually-installed (non-Docker/Podman) deployment starts with no
        // rules at all - unlike the container image, which bakes all three
        // rulesets in and copies them into place before the server ever
        // accepts a request. Nothing breaks without rules (each analyzer
        // degrades gracefully), but results are silently emptier than
        // expected with no indication why - nudge new manual installs at the
        // Rules modal once, rather than leaving them to discover this only
        // by noticing an analysis came back oddly empty.
        // Unconditional (not opt-in) - unlike checkForStaleRules() below,
        // which only nudges about rules that exist but have gone stale,
        // "nothing was ever downloaded" means every detection engine is
        // completely empty, important enough to always surface once
        // rather than gate behind a setting the user hasn't found yet.
        // Populated by checkForMissingRules() from /api/rules-info's
        // suricata.sidRanges - the single source of truth generated from
        // suricata_sid_ranges.SURICATA_SID_RANGES (see db.py's
        // sid_ranges_sql_case() for the server-side equivalent). null until
        // that fetch resolves; classifyRuleset() below handles that gap.
        // NOTE: must stay `var` (not let) so it attaches to the global
        // object - the JSDOM test harness assigns/reads it via separate
        // script evaluations, same reason as currentFilters/truncatedTypes.
        var SID_RANGES = null;

        // Best-effort mapping of an alert's signature_id to the curated
        // ruleset it most likely came from - client-side equivalent of
        // suricata_sid_ranges.classify_alert_ruleset(). Returns '' (not
        // 'Other / Unrecognized', which would misleadingly claim a real
        // classification) while SID_RANGES hasn't loaded yet.
        function classifyRuleset(sid) {
            if (sid === undefined || sid === null || !SID_RANGES) return '';
            const n = Number(sid);
            if (!Number.isFinite(n)) return '';
            for (const r of SID_RANGES) {
                if (n >= r.min && (r.max === null || n <= r.max)) return r.label;
            }
            return 'Other / Unrecognized';
        }

        async function checkForMissingRules() {
            try {
                const resp = await fetch('/api/rules-info');
                if (!resp.ok) return;
                const info = await resp.json();
                const noRules = info.suricata.count === null
                    && info.yara.count === null
                    && info.sigma.windows.count === null
                    && info.sigma.linux.count === null;
                if (noRules) {
                    showToast('No rulesets are configured yet — Suricata/YARA/Sigma detections will be empty until you set them up.', {
                        sticky: true,
                        actionLabel: 'Open Rules',
                        onAction: showRulesModal,
                    });
                }
                // Populates classifyRuleset()'s cache - this call is
                // fire-and-forget from init(), not awaited before
                // loadAnalysis(), so on a slow connection the alert table's
                // very first render could happen before this resolves (see
                // classifyRuleset()). Re-render the alert section if one is
                // already on screen so that race self-corrects immediately
                // instead of waiting for the next unrelated interaction.
                if (info.suricata.sidRanges) {
                    SID_RANGES = info.suricata.sidRanges;
                    if (document.getElementById('section-alert')) {
                        buildSection('alert', tabDataCache['alert'] || []);
                    }
                    if (document.getElementById('section-protocol_decode')) {
                        buildSection('protocol_decode', tabDataCache['protocol_decode'] || []);
                    }
                }
            } catch (e) {
                // Ignore - not worth surfacing an error over a background nudge
            }
        }

        const RULESET_LABELS = { suricata: 'Suricata', yara: 'YARA', sigma: 'Sigma' };

        let rulesPollInterval = null;
        // Separate 1s ticker just for the "Updating… Ns" elapsed-time
        // display, so it counts up every second instead of only jumping
        // every 2s alongside rulesPollInterval's actual network fetch.
        // Only runs while at least one ruleset update is actually in
        // progress (started/stopped from refreshRulesModal's own
        // anyRunning check below) - re-renders from cache, no extra
        // network calls.
        let rulesTickInterval = null;
        let rulesPrevRunning = { suricata: false, yara: false, sigma: false };
        // Client-side only (the server doesn't track a start timestamp) -
        // set the moment a ruleset is first observed running (either just
        // triggered, or already in flight when the modal is (re)opened) and
        // cleared once it's no longer running. Good enough for an
        // approximate elapsed-time display; reopening mid-update just
        // starts the count from the reopen, not the true start.
        let ruleUpdateStartTimes = { suricata: null, yara: null, sigma: null };
        // Log box is collapsed by default (during and after an update) -
        // "View Log" reveals it on demand rather than always showing the
        // raw streaming output, which read as noisy for a plain progress
        // indicator. Persists across poll ticks until explicitly toggled.
        let ruleLogExpanded = { suricata: false, yara: false, sigma: false };
        // 'success' | 'error' | null - set only on an observed running->done
        // transition (same signal the completion toast uses), never from the
        // server's default idle state ({running: false, done: true, error:
        // null} even before anything has ever been triggered) - otherwise
        // every ruleset would show a false checkmark on first load.
        let ruleLastResult = { suricata: null, yara: null, sigma: null };
        let lastRulesInfo = null;
        let lastRulesStatus = null;

        // name -> bool, which of info.suricata.availableSources the user has
        // checked. Only (re)synced from the server's enabledSources when the
        // modal is (re)opened (suricataSelectionInitialized reset in
        // closeRulesModal(), consumed once in refreshRulesModal()) - not on
        // every 2s poll tick, or an in-progress checkbox edit would get
        // stomped mid-click the same way staleThresholdDaysInput would if it
        // weren't guarded against the poll.
        let suricataSourceSelection = {};
        let suricataSelectionInitialized = false;
        let suricataSourcesExpanded = false;

        // Whether to leave Suricata's own bundled protocol-command-decode
        // event rules active (e.g. "SURICATA STREAM excessive
        // retransmissions") instead of suppressed - off by default, since
        // these are noisy built-in stream/decoder anomaly events bundled
        // identically into every source's own fetch, not a real per-source
        // ruleset choice. Re-synced from info.suricata.showProtocolDecodeAlerts
        // alongside suricataSourceSelection, guarded by the same
        // suricataSelectionInitialized flag (see its own comment above).
        let showProtocolDecodeAlerts = false;

        function formatRuleCount(count) {
            return (count === null || count === undefined) ? 'no rules found' : count.toLocaleString() + ' rules';
        }

        function formatRuleDate(epoch) {
            return epoch ? new Date(epoch * 1000).toLocaleString() : 'never';
        }

        // thresholdHours comes from /api/rules-info's staleThresholdHours
        // (server's config.RULES_MAX_AGE_HOURS) rather than a separate
        // hardcoded constant here - this used to be its own frontend-only
        // 30-day cutoff, independently of the backend's 'stale' field
        // (used by checkForStaleRules()'s notification), so the same
        // ruleset could show as fresh here while triggering that
        // notification, or vice versa. Both now agree by construction.
        function isRulesetStale(epoch, thresholdHours) {
            return !epoch || (Date.now() - epoch * 1000) > thresholdHours * 3600000;
        }

        // Flags an "updated" date as stale (or missing) so an analyst
        // notices at a glance without having to do the date math themselves.
        function formatDateSpan(epoch, thresholdHours) {
            const style = isRulesetStale(epoch, thresholdHours) ? ' style="color: var(--badge-warning-text);"' : '';
            return `<span${style}>${formatRuleDate(epoch)}</span>`;
        }

        // Canonical source for each ruleset - same projects/links listed in
        // docs/credits.md - shown in the Rules modal so an analyst knows
        // what they're pulling in before clicking Update.
        // Suricata deliberately excluded - unlike YARA/Sigma, it's no
        // longer a single fixed source now that sources are individually
        // enable/disable-able (see renderRuleSection()'s suricata-specific
        // branch below), so a single hardcoded "(Emerging Threats Open)"
        // link would misname whatever's actually enabled.
        const RULESET_SOURCES = {
            yara: { label: 'YARA Forge', url: 'https://github.com/YARAHQ/yara-forge' },
            sigma: { label: 'SigmaHQ', url: 'https://github.com/SigmaHQ/sigma' },
        };

        function formatElapsed(seconds) {
            if (seconds < 60) return `${seconds}s`;
            return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
        }

        function renderRuleSection(name, label, countText, statusEntry, isLast) {
            const logText = statusEntry.lines.join('\n');
            const source = RULESET_SOURCES[name];
            const expanded = ruleLogExpanded[name];
            const startTime = ruleUpdateStartTimes[name];
            const lastResult = ruleLastResult[name];
            const resultIcon = !statusEntry.running && lastResult
                ? `<span style="color: ${lastResult === 'error' ? 'var(--badge-danger-text)' : 'var(--badge-success-text)'};" title="${lastResult === 'error' ? 'Last update failed' : 'Last update succeeded'}">${lastResult === 'error' ? X_ICON_SVG : CHECKMARK_ICON_SVG}</span>`
                : '';
            // The Update button already reads "Updating…" while running, so
            // a separate line repeating "Updating…" alongside it (its only
            // other job being the elapsed-seconds counter) was pure
            // redundancy - the spinner+counter now render directly inside
            // the button itself instead (see updateButtonLabel below).
            const updateButtonLabel = statusEntry.running
                ? `<span class="rule-spinner"></span>Updating… ${startTime ? formatElapsed(Math.max(0, Math.round((Date.now() - startTime) / 1000))) : ''}`
                : 'Update';
            const logToggle = logText
                ? `<button data-action="toggle-rule-log" data-name="${escapeHtml(name)}" style="background: none; color: var(--accent); border: none; padding: 0; cursor: pointer; font-size: 0.8rem; text-decoration: underline;">${expanded ? 'Hide Log' : 'View Log'}</button>`
                : '';
            const sectionDivider = isLast ? '' : 'margin-bottom: 20px; padding-bottom: 15px; border-bottom: 1px solid var(--bg-hover);';
            // Suricata's heading link opens the sources picker
            // (toggleSuricataSources()) instead of linking to one
            // hardcoded source's site - see the RULESET_SOURCES comment
            // above for why a static "(Emerging Threats Open)" link would
            // be inaccurate now. This is the *only* trigger for the picker
            // - it used to be duplicated with a separate "Choose Rulesets"
            // button in renderSuricataSourcesSection(), which was pure
            // redundancy once this heading link did the same thing, so
            // that button was removed in favor of this one label reflecting
            // expanded/collapsed state.
            const sourceLink = source
                ? `<a href="${source.url}" target="_blank" rel="noopener noreferrer" style="color: var(--accent); text-decoration: none; font-size: 0.8rem; margin-left: 6px;">(${source.label})</a>`
                : `<button data-action="toggle-suricata-sources" style="background: none; color: var(--accent); border: none; padding: 0; cursor: pointer; font-size: 0.8rem; margin-left: 6px;">(${suricataSourcesExpanded ? 'Hide Rulesets' : 'Enable/Disable Rulesets'})</button>`;
            return `
                <div style="${sectionDivider}">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px; gap: 10px;">
                        <div>
                            <strong style="color: var(--text-bright);">${label}</strong>
                            ${sourceLink}
                            <span style="color: var(--text-muted); font-size: 0.9rem;"> — ${countText}</span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            ${resultIcon}
                            ${logToggle}
                            <button data-action="update-ruleset" data-arg="${escapeHtml(name)}" ${statusEntry.running ? 'disabled' : ''} style="background: var(--bg-hover); color: var(--text-primary); border: 1px solid var(--border-color); padding: 6px 14px; border-radius: 6px; cursor: pointer; white-space: nowrap;">${updateButtonLabel}</button>
                        </div>
                    </div>
                    ${expanded && logText ? `<div class="rule-update-log" data-ruleset="${name}">${escapeHtml(logText)}</div>` : ''}
                </div>
            `;
        }

        // Additive to renderRuleSection('suricata', ...) above - a
        // collapsible checkbox list of the curated free/non-commercial
        // suricata-update sources (info.suricata.availableSources, the
        // single source of truth read from the server so this never drifts
        // from suricata_analyzer.SURICATA_RULE_SOURCES). Collapsed by
        // default, same disclosure pattern as the update log's View/Hide Log.
        function renderSuricataSourcesSection(info) {
            const available = (info.suricata && info.suricata.availableSources) || {};
            const names = Object.keys(available);
            if (!names.length) return '';
            const rows = names.map(function(name) {
                const src = available[name];
                const checked = suricataSourceSelection[name] ? 'checked' : '';
                // Surfaces per-source caveats worth knowing before enabling
                // (e.g. ipfire/dbl's ~51 MiB / 30+ second first fetch) plus
                // a generic "needs internet the first time" callout for any
                // source bakedIn=false doesn't cover - both driven from
                // SURICATA_RULE_SOURCES/BAKED_IN_SURICATA_SOURCES server-side,
                // not hardcoded per-source here, so a future addition to
                // either automatically gets the same treatment.
                const notes = [];
                if (src.note) notes.push(src.note);
                if (src.bakedIn === false) notes.push("not included in the app image - needs internet the first time it's enabled");
                // An inline "WARNING!" marker with the detail in its title
                // tooltip, rather than always-visible text - a full note
                // rendered inline forced a horizontal scrollbar in this
                // list's narrow two-column layout (columns: 2 below). title
                // only reaches mouse users though - iOS/Android don't show
                // it on tap (no hover state) - so it's also a tap/click
                // target that shows the same text as a toast, which works
                // on touch.
                const noteText = notes.join(' - ');
                // data-action="show-source-note" (see STATIC_ACTIONS):
                // preventDefault keeps the click from toggling the
                // wrapping <label>'s checkbox, and the note text rides in
                // its own data-note attribute (escapeHtml'd - the HTML
                // parser decodes it back before dataset ever sees it).
                const noteHtml = notes.length
                    ? `<span title="${escapeHtml(noteText)}" data-action="show-source-note" data-note="${escapeHtml(noteText)}" style="color: var(--badge-warning-text); font-size: 0.7rem; font-weight: bold; cursor: help; white-space: nowrap;">WARNING!</span>`
                    : '';
                // break-inside: avoid keeps one entry from being split
                // across the column break below.
                // Same checkbox-as-slider markup/class as helpShowAgain and
                // every theme toggle (see .theme-switch/.theme-switch-slider
                // in socrates.css) - reused rather than a new style, so it
                // follows the current theme's palette like those already do.
                return `
                    <label style="display: flex; align-items: center; gap: 8px; padding: 4px 0; font-size: 0.85rem; color: var(--text-primary); cursor: pointer; break-inside: avoid;">
                        <span class="theme-switch">
                            <input type="checkbox" ${checked} data-change-action="suricata-source-toggle" data-name="${escapeHtml(name)}">
                            <span class="theme-switch-slider"></span>
                        </span>
                        <span>${escapeHtml(src.label)}</span>
                        <a href="${src.url}" target="_blank" rel="noopener noreferrer" style="color: var(--text-muted); font-size: 0.75rem; text-decoration: none;" data-action="stop-propagation">(source)</a>
                        ${noteHtml}
                    </label>`;
            }).join('');
            // Excludes any not-baked-in source (currently just IPFire DBL)
            // from "Enable All" rather than a blanket enable-everything -
            // same bakedIn criterion the WARNING! marker uses above, so the
            // button's label and its actual behavior can't drift apart, and
            // a future source in the same situation is automatically
            // excluded (and named here) too, without another code change.
            // Users are otherwise liable to click Enable All without ever
            // reading that source's warning and get hit with its slow first
            // fetch unexpectedly.
            const notBakedIn = names.filter(function(n) { return available[n].bakedIn === false; });
            const enableAllLabel = notBakedIn.length
                ? `Enable All (except ${notBakedIn.map(function(n) { return available[n].label; }).join(', ')})`
                : 'Enable All';
            const bulkLinks = `
                <div style="display: flex; justify-content: center; gap: 10px; margin-bottom: 6px;">
                    <button data-action="enable-all-suricata-sources" style="background: none; color: var(--accent); border: none; padding: 0; cursor: pointer; font-size: 0.75rem; text-decoration: underline;">${escapeHtml(enableAllLabel)}</button>
                    <button data-action="reset-suricata-sources" style="background: none; color: var(--accent); border: none; padding: 0; cursor: pointer; font-size: 0.75rem; text-decoration: underline;">Revert to Default (ET Open)</button>
                </div>`;
            // A classtype-based filter, not a per-source choice - every
            // curated source above bundles an identical copy of Suricata's
            // own built-in stream/decoder anomaly rules (e.g. "SURICATA
            // STREAM excessive retransmissions"), so this can't be one more
            // row in the per-source list. Off by default (matches
            // showProtocolDecodeAlerts's own default) - these events are
            // noise for most analysts, not a per-traffic-content alert.
            const decodeAlertsRow = `
                <div style="margin-bottom: 8px; padding-bottom: 8px; border-bottom: 1px solid var(--bg-hover);">
                    <label style="display: flex; align-items: center; gap: 8px; padding: 4px 0; font-size: 0.85rem; color: var(--text-primary); cursor: pointer;">
                        <span class="theme-switch">
                            <input type="checkbox" ${showProtocolDecodeAlerts ? 'checked' : ''} data-change-action="protocol-decode-toggle">
                            <span class="theme-switch-slider"></span>
                        </span>
                        <span>Show protocol-anomaly noise alerts <span style="color: var(--text-muted);">("Generic Protocol Command Decode", e.g. excessive retransmissions - off by default)</span></span>
                    </label>
                </div>`;
            // No trigger button here anymore - the Suricata heading's own
            // "(Enable/Disable Rulesets)"/"(Hide Rulesets)" link
            // (renderRuleSection()) is the only way to expand/collapse
            // this, so when collapsed there's nothing to render at all.
            return suricataSourcesExpanded
                ? `<div style="margin-top: 8px;">${decodeAlertsRow}${bulkLinks}<div class="suricata-sources-list" style="columns: 2; column-gap: 16px; max-height: 260px; overflow-y: auto; border: 1px solid var(--bg-hover); border-radius: 6px; padding: 4px 12px;">${rows}</div></div>`
                : '';
        }

        // Only one of the three per-ruleset logs and the Suricata sources
        // list may be open at a time - opening any of them collapses
        // whichever of the other three was open, so the modal's total
        // height stays bounded instead of stacking multiple long disclosed
        // sections and forcing a vertical scrollbar.
        function collapseAllRulesDisclosures() {
            ruleLogExpanded = { suricata: false, yara: false, sigma: false };
            suricataSourcesExpanded = false;
        }

        function toggleSuricataSources() {
            const opening = !suricataSourcesExpanded;
            collapseAllRulesDisclosures();
            suricataSourcesExpanded = opening;
            reRenderRulesModalFromCache();
        }

        function handleSuricataSourceToggle(name, checked) {
            suricataSourceSelection[name] = checked;
        }

        function handleShowProtocolDecodeAlertsToggle(checked) {
            showProtocolDecodeAlerts = checked;
        }

        // Skips any not-baked-in source (bakedIn === false) - see the
        // enableAllLabel comment in renderSuricataSourcesSection() for why:
        // the button's own label names exactly what this skips, driven from
        // the same bakedIn field, so they can't disagree.
        function enableAllSuricataSources() {
            const available = (lastRulesInfo && lastRulesInfo.suricata && lastRulesInfo.suricata.availableSources) || {};
            Object.keys(available).forEach(function(name) {
                suricataSourceSelection[name] = available[name].bakedIn !== false;
            });
            reRenderRulesModalFromCache();
        }

        // Checks et/open and unchecks everything else, rather than
        // unchecking everything - an all-unchecked state used to be how
        // "Disable All" worked, relying on _reconcile_suricata_sources()'s
        // empty-selection fallback to DEFAULT_SURICATA_SOURCES (['et/open'])
        // once Update was actually clicked. That left the checkboxes lying
        // about the pending state: closing the modal without clicking
        // Update (nothing was ever POSTed) and reopening it re-synced
        // suricataSourceSelection from the server's still-unchanged
        // enabledSources, so et/open silently reappeared checked. Checking
        // it here up front keeps the checkbox truthful before *and* after
        // Update is clicked.
        function resetSuricataSourcesToDefault() {
            const available = (lastRulesInfo && lastRulesInfo.suricata && lastRulesInfo.suricata.availableSources) || {};
            // Server-provided, not hardcoded here - DEFAULT_SURICATA_SOURCES
            // in suricata_analyzer.py is the single source of truth (see
            // /api/rules-info's defaultSources field), same reasoning as
            // reading bakedIn instead of hardcoding which sources are
            // baked in.
            const defaultSources = (lastRulesInfo && lastRulesInfo.suricata && lastRulesInfo.suricata.defaultSources) || [];
            Object.keys(available).forEach(function(name) {
                suricataSourceSelection[name] = defaultSources.includes(name);
            });
            reRenderRulesModalFromCache();
        }

        function toggleRuleLog(name) {
            const opening = !ruleLogExpanded[name];
            collapseAllRulesDisclosures();
            ruleLogExpanded[name] = opening;
            reRenderRulesModalFromCache();
        }

        function renderRulesModalBody(info, status) {
            const t = _resolveStaleThresholdHours(info.staleThresholdHours);
            const suricataText = `${formatRuleCount(info.suricata.count)} — updated ${formatDateSpan(info.suricata.updated, t)}`;
            const yaraText = `${formatRuleCount(info.yara.count)} — updated ${formatDateSpan(info.yara.updated, t)}`;
            // Combined into one count/date like Suricata/YARA - Windows and
            // Linux stay two separate underlying files (analysis still
            // auto-picks the matching one per artifact, see detect_os() in
            // sigma_analyzer.py), this only changes what's *reported* here.
            // null total only when neither has ever been downloaded; the
            // reported "updated" is the older of the two dates present
            // (mirrors get_suricata_rules_info()'s "oldest active file"
            // convention - the least-fresh ruleset is what should count as
            // stale, not whichever happened to refresh most recently).
            const sigmaTotalCount = (info.sigma.windows.count === null && info.sigma.linux.count === null)
                ? null
                : (info.sigma.windows.count || 0) + (info.sigma.linux.count || 0);
            const sigmaUpdated = [info.sigma.windows.updated, info.sigma.linux.updated]
                .filter(function(e) { return e !== null && e !== undefined; })
                .sort(function(a, b) { return a - b; })[0] ?? null;
            const sigmaText = `${formatRuleCount(sigmaTotalCount)} — updated ${formatDateSpan(sigmaUpdated, t)}`;
            // Ordered shortest-to-longest output (YARA/Sigma are a couple
            // lines; Suricata's suricata-update log can run to dozens of
            // lines) so the two quick summaries are visible without
            // scrolling past the long, variable-length Suricata log first.
            return (
                renderRuleSection('yara', RULESET_LABELS.yara, yaraText, status.yara, false) +
                renderRuleSection('sigma', RULESET_LABELS.sigma, sigmaText, status.sigma, false) +
                renderRuleSection('suricata', RULESET_LABELS.suricata, suricataText, status.suricata, true) +
                renderSuricataSourcesSection(info)
            );
        }

        // Replacing innerHTML wholesale on every poll tick would otherwise
        // reset each log box's scroll position to the top every ~2s
        // indefinitely (polling never stops while the modal is open) -
        // keyed by ruleset name (not index) since a ruleset's log box only
        // exists once it has lines, so the set of visible boxes can change
        // between ticks. Factored out from refreshRulesModal so
        // toggleRuleLog() can re-render from the last-fetched data
        // instantly, without waiting on a fresh fetch just to flip a
        // View/Hide Log button.
        function renderRulesModalBodyIntoDom(info, status) {
            const modalBody = document.getElementById('rulesModalBody');
            // Replacing innerHTML destroys any in-progress text selection
            // (e.g. the user highlighting a log line to copy it) even though
            // the visible text is unchanged - a fresh DOM node isn't the same
            // node the Selection API is anchored to. Skip this tick entirely
            // while the user has an active selection inside the modal, same
            // "don't yank it out from under them" idea as refreshRulesModal's
            // document.activeElement guard on the days input.
            const selection = window.getSelection();
            if (selection && !selection.isCollapsed && modalBody.contains(selection.anchorNode)) {
                return;
            }
            const scrollPositions = {};
            modalBody.querySelectorAll('.rule-update-log').forEach(function(el) {
                scrollPositions[el.dataset.ruleset] = el.scrollTop;
            });
            // Same problem as the log boxes above - the checkbox list is
            // its own scrollable container (see renderSuricataSourcesSection)
            // and gets wiped by the innerHTML replacement below on every 2s
            // poll tick just like they do.
            const sourcesListEl = modalBody.querySelector('.suricata-sources-list');
            const sourcesScrollTop = sourcesListEl ? sourcesListEl.scrollTop : null;
            modalBody.innerHTML = renderRulesModalBody(info, status);
            modalBody.querySelectorAll('.rule-update-log').forEach(function(el) {
                if (el.dataset.ruleset in scrollPositions) {
                    el.scrollTop = scrollPositions[el.dataset.ruleset];
                }
            });
            if (sourcesScrollTop !== null) {
                const newSourcesListEl = modalBody.querySelector('.suricata-sources-list');
                if (newSourcesListEl) newSourcesListEl.scrollTop = sourcesScrollTop;
            }
        }

        // Shared by every client-side-only change (log toggle, source
        // checkbox, threshold input) that wants the modal to reflect it
        // immediately from the last-fetched data, without waiting on the
        // next 2s poll tick. A no-op before the first successful poll,
        // since there's nothing cached yet to re-render.
        function reRenderRulesModalFromCache() {
            if (lastRulesInfo && lastRulesStatus) {
                renderRulesModalBodyIntoDom(lastRulesInfo, lastRulesStatus);
            }
        }

        // Polls while the modal is open (stops on close) rather than
        // continuing in the background like the old single-job modal did -
        // three independent completion timers isn't worth the complexity;
        // the jobs themselves keep running server-side regardless, and
        // reopening the modal always reflects current truth.
        async function refreshRulesModal() {
            try {
                const [infoResp, statusResp] = await Promise.all([
                    fetch('/api/rules-info'),
                    fetch('/api/rule-update-status'),
                ]);
                const info = await infoResp.json();
                const status = await statusResp.json();
                if (!suricataSelectionInitialized) {
                    suricataSourceSelection = {};
                    (info.suricata.enabledSources || []).forEach(function(name) {
                        suricataSourceSelection[name] = true;
                    });
                    showProtocolDecodeAlerts = !!info.suricata.showProtocolDecodeAlerts;
                    suricataSelectionInitialized = true;
                }
                ['suricata', 'yara', 'sigma'].forEach(function(name) {
                    if (status[name].running && !ruleUpdateStartTimes[name]) {
                        ruleUpdateStartTimes[name] = Date.now();
                    } else if (!status[name].running) {
                        ruleUpdateStartTimes[name] = null;
                    }
                    if (rulesPrevRunning[name] && !status[name].running) {
                        ruleLastResult[name] = status[name].error ? 'error' : 'success';
                        showToast(status[name].error
                            ? (RULESET_LABELS[name] + ' update error: ' + status[name].error)
                            : (RULESET_LABELS[name] + ' rules updated'));
                    }
                    rulesPrevRunning[name] = status[name].running;
                });
                lastRulesInfo = info;
                lastRulesStatus = status;
                renderRulesModalBodyIntoDom(info, status);
                const anyRunning = ['suricata', 'yara', 'sigma'].some(n => status[n].running);
                document.getElementById('updateAllRulesBtn').disabled = anyRunning;
                if (anyRunning && !rulesTickInterval) {
                    rulesTickInterval = setInterval(reRenderRulesModalFromCache, 1000);
                } else if (!anyRunning && rulesTickInterval) {
                    clearInterval(rulesTickInterval);
                    rulesTickInterval = null;
                }
                // Reflects the effective threshold (override if set, else
                // the server default) - but never while the user has this
                // field focused, since refreshRulesModal() polls every 2s
                // and would otherwise yank a value they're mid-typing.
                const daysInput = document.getElementById('staleThresholdDaysInput');
                if (daysInput && document.activeElement !== daysInput) {
                    daysInput.value = getUserStaleThresholdDays() ?? Math.round(info.staleThresholdHours / 24);
                }
            } catch (e) {
                // Ignore -- next poll will retry.
            }
        }

        // expandSuricataSources: true opens the modal with the sources
        // picker already expanded (e.g. the welcome help table's "Multiple
        // Rulesets" link) rather than requiring an extra click on "(Show
        // Rulesets)" once the modal is already open. Must be set before
        // refreshRulesModal()'s first render below, not after.
        async function showRulesModal(expandSuricataSources) {
            closeOtherMenuModals('rulesModal');
            document.getElementById('checkForStaleRules').checked = safeStorageGet(localStorage, 'socrates_checkForStaleRules') === 'true';
            if (expandSuricataSources) {
                collapseAllRulesDisclosures();
                suricataSourcesExpanded = true;
            }
            document.getElementById('rulesModal').classList.add('active');
            await refreshRulesModal();
            if (!rulesPollInterval) {
                rulesPollInterval = setInterval(refreshRulesModal, 2000);
            }
        }

        function closeRulesModal() {
            document.getElementById('rulesModal').classList.remove('active');
            if (rulesPollInterval) {
                clearInterval(rulesPollInterval);
                rulesPollInterval = null;
            }
            if (rulesTickInterval) {
                clearInterval(rulesTickInterval);
                rulesTickInterval = null;
            }
            // Re-sync the checkbox selection from the server next time the
            // modal opens, in case another tab/session changed it.
            suricataSelectionInitialized = false;
        }

        async function triggerRulesetUpdate(name) {
            const body = { ruleset: name };
            if (name === 'suricata' || name === 'all') {
                body.sources = Object.keys(suricataSourceSelection).filter(k => suricataSourceSelection[k]);
                body.showProtocolDecodeAlerts = showProtocolDecodeAlerts;
            }
            await fetch('/api/update-rules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
            await refreshRulesModal();
            // Only (re)start polling if the modal is still open - closing it
            // (Escape/backdrop/close button) while this fetch/refresh was
            // still in flight already cleared rulesPollInterval, and restarting
            // it here unconditionally would leak an indefinite background
            // poll of a hidden modal.
            const rulesModal = document.getElementById('rulesModal');
            if (!rulesPollInterval && rulesModal && rulesModal.classList.contains('active')) {
                rulesPollInterval = setInterval(refreshRulesModal, 2000);
            }
        }

        async function toggleDiagram() {
            diagramMode = !diagramMode;
            if (diagramMode) {
                const visibleSection = document.querySelector('.section:not(.section-hidden):not(.agg-section)');
                const eventType = visibleSection ? visibleSection.id.replace('section-', '') : null;
                if (eventType && eventType !== 'sigmaalert' && eventType !== 'log'
                    && Object.keys(currentFilters).length > 0) {
                    await ensureCappedBatch(eventType);
                }
            }
            updateFilterBarVisibility();
            await updateSankeyDiagram();
        }

        async function toggleAggregations() {
            advancedMode = !advancedMode;
            const visibleSection = document.querySelector('.section:not(.section-hidden):not(.agg-section)');
            if (!visibleSection) {
                // Binary analysis mode: no tab sections, rebuild aggregations directly
                if (advancedMode) {
                    hiddenAggregations = new Set();
                    aggPage = {}; aggFullCountsCache = {}; aggTotalsCache = {};
                    await rebuildVisibleAggregations();
                } else {
                    const aggContainer = document.getElementById('aggregations');
                    if (aggContainer) aggContainer.innerHTML = AGG_COLLAPSED_HTML;
                }
                updateFilterBarVisibility();
                return;
            }
            if (advancedMode) {
                hiddenAggregations = new Set();
                aggPage = {}; aggFullCountsCache = {}; aggTotalsCache = {};
                await rebuildVisibleAggregations();
            } else {
                const aggContainer = document.getElementById('aggregations');
                if (aggContainer) {
                    aggContainer.innerHTML = AGG_COLLAPSED_HTML;
                }
            }
            updateFilterBarVisibility();
        }
        
        const typeLabels = {
            alert: 'Network Alerts',
            anomaly: 'Anomalies',
            protocol_decode: 'Decoder Alerts',
            dns: 'DNS Queries',
            dns_heuristics: 'DNS Heuristics',
            filealerts: 'File Alerts',
            fileinfo: 'File Info',
            flow: 'Flows',
            ftp: 'FTP',
            http: 'HTTP',
            log: 'Log Events',
            sigmaalert: 'Sigma Alerts',
            stats: 'Stats',
            tls: 'TLS',
            // Every other event_type falls back to type.toUpperCase() below
            // (e.g. 'smtp' -> 'SMTP'), which is fine for a single short
            // word/acronym - but bittorrent_dht and ftp_data are the only
            // two raw type names with an underscore, and .stat-label's
            // word-break: keep-all (so ordinary words never wrap mid-word)
            // means an underscore-joined fallback can't wrap at all,
            // overflowing a narrow stat-card (e.g. "BITTORRENT_DHT" on a
            // sample with 20+ event types squeezing the grid). A real
            // space here gives the label a wrap point like every other
            // multi-word entry above already has.
            bittorrent_dht: 'BitTorrent DHT',
            ftp_data: 'FTP Data'
        };
        
        function buildSankeyData(events) {
            const nodeMap = new Map();
            const linkMap = new Map();

            function getNodeId(name, column) {
                return column + ':' + name;
            }

            function addNode(name, column) {
                const id = getNodeId(name, column);
                if (!nodeMap.has(id)) {
                    nodeMap.set(id, { id: id, name: name, column: column });
                }
                return id;
            }

            function addLink(sourceId, targetId) {
                const key = sourceId + '->' + targetId;
                if (!linkMap.has(key)) {
                    linkMap.set(key, { source: sourceId, target: targetId, value: 0 });
                }
                linkMap.get(key).value += 1;
            }

            for (const e of events) {
                if (!e || e.event_type === 'stats') continue;
                const src = e.src_ip || '?';
                const dst = e.dest_ip || '?';
                const port = String(e.dest_port || '?');
                const srcId = addNode(src, 0);
                const dstId = addNode(dst, 1);
                const portId = addNode(port, 2);
                addLink(srcId, dstId);
                addLink(dstId, portId);
            }

            function capColumn(columnIndex, limit) {
                const columnNodes = Array.from(nodeMap.values()).filter(n => n.column === columnIndex);
                if (columnNodes.length <= limit) return;
                columnNodes.sort((a, b) => {
                    const av = Array.from(linkMap.values()).filter(l => l.source === a.id || l.target === a.id).reduce((s, l) => s + l.value, 0);
                    const bv = Array.from(linkMap.values()).filter(l => l.source === b.id || l.target === b.id).reduce((s, l) => s + l.value, 0);
                    return bv - av;
                });
                const otherId = addNode('Other', columnIndex);

                for (const node of columnNodes.slice(limit)) {
                    nodeMap.delete(node.id);
                }

                const newLinks = new Map();
                for (const [key, link] of linkMap) {
                    const s = link.source;
                    const t = link.target;
                    const sExists = nodeMap.has(s);
                    const tExists = nodeMap.has(t);
                    if (sExists && tExists) {
                        newLinks.set(key, link);
                    } else if (!sExists && tExists) {
                        const newKey = otherId + '->' + t;
                        const existing = newLinks.get(newKey);
                        if (existing) { existing.value += link.value; }
                        else { newLinks.set(newKey, { source: otherId, target: t, value: link.value }); }
                    } else if (sExists && !tExists) {
                        const newKey = s + '->' + otherId;
                        const existing = newLinks.get(newKey);
                        if (existing) { existing.value += link.value; }
                        else { newLinks.set(newKey, { source: s, target: otherId, value: link.value }); }
                    }
                }
                linkMap.clear();
                for (const [k, v] of newLinks) { linkMap.set(k, v); }
            }

            for (let i = 0; i < 3; i++) {
                capColumn(i, CONFIG.SANKEY_MAX_NODES_PER_COLUMN);
            }

            return { nodes: Array.from(nodeMap.values()), links: Array.from(linkMap.values()) };
        }

        function renderSankeySVG(data, container) {
            const width = container.clientWidth || 900;
            const nodesByCol = [[], [], []];
            for (const n of data.nodes) { nodesByCol[n.column].push(n); }
            const maxColNodes = Math.max(nodesByCol[0].length, nodesByCol[1].length, nodesByCol[2].length);
            const minNodeH = 8;
            const nodeGap = 4;
                    const height = Math.max(400, maxColNodes * (minNodeH + nodeGap) + CONFIG.SANKEY_BOTTOM_MARGIN);
            container.innerHTML = '';

            if (!data.nodes.length) return;

            const svg = d3.select(container).append('svg')
                .attr('class', 'sankey-svg')
                .attr('width', width)
                .attr('height', height)
                .attr('viewBox', [0, 0, width, height]);

            const nodeIndex = new Map();
            data.nodes.forEach((n, i) => nodeIndex.set(n.id, i));

            const graph = {
                nodes: data.nodes.map(n => ({ name: n.name, column: n.column })),
                links: data.links.map(l => ({
                    source: nodeIndex.get(l.source),
                    target: nodeIndex.get(l.target),
                    value: l.value
                }))
            };

            const sankey = d3.sankey()
                .nodeWidth(18)
                .nodePadding(nodeGap)
                .extent([[30, 35], [width - 30, height - 10]]);

            let { nodes, links } = sankey(graph);

            function ipToColor(ip) {
                let hash = 0;
                for (let i = 0; i < ip.length; i++) { hash = ((hash << 5) - hash) + ip.charCodeAt(i); }
                return 'hsl(' + (Math.abs(hash) % 360) + ', 70%, 60%)';
            }

            const linkGroup = svg.append('g');
            linkGroup.selectAll('path')
                .data(links)
                .join('path')
                .attr('class', 'sankey-link')
                .attr('d', d3.sankeyLinkHorizontal())
                .attr('stroke', d => ipToColor(d.source.name))
                .attr('stroke-width', d => Math.max(d.width, 1))
                .on('click', function(event, d) {
                    const visibleSection = document.querySelector('.section:not(.section-hidden):not(.agg-section)');
                    if (!visibleSection) return;
                    applyFilters(visibleSection.id, [
                        {column: getColumnNameFromSankeyColumn(d.source.column), value: d.source.name},
                        {column: getColumnNameFromSankeyColumn(d.target.column), value: d.target.name}
                    ]);
                })
                .append('title')
                .text(d => d.source.name + ' \u2192 ' + d.target.name + ' (' + d.value + ')');

            const nodeGroup = svg.append('g')
                .selectAll('g')
                .data(nodes)
                .join('g')
                .attr('class', 'sankey-node')
                .attr('transform', d => 'translate(' + d.x0 + ',' + d.y0 + ')');

            nodeGroup.append('rect')
                .attr('height', d => d.y1 - d.y0)
                .attr('width', d => d.x1 - d.x0)
                .on('click', function(event, d) {
                    const visibleSection = document.querySelector('.section:not(.section-hidden):not(.agg-section)');
                    if (!visibleSection) return;
                    applyFilters(visibleSection.id, [
                        {column: getColumnNameFromSankeyColumn(d.column), value: d.name}
                    ]);
                })
                .append('title')
                .text(d => d.name + ' (' + d.value + ')');

            nodeGroup.append('text')
                .attr('x', d => d.x0 < width / 2 ? (d.x1 - d.x0) + 5 : -5)
                .attr('y', d => (d.y1 - d.y0) / 2)
                .attr('dy', '0.35em')
                .attr('text-anchor', d => d.x0 < width / 2 ? 'start' : 'end')
                .style('opacity', d => (d.y1 - d.y0) >= minNodeH ? 1 : 0)
                .text(d => {
                    const label = d.name + ' (' + d.value + ')';
                    return label.length > 24 ? d.name.slice(0, 21) + '\u2026 (' + d.value + ')' : label;
                });

            const colLabels = ['Source IP', 'Dest IP', 'Dest Port'];
            const colCenters = [0, 1, 2].map(i => {
                const colNodes = nodes.filter(n => n.column === i);
                if (!colNodes.length) return width * (i + 0.5) / 3;
                return d3.mean(colNodes, n => (n.x0 + n.x1) / 2);
            });

            svg.append('g')
                .selectAll('text')
                .data(colLabels)
                .join('text')
                .attr('class', 'sankey-title')
                .attr('x', (d, i) => colCenters[i])
                .attr('y', 20)
                .attr('text-anchor', 'middle')
                .text(d => d);
        }

        function getSankeyEvents() {
            const visibleSection = document.querySelector('.section:not(.section-hidden):not(.agg-section)');
            if (!visibleSection) return [];
            const eventType = visibleSection.id.replace('section-', '');
            if (eventType === 'all') {
                return getFilteredEvents(visibleSection.id, allEvents, 'all');
            }
            const events = tabDataCache[eventType] || [];
            return getFilteredEvents(visibleSection.id, events, eventType);
        }

        async function updateSankeyDiagram() {
            const sankeyPanel = document.getElementById('sankeyPanel');
            if (!sankeyPanel) return;
            sankeyPanel.innerHTML = '';

            if (!diagramMode) {
                sankeyPanel.innerHTML = '<div class="section-toggle-bar" data-action="toggle-diagram">▸ Sankey Diagram</div>';
                return;
            }

            sankeyPanel.innerHTML = '<div class="section-toggle-bar" data-action="toggle-diagram">▾ Sankey Diagram</div><div style="padding:20px;color:var(--text-muted);display:flex;align-items:center;gap:8px;"><span class="ascii-loading"></span>Loading Sankey diagram...</div>';

            const visibleSection = document.querySelector('.section:not(.section-hidden):not(.agg-section)');
            const eventType = visibleSection ? visibleSection.id.replace('section-', '') : null;

            // bumpSankeyFetchGeneration(), not bumpFetchGeneration() - see
            // that counter's own comment for why Sankey staleness must not
            // be tracked against the shared one.
            const gen = bumpSankeyFetchGeneration();
            let data;
            try {
                if (canUseServerSankey(eventType)) {
                    data = await fetchSankeyData(eventType);
                } else {
                    data = buildSankeyData(getSankeyEvents());
                }
            } catch (e) {
                // Without this, a network hiccup or a bad/oversized
                // response on a large sample (e.g. a 200K+ event analysis)
                // left the panel stuck on "Loading Sankey diagram..."
                // forever - the "Loading..." markup was already written
                // above and nothing downstream ever ran to replace it.
                if (isStaleSankeyFetch(gen)) return;
                console.error('Failed to load Sankey diagram:', e);
                sankeyPanel.innerHTML = '<div class="section-toggle-bar" data-action="toggle-diagram">▾ Sankey Diagram</div><div style="padding:20px;color:var(--text-muted);">Error loading Sankey diagram</div>';
                return;
            }
            if (isStaleSankeyFetch(gen)) return;

            if (!data || !data.nodes || data.nodes.length === 0) {
                sankeyPanel.innerHTML = '<div class="section-toggle-bar" data-action="toggle-diagram">▾ Sankey Diagram</div>';
                return;
            }
            sankeyPanel.innerHTML = '<div class="section-toggle-bar" data-action="toggle-diagram">▾ Sankey Diagram</div><div class="sankey-content"></div>';
            const svgContainer = sankeyPanel.querySelector('.sankey-content');
            renderSankeySVG(data, svgContainer);
        }

        function getColumnsForType(eventType) {
            switch(eventType) {
                case 'alert':
                case 'protocol_decode':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Alert', 'Category', 'Ruleset', 'Severity'];
                case 'dns':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Query', 'Type'];
                case 'http':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Method', 'Host', 'URL', 'User-Agent', 'Status'];
                case 'tls':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'SNI / Host', 'Version', 'Subject', 'Issuer'];
                case 'flow':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Pkts →', 'Pkts ←', 'Bytes →', 'Bytes ←', 'State', 'Alerted'];
                case 'fileinfo':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Filename'];
                case 'filealerts':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Rule Name', 'Tags'];
                case 'modbus':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Function', 'Unit ID', 'Access Type', 'Category', 'Error Flags'];
                case 'dnp3':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Type', 'Source Addr', 'Dest Addr', 'Function'];
                case 'pgsql':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Query', 'Command', 'Rows', 'SSL'];
                case 'enip':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Command', 'Status'];
                case 'log': {
                    const logEvents = tabDataCache['log'] || [];
                    const cols = discoverLogColumns(logEvents);
                    const labels = ['Time'];
                    cols.forEach(c => labels.push(c.label));
                    labels.push('Detail');
                    return labels;
                }
                case 'sigmaalert':
                    return ['Time', 'Severity', 'Rule', 'MITRE Technique', 'Log Source'];
                case 'quic':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'SNI', 'QUIC Version', 'JA3', 'JA3S'];
                case 'dhcp':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'DHCP Type', 'Client MAC', 'Assigned IP', 'Hostname'];
                case 'ftp_data':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'FTP Command', 'Filename'];
                case 'smb':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'SMB Command', 'Filename', 'Share', 'SMB User'];
                case 'ssh':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Client Version', 'Server Version'];
                case 'krb5':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Client', 'Service', 'Realm', 'Error Code'];
                case 'sip':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'SIP Method', 'URI', 'SIP Code', 'Reason'];
                case 'snmp':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'SNMP Version', 'PDU Type', 'Community'];
                case 'mqtt':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'MQTT Type', 'Topic', 'Client ID'];
                case 'dcerpc':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Interface UUID', 'Opnum', 'Call ID'];
                case 'rdp':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'RDP Event', 'Cookie', 'Client Name'];
                case 'tftp':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Packet', 'File', 'Mode'];
                case 'ike':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Exchange Type', 'IKE Version', 'Init SPI'];
                case 'nfs':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Procedure', 'Filename'];
                case 'rfb':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Client Version', 'Server Version', 'Security Type'];
                case 'bittorrent_dht':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Request Type', 'Info Hash'];
                case 'smtp':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Helo', 'Mail From', 'Rcpt To'];
                case 'ftp':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Command', 'Command Data', 'Completion Code', 'Reply'];
                case 'anomaly':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Event', 'Type', 'Layer', 'App Proto'];
                case 'ntp':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Version', 'Mode', 'Stratum', 'Reference ID'];
                case 'websocket':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Opcode', 'Fin', 'Payload'];
                case 'pop3':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Command', 'Args', 'Status'];
                case 'mdns':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Query', 'Type'];
                case 'ldap':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Operation', 'Message ID', 'Result Code'];
                case 'arp':
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Opcode', 'Src MAC', 'Dest MAC'];
                case 'all':
                    return ALL_EVENTS_COLUMNS;
                default:
                    return ['Time', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port'];
            }
        }
        
        // A fixed, unlabeled trailing note-icon cell shared by every row
        // renderer - not one of the sortable `columns` a table declares
        // (adding it there would shift every sort-column index), so it's
        // baked directly into each renderer's own markup and into
        // renderPaginatedTable's header instead.
        //
        // Only rendered for a row that already HAS a note - same
        // omit-entirely convention as the Previous Analyses list's own
        // notes button (has_notes: false -> no button at all), rather than
        // a muted-vs-accent color distinction that's hard to tell apart on
        // some themes. A note-less row shows nothing here; adding a first
        // note happens from the expanded detail panel instead (see
        // rowNoteDetailHtml below), not from this collapsed-row cell.
        //
        // id is passed through escapeHtml like note, not interpolated
        // raw, even though it's always a real SQL integer in production -
        // same "escape every attribute value regardless of expected type"
        // convention buildLogEventRow/buildSigmaAlertRow already use for
        // their own detailId. openRowNoteEditor parses it back to a number.
        // The <td>'s own data-action="row-note-cell" (a preventDefault/
        // stopPropagation no-op in STATIC_ACTIONS) shadows the row's
        // 'toggle-row' action for clicks that land in the cell but miss
        // the icon - the dispatcher only ever runs the CLOSEST
        // data-action - matching the old behavior where such clicks
        // never expanded the row.
        function rowNoteIconHtml(table, id, note) {
            if (!(note && note.trim())) return '<td class="row-note-cell"></td>';
            const preview = note.slice(0, 200);
            return `<td class="row-note-cell" data-action="row-note-cell"><span class="row-note-icon" data-action="open-row-note-editor" data-table="${escapeHtml(table)}" data-row-id="${escapeHtml(String(id))}" data-note="${escapeHtml(note)}" title="${escapeHtml(preview)}" style="cursor: pointer; color: var(--accent);">${NOTES_ICON_SVG}</span></td>`;
        }

        // The value half of the detail panel's Note row, split out from
        // rowNoteDetailHtml below so saveAnalysisNotes() can refresh just
        // this span in place after a save - the detail panel is rendered
        // once and only toggled visible/hidden (see toggleRow), not
        // re-rendered on each expand, so without this the panel would go
        // on showing the pre-save "+ Add Note" link/stale text until the
        // whole table next re-renders. The "detail-value" class matches
        // every other value cell's styling; "row-note-detail-value" is the
        // stable hook for that in-place replacement.
        function rowNoteDetailValueHtml(table, id, note) {
            const has = !!(note && note.trim());
            const editLink = `<a href="#" class="row-note-edit-link" data-action="open-row-note-editor" data-table="${escapeHtml(table)}" data-row-id="${escapeHtml(String(id))}" data-note="${escapeHtml(note || '')}" style="color: var(--accent); text-decoration: none;">${has ? 'Edit' : '+ Add Note'}</a>`;
            const value = has ? `${escapeHtml(note)} ${editLink}` : editLink;
            return `<span class="detail-value row-note-detail-value">${value}</span>`;
        }

        // The "Add Note" / "Edit Note" row for an expanded detail panel -
        // embeds directly into an already-open display:grid detail
        // section, preceded by its own section divider (same htmlSection
        // convention as "Connection"/"Alert Details"/"DNS Details" etc.)
        // so it reads as a distinct section rather than one more row
        // blended into whatever type-specific section happens to precede
        // it. A fixed accent color (not a per-event-type COLORS.EVENT
        // entry) since this section means the same thing regardless of
        // which event type it's attached to, and ties visually to the
        // note icon/links, which already use the same color. The
        // label/value pair after it is a plain span pair, same shape
        // htmlRow produces (not reused directly since the value half
        // needs its own targetable class - see rowNoteDetailValueHtml
        // above). This is the ONLY way to add a first note to a row (see
        // rowNoteIconHtml above); editing an existing one works from
        // either place.
        function rowNoteDetailHtml(table, id, note) {
            return htmlSection('Notes', 'var(--accent)') + `<span class="detail-label">Note</span>${rowNoteDetailValueHtml(table, id, note)}`;
        }

        // Row-cell pivot menu (Include/Exclude/Only, see handleRowCellClick)
        // data, baked once per row at render time rather than resolved from
        // a click-time id lookup - this is the ONE place that needs
        // touching per table type (not every individual <td> in every
        // event-type case of buildRowForEvent's switch) since it emits a
        // single data-pivot attribute on the <tr> covering every cell.
        //
        // data-pivot is a JSON array of [column, value] pairs (or null),
        // index-aligned with the row's rendered <td> DOM position - NOT
        // filtered down to just the pivotable columns, since
        // handleRowCellClick locates an entry purely by the clicked cell's
        // DOM child index. 'Time' is always null: excluded for the same
        // reason buildAggregationTablesCore's own excludeCols already
        // excludes it from that click-to-filter feature - a raw timestamp
        // is a poor Include/Exclude/Only target. An empty/missing value is
        // also null, so clicking a blank cell just falls through to the
        // normal row-expand behavior instead of offering to filter on ''.
        //
        // extractFn must be whichever of extractValue/extractAllValue/
        // extractLogValue/extractSigmaValue this table's own filtering
        // (matchesCurrentFilters call site) already uses for eventType, so
        // a value clicked here is guaranteed to compare equal against that
        // same column's value on every other row once applied as a filter.
        function pivotDataAttrsHtml(e, eventType, columns, extractFn) {
            const pairs = columns.map((col, i) => {
                if (col === 'Time') return null;
                const val = extractFn(e, col, i);
                return (val === '' || val === null || val === undefined) ? null : [col, val];
            });
            // encodeURIComponent, not escapeHtml - a column value can be
            // arbitrary attacker-influenced content (a log field, an HTTP
            // header...) containing JSON's own '"' delimiter, which
            // escapeHtml would turn into literal &quot; text sitting
            // *inside* this already-double-quoted HTML attribute. Real
            // browsers parse/serialize that back correctly (attribute
            // values only strictly need their delimiter quote and '&'
            // escaped, not '<'/'>'), so it isn't actually exploitable, but
            // it does mean a naive "does the rendered HTML string contain
            // '<script>'" check can false-positive on it. Percent-encoding
            // sidesteps the whole question - the attribute value is plain
            // ASCII with no HTML-meaningful characters at all.
            return ` data-event-type="${escapeHtml(eventType)}" data-pivot="${encodeURIComponent(JSON.stringify(pairs))}"`;
        }

        // Shared leading cells for every per-type event row: timestamp, proto
        // badge, and the source/dest IP:PORT columns.
        function rowPrefixCells(e) {
            const ts = (e.timestamp || '').slice(0, 19);
            const proto = e.proto || '';
            const srcIp = e.src_ip || '';
            const srcPort = e.src_port || '';
            const dstIp = e.dest_ip || '';
            const dstPort = e.dest_port || '';
            const eventType = e.event_type || '';
            const pivotAttrs = pivotDataAttrsHtml(e, eventType, getColumnsForType(eventType), extractValue);
            // Carries the alert's own matching key for the "Acknowledge all
            // instances" pivot menu action (see acknowledgeableRowInfo) -
            // baked into the row at render time rather than looked up from
            // tabDataCache when clicked, since tabDataCache[eventType] is
            // often empty: the default (no filter/sort) view fetches each
            // page through fetchEventsPage()'s own local `items`, which
            // never touches tabDataCache at all (see canUseScalableFetchForSort
            // in buildSection).
            const identityAttr = eventType === 'alert'
                ? ` data-alert-identity="${escapeHtml(String(e.alert?.signature_id || e.alert?.signature || ''))}"`
                : '';
            // Carries this row's own community_id (see showPivotMenu's
            // Correlate entry), independent of pivotAttrs above - Correlate
            // must work from ANY field's pivot menu on this row, not just
            // one clicked directly on the Community ID value itself, so it
            // can't rely on that value having been the one clicked.
            const communityIdAttr = e.community_id ? ` data-community-id="${escapeHtml(e.community_id)}"` : '';
            return `<tr data-id="${escapeHtml(String(e.id))}"${pivotAttrs}${identityAttr}${communityIdAttr} data-action="toggle-row"><td class="timestamp">${escapeHtml(ts)}</td><td>${valueDotSpan(DOT_COLORS.PROTO[proto.toUpperCase()])}${escapeHtml(proto)}</td><td class="mono-fixed" title="${escapeHtml(srcIp)}">${escapeHtml(srcIp)}</td><td class="mono-fixed">${escapeHtml(String(srcPort))}</td><td class="mono-fixed" title="${escapeHtml(dstIp)}">${escapeHtml(dstIp)}</td><td class="mono-fixed">${escapeHtml(String(dstPort))}</td>`;
        }

        function buildRowForEvent(e) {
            const etype = e.event_type || '';
            const formatted = formatEvent(e);

            let row = '';
            let colSpan = 6;

            switch(etype) {
                case 'alert':
                case 'protocol_decode':
                    const sig = e.alert?.signature || 'N/A';
                    const cat = e.alert?.category || '';
                    const ruleset = classifyRuleset(e.alert?.signature_id);
                    const sev = e.alert?.severity || 0;
                    const sevColor = COLORS.SEVERITY[sev] || COLORS.SEVERITY.default;
                    colSpan = 10;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(sig)}</td><td>${escapeHtml(cat)}</td><td>${escapeHtml(ruleset)}</td><td>${valueDotSpan(sevColor)}Sev ${sev}</td></tr>`;
                    break;
                case 'dns':
                    // Suricata 8's new V3 DNS logging format moved rrname/
                    // rrtype off the top level into queries[0] - see the
                    // 'Query'/'Type' cases in extractValue for details.
                    const rrname = e.dns?.rrname || e.dns?.queries?.[0]?.rrname || '';
                    const rrtype = e.dns?.rrtype || e.dns?.queries?.[0]?.rrtype || '';
                    colSpan = 8;
                    row = rowPrefixCells(e) + `<td class="mono">${escapeHtml(rrname)}</td><td>${valueDotSpan(DOT_COLORS.DNS_TYPE[rrtype.toUpperCase()])}${escapeHtml(rrtype)}</td></tr>`;
                    break;
                case 'http':
                    const method = e.http?.http_method || '';
                    const host = e.http?.hostname || '';
                    const url = e.http?.url || '';
                    const status = e.http?.status || '';
                    const ua = (e.http?.http_user_agent || '').slice(0, CONFIG.TLS_ISSUER_MAX_LENGTH);
                    const statusColor = status && parseInt(status) < 400 ? 'var(--badge-success-text)' : status && parseInt(status) < 500 ? 'var(--badge-warning-text)' : 'var(--badge-danger-text)';
                    colSpan = 11;
                    row = rowPrefixCells(e) + `<td>${valueDotSpan(DOT_COLORS.HTTP_METHOD[method.toUpperCase()])}${escapeHtml(method)}</td><td class="mono">${escapeHtml(host)}</td><td class="mono">${escapeHtml(url)}</td><td>${escapeHtml(ua)}</td><td>${valueDotSpan(statusColor)}${escapeHtml(String(status))}</td></tr>`;
                    break;
                case 'tls':
                    const sni = e.tls?.sni || '-';
                    const version = e.tls?.version || '-';
                    const subject = (e.tls?.subject || '-').slice(0, CONFIG.TLS_SUBJECT_MAX_LENGTH);
                    let issuer = e.tls?.issuerdn || '-';
                    if (issuer && issuer.includes('CN=')) issuer = issuer.split('CN=')[1].split(',')[0];
                    colSpan = 10;
                    row = rowPrefixCells(e) + `<td class="mono">${escapeHtml(sni)}</td><td>${valueDotSpan(tlsVersionColor(version))}${escapeHtml(version)}</td><td class="mono">${escapeHtml(subject)}</td><td class="mono">${escapeHtml(issuer.slice(0, CONFIG.TLS_ISSUER_MAX_LENGTH))}</td></tr>`;
                    break;
                case 'flow':
                    const pktsTs = e.flow?.pkts_toserver || 0;
                    const pktsTc = e.flow?.pkts_toclient || 0;
                    const bytesTs = e.flow?.bytes_toserver || 0;
                    const bytesTc = e.flow?.bytes_toclient || 0;
                    const state = e.flow?.state || '';
                    const alerted = e.flow?.alerted || false;
                    const alertedColor = alerted ? 'var(--badge-danger-text)' : 'var(--badge-success-text)';
                    const alertedText = alerted ? 'Yes' : 'No';
                    colSpan = 12;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(String(pktsTs.toLocaleString()))}</td><td>${escapeHtml(String(pktsTc.toLocaleString()))}</td><td>${escapeHtml(String(bytesTs.toLocaleString()))}</td><td>${escapeHtml(String(bytesTc.toLocaleString()))}</td><td>${escapeHtml(state)}</td><td>${valueDotSpan(alertedColor)}${escapeHtml(alertedText)}</td></tr>`;
                    break;
                case 'fileinfo':
                    const filename = e.fileinfo?.filename || '';
                    colSpan = 7;
                    row = rowPrefixCells(e) + `<td class="mono">${escapeHtml(filename)}</td></tr>`;
                    break;
                case 'filealerts':
                    const fa = e.filealerts || {};
                    const ruleName = fa.rule_name || 'N/A';
                    const tagsHtml = (fa.tags || []).map(t => yaraTagBadgeHtml(t)).join('');
                    colSpan = 8;
                    row = rowPrefixCells(e) + `<td style="max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(ruleName)}</td><td>${tagsHtml}</td></tr>`;
                    break;
                case 'modbus': {
                    const mr = e.modbus?.request || {};
                    colSpan = 11;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(mr.function_code || '')}</td><td>${escapeHtml(String(mr.unit_id || ''))}</td><td>${escapeHtml(mr.access_type || '')}</td><td>${escapeHtml(mr.category || '')}</td><td>${escapeHtml(mr.error_flags || '')}</td></tr>`;
                    break;
                }
                case 'dnp3': {
                    const dnp = e.dnp3 || {};
                    const dnpType = dnp.type || dnp.request?.type || dnp.response?.type || '';
                    const dnpSrc = dnp.src !== undefined ? dnp.src : (dnp.request?.src !== undefined ? dnp.request.src : '');
                    const dnpDst = dnp.dst !== undefined ? dnp.dst : (dnp.request?.dst !== undefined ? dnp.request.dst : '');
                    const dnpFunc = dnp.application?.function_code !== undefined ? dnp.application.function_code : (dnp.request?.application?.function_code !== undefined ? dnp.request.application.function_code : (dnp.response?.application?.function_code !== undefined ? dnp.response.application.function_code : ''));
                    colSpan = 10;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(dnpType)}</td><td>${escapeHtml(String(dnpSrc))}</td><td>${escapeHtml(String(dnpDst))}</td><td>${escapeHtml(String(dnpFunc))}</td></tr>`;
                    break;
                }
                case 'pgsql': {
                    const pq = e.pgsql || {};
                    const pqQuery = (pq.request?.simple_query || '').slice(0, 60);
                    const pqCmd = pq.response?.command_completed || '';
                    const pqRows = pq.response?.data_rows !== undefined ? pq.response.data_rows : '';
                    const pqSsl = pq.response?.ssl_accepted !== undefined ? (pq.response.ssl_accepted ? 'Yes' : 'No') : '';
                    colSpan = 10;
                    row = rowPrefixCells(e) + `<td class="mono" style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(pq.request?.simple_query || '')}">${escapeHtml(pqQuery)}</td><td>${escapeHtml(pqCmd)}</td><td>${escapeHtml(String(pqRows))}</td><td>${escapeHtml(pqSsl)}</td></tr>`;
                    break;
                }
                case 'enip': {
                    const en = e.enip || {};
                    const enCommand = en.request?.command || en.response?.command || '';
                    const enStatus = en.response?.status || en.request?.status || '';
                    colSpan = 8;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(enCommand)}</td><td>${escapeHtml(enStatus)}</td></tr>`;
                    break;
                }
                case 'quic': {
                    const q = e.quic || {};
                    colSpan = 10;
                    row = rowPrefixCells(e) + `<td class="mono">${escapeHtml(q.sni || '')}</td><td>${escapeHtml(q.version || '')}</td><td class="mono" title="${escapeHtml(q.ja3?.string || '')}">${escapeHtml(q.ja3?.hash || '')}</td><td class="mono" title="${escapeHtml(q.ja3s?.string || '')}">${escapeHtml(q.ja3s?.hash || '')}</td></tr>`;
                    break;
                }
                case 'dhcp': {
                    const dh = e.dhcp || {};
                    colSpan = 10;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(dh.dhcp_type || dh.type || '')}</td><td class="mono">${escapeHtml(dh.client_mac || '')}</td><td class="mono">${escapeHtml(dh.assigned_ip || '')}</td><td>${escapeHtml(dh.hostname || '')}</td></tr>`;
                    break;
                }
                case 'ftp_data': {
                    const fd = e.ftp_data || {};
                    colSpan = 8;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(fd.command || '')}</td><td class="mono">${escapeHtml(fd.filename || '')}</td></tr>`;
                    break;
                }
                case 'smb': {
                    const sm = e.smb || {};
                    colSpan = 10;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(sm.command || '')}</td><td class="mono">${escapeHtml(sm.filename || '')}</td><td>${escapeHtml(sm.share || '')}</td><td>${escapeHtml(sm.ntlmssp?.user || sm.kerberos?.cname || '')}</td></tr>`;
                    break;
                }
                case 'ssh': {
                    const sh = e.ssh || {};
                    colSpan = 8;
                    row = rowPrefixCells(e) + `<td class="mono">${escapeHtml(sh.client?.software_version || '')}</td><td class="mono">${escapeHtml(sh.server?.software_version || '')}</td></tr>`;
                    break;
                }
                case 'krb5': {
                    const kb = e.krb5 || {};
                    colSpan = 10;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(kb.cname || '')}</td><td>${escapeHtml(kb.sname || '')}</td><td>${escapeHtml(kb.realm || '')}</td><td>${escapeHtml(kb.error_code || '')}</td></tr>`;
                    break;
                }
                case 'sip': {
                    const sp = e.sip || {};
                    colSpan = 10;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(sp.method || '')}</td><td class="mono">${escapeHtml(sp.uri || '')}</td><td>${escapeHtml(String(sp.code || ''))}</td><td>${escapeHtml(sp.reason || '')}</td></tr>`;
                    break;
                }
                case 'snmp': {
                    const sn = e.snmp || {};
                    colSpan = 9;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(String(sn.version || ''))}</td><td>${escapeHtml(sn.pdu_type || '')}</td><td>${escapeHtml(sn.community || '')}</td></tr>`;
                    break;
                }
                case 'mqtt': {
                    const mq = e.mqtt || {};
                    const mqttType = Object.keys(mq)[0] || '';
                    const mqttSub = mq[mqttType] || {};
                    const topic = mqttSub.topic || (mqttSub.topics || []).map(t => t.topic || t).join(', ') || '';
                    colSpan = 9;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(mqttType)}</td><td class="mono">${escapeHtml(topic)}</td><td>${escapeHtml(mqttSub.client_id || '')}</td></tr>`;
                    break;
                }
                case 'dcerpc': {
                    const dc = e.dcerpc || {};
                    const dcUuid = (dc.interfaces || [])[0]?.uuid || '';
                    colSpan = 9;
                    row = rowPrefixCells(e) + `<td class="mono">${escapeHtml(dcUuid)}</td><td>${escapeHtml(String(dc.req?.opnum ?? dc.request?.opnum ?? ''))}</td><td>${escapeHtml(String(dc.call_id ?? ''))}</td></tr>`;
                    break;
                }
                case 'rdp': {
                    const rd = e.rdp || {};
                    colSpan = 9;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(rd.event_type || '')}</td><td class="mono">${escapeHtml(rd.cookie || '')}</td><td>${escapeHtml(rd.client_name || '')}</td></tr>`;
                    break;
                }
                case 'tftp': {
                    const tf = e.tftp || {};
                    colSpan = 9;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(tf.packet || '')}</td><td class="mono">${escapeHtml(tf.file || '')}</td><td>${escapeHtml(tf.mode || '')}</td></tr>`;
                    break;
                }
                case 'ike': {
                    const ik = e.ike || {};
                    const ikeVersion = (ik.version_major !== undefined) ? `${ik.version_major}.${ik.version_minor || 0}` : '';
                    colSpan = 9;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(ik.exchange_type || '')}</td><td>${escapeHtml(ikeVersion)}</td><td class="mono">${escapeHtml(ik.init_spi || '')}</td></tr>`;
                    break;
                }
                case 'nfs': {
                    const nf = e.nfs || {};
                    colSpan = 8;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(nf.procedure || '')}</td><td class="mono">${escapeHtml(nf.filename || '')}</td></tr>`;
                    break;
                }
                case 'rfb': {
                    const rf = e.rfb || {};
                    const cpv = rf.client_protocol_version;
                    const spv = rf.server_protocol_version;
                    const clientVer = cpv ? `${cpv.major}.${cpv.minor}` : '';
                    const serverVer = spv ? `${spv.major}.${spv.minor}` : '';
                    const securityType = rf.authentication?.security_type;
                    colSpan = 9;
                    row = rowPrefixCells(e) + `<td class="mono">${escapeHtml(clientVer)}</td><td class="mono">${escapeHtml(serverVer)}</td><td>${escapeHtml(securityType != null ? String(securityType) : '')}</td></tr>`;
                    break;
                }
                case 'bittorrent_dht': {
                    const bt = e.bittorrent_dht || {};
                    colSpan = 8;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(bt.request_type || bt.request?.request_type || '')}</td><td class="mono">${escapeHtml(bt.info_hash || bt.request?.info_hash || '')}</td></tr>`;
                    break;
                }
                case 'smtp': {
                    const sm2 = e.smtp || {};
                    colSpan = 9;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(sm2.helo || '')}</td><td class="mono">${escapeHtml(sm2.mail_from || '')}</td><td class="mono">${escapeHtml((sm2.rcpt_to || []).join(', '))}</td></tr>`;
                    break;
                }
                case 'ftp': {
                    const ft = e.ftp || {};
                    const ftReply = (ft.reply || []).join(' | ').slice(0, 100);
                    colSpan = 10;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(ft.command || '')}</td><td class="mono">${escapeHtml(ft.command_data || '')}</td><td>${escapeHtml((ft.completion_code || []).join(', '))}</td><td class="mono">${escapeHtml(ftReply)}</td></tr>`;
                    break;
                }
                case 'anomaly': {
                    const an = e.anomaly || {};
                    colSpan = 10;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(an.event || '')}</td><td>${escapeHtml(an.type || '')}</td><td>${escapeHtml(an.layer || '')}</td><td>${escapeHtml(an.app_proto || '')}</td></tr>`;
                    break;
                }
                case 'ntp': {
                    const nt = e.ntp || {};
                    colSpan = 10;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(nt.version !== undefined ? String(nt.version) : '')}</td><td>${escapeHtml(nt.mode !== undefined ? String(nt.mode) : '')}</td><td>${escapeHtml(nt.stratum !== undefined ? String(nt.stratum) : '')}</td><td class="mono">${escapeHtml(nt.reference_id || '')}</td></tr>`;
                    break;
                }
                case 'websocket': {
                    const ws = e.websocket || {};
                    const payload = ws.payload_printable || ws.payload_base64 || '';
                    colSpan = 9;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(ws.opcode || '')}</td><td>${escapeHtml(ws.fin !== undefined ? String(ws.fin) : '')}</td><td class="mono">${escapeHtml(payload.slice(0, 100))}</td></tr>`;
                    break;
                }
                case 'pop3': {
                    const p3 = e.pop3 || {};
                    const p3args = (p3.request?.args || []).join(' ');
                    colSpan = 9;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(p3.request?.command || '')}</td><td class="mono">${escapeHtml(p3args)}</td><td>${escapeHtml(p3.response?.status || '')}</td></tr>`;
                    break;
                }
                case 'mdns': {
                    const md = e.mdns || {};
                    const mdQuery = md.queries?.[0] || {};
                    colSpan = 8;
                    row = rowPrefixCells(e) + `<td class="mono">${escapeHtml(mdQuery.rrname || '')}</td><td>${valueDotSpan(DOT_COLORS.DNS_TYPE[(mdQuery.rrtype || '').toUpperCase()])}${escapeHtml(mdQuery.rrtype || '')}</td></tr>`;
                    break;
                }
                case 'ldap': {
                    const ld = e.ldap || {};
                    const ldOp = ld.request?.operation || ld.responses?.[0]?.operation || '';
                    const ldMsgId = ld.request?.message_id !== undefined ? ld.request.message_id : (ld.responses?.[0]?.message_id !== undefined ? ld.responses[0].message_id : '');
                    // result_code lives inside a differently-named
                    // sub-object per operation (bind_response, search_
                    // result_done, ...) - look for the first response with one.
                    const ldResult = (ld.responses || []).map(r => {
                        for (const key in r) {
                            if (r[key] && typeof r[key] === 'object' && 'result_code' in r[key]) return r[key].result_code;
                        }
                        return undefined;
                    }).find(v => v !== undefined) || '';
                    colSpan = 9;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(ldOp)}</td><td>${escapeHtml(String(ldMsgId))}</td><td>${escapeHtml(ldResult)}</td></tr>`;
                    break;
                }
                case 'arp': {
                    const ap = e.arp || {};
                    colSpan = 9;
                    row = rowPrefixCells(e) + `<td>${escapeHtml(ap.opcode || '')}</td><td class="mono">${escapeHtml(ap.src_mac || '')}</td><td class="mono">${escapeHtml(ap.dest_mac || '')}</td></tr>`;
                    break;
                }
                default:
                    colSpan = 6;
                    row = rowPrefixCells(e) + `</tr>`;
            }

            // Every case above ends its row with a literal '</tr>' - insert
            // the note-icon cell just before it rather than touching each
            // of the ~30 cases individually, and bump colSpan by 1 here
            // (its one point of consumption) to match, rather than at each
            // case's own assignment.
            row = row.slice(0, -'</tr>'.length) + rowNoteIconHtml('events', e.id, e.row_note) + '</tr>';

            return row + `<tr class="detail-row"><td colspan="${colSpan + 1}"><div class="detail-content">${formatted}</div></td></tr>`;
        }
        
        function buildFileInfoHtml(events) {
            const fileinfoEvent = events.find(e => e.event_type === 'fileinfo');
            if (!fileinfoEvent || !fileinfoEvent.fileinfo) return '';

            const fi = fileinfoEvent.fileinfo;
            const meta = fi.metadata || {};
            const strings = (meta.strings || []).slice(0, 10);
            const stringsHtml = strings.length
                ? `<span class="value" style="word-break: break-all;">${escapeHtml(strings.join(', '))}</span>`
                : '<span class="value" style="color: var(--bg-hover-light);">—</span>';

            const exif = meta.exif || {};
            const exifEntries = Object.entries(exif).slice(0, 12);
            const exifHtml = exifEntries.length
                ? exifEntries.map(([k, v]) => `<span class="label">${escapeHtml(k)}</span><span class="value" style="word-break: break-all;">${escapeHtml(v)}</span>`).join('')
                : '';

            return `
                <div class="file-info-card">
                    <h3>${FILE_ICON_SVG} File Info</h3>
                    <div class="file-info-grid">
                        <span class="label">Filename</span><span class="value">${escapeHtml(fi.filename || '')}</span>
                        <span class="label">Size</span><span class="value">${escapeHtml(String((fi.size || 0).toLocaleString()))} bytes</span>
                        <span class="label">MD5</span><span class="value">${escapeHtml(fi.md5 || '')}</span>
                        <span class="label">SHA1</span><span class="value">${escapeHtml(fi.sha1 || '')}</span>
                        <span class="label">SHA256</span><span class="value">${escapeHtml(fi.sha256 || '')}</span>
                        <span class="label">Magic</span><span class="value">${escapeHtml(fi.magic || '')}</span>
                        ${meta.mime_type ? `<span class="label">MIME Type</span><span class="value">${escapeHtml(meta.mime_type)}</span>` : ''}
                        ${meta.entropy !== undefined ? `<span class="label">Entropy</span><span class="value">${escapeHtml(String(meta.entropy))}</span>` : ''}
                        ${exifHtml}
                        ${strings.length ? `<span class="label">Top Strings</span>${stringsHtml}` : ''}
                    </div>
                </div>
            `;
        }

        // buildBinaryYaraTable/buildBinaryAggregations each also define
        // their own identical local ['Rule Name', 'Tags', 'Author'] array
        // (pre-existing, left as-is) - this one is just for
        // pivotDataAttrsHtml below, which needs it by name.
        const BINARY_YARA_COLUMNS = ['Rule Name', 'Tags', 'Author'];

        function buildBinaryYaraRow(e) {
            const fa = e.filealerts || {};
            const ruleName = fa.rule_name || 'N/A';
            const tagsHtml = (fa.tags || []).map(t => yaraTagBadgeHtml(t)).join('');
            const author = fa.author || '';
            const formatted = formatEvent(e);
            const pivotAttrs = pivotDataAttrsHtml(e, 'binary', BINARY_YARA_COLUMNS, extractValue);
            return `<tr data-id="${escapeHtml(String(e.id))}"${pivotAttrs} data-action="toggle-row"><td style="max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(ruleName)}</td><td>${tagsHtml}</td><td>${escapeHtml(author)}</td>${rowNoteIconHtml('events', e.id, e.row_note)}</tr><tr class="detail-row"><td colspan="4"><div class="detail-content">${formatted}</div></td></tr>`;
        }

        function buildBinaryYaraTable(events) {
            const columns = ['Rule Name', 'Tags', 'Author'];
            const sorted = [...events].sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));

            let filteredEvents = sorted;
            if (Object.keys(currentFilters).length > 0) {
                filteredEvents = sorted.filter(e => matchesCurrentFilters(e, (ev, col) => extractValue(ev, col, -1)));
            }

            let html = '<div class="section-content">';
            if (filteredEvents.length === 0 && Object.keys(currentFilters).length > 0) {
                html += EMPTY_FILTER_STATE_HTML;
            } else if (filteredEvents.length === 0) {
                html += '<div style="padding: 40px; text-align: center; color: var(--text-muted); font-size: 0.95rem;">No YARA matches found</div>';
            } else {
                html += renderPaginatedTable({
                    sectionKey: 'section-binary',
                    columns,
                    items: filteredEvents,
                    extractFn: extractValue,
                    rowRenderer: buildBinaryYaraRow,
                    rerender: () => buildBinaryAnalysisView(allEvents)
                });
            }
            html += '</div>';
            return html;
        }

        function buildBinaryAggregations(events) {
            const aggContainer = document.getElementById('aggregations');
            if (!aggContainer) return;
            if (!advancedMode) {
                aggContainer.innerHTML = AGG_COLLAPSED_HTML;
                return;
            }
            const columns = ['Rule Name', 'Tags', 'Author'];
            const html = buildAggregationTablesCore(events, columns, 'section-binary', extractValue);
            aggContainer.innerHTML = _wrapAggPanel(html);
        }

        function buildBinaryAnalysisView(events, baseEvents) {
            const fileAlerts = events.filter(e => e.event_type === 'filealerts');
            const filteredAlerts = fileAlerts.filter(e => matchesCurrentFilters(e, (ev, col) => extractValue(ev, col, -1)));
            const fileInfoSource = baseEvents || baseAllEvents || events;
            const fileInfoHtml = buildFileInfoHtml(fileInfoSource);
            const fileInfoContainer = document.getElementById('fileInfoContainer');
            if (fileInfoContainer) {
                fileInfoContainer.innerHTML = fileInfoHtml;
                fileInfoContainer.style.display = 'block';
            }
            const yaraTableHtml = buildBinaryYaraTable(filteredAlerts);
            const sectionsEl = document.getElementById('sections');
            if (sectionsEl) {
                sectionsEl.innerHTML = yaraTableHtml;
            }
            buildBinaryAggregations(filteredAlerts);
        }
        
        function buildLogEventRow(evt, columns) {
            let jsonData = _parseLogEventJson(evt);
            const timestamp = escapeHtml((evt.timestamp || '').slice(0, 19));
            const detail = getLogEventSmartDetail(jsonData);
            const detailTruncated = detail.length > 120 ? detail.slice(0, 117) + '...' : detail;
            const detailId = 'log-detail-' + (evt.row_id || ++_detailIdCounter);
            // Both the detail row's id attribute and the collapsed row's
            // data-detail-id are plain HTML attribute values now - one
            // escaping (escapeHtml) covers both.
            const detailIdAttr = escapeHtml(String(detailId));
            const totalCols = 3 + (columns ? columns.length : 0); // Time + [cols] + Detail + Note

            // Mirrors getColumnsForType('log')'s own ['Time', ...labels,
            // 'Detail'] shape, but built from the columns already passed in
            // here rather than calling getColumnsForType('log') (which
            // re-derives columns via discoverLogColumns() by rescanning
            // every cached log event - fine once per table render, but
            // O(rows) work that must not run again per row).
            const pivotColumns = ['Time', ...(columns || []).map(c => c.label), 'Detail'];
            const pivotAttrs = pivotDataAttrsHtml(evt, 'log', pivotColumns, extractLogValue);
            let row = `<tr data-id="${escapeHtml(String(evt.id))}"${pivotAttrs} data-action="toggle-log-row" data-detail-id="${detailIdAttr}">`;
            row += `<td class="timestamp">${timestamp}</td>`;
            if (columns) {
                columns.forEach(c => {
                    let val = '';
                    if (c.type === 'base') {
                        if (c.field === 'Channel') val = jsonData.Channel || jsonData.Provider_Name || evt.app_proto || '';
                        else if (c.field === 'EventID') val = String(jsonData.EventID || '');
                        else if (c.field === 'Computer') val = jsonData.Computer || '';
                    } else {
                        val = getLogColumnValue(evt, c.field);
                    }
                    row += `<td>${val ? escapeHtml(val) : '<span style="color:var(--text-muted);">—</span>'}</td>`;
                });
            }
            row += `<td>${detailTruncated ? escapeHtml(detailTruncated) : '<span style="color:var(--text-muted);">—</span>'}</td>`;
            row += rowNoteIconHtml('events', evt.id, evt.row_note);
            row += '</tr>';

            const detailHtml = formatLogEventDetail(jsonData);
            // formatLogEventDetail is also reused nested inside a Sigma
            // alert's own detail panel (the "Matched Event" sub-section,
            // see formatSigmaAlertDetail) where a note row would belong to
            // the wrong thing - the embedded raw log, not the alert - so
            // the note row is appended here at this call site instead of
            // inside formatLogEventDetail itself, in its own small grid
            // rather than assuming formatLogEventDetail's own grid is
            // still open (it isn't - its markup is already closed).
            const noteHtml = `<div style="display: grid; grid-template-columns: 140px minmax(0, 1fr); gap: 8px 12px; font-size: 0.9rem; margin-top: 10px;">${rowNoteDetailHtml('events', evt.id, evt.row_note)}</div>`;
            row += `<tr class="detail-row" id="${detailIdAttr}"><td colspan="${totalCols}"><div class="log-detail-panel">${detailHtml}${noteHtml}</div></td></tr>`;
            return row;
        }

        function toggleLogRow(tr, detailId, event) {
            if (handleRowCellClick(tr, event)) return;
            const detailRow = document.getElementById(detailId);
            if (detailRow) {
                tr.classList.toggle('expanded-row');
                detailRow.classList.toggle('visible');
            }
        }

        function buildSigmaAlertRow(alert) {
            const sev = (alert.severity || 'low').toLowerCase();
            const sevColor = DOT_COLORS.SIGMA_SEVERITY[sev] || DOT_COLORS.SIGMA_SEVERITY.informational;
            const ruleTitle = escapeHtml(alert.rule_title || 'Unknown');
            const ruleId = escapeHtml(alert.rule_id || '');
            const timestamp = escapeHtml(alert.timestamp || '');
            const logsource = escapeHtml(alert.logsource || '');

            const mitreHtml = mitreTechniquesHtml(alert.mitre_techniques);

            const detailId = 'sigma-detail-' + (alert.id || Math.random().toString(36).substr(2, 9));
            // See buildLogEventRow: one escapeHtml covers both attribute uses.
            const detailIdAttr = escapeHtml(String(detailId));

            const pivotAttrs = pivotDataAttrsHtml(alert, 'sigmaalert', getColumnsForType('sigmaalert'), extractSigmaValue);
            // See rowPrefixCells' own comment - same "bake the matching key
            // into the row at render time" reasoning, for sigma_alerts'
            // rule_id instead of events' signature_id.
            let row = `<tr data-id="${escapeHtml(String(alert.id))}"${pivotAttrs} data-alert-identity="${ruleId}" data-action="toggle-sigma-row" data-detail-id="${detailIdAttr}">`;
            row += `<td class="timestamp">${timestamp}</td>`;
            row += `<td>${valueDotSpan(sevColor)}${escapeHtml(sev.toUpperCase())}</td>`;
            row += `<td><strong>${ruleTitle}</strong>${ruleId ? '<br><span style="color:var(--text-muted);font-size:0.8rem;">' + ruleId + '</span>' : ''}</td>`;
            row += `<td>${mitreHtml}</td>`;
            row += `<td>${logsource}</td>`;
            row += rowNoteIconHtml('sigma_alerts', alert.id, alert.row_note);
            row += '</tr>';

            const detailHtml = formatSigmaAlertDetail(alert);
            row += `<tr class="detail-row" id="${detailIdAttr}"><td colspan="6"><div class="log-detail-panel">${detailHtml}</div></td></tr>`;
            return row;
        }

        function toggleSigmaRow(tr, detailId, event) {
            if (handleRowCellClick(tr, event)) return;
            const detailRow = document.getElementById(detailId);
            if (detailRow) {
                const wasHidden = !detailRow.classList.contains('visible');
                tr.classList.toggle('expanded-row');
                detailRow.classList.toggle('visible');
                if (wasHidden) {
                    loadPlaybookSectionIfPresent(detailRow);
                    loadAiSummaryPlaceholders(detailRow);
                }
            }
        }

        // Log Analysis UI helpers
        let _detailIdCounter = 0;
        const LOG_FIELD_LABELS = {
            'Image': 'Image', 'CommandLine': 'Command Line', 'Commandline': 'Command Line',
            'User': 'User', 'TargetUserName': 'Target User',
            'SourceIp': 'Source IP', 'SourceIP': 'Source IP',
            'DestinationIp': 'Dest IP', 'DestIP': 'Dest IP',
            'TargetFilename': 'Target File', 'TargetObject': 'Target Object',
            'ParentImage': 'Parent Image', 'IpAddress': 'IP Address',
            'LogonType': 'Logon Type', 'ServiceName': 'Service',
            'SourcePort': 'Src Port', 'DestinationPort': 'Dst Port',
            'ProcessId': 'PID', 'ParentProcessId': 'Parent PID',
            'exe': 'Executable', 'comm': 'Command', 'auid': 'Audit UID', 'uid': 'UID',
            'pid': 'PID', 'ppid': 'Parent PID', 'message': 'Message', 'msg': 'Message',
            'Message': 'Message', 'query': 'Query', 'hostname': 'Hostname', 'host': 'Host',
            'program': 'Program', 'facility': 'Facility', 'priority': 'Priority', 'level': 'Level',
            'type': 'Type', 'syscall': 'Syscall', 'terminal': 'Terminal',
            'status': 'Status', 'method': 'Method', 'url': 'URL', 'port': 'Port',
            'ip': 'IP', 'service': 'Service', 'action': 'Action', 'result': 'Result',
            'cmd': 'Command', 'command': 'Command', 'path': 'Path', 'file': 'File',
            'src_ip': 'Source IP', 'src_port': 'Source Port', 'dest_ip': 'Dest IP', 'dest_port': 'Dest Port',
            'dst_ip': 'Dest IP', 'dst_port': 'Dest Port',
        };

        const LOG_FIELD_PRIORITY = {
            'Image': 100, 'CommandLine': 100, 'Commandline': 100, 'cmd': 100, 'command': 100, 'comm': 100, 'exe': 100,
            'User': 95, 'TargetUserName': 95, 'uid': 93, 'auid': 93,
            'SourceIp': 90, 'DestinationIp': 90, 'SourceIP': 90, 'DestIP': 90, 'src_ip': 90, 'dst_ip': 90, 'ip': 90,
            'TargetFilename': 85, 'TargetObject': 80, 'path': 83, 'file': 83,
            'ParentImage': 78, 'IpAddress': 78,
            'LogonType': 75, 'ServiceName': 75, 'service': 75,
            'SourcePort': 72, 'DestinationPort': 72, 'port': 72, 'src_port': 72, 'dest_port': 72, 'dst_port': 72,
            'ProcessId': 70, 'ParentProcessId': 70, 'pid': 70, 'ppid': 70,
            'message': 65, 'msg': 65, 'Message': 65, 'query': 65,
            'hostname': 65, 'host': 65, 'program': 63, 'facility': 62, 'priority': 62, 'level': 62,
            'type': 60, 'syscall': 60, 'terminal': 60, 'action': 60, 'result': 60,
            'status': 58, 'method': 58, 'url': 58,
            'Channel': 50, 'EventID': 50, 'Computer': 50,
        };

        const LOG_NOISE_FIELDS = new Set([
            'timestamp', 'event_type', 'id', 'json_data', 'row_id',
            'proto', 'flow_id', 'tx_id', 'pcap_cnt', 'event_id',
            'TimeCreated', 'SystemTime', 'UtcTime', 'TimeCreated_systemTime',
            'Provider_Name', 'ProviderName', 'ProviderGuid',
            'RecordNumber', 'EventRecordID', 'EventRecordId',
            'ProcessGuid', 'LogonGuid', 'ParentProcessGuid',
            'Version', 'Description', 'Company', 'Product', 'FileVersion',
            'Task', 'Opcode', 'Keywords', 'Level',
        ]);

        function _getLabelForField(field) {
            return LOG_FIELD_LABELS[field] || field;
        }

        function _getFieldForLabel(label) {
            for (const [field, lbl] of Object.entries(LOG_FIELD_LABELS)) {
                if (lbl === label) return field;
            }
            return label;
        }

        function _parseLogEventJson(event) {
            let jd = event.json_data;
            if (typeof jd === 'string') {
                try { jd = JSON.parse(jd || '{}'); } catch(e) { jd = {}; }
            }
            if (!jd || typeof jd !== 'object') return {};
            // Unwrap nested json_data (outer dict has event_type, timestamp, etc.)
            if (jd.json_data) {
                if (typeof jd.json_data === 'string') {
                    try { jd = JSON.parse(jd.json_data); } catch(e) {}
                } else if (typeof jd.json_data === 'object') {
                    jd = jd.json_data;
                }
            }
            return jd;
        }

        function discoverLogColumns(events) {
            if (!events || events.length === 0) return [];
            const total = events.length;
            const threshold = Math.max(2, total * 0.1);
            const counts = {};
            const allFields = new Set();

            events.forEach(e => {
                const jd = _parseLogEventJson(e);
                if (!jd || typeof jd !== 'object') return;
                Object.keys(jd).forEach(k => {
                    if (LOG_NOISE_FIELDS.has(k)) return;
                    allFields.add(k);
                    const val = jd[k];
                    if (val !== undefined && val !== null && val !== '') {
                        counts[k] = (counts[k] || 0) + 1;
                    }
                });
            });

            const baseFields = ['Channel', 'EventID', 'Computer'];
            const baseCols = [];
            baseFields.forEach(f => {
                if ((counts[f] || 0) > 0) {
                    baseCols.push({ field: f, label: _getLabelForField(f), type: 'base' });
                }
            });

            const discovered = Array.from(allFields)
                .filter(f => !baseFields.includes(f))
                .filter(f => (counts[f] || 0) >= threshold)
                .sort((a, b) => {
                    const pa = LOG_FIELD_PRIORITY[a] || 0;
                    const pb = LOG_FIELD_PRIORITY[b] || 0;
                    if (pb !== pa) return pb - pa;
                    return (counts[b] || 0) - (counts[a] || 0);
                })
                .slice(0, 6 - baseCols.length)
                .map(f => ({ field: f, label: _getLabelForField(f), type: 'dynamic' }));

            return [...baseCols, ...discovered];
        }

        function getLogColumnValue(event, field) {
            const jd = _parseLogEventJson(event);
            const val = jd[field];
            if (val === undefined || val === null || val === '') return '';
            return String(val);
        }

        function getLogEventSmartDetail(jsonData) {
            const jd = jsonData;
            if (!jd || typeof jd !== 'object') return '';
            // Network events
            if (jd.SourceIp || jd.DestinationIp || jd.src_ip || jd.dst_ip) {
                const src = jd.SourceIp || jd.src_ip || '';
                const sport = jd.SourcePort || jd.src_port || '';
                const dst = jd.DestinationIp || jd.dst_ip || '';
                const dport = jd.DestinationPort || jd.dest_port || jd.dst_port || '';
                let detail = '';
                if (src && sport) detail += `${src}:${sport}`;
                else if (src) detail += src;
                if (detail && (dst || dport)) detail += ' → ';
                if (dst && dport) detail += `${dst}:${dport}`;
                else if (dst) detail += dst;
                return detail;
            }
            // Process events
            if (jd.CommandLine || jd.cmd || jd.command || jd.comm) return String(jd.CommandLine || jd.cmd || jd.command || jd.comm);
            if (jd.Image || jd.exe) return String(jd.Image || jd.exe);
            // File events
            if (jd.TargetFilename || jd.path || jd.file) return String(jd.TargetFilename || jd.path || jd.file);
            // Registry events
            if (jd.TargetObject) return String(jd.TargetObject);
            // Auth events
            if (jd.TargetUserName || jd.uid || jd.auid) return String(jd.TargetUserName || jd.uid || jd.auid);
            if (jd.User) return String(jd.User);
            // Service events
            if (jd.ServiceName || jd.service) return String(jd.ServiceName || jd.service);
            // Query / URL
            if (jd.query || jd.hostname || jd.host) return String(jd.query || jd.hostname || jd.host);
            if (jd.url || jd.method || jd.status) {
                return [jd.method, jd.url, jd.status].filter(Boolean).join(' ');
            }
            // Fallback
            if (jd.message || jd.msg || jd.Message) return String(jd.message || jd.msg || jd.Message);
            return '';
        }

        // currentFilters[col] is polymorphic: a plain string means "exact
        // match" (the original shape, still written as-is by
        // applyFilters() - now only reached via clicking a Sankey diagram
        // link/node, since aggregation-table rows moved to the pivot menu
        // below). An {include, exclude} object is the newer shape written
        // by includeFilterValue()/excludeFilterValue()/onlyFilterValue()
        // (the row-cell/aggregation-row pivot menu) - include acts as an
        // OR-broadened allow-list for that one column, exclude as a
        // deny-list, and both can be non-empty at once. Different columns
        // still AND together either way.
        function matchesCurrentFilters(e, extractFn) {
            for (const [col, spec] of Object.entries(currentFilters)) {
                if (typeof spec === 'string') {
                    if (extractFn(e, col) !== spec) return false;
                    continue;
                }
                const val = extractFn(e, col);
                if (spec.include && spec.include.length > 0 && !spec.include.includes(val)) return false;
                if (spec.exclude && spec.exclude.length > 0 && spec.exclude.includes(val)) return false;
            }
            return true;
        }

        function parseMitreTechniques(mitreJson) {
            try {
                return JSON.parse(mitreJson || '[]').map(t => t.replace(/^attack\./i, '').toUpperCase());
            } catch(e) {
                return [];
            }
        }

        function mitreTechniquesHtml(mitreJson) {
            return parseMitreTechniques(mitreJson).map(tid => {
                // Sub-techniques (e.g. T1055.012) live at a nested MITRE URL
                // (/techniques/T1055/012/), not a dotted slug.
                const urlPath = tid.split('.').map(encodeURIComponent).join('/');
                // data-action="stop-propagation": shadows the row's own
                // toggle action (the dispatcher runs only the closest
                // data-action) so clicking the tag opens the MITRE page
                // without also expanding/collapsing the row.
                return `<a href="https://attack.mitre.org/techniques/${urlPath}/" target="_blank" rel="noopener noreferrer" class="mitre-tag" data-action="stop-propagation">${escapeHtml(tid)}</a>`;
            }).join('');
        }

        function extractSigmaValue(alert, col) {
            switch(col) {
                case 'Severity': return alert.severity || '';
                case 'Rule': return alert.rule_title || '';
                case 'MITRE Technique': return parseMitreTechniques(alert.mitre_techniques).join(', ');
                case 'Log Source': return alert.logsource || '';
                case 'Time': return alert.timestamp || '';
                default: {
                    // Dynamic column from original_log
                    try {
                        const logObj = JSON.parse(alert.original_log || '{}');
                        if (logObj && typeof logObj === 'object') {
                            const field = _getFieldForLabel(col);
                            return String(logObj[field] || '');
                        }
                    } catch(e) { return ''; }
                    return '';
                }
            }
        }

        function extractLogValue(ev, col) {
            if (col === 'Time') return (ev.timestamp || '').slice(0, 19);
            if (col === 'Detail') return getLogEventSmartDetail(_parseLogEventJson(ev));
            return getLogColumnValue(ev, _getFieldForLabel(col));
        }

        function getFilteredLogEvents(events) {
            if (Object.keys(currentFilters).length === 0) return events;
            return events.filter(e => matchesCurrentFilters(e, extractLogValue));
        }

        function getFilteredSigmaAlerts(alerts) {
            if (Object.keys(currentFilters).length === 0) return alerts;
            return alerts.filter(a => matchesCurrentFilters(a, extractSigmaValue));
        }

        // DNS Heuristics - a derived, client-computed view over the same
        // 'dns' event batch the real DNS tab uses (see buildDnsHeuristicsSection
        // below), grouping queries by registrable domain and flagging ones
        // that look like DGA/tunneling activity. Not a rule engine match
        // (unlike Suricata/Sigma alerts) - a heuristic score meant to
        // narrow an analyst's attention, so it's surfaced as its own tab
        // rather than folded into the acknowledge/playbook alert pipeline
        // built for real rule matches.

        // A short, deliberately non-exhaustive allowlist of CDN/cloud
        // suffixes that legitimately generate long, random-looking
        // subdomains as part of normal operation (asset hashes, edge PoP
        // routing, etc.) - without this, those would dominate the flagged
        // list and drown out real signal. Reduces noise, doesn't eliminate
        // it - an analyst in an unusual environment may still see false
        // positives from CDNs not on this list.
        const DNS_HEURISTICS_CDN_SUFFIXES = [
            'amazonaws.com', 'cloudfront.net', 'akamaiedge.net', 'akamaitechnologies.com',
            'akamai.net', 'azureedge.net', 'azurewebsites.net', 'windows.net',
            'googleusercontent.com', 'gstatic.com', 'googleapis.com', 'googlesyndication.com',
            'doubleclick.net', 'fastly.net', 'fastlylb.net', 'cloudflare.net',
            'edgekey.net', 'edgesuite.net', 'edgecastcdn.net', 'msedge.net',
            'trafficmanager.net', 'cdn77.org', 'stackpathdns.com',
        ];

        function _isKnownCdnSuffix(suffix) {
            return DNS_HEURISTICS_CDN_SUFFIXES.some(s => suffix === s || suffix.endsWith('.' + s));
        }

        // Common two-label public suffixes (co.uk, com.au, ...) that need a
        // third label pulled in to reach the real registrable domain - not
        // a full Public Suffix List implementation (that's a large,
        // frequently-updated dataset, at odds with this app's offline/
        // self-contained design - see AGENTS.md's detection-rule-freshness
        // reasoning for the same tradeoff elsewhere), just enough common
        // cases to keep the biggest offenders from being mis-grouped.
        const DNS_HEURISTICS_MULTI_PART_SUFFIXES = new Set([
            'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'ltd.uk', 'net.uk',
            'com.au', 'net.au', 'org.au', 'com.br', 'com.cn', 'com.mx', 'com.tr',
            'co.jp', 'co.nz', 'co.in', 'co.za', 'co.kr', 'com.sg', 'co.id',
        ]);

        function dnsRegistrableSuffix(domain) {
            const labels = domain.toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
            if (labels.length < 2) return domain.toLowerCase();
            const lastTwo = labels.slice(-2).join('.');
            if (labels.length >= 3 && DNS_HEURISTICS_MULTI_PART_SUFFIXES.has(lastTwo)) {
                return labels.slice(-3).join('.');
            }
            return lastTwo;
        }

        function shannonEntropyBits(str) {
            if (!str) return 0;
            const counts = {};
            for (const ch of str) counts[ch] = (counts[ch] || 0) + 1;
            let entropy = 0;
            for (const ch in counts) {
                const p = counts[ch] / str.length;
                entropy -= p * Math.log2(p);
            }
            return entropy;
        }

        // Fraction of characters that are a/e/i/o/u - digits and
        // consonants both count as "not a vowel", so this naturally
        // penalizes both digit-heavy strings (classic DGA output like
        // "08kcbghk807qtl9") and pure-random consonant strings alike,
        // without needing a separate digit-specific check. English
        // words/word-mashups (even long, unusual-looking ones like
        // "furtheringthemagic") sit around 30-40%; a uniformly random
        // string over the full alnum charset sits far lower.
        function vowelRatio(str) {
            if (!str) return 0;
            return (str.match(/[aeiou]/g) || []).length / str.length;
        }

        // Only scored above this length - entropy on short strings is
        // noisy (a handful of characters can look "random" by chance),
        // which is exactly the false-positive mode a length floor exists
        // to cut off.
        const DNS_HEURISTICS_MIN_ENTROPY_PREFIX_LENGTH = 10;
        const DNS_HEURISTICS_ENTROPY_THRESHOLD = 3.5;
        // Below random-uniform-lowercase's own expected ~19% (5/26) and
        // comfortably below ordinary English's ~30-40% - see
        // vowelRatio's own comment for why this, not a digit-presence
        // check, is what actually separates "furtheringthemagic" (0.33)
        // from "08kcbghk807qtl9" (0.0) despite their nearly identical
        // entropy (3.50 vs 3.51).
        const DNS_HEURISTICS_DGA_MAX_VOWEL_RATIO = 0.20;
        const DNS_HEURISTICS_LONG_NAME_LENGTH = 60;
        const DNS_HEURISTICS_LONG_LABEL_LENGTH = 50;
        // Distinct subdomains under one suffix, not raw query count - a
        // chatty app repeatedly resolving the SAME name isn't suspicious,
        // but many unique names under one suffix is a much more specific
        // tunneling/DGA signal.
        const DNS_HEURISTICS_FANOUT_THRESHOLD = 15;

        // Groups `events` (a 'dns' event array) by registrable domain,
        // scores each group against a handful of independent heuristics,
        // and returns only the ones that tripped at least one - sorted
        // highest score first. Each event contributes to its own suffix
        // group regardless of which specific query it is; scoring happens
        // once per group afterward, not per event.
        function computeDnsHeuristics(events) {
            const bySuffix = new Map();

            events.forEach(e => {
                const domain = (e.dns?.rrname || e.dns?.queries?.[0]?.rrname || '').toLowerCase();
                if (!domain) return;
                const qtype = (e.dns?.rrtype || e.dns?.queries?.[0]?.rrtype || '').toUpperCase();
                const suffix = dnsRegistrableSuffix(domain);
                if (_isKnownCdnSuffix(suffix)) return;

                let rec = bySuffix.get(suffix);
                if (!rec) {
                    rec = {
                        suffix, queryCount: 0, names: new Map(), srcIps: new Set(),
                        maxEntropy: 0, maxEntropyName: '', maxNameLength: 0,
                        maxLabelLength: 0, txtNullCount: 0, firstSeen: null, lastSeen: null,
                    };
                    bySuffix.set(suffix, rec);
                }

                rec.queryCount++;
                rec.names.set(domain, (rec.names.get(domain) || 0) + 1);
                if (e.src_ip) rec.srcIps.add(e.src_ip);
                rec.maxNameLength = Math.max(rec.maxNameLength, domain.length);
                rec.maxLabelLength = Math.max(rec.maxLabelLength, ...domain.split('.').map(l => l.length));

                const suffixWithDot = '.' + suffix;
                const prefix = domain.endsWith(suffixWithDot)
                    ? domain.slice(0, domain.length - suffixWithDot.length)
                    : (domain === suffix ? '' : domain);
                const prefixCompact = prefix.replace(/\./g, '');
                if (prefixCompact.length >= DNS_HEURISTICS_MIN_ENTROPY_PREFIX_LENGTH) {
                    const ent = shannonEntropyBits(prefixCompact);
                    if (ent > rec.maxEntropy) {
                        rec.maxEntropy = ent;
                        rec.maxEntropyName = domain;
                    }
                }

                if (qtype === 'TXT' || qtype === 'NULL') rec.txtNullCount++;

                const ts = e.timestamp || '';
                if (ts) {
                    if (!rec.firstSeen || ts < rec.firstSeen) rec.firstSeen = ts;
                    if (!rec.lastSeen || ts > rec.lastSeen) rec.lastSeen = ts;
                }
            });

            const results = [];
            bySuffix.forEach(rec => {
                const reasons = [];
                let score = 0;

                if (rec.maxEntropy > DNS_HEURISTICS_ENTROPY_THRESHOLD) {
                    reasons.push('High-entropy subdomain');
                    score += 35;
                }
                // Separate from the subdomain-prefix check above, and
                // scored against the registrable label itself (the first
                // label of rec.suffix, e.g. "08kcbghk807qtl9" from
                // "08kcbghk807qtl9.top") - DNS tunneling and DGA malware
                // put their randomness in different places. Tunneling
                // fans many random subdomains out under one fixed,
                // otherwise-ordinary parent domain (caught above); a DGA
                // instead generates the base domain itself, usually
                // queried once with nothing distinctive in front of it -
                // exactly the case the prefix-only check above computes
                // an empty prefix for and silently skips.
                //
                // Entropy alone isn't enough here: a long lowercase
                // word-mashup domain (e.g. "furtheringthemagic.com", a
                // real false positive this shipped with briefly) can land
                // right next to genuine DGA output in raw entropy - 3.50
                // vs 3.51 for "08kcbghk807qtl9", practically tied. Vowel
                // ratio is what actually tells them apart (0.33 vs 0.0 -
                // see vowelRatio's own comment), so it's required
                // alongside entropy, not scored as its own separate
                // reason.
                const suffixLabel = rec.suffix.split('.')[0];
                if (suffixLabel.length >= DNS_HEURISTICS_MIN_ENTROPY_PREFIX_LENGTH
                        && shannonEntropyBits(suffixLabel) > DNS_HEURISTICS_ENTROPY_THRESHOLD
                        && vowelRatio(suffixLabel) < DNS_HEURISTICS_DGA_MAX_VOWEL_RATIO) {
                    reasons.push('High-entropy domain name (possible DGA)');
                    score += 35;
                }
                if (rec.maxNameLength > DNS_HEURISTICS_LONG_NAME_LENGTH || rec.maxLabelLength > DNS_HEURISTICS_LONG_LABEL_LENGTH) {
                    reasons.push('Unusually long query name');
                    score += 15;
                }
                const distinctNames = rec.names.size;
                if (distinctNames >= DNS_HEURISTICS_FANOUT_THRESHOLD) {
                    reasons.push('High distinct-subdomain fan-out');
                    score += 30;
                }
                if (rec.txtNullCount > 0) {
                    reasons.push('TXT/NULL query type');
                    score += 20;
                }

                if (score === 0) return;

                results.push({
                    domain: rec.suffix,
                    score: Math.min(100, score),
                    reasons,
                    queryCount: rec.queryCount,
                    distinctNames,
                    sampleQuery: rec.maxEntropyName || Array.from(rec.names.keys())[0] || rec.suffix,
                    sourceCount: rec.srcIps.size,
                    firstSeen: rec.firstSeen,
                    lastSeen: rec.lastSeen,
                });
            });

            results.sort((a, b) => b.score - a.score);
            return results;
        }

        const DNS_HEURISTIC_COLUMNS = ['Domain', 'Score', 'Reasons', 'Sample Query', 'Queries', 'Distinct Names', 'First Seen'];

        function extractDnsHeuristicValue(item, col) {
            switch (col) {
                case 'Domain': return item.domain;
                case 'Score': return item.score;
                case 'Reasons': return item.reasons.join(', ');
                case 'Sample Query': return item.sampleQuery;
                case 'Queries': return item.queryCount;
                case 'Distinct Names': return item.distinctNames;
                case 'First Seen': return (item.firstSeen || '').slice(0, 19);
                default: return '';
            }
        }

        function dnsHeuristicRowHtml(item) {
            const scoreColor = item.score >= 60 ? 'var(--badge-danger-text)' : item.score >= 35 ? 'var(--badge-warning-text)' : 'var(--text-muted)';
            // data-id is what getVisibleDataTableRows() (the Up/Down
            // keyboard nav item list) selects on - tr[data-id] - without
            // it these rows are invisible to keyboard navigation entirely.
            // computeDnsHeuristics() already groups by registrable domain,
            // so item.domain is guaranteed unique within one table's rows,
            // same uniqueness property a real numeric event id has. The
            // only other reader of data-id (acknowledgeableRowInfo, for
            // the pivot menu's Acknowledge button) never runs against
            // these rows - they have no pivot menu at all, just the
            // 'view-dns-heuristic-domain' click action (which reads the
            // domain back from this same data-id) - so a non-numeric
            // value here is safe.
            return `<tr class="dns-heuristic-row" data-id="${escapeHtml(item.domain)}" data-action="view-dns-heuristic-domain" style="cursor:pointer;" title="Click to view matching DNS queries">` +
                `<td class="mono">${escapeHtml(item.domain)}</td>` +
                `<td>${valueDotSpan(scoreColor)}${item.score}</td>` +
                `<td>${escapeHtml(item.reasons.join(', '))}</td>` +
                `<td class="mono">${escapeHtml(item.sampleQuery)}</td>` +
                `<td>${item.queryCount.toLocaleString()}</td>` +
                `<td>${item.distinctNames.toLocaleString()}</td>` +
                `<td class="timestamp">${escapeHtml((item.firstSeen || '').slice(0, 19))}</td>` +
                `<td></td>` +
                `</tr>`;
        }

        // Jumps to the real DNS tab, scoped to this suffix - a free-text
        // search (huntFilterValue), not a column filter (onlyFilterValue),
        // since `domain` here is the grouping suffix (e.g. "example.com"),
        // not a single query's exact name - a phrase search still matches
        // "xk3f9.example.com" (FTS5 tokenizes on the dots, so "example"
        // immediately followed by "com" matches regardless of what
        // precedes it), where an exact-equality column filter would not.
        // Goes through huntFilterValue (not a hand-rolled shortcut) so its
        // tabDataCache invalidation runs too - the DNS tab may already be
        // cached from an earlier, differently-scoped visit.
        async function viewDnsHeuristicDomain(domain) {
            await huntFilterValue(domain);
            const card = document.querySelector('.stat-card[data-section="section-dns"]');
            showTab('section-dns', card || null);
        }

        const DNS_HEURISTICS_INFO_COLLAPSED_KEY = 'socrates_dnsHeuristicsInfoCollapsed';

        // This tab behaves nothing like any other data-type tab - rows are
        // aggregated per-domain (not raw events), clicking one navigates
        // away entirely instead of expanding a detail panel, and the
        // scoring criteria aren't visible anywhere in the column headers -
        // so unlike every other tab, it gets its own explanatory card.
        // Collapsible (reusing the same .agg-panel/.section-toggle-bar
        // look as the Sankey/Aggregation Tables panels) rather than a
        // permanent fixture, since re-reading the same explanation on
        // every visit is just clutter once an analyst already knows it -
        // state persists across visits via localStorage, defaulting open
        // the first time.
        function dnsHeuristicsInfoCardHtml() {
            const collapsed = safeStorageGet(localStorage, DNS_HEURISTICS_INFO_COLLAPSED_KEY) === 'true';
            const arrow = collapsed ? '▸' : '▾';
            const display = collapsed ? 'none' : 'block';
            return `<div class="agg-panel" style="margin-bottom: 15px;">
                <div class="section-toggle-bar dns-heuristics-info-toggle" data-action="toggle-dns-heuristics-info">${arrow} About DNS Heuristics</div>
                <div class="dns-heuristics-info-body" style="display:${display}; padding: 16px 20px; color: var(--text-muted); font-size: 0.85rem; line-height: 1.7;">
                    <p style="margin:0 0 10px 0;">This tab groups DNS queries by registrable domain and flags ones that look like DNS tunneling or DGA (Domain Generation Algorithm) malware, based on patterns in <em>this capture only</em>. It's a heuristic, not a rule match - treat a flag as a lead to investigate, not a confirmed verdict.</p>
                    <p style="margin:0 0 6px 0; color: var(--text-bright);">A domain is flagged when it trips one or more of:</p>
                    <ul style="margin:0 0 10px 0; padding-left: 20px;">
                        <li><strong>High-entropy subdomain</strong> - a random-looking label (10+ characters) under an otherwise ordinary parent domain, the classic DNS tunneling shape.</li>
                        <li><strong>High-entropy domain name (possible DGA)</strong> - the registrable domain itself looks algorithmically generated (high character entropy, few vowels) rather than a real word or brand.</li>
                        <li><strong>High distinct-subdomain fan-out</strong> - 15 or more unique subdomains queried under the same parent, not just repeated lookups of the same name.</li>
                        <li><strong>Unusually long query name</strong> - an overall name or single label far longer than typical.</li>
                        <li><strong>TXT/NULL query type</strong> - record types more associated with tunneling/exfil tooling than ordinary browsing.</li>
                    </ul>
                    <p style="margin:0 0 10px 0;">Common CDN/cloud domains (Amazon, Akamai, Cloudflare, Google, Fastly, and similar) are excluded up front, since they legitimately generate random-looking subdomains as part of normal operation.</p>
                    <p style="margin:0;">Clicking a row jumps to the real <strong>DNS Queries</strong> tab, searched for that domain, so you can see every individual query behind the score.</p>
                </div>
            </div>`;
        }

        function toggleDnsHeuristicsInfo(bar) {
            const body = bar.nextElementSibling;
            const collapsed = body.style.display === 'none';
            body.style.display = collapsed ? 'block' : 'none';
            bar.textContent = (collapsed ? '▾' : '▸') + ' About DNS Heuristics';
            if (collapsed) {
                safeStorageRemove(localStorage, DNS_HEURISTICS_INFO_COLLAPSED_KEY);
            } else {
                safeStorageSet(localStorage, DNS_HEURISTICS_INFO_COLLAPSED_KEY, 'true');
            }
        }

        function buildDnsHeuristicsSectionContent(sectionId, items) {
            const container = document.getElementById(sectionId);
            if (!container) return;
            let html = '<div class="section-content">';
            html += dnsHeuristicsInfoCardHtml();
            if (items.length === 0) {
                html += `<div class="no-matches">No suspicious DNS activity detected${currentSearch.length > 0 ? ' for the current search' : ''}</div>`;
            } else {
                html += renderPaginatedTable({
                    sectionKey: sectionId,
                    columns: DNS_HEURISTIC_COLUMNS,
                    items,
                    extractFn: extractDnsHeuristicValue,
                    rowRenderer: dnsHeuristicRowHtml,
                    rerender: () => buildDnsHeuristicsSectionContent(sectionId, items),
                });
            }
            html += '</div>';
            container.innerHTML = html;
        }

        async function buildDnsHeuristicsSection() {
            await ensureCappedBatch('dns');
            const events = tabDataCache['dns'] || [];
            const items = computeDnsHeuristics(events);
            buildDnsHeuristicsSectionContent('section-dns_heuristics', items);
        }

        function buildLogSectionContent(sectionId, events) {
            const container = document.getElementById(sectionId);
            if (!container) return;
            let html = '<div class="section-content">';
            if (events.length === 0 && Object.keys(currentFilters).length > 0) {
                html += EMPTY_FILTER_STATE_HTML;
            } else if (events.length === 0) {
                html += '<div class="no-matches">No log events found</div>';
            } else {
                const discoveredCols = discoverLogColumns(events);
                const columns = ['Time', ...discoveredCols.map(c => c.label), 'Detail'];
                html += renderPaginatedTable({
                    sectionKey: sectionId,
                    columns,
                    items: events,
                    extractFn: extractLogValue,
                    rowRenderer: (evt) => buildLogEventRow(evt, discoveredCols),
                    rerender: () => buildLogSectionContent(sectionId, events)
                });
            }
            html += '</div>';
            container.innerHTML = html;
        }

        // `alerts` is ignored in scalable mode (no active filter/sort) - the
        // function fetches its own current page directly from the server, so
        // callers may pass null there (e.g. loadTabData's scalable branch).
        async function buildSigmaAlertSectionContent(sectionId, alerts) {
            const container = document.getElementById(sectionId);
            if (!container) return;

            if (canUseScalableFetch()) {
                const { items, serverTotal, gen } = await fetchSigmaAlertsPage();
                if (isStaleFetch(gen)) return;
                let html = '<div class="section-content">';
                if (serverTotal === 0) {
                    html += '<div class="no-matches">No Sigma alerts detected</div>';
                } else {
                    html += renderPaginatedTable({
                        sectionKey: sectionId,
                        columns: getColumnsForType('sigmaalert'),
                        items,
                        serverTotal,
                        extractFn: extractSigmaValue,
                        rowRenderer: buildSigmaAlertRow,
                        // Recomputes a real, filtered list rather than hardcoding
                        // null - a sort click (sigmaalert isn't server-sortable)
                        // flips canUseScalableFetch() false before invoking this
                        // same closure, so it must not assume scalable mode still
                        // applies. tabDataCache['sigmaalert'] is guaranteed
                        // populated by then since sortCurrentTable always awaits
                        // ensureCappedBatch() first for non-server-sortable types.
                        rerender: () => buildSigmaAlertSectionContent(sectionId, getFilteredSigmaAlerts(tabDataCache['sigmaalert'] || []))
                    });
                }
                html += '</div>';
                container.innerHTML = html;
                return;
            }

            // Defensive fallback matching buildBinaryAnalysisView's `||` style -
            // guards against any caller (present or future) passing a falsy
            // alerts value into this branch, which reads alerts.length below.
            if (!alerts) {
                alerts = getFilteredSigmaAlerts(tabDataCache['sigmaalert'] || []);
            }

            let html = '<div class="section-content">';
            if (alerts.length === 0 && Object.keys(currentFilters).length > 0) {
                html += EMPTY_FILTER_STATE_HTML;
            } else if (alerts.length === 0) {
                html += '<div class="no-matches">No Sigma alerts detected</div>';
            } else {
                html += renderPaginatedTable({
                    sectionKey: sectionId,
                    columns: getColumnsForType('sigmaalert'),
                    items: alerts,
                    extractFn: extractSigmaValue,
                    rowRenderer: buildSigmaAlertRow,
                    rerender: () => buildSigmaAlertSectionContent(sectionId, alerts)
                });
            }
            html += '</div>';
            container.innerHTML = html;
        }

        // Builds one column's whole <div class="agg-section">...</div>
        // block - header/close button, the current page's rows, and
        // Prev/Next controls if there's more than one page. `entries` is
        // already the exact [value, count] pairs to display, in display
        // order; `total`/`page` drive the pagination controls only, no
        // further slicing happens here. Shared by both the full-section
        // renderer below (_renderAggTablesHtml) and changeAggPage's
        // single-table patch, so the two can never render this markup
        // differently from each other.
        function _renderOneAggTableHtml(sectionId, col, entries, total, page) {
            let html = `<div class="section agg-section" data-col="${escapeHtml(col)}"><div class="section-content"><div class="agg-table">
                <div class="agg-header"><span>${escapeHtml(col)}</span><button class="agg-close" data-action="hide-agg-table" data-section-id="${escapeHtml(sectionId)}" data-col="${escapeHtml(col)}" title="Hide">&times;</button></div>
                <table><thead><tr><th style="width:60px;text-align:right;">Count</th><th>Value</th></tr></thead><tbody>`;
            for (const [val, count] of entries) {
                const escapedVal = escapeHtml(val);
                const filterVal = val === '(empty)' ? '' : val;
                // data-agg-pivot (delegated, see the pivot-menu click
                // listener below), not a direct call to the old
                // (now-removed) single-value applyFilter helper - val is
                // arbitrary field content, and the pivot menu needs the raw
                // value for Hunt/Copy/the lookup sites, not just a
                // JS-string-escaped one for a single hardcoded call. The
                // "(empty)" bucket has nothing meaningful to pivot on
                // (matches pivotDataAttrsHtml/htmlRowText's own empty-value
                // exclusion) - left without the attribute, so it's not
                // clickable at all.
                const pivotAttr = filterVal
                    ? ` data-agg-pivot="${encodeURIComponent(JSON.stringify([sectionId, col, filterVal]))}"`
                    : '';
                html += `<tr class="agg-row"${pivotAttr}>
                    <td style="text-align:right;color:var(--text-muted);">${count}</td><td class="agg-cell" title="${escapedVal}">${escapedVal}</td>
                </tr>`;
            }
            html += '</tbody></table>';
            if (total > AGG_PAGE_SIZE) {
                const totalPages = Math.max(1, Math.ceil(total / AGG_PAGE_SIZE));
                html += `<div class="agg-pagination">
                    <button type="button" class="agg-page-btn" data-action="change-agg-page" data-section-id="${escapeHtml(sectionId)}" data-col="${escapeHtml(col)}" data-delta="-1" ${page <= 1 ? 'disabled' : ''}>&larr; Prev</button>
                    <span class="agg-page-info">Page ${page} of ${totalPages}</span>
                    <button type="button" class="agg-page-btn" data-action="change-agg-page" data-section-id="${escapeHtml(sectionId)}" data-col="${escapeHtml(col)}" data-delta="1" ${page >= totalPages ? 'disabled' : ''}>Next &rarr;</button>
                </div>`;
            }
            html += '</div></div></div>';
            return html;
        }

        // Shared aggregation-table renderer: columns control display order,
        // hidden columns are skipped. countsByColumn shape depends on the
        // caller:
        //
        // - Client-computed callers (log/sigmaalert/binary/'all' client-
        //   fallback) pass the FULL {value: count} map for every column -
        //   `totals` is omitted, so this derives each column's total from
        //   the map's own size and slices out the current page itself. The
        //   full map is also stashed in aggFullCountsCache so changeAggPage
        //   can re-slice later without recomputing from events.
        // - Server-aggregated callers (buildAggregationsSection/
        //   buildAggregationsSectionAll) pass `totals` (from
        //   fetchAggregationTotals) plus a countsByColumn that already only
        //   holds page 1's rows per column (from the bulk
        //   /api/aggregation-data fetch) - no slicing needed, just render.
        function _renderAggTablesHtml(countsByColumn, columns, sectionId, totals) {
            if (!totals) aggFullCountsCache[sectionId] = countsByColumn;
            let html = '';
            for (const col of columns) {
                if (hiddenAggregations.has(sectionId + ':' + col)) continue;
                const colCounts = countsByColumn[col] || {};
                const page = aggPage[sectionId + ':' + col] || 1;
                let entries, total;
                if (totals) {
                    total = totals[col] || 0;
                    // Re-sorted here too (not just trusted as "already in
                    // server order") - plain-object key iteration order in
                    // JS reorders integer-like string keys (e.g. a Dest
                    // Port column's "443"/"80") numerically ascending ahead
                    // of every other key, regardless of insertion order, so
                    // trusting Object.entries() to preserve the server's
                    // count-descending order would silently misorder any
                    // numeric-looking value column.
                    entries = Object.entries(colCounts).sort((a, b) => b[1] - a[1]);
                } else {
                    const sorted = Object.entries(colCounts).sort((a, b) => b[1] - a[1]);
                    total = sorted.length;
                    const start = (page - 1) * AGG_PAGE_SIZE;
                    entries = sorted.slice(start, start + AGG_PAGE_SIZE);
                }
                if (total === 0) continue;
                html += _renderOneAggTableHtml(sectionId, col, entries, total, page);
            }
            return html;
        }

        function _aggPageSizeSelectorHtml() {
            const options = AGG_PAGE_SIZE_OPTIONS.map(n =>
                `<option value="${n}"${n === AGG_PAGE_SIZE ? ' selected' : ''}>${n}</option>`
            ).join('');
            return `<div class="agg-page-size-bar"><label for="aggPageSizeSelect">Items per page</label>
                <select id="aggPageSizeSelect" data-change-action="change-agg-page-size">${options}</select></div>`;
        }

        function _wrapAggPanel(innerHtml) {
            return '<div class="agg-panel"><div class="section-toggle-bar" data-action="toggle-aggregations">▾ Aggregation Tables</div><div class="agg-content">'
                + _aggPageSizeSelectorHtml() + innerHtml + '</div></div>';
        }

        // Rebuilds whichever Aggregation Tables view currently applies -
        // binary analysis mode (no tab sections at all) or the visible
        // tab's own section - shared by toggleAggregations() (opening the
        // panel) and changeAggPageSize() (page size changed while already
        // open), so the section/eventType routing logic can't drift between
        // the two call sites.
        async function rebuildVisibleAggregations() {
            const visibleSection = document.querySelector('.section:not(.section-hidden):not(.agg-section)');
            if (!visibleSection) {
                const fileAlerts = allEvents.filter(e => e.event_type === 'filealerts');
                const filtered = fileAlerts.filter(e => matchesCurrentFilters(e, (ev, col) => extractValue(ev, col, -1)));
                buildBinaryAggregations(filtered);
                return;
            }
            const eventType = visibleSection.id.replace('section-', '');
            // needsFullBatch (not an unconditional ensureCappedBatch) so
            // opening the aggregation view for an eligible pcap per-type tab
            // with no active filter goes straight through
            // buildAggregationsSection's own server-aggregation branch
            // instead of always eagerly fetching the full capped batch.
            if (needsFullBatch(eventType)) await ensureCappedBatch(eventType);
            if (eventType === 'all') {
                await buildAggregationsSectionAll();
            } else if (isLogAnalysisMode && eventType === 'log') {
                const events = tabDataCache['log'] || [];
                buildLogAggregations(getFilteredLogEvents(events), visibleSection.id);
            } else if (isLogAnalysisMode && eventType === 'sigmaalert') {
                const alerts = tabDataCache['sigmaalert'] || [];
                buildSigmaAlertAggregations(getFilteredSigmaAlerts(alerts), visibleSection.id);
            } else {
                const events = tabDataCache[eventType] || [];
                const filtered = getFilteredEvents(visibleSection.id, events, eventType);
                await buildAggregationsSection(eventType, filtered);
            }
        }

        // "Items per page" selector's onchange handler (see
        // _aggPageSizeSelectorHtml) - applies to every Aggregation Table at
        // once, not per-column like the old escalating "Show more" tiers
        // this pagination feature replaced, since a per-table selector
        // would mean one selector per column and real UI clutter.
        async function changeAggPageSize(newSize) {
            const parsed = parseInt(newSize, 10);
            AGG_PAGE_SIZE = AGG_PAGE_SIZE_OPTIONS.includes(parsed) ? parsed : CONFIG.AGGREGATION_TOP_N;
            safeStorageSet(localStorage, AGG_PAGE_SIZE_STORAGE_KEY, String(AGG_PAGE_SIZE));
            aggPage = {}; aggFullCountsCache = {}; aggTotalsCache = {};
            await rebuildVisibleAggregations();
        }

        function buildLogAggregations(events, sectionId) {
            const aggContainer = document.getElementById('aggregations');
            if (!aggContainer) return;
            if (!advancedMode) {
                aggContainer.innerHTML = AGG_COLLAPSED_HTML;
                return;
            }
            const counts = {};
            const columns = discoverLogColumns(events);
            const aggCols = columns.map(c => c.label);
            aggCols.forEach(col => { counts[col] = {}; });
            events.forEach(e => {
                const jd = _parseLogEventJson(e);
                columns.forEach(c => {
                    let val = '';
                    if (c.type === 'base') {
                        if (c.field === 'Channel') val = jd.Channel || jd.Provider_Name || e.app_proto || '';
                        else if (c.field === 'EventID') val = String(jd.EventID || '');
                        else if (c.field === 'Computer') val = jd.Computer || '';
                    } else {
                        val = String(jd[c.field] || '');
                    }
                    if (val) counts[c.label][val] = (counts[c.label][val] || 0) + 1;
                });
            });
            aggContainer.innerHTML = _wrapAggPanel('<div class="agg-grid">' + _renderAggTablesHtml(counts, aggCols, sectionId) + '</div>');
        }

        function discoverSigmaAlertColumns(alerts) {
            if (!alerts || alerts.length === 0) return [];
            const total = alerts.length;
            const threshold = Math.max(2, total * 0.1);
            const counts = {};
            const allFields = new Set();

            alerts.forEach(a => {
                try {
                    const logObj = JSON.parse(a.original_log || '{}');
                    if (!logObj || typeof logObj !== 'object') return;
                    Object.keys(logObj).forEach(k => {
                        if (LOG_NOISE_FIELDS.has(k)) return;
                        allFields.add(k);
                        const val = logObj[k];
                        if (val !== undefined && val !== null && val !== '') {
                            counts[k] = (counts[k] || 0) + 1;
                        }
                    });
                } catch(e) {}
            });

            return Array.from(allFields)
                .filter(f => (counts[f] || 0) >= threshold)
                .sort((a, b) => (counts[b] || 0) - (counts[a] || 0))
                .slice(0, 3)
                .map(f => ({ field: f, label: _getLabelForField(f) }));
        }

        function buildSigmaAlertAggregations(alerts, sectionId) {
            const aggContainer = document.getElementById('aggregations');
            if (!aggContainer) return;
            if (!advancedMode) {
                aggContainer.innerHTML = AGG_COLLAPSED_HTML;
                return;
            }
            const counts = {};
            const baseCols = ['Severity', 'Rule', 'MITRE Technique', 'Log Source'];
            const dynamicCols = discoverSigmaAlertColumns(alerts);
            const aggCols = [...baseCols, ...dynamicCols.map(c => c.label)];
            aggCols.forEach(col => { counts[col] = {}; });
            alerts.forEach(a => {
                const sev = a.severity || '';
                if (sev) counts['Severity'][sev] = (counts['Severity'][sev] || 0) + 1;
                const rule = a.rule_title || '';
                if (rule) counts['Rule'][rule] = (counts['Rule'][rule] || 0) + 1;
                parseMitreTechniques(a.mitre_techniques).forEach(tid => {
                    if (tid) counts['MITRE Technique'][tid] = (counts['MITRE Technique'][tid] || 0) + 1;
                });
                const logsource = a.logsource || '';
                if (logsource) counts['Log Source'][logsource] = (counts['Log Source'][logsource] || 0) + 1;
                dynamicCols.forEach(c => {
                    let val = '';
                    try {
                        const logObj = JSON.parse(a.original_log || '{}');
                        if (logObj && typeof logObj === 'object') {
                            val = String(logObj[c.field] || '');
                        }
                    } catch(e) {}
                    if (val) counts[c.label][val] = (counts[c.label][val] || 0) + 1;
                });
            });
            aggContainer.innerHTML = _wrapAggPanel('<div class="agg-grid">' + _renderAggTablesHtml(counts, aggCols, sectionId) + '</div>');
        }

        function formatLogEventDetail(jsonData) {
            if (!jsonData || Object.keys(jsonData).length === 0) return '<div style="color:var(--text-muted);padding:10px;">No event data available</div>';

            const sections = [
                {
                    title: 'Event Info',
                    color: '#b0b0b0',
                    fields: ['Channel', 'EventID', 'EventRecordID', 'Computer', 'SystemTime', 'UtcTime', 'Level', 'Task', 'Opcode', 'Keywords']
                },
                {
                    title: 'Process',
                    color: '#58a6ff',
                    fields: ['Image', 'CommandLine', 'CurrentDirectory', 'ParentImage', 'ParentCommandLine', 'ParentProcessId', 'ProcessId', 'ProcessGuid', 'IntegrityLevel', 'OriginalFileName']
                },
                {
                    title: 'Network',
                    color: '#66bb6a',
                    fields: ['SourceIp', 'SourcePort', 'SourceHostname', 'DestinationIp', 'DestinationPort', 'DestinationHostname', 'DestinationPortName', 'Protocol', 'Initiated']
                },
                {
                    title: 'User',
                    color: '#ffa726',
                    fields: ['User', 'UserID', 'LogonId', 'LogonGuid', 'TerminalSessionId']
                },
                {
                    title: 'File / Hashes',
                    color: '#9c27b0',
                    fields: ['Hashes', 'MD5', 'SHA1', 'SHA256', 'IMPHASH', 'Signed', 'Signature', 'SignatureStatus']
                },
                {
                    title: 'Other',
                    color: '#8b949e',
                    fields: ['Provider_Name', 'RuleName', 'Guid', 'Version', 'Description', 'Company', 'Product', 'FileVersion', 'ImageLoaded', 'PipeName']
                },
                {
                    title: 'Source',
                    color: '#8b949e',
                    fields: ['OriginalLogfile']
                }
            ];

            let html = `<div style="display: grid; grid-template-columns: 140px minmax(0, 1fr); gap: 8px 12px; font-size: 0.9rem; overflow-wrap: break-word;">`;
            let hasAny = false;

            for (const section of sections) {
                let sectionHtml = '';
                for (const field of section.fields) {
                    const val = jsonData[field];
                    if (val !== undefined && val !== null && val !== '') {
                        sectionHtml += htmlRowText(field, String(val), 'mono', undefined, true);
                    }
                }
                if (sectionHtml) {
                    html += htmlSection(section.title, section.color);
                    html += sectionHtml;
                    hasAny = true;
                }
            }

            // Raw JSON fallback for any fields not in known sections
            const knownFields = new Set(sections.flatMap(s => s.fields));
            const remaining = Object.entries(jsonData).filter(([k, v]) => {
                return !knownFields.has(k) && v !== undefined && v !== null && v !== '';
            });
            if (remaining.length > 0) {
                html += htmlSection('Raw Data', '#8b949e');
                for (const [k, v] of remaining) {
                    html += htmlRowText(k, String(v), 'mono', undefined, true);
                }
                hasAny = true;
            }

            html += '</div>';
            return hasAny ? html : '<div style="color:var(--text-muted);padding:10px;">No event data available</div>';
        }

        function formatSigmaAlertDetail(alert) {
            let html = `<div style="display: grid; grid-template-columns: 140px minmax(0, 1fr); gap: 8px 12px; font-size: 0.9rem; overflow-wrap: break-word;">`;

            // Matched Event
            let eventHtml = '';
            try {
                const logObj = JSON.parse(alert.original_log || '{}');
                if (logObj && Object.keys(logObj).length > 0) {
                    eventHtml = formatLogEventDetail(logObj);
                }
            } catch(e) {}
            if (eventHtml) {
                html += htmlSection('Matched Event', COLORS.EVENT.log);
                html += `<div style="grid-column: 1 / -1;">${eventHtml}</div>`;
            }

            // Sigma Rule
            html += htmlSection('Sigma Rule', COLORS.EVENT.sigmaalert);
            html += htmlRowText('Rule Title', alert.rule_title);
            html += aiSummaryPlaceholderHtml('sigma', alert.rule_id);
            html += htmlRowText('Rule ID', alert.rule_id);
            html += htmlRowText('Severity', alert.severity);
            html += htmlRowText('Level', alert.level);
            html += htmlRowText('Log Source', alert.logsource);

            const mitreHtml = mitreTechniquesHtml(alert.mitre_techniques);
            if (mitreHtml) {
                html += htmlRow('MITRE Techniques', mitreHtml);
            }

            let tagsText = '';
            try {
                const tags = JSON.parse(alert.tags || '[]');
                if (tags.length > 0) {
                    tagsText = tags.join(', ');
                }
            } catch(e) {}
            if (tagsText) {
                html += htmlRowText('Tags', tagsText);
            }

            // See renderAlertDetails' own comment - same hidden anchor,
            // populated (or not) by loadPlaybookSectionIfPresent on first
            // expand.
            html += `<span class="playbook-section-placeholder" data-detection-type="sigma" data-rule-id="${escapeHtml(String(alert.rule_id || ''))}" style="display:none;"></span>`;

            html += rowNoteDetailHtml('sigma_alerts', alert.id, alert.row_note);
            html += '</div>';
            return html;
        }

        async function buildSection(eventType, events) {
            const columns = getColumnsForType(eventType);
            const sectionId = `section-${eventType}`;
            const container = document.getElementById(sectionId);
            if (!container) return;

            if (canUseScalableFetchForSort(eventType)) {
                const { items, serverTotal, gen } = await fetchEventsPage(eventType);
                if (isStaleFetch(gen)) return;
                let html = '<div class="section-content">';
                html += renderPaginatedTable({
                    sectionKey: sectionId,
                    columns,
                    items,
                    serverTotal,
                    extractFn: extractValue,
                    rowRenderer: buildRowForEvent,
                    rerender: () => buildSection(eventType, tabDataCache[eventType] || [])
                });
                html += '</div>';
                try {
                    container.innerHTML = html;
                } catch(e) {
                    console.error('Failed to render section:', e);
                    container.innerHTML = '<div class="loading">Error rendering table</div>';
                }
                return;
            }

            const sorted = [...events].sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));

            let filteredEvents = sorted;
            if (Object.keys(currentFilters).length > 0) {
                filteredEvents = sorted.filter(e => matchesCurrentFilters(e, (ev, col) => extractValue(ev, col, columns.indexOf(col))));
            }

            let html = '<div class="section-content">';
            if (filteredEvents.length === 0 && Object.keys(currentFilters).length > 0) {
                html += EMPTY_FILTER_STATE_HTML;
            } else {
                html += renderPaginatedTable({
                    sectionKey: sectionId,
                    columns,
                    items: filteredEvents,
                    extractFn: extractValue,
                    rowRenderer: buildRowForEvent,
                    rerender: () => buildSection(eventType, events)
                });
            }
            html += '</div>';

            try {
                container.innerHTML = html;
            } catch(e) {
                console.error('Failed to render section:', e);
                container.innerHTML = '<div class="loading">Error rendering table</div>';
            }
        }

        async function buildAggregationsSection(eventType, events) {
            const aggContainer = document.getElementById('aggregations');
            if (!aggContainer) return;

            if (!advancedMode) {
                aggContainer.innerHTML = AGG_COLLAPSED_HTML;
                return;
            }

            const sectionId = `section-${eventType}`;

            if (canUseServerAggregation(eventType)) {
                const [data, totals] = await Promise.all([
                    fetchAggregationData(eventType),
                    fetchAggregationTotals(eventType),
                ]);
                aggTotalsCache[sectionId] = totals;
                const countsByColumn = {};
                for (const [col, entries] of Object.entries(data)) {
                    countsByColumn[col] = {};
                    for (const { value, count } of entries) countsByColumn[col][value] = count;
                }
                const html = '<div class="agg-grid">' + _renderAggTablesHtml(countsByColumn, getColumnsForType(eventType), sectionId, totals) + '</div>';
                aggContainer.innerHTML = _wrapAggPanel(html);
                return;
            }

            aggContainer.innerHTML = _wrapAggPanel(buildAggregationTables(events, eventType));
        }
        
        // Whether the row table/aggregations/diagram for the currently-visible
        // tab are known to be operating on a capped (partial) dataset - see
        // truncatedTypes, maintained by ensureCappedBatch.
        function isCurrentTabTruncated() {
            const eventType = getVisibleEventType();
            return !!eventType && truncatedTypes.has(eventType);
        }

        function getVisibleEventType() {
            const visibleSection = document.querySelector('.section:not(.section-hidden):not(.agg-section)');
            const type = visibleSection ? visibleSection.id.replace('section-', '') : null;
            // DNS Heuristics is a derived view over the same underlying
            // 'dns' batch (see buildDnsHeuristicsSection) - truncation is
            // tracked in truncatedTypes under 'dns', not a separate
            // 'dns_heuristics' key, so this reuses the existing truncation
            // banner instead of needing a second one.
            return type === 'dns_heuristics' ? 'dns' : type;
        }

        // Actual number of rows currently cached for eventType - used in the
        // truncation-warning message since the effective limit is user-configurable
        // (getUserQueryLimit()) and may itself still be clamped lower server-side.
        function getFetchedLengthForType(eventType) {
            return (eventType === 'all' ? allEvents : (tabDataCache[eventType] || [])).length;
        }

        function buildFilterBarHtml() {
            const hasFilters = Object.keys(currentFilters).length > 0;
            let html = '';
            if (currentSearch.length > 0 || hasFilters) {
                html += `<div class="filter-bar"><span class="filter-label">${SEARCH_ICON_SVG} Active:</span>`;
                for (let i = 0; i < currentSearch.length; i++) {
                    const term = currentSearch[i];
                    html += `<span class="filter-chip">${SEARCH_ICON_SVG} "${escapeHtml(term)}" <span class="filter-chip-remove" data-action="clear-search-term" data-index="${i}">&times;</span></span>`;
                }
                for (const [col, spec] of Object.entries(currentFilters)) {
                    if (typeof spec === 'string') {
                        html += `<span class="filter-chip">${escapeHtml(col)}: ${escapeHtml(spec)} <span class="filter-chip-remove" data-action="clear-filter" data-col="${escapeHtml(col)}">&times;</span></span>`;
                        continue;
                    }
                    // Object shape (pivot menu's include/exclude) - one
                    // removable chip per value, unlike the string shape's
                    // one chip per column, since multiple include/exclude
                    // values can be active on the same column at once.
                    for (const val of (spec.include || [])) {
                        html += `<span class="filter-chip">${escapeHtml(col)}: ${escapeHtml(val)} <span class="filter-chip-remove" data-action="clear-filter-value" data-col="${escapeHtml(col)}" data-kind="include" data-value="${escapeHtml(val)}">&times;</span></span>`;
                    }
                    for (const val of (spec.exclude || [])) {
                        html += `<span class="filter-chip filter-chip-exclude">${escapeHtml(col)} ≠ ${escapeHtml(val)} <span class="filter-chip-remove" data-action="clear-filter-value" data-col="${escapeHtml(col)}" data-kind="exclude" data-value="${escapeHtml(val)}">&times;</span></span>`;
                    }
                }
                html += '<button class="filter-clear-all" data-action="clear-all-filters">Clear All</button></div>';
            }
            if (isCurrentTabTruncated()) {
                const fetchedCount = getFetchedLengthForType(getVisibleEventType()).toLocaleString();
                html += `<div class="filter-bar"><span style="color: var(--badge-warning-text);">⚠ Showing the first ${fetchedCount} matching events for this view — results may be incomplete (you can raise the limit in <a href="#" data-action="show-settings-modal" style="color: var(--accent); text-decoration: underline; font-weight: 600;">Settings</a>).</span></div>`;
            }
            return html;
        }

        function updateFilterBarVisibility() {
            const filterBarContainer = document.getElementById('filterBarContainer');
            if (!filterBarContainer) return;

            const hasFilters = Object.keys(currentFilters).length > 0;
            if (currentSearch.length > 0 || hasFilters || isCurrentTabTruncated()) {
                filterBarContainer.innerHTML = buildFilterBarHtml();
                filterBarContainer.style.display = 'block';
            } else {
                filterBarContainer.innerHTML = '';
                filterBarContainer.style.display = 'none';
            }
        }
        
        let eventStats = {};

        // The Acknowledged Alerts stat card's count (see buildStats()
        // below) - unlike every other card, this isn't derivable from
        // eventStats (acknowledged rows are excluded from every other
        // count by design, see db.py's _build_where_conditions/
        // _sigma_alert_where), so it needs its own dedicated fetch rather
        // than reading off the same object every other card already has
        // in hand. acknowledgedAlertsCountStale starts true (so the very
        // first buildStats() call after page load fetches it) and gets
        // set true again by refreshAnalysisData() (which every acknowledge/
        // un-acknowledge action already calls) - buildStats() itself
        // fetches and re-renders lazily whenever it sees the stale flag,
        // rather than this being threaded through every one of buildStats()'s
        // own several call sites by hand.
        let acknowledgedAlertsCount = 0;
        let acknowledgedAlertsCountStale = true;

        // The DNS Heuristics stat card's count - same lazy-refresh shape
        // as acknowledgedAlertsCount just above (see its own comment) and
        // for the same underlying reason: the real number (how many
        // domains actually scored above 0, see computeDnsHeuristics)
        // isn't in eventStats at all, and computing it requires the full
        // 'dns' batch fetched and scored, not just a count. Without this,
        // the card would have to show the raw DNS event count instead -
        // which it did briefly, and which reads as "157 suspicious
        // things" on a card literally labeled DNS Heuristics when only a
        // handful (or zero) actually scored.
        let dnsHeuristicsFlaggedCount = 0;
        let dnsHeuristicsCountStale = true;

        async function refreshDnsHeuristicsCount() {
            if (isLogAnalysisMode || !currentMd5) {
                dnsHeuristicsFlaggedCount = 0;
                return;
            }
            try {
                // A dedicated fetch, not ensureCappedBatch('dns')/
                // tabDataCache - this runs fire-and-forget from inside
                // buildStats() (see the lazy self-refresh block below),
                // triggered from the FIRST buildStats() call inside
                // refreshAnalysisData(), which only clears tabDataCache
                // AFTER that call returns. ensureCappedBatch's cache check
                // runs synchronously ahead of any real fetch, so it used
                // to race ahead of that clear and see a stale, narrower
                // (sometimes even empty) tabDataCache['dns'] left over
                // from an earlier search-filtered tab visit - scoring the
                // wrong dataset and then sticking with the wrong count
                // once dnsHeuristicsCountStale flipped back to false.
                const qParam = buildSearchQuery();
                const resp = await fetch(`/api/events?md5=${encodeURIComponent(currentMd5)}&type=dns&limit=${getUserQueryLimit()}${qParam}&t=${Date.now()}`);
                const events = await resp.json();
                dnsHeuristicsFlaggedCount = computeDnsHeuristics(events).length;
            } catch (e) {
                dnsHeuristicsFlaggedCount = 0;
            }
            buildStats(await computeFilteredStats());
        }

        async function refreshAcknowledgedAlertsCount() {
            if (isLogAnalysisMode || !currentMd5) {
                acknowledgedAlertsCount = 0;
                return;
            }
            try {
                const [alertResp, sigmaResp] = await Promise.all([
                    fetch(`/api/count?md5=${encodeURIComponent(currentMd5)}&type=alert&acknowledged=only&t=${Date.now()}`),
                    fetch(`/api/sigma-count?md5=${encodeURIComponent(currentMd5)}&acknowledged=only&t=${Date.now()}`)
                ]);
                const alertCount = (await alertResp.json()).count || 0;
                const sigmaCount = (await sigmaResp.json()).count || 0;
                acknowledgedAlertsCount = alertCount + sigmaCount;
            } catch (e) {
                acknowledgedAlertsCount = 0;
            }
            buildStats(await computeFilteredStats());
        }

        function eventMatchesFilters(event) {
            if (Object.keys(currentFilters).length === 0) return true;
            return matchesCurrentFilters(event, (ev, col) => {
                if (col === 'Type' || col === 'Detail') {
                    const allColIndex = ALL_EVENTS_COLUMNS.indexOf(col);
                    return extractAllValue(ev, col, allColIndex);
                }
                return extractValue(event, col, -1);
            });
        }

        async function computeFilteredStats() {
            if (isLogAnalysisMode) {
                // eventMatchesFilters/sigmaAlertMatchesFilters only check
                // currentFilters (search is already reflected server-side in
                // eventStats via /api/count?q=/api/sigma-count?q=), so with no
                // active column filter eventStats already holds the exact
                // same counts - no need to touch the full arrays at all.
                if (Object.keys(currentFilters).length === 0) {
                    return eventStats;
                }
                await ensureCappedBatch('log');
                await ensureCappedBatch('sigmaalert');
                const stats = {};
                const logEvents = tabDataCache['log'] || [];
                const sigmaAlerts = tabDataCache['sigmaalert'] || [];
                let logCount = 0;
                for (const e of logEvents) {
                    if (eventMatchesFilters(e)) logCount++;
                }
                if (logCount > 0) stats['log'] = logCount;
                let sigmaCount = 0;
                for (const a of sigmaAlerts) {
                    if (sigmaAlertMatchesFilters(a)) sigmaCount++;
                }
                if (sigmaCount > 0) stats['sigmaalert'] = sigmaCount;
                return stats;
            }
            // eventMatchesFilters only ever checks currentFilters (search is
            // already reflected server-side in eventStats via /api/stats?q=),
            // so with no active column filter every event trivially matches -
            // eventStats already holds the exact same per-type counts, no need
            // to touch allEvents at all.
            if (Object.keys(currentFilters).length === 0) {
                return eventStats;
            }
            await ensureCappedBatch('all');
            const stats = {};
            const events = allEvents.filter(e => e.event_type !== 'stats');
            for (const e of events) {
                if (eventMatchesFilters(e)) {
                    const type = e.event_type || 'unknown';
                    stats[type] = (stats[type] || 0) + 1;
                }
            }
            return stats;
        }

        function sigmaAlertMatchesFilters(alert) {
            if (Object.keys(currentFilters).length === 0) return true;
            return matchesCurrentFilters(alert, extractSigmaValue);
        }

        // Counts a .stat-number element up from 0 to target on a
        // decelerating ease-out curve instead of snapping straight to the
        // final value - reads as data "arriving" rather than just
        // appearing, on every buildStats() call (initial load, filter/
        // search apply, tab switch). Skipped under prefers-reduced-motion:
        // reduce, jumping straight to the final value instead - this is
        // pure decoration, not information the motion itself conveys, so
        // honoring that preference costs nothing functionally.
        function animateStatNumber(el, target) {
            // Count-up is a playful flourish, reserved for the fun themes -
            // reuses THEMED_LOADING_PHRASES as the single source of truth for
            // "is this a fun theme" rather than maintaining a second list.
            const reducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
            if (reducedMotion || !THEMED_LOADING_PHRASES[getCurrentTheme()]) {
                el.textContent = target.toLocaleString();
                return;
            }
            const duration = 500;
            const start = performance.now();
            function tick(now) {
                const progress = Math.min((now - start) / duration, 1);
                const eased = 1 - Math.pow(1 - progress, 3);
                el.textContent = Math.round(target * eased).toLocaleString();
                if (progress < 1) {
                    requestAnimationFrame(tick);
                }
            }
            requestAnimationFrame(tick);
        }

        function buildStats(filteredStats) {
            const grid = document.getElementById('statsGrid');
            const stats = [];
            let allFiltered = 0;

            eventTypes.forEach(type => {
                const filtered = filteredStats ? (filteredStats[type] || 0) : (eventStats[type] || 0);
                allFiltered += filtered;
                // Inserted immediately before the real DNS Queries card
                // (rather than appended after every other card, with
                // 'all'/'acknowledged') so it reads as "the DNS-specific
                // view" sitting right next to "DNS Queries", not a
                // catch-all tacked onto the end of the whole row. Gated on
                // the lazily-computed flagged-domain count (see
                // dnsHeuristicsFlaggedCount/refreshDnsHeuristicsCount
                // below and dnsHeuristicsCountStale's own comment) - NOT
                // the raw DNS event count, which would read as "this many
                // suspicious things" on a card literally labeled DNS
                // Heuristics. Guarded by !isLogAnalysisMode for parity
                // with 'all'/'acknowledged' below even though 'dns' can't
                // actually occur in log-analysis mode in practice.
                if (type === 'dns' && !isLogAnalysisMode) {
                    stats.push({
                        id: 'dns_heuristics',
                        label: 'DNS Heuristics',
                        count: dnsHeuristicsFlaggedCount,
                        color: '#ff9800'
                    });
                }
                stats.push({
                    id: type,
                    label: typeLabels[type] || type.toUpperCase(),
                    count: filtered,
                    color: COLORS.EVENT[type] || COLORS.EVENT.tls
                });
            });

            if (!isLogAnalysisMode) {
                stats.push({
                    id: 'all',
                    label: 'All Events',
                    count: allFiltered,
                    color: 'var(--text-bright)'
                });
                // Not filtered by the current search/filter bar the way
                // every other card above is (filteredStats has no entry
                // for it - there's nothing to filter, acknowledged rows
                // are already excluded from every other query) - always
                // shows the same count regardless of what's currently
                // searched/filtered.
                stats.push({
                    id: 'acknowledged',
                    label: 'Acknowledged Alerts',
                    count: acknowledgedAlertsCount,
                    color: 'var(--text-muted)'
                });
            }

            const visibleSection = document.querySelector('.section:not(.section-hidden):not(.agg-section)');
            // find(s => s.count > 0), not just stats[0] - a zero-count
            // entry (e.g. log analysis with sigma alerts disabled/absent,
            // sorted ahead of 'log' by priority - see sortEventTypes) gets
            // filtered out of the actual rendered grid below and so can
            // never really be "active" - falling back to it left NO card
            // marked tab-active at all (real user report: keyboard
            // navigation broke identically to the PCAP-mode bugs already
            // fixed, because activeColumnStatCards()'s own .tab-active
            // fallback then found nothing either).
            const activeType = visibleSection ? visibleSection.id.replace('section-', '') : (stats.find(s => s.count > 0) || {}).id;
            // A type only ever reaches eventTypes because it had at least
            // one event in the unfiltered sample (see eventTypes' own
            // derivation from baseEventStats), so count === 0 here only
            // happens once a search/filter has narrowed it away entirely -
            // dropped rather than shown disabled, so a heavily-filtered
            // large sample (20+ event types, most zeroed out) doesn't turn
            // into a wall of grayed-out cards.
            grid.innerHTML = stats.filter(s => s.count > 0).map(s => {
                // Filtered/searched-down counts show as just the filtered
                // number, not "filtered / total" - the filter bar's own
                // chips already signal that a filter is active, and a
                // combined "count / total" string could run to twice the
                // length of a lone count on a large sample (e.g. "229,378 /
                // 229,831"), which no stat-card width/font-size could
                // reliably keep from overflowing.
                const countDisplay = s.count.toLocaleString();
                const activeClass = s.id === activeType ? ' tab-active' : '';
                // Rendered starting at 0, then animated up to countDisplay
                // by animateStatNumber() below - aria-label carries the
                // real final value immediately so assistive tech isn't
                // stuck reading "0" or a mid-animation number.
                return `
                    <div class="stat-card${activeClass}" data-action="show-tab" data-section="section-${s.id}">
                        <div class="stat-number" style="color: ${s.color}" aria-label="${countDisplay}">0</div>
                        <div class="stat-label">${s.label}</div>
                    </div>
                `;
            }).join('');
            const numberEls = grid.querySelectorAll('.stat-number');
            stats.filter(s => s.count > 0).forEach((s, i) => animateStatNumber(numberEls[i], s.count));

            // Lazy self-refresh for the Acknowledged Alerts card - see
            // acknowledgedAlertsCountStale's own comment for why this
            // lives here rather than being threaded through every one of
            // this function's several call sites by hand. Guarded so the
            // recursive buildStats() call refreshAcknowledgedAlertsCount()
            // itself makes doesn't loop.
            if (acknowledgedAlertsCountStale) {
                acknowledgedAlertsCountStale = false;
                refreshAcknowledgedAlertsCount();
            }

            // Lazy self-refresh for the DNS Heuristics card - same
            // pattern as Acknowledged Alerts just above, same reason.
            if (dnsHeuristicsCountStale) {
                dnsHeuristicsCountStale = false;
                refreshDnsHeuristicsCount();
            }
        }

        function buildSections() {
            const sectionsEl = document.getElementById('sections');
            let html = '';
            
            eventTypes.forEach((type, i) => {
                const label = typeLabels[type] || type.toUpperCase();
                html += `<div class="section${i > 0 ? ' section-hidden' : ''}" id="section-${type}"><div class="section-header">${label}</div><div class="loading">Loading...</div></div>`;
            });
            
            html += '<div class="section section-hidden" id="section-all"><div class="section-header">All Events</div><div class="loading">Loading...</div></div>';
            html += '<div class="section section-hidden" id="section-acknowledged"><div class="section-header">Acknowledged Alerts</div><div class="loading">Loading...</div></div>';
            html += '<div class="section section-hidden" id="section-dns_heuristics"><div class="section-header">DNS Heuristics</div><div class="loading">Loading...</div></div>';
            sectionsEl.innerHTML = html;
            
        }
        
        function buildAllEventRow(e) {
            const ts = (e.timestamp || '').slice(0, 19);
            const etype = e.event_type || '';
            const proto = e.proto || '';
            const srcIp = e.src_ip || '';
            const srcPort = e.src_port || '';
            const dstIp = e.dest_ip || '';
            const dstPort = e.dest_port || '';
            // Uses the canonical Detail logic (extractValue's 'Detail' case)
            // instead of maintaining a separate, independently-drifted copy -
            // the old inline copy here was missing modbus/dnp3/pgsql/filealerts
            // (always blank), even though those were already correctly
            // sortable/filterable via extractValue elsewhere.
            const detail = extractValue(e, 'Detail', -1);
            const formatted = formatEvent(e);
            const pivotAttrs = pivotDataAttrsHtml(e, 'all', ALL_EVENTS_COLUMNS, extractAllValue);
            const communityIdAttr = e.community_id ? ` data-community-id="${escapeHtml(e.community_id)}"` : '';
            return `<tr data-id="${escapeHtml(String(e.id))}"${pivotAttrs}${communityIdAttr} data-action="toggle-row"><td class="timestamp">${escapeHtml(ts)}</td><td>${valueDotSpan(COLORS.EVENT[etype])}${escapeHtml(etype.toUpperCase())}</td><td>${valueDotSpan(DOT_COLORS.PROTO[proto.toUpperCase()])}${escapeHtml(proto)}</td><td class="mono-fixed" title="${escapeHtml(srcIp)}">${escapeHtml(srcIp)}</td><td class="mono-fixed">${escapeHtml(String(srcPort))}</td><td class="mono-fixed" title="${escapeHtml(dstIp)}">${escapeHtml(dstIp)}</td><td class="mono-fixed">${escapeHtml(String(dstPort))}</td><td class="mono">${escapeHtml(detail)}</td>${rowNoteIconHtml('events', e.id, e.row_note)}</tr><tr class="detail-row"><td colspan="9"><div class="detail-content">${formatted}</div></td></tr>`;
        }

        async function buildAllEvents() {
            const allColumns = ALL_EVENTS_COLUMNS;
            const sectionId = 'section-all';
            const container = document.getElementById(sectionId);
            if (!container) return;

            if (canUseScalableFetchForSort('all')) {
                const { items, serverTotal, gen } = await fetchEventsPage('all');
                if (isStaleFetch(gen)) return;
                let html = '<div class="section-content">';
                html += renderPaginatedTable({
                    sectionKey: sectionId,
                    columns: allColumns,
                    items,
                    serverTotal,
                    extractFn: extractAllValue,
                    rowRenderer: buildAllEventRow,
                    rerender: buildAllEvents
                });
                html += '</div>';
                container.innerHTML = html;
                return;
            }

            const sortedAll = [...allEvents].filter(e => e.event_type !== 'stats').sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));

            if (sortedAll.length === 0) return;

            let filteredEvents = sortedAll;
            if (Object.keys(currentFilters).length > 0) {
                filteredEvents = sortedAll.filter(e => matchesCurrentFilters(e, (ev, col) => extractAllValue(ev, col, allColumns.indexOf(col))));
            }

            let html = '<div class="section-content">';
            if (filteredEvents.length === 0 && Object.keys(currentFilters).length > 0) {
                html += EMPTY_FILTER_STATE_HTML;
            } else {
                html += renderPaginatedTable({
                    sectionKey: sectionId,
                    columns: allColumns,
                    items: filteredEvents,
                    extractFn: extractAllValue,
                    rowRenderer: buildAllEventRow,
                    rerender: buildAllEvents
                });
            }
            html += '</div>';

            container.innerHTML = html;
        }

        // Fetches both acknowledged-only sets in parallel and hands off to
        // renderAcknowledgedAlertsGroups() below. Reuses buildAllEventRow()/
        // buildSigmaAlertRow() exactly as each already is (same columns,
        // same expand/toggle mechanism, same detail formatter) rather than
        // a new unified renderer - Network Alerts and Sigma Alerts have no
        // existing combined view to build on the way "All Events" does for
        // types that already share the one `events` table, so two
        // clearly-labeled groups reusing proven code is far less risk than
        // inventing a shared renderer for what's fundamentally a review bin.
        async function buildAcknowledgedAlertsSection() {
            const sectionEl = document.getElementById('section-acknowledged');
            if (!sectionEl || !currentMd5) return;
            const qParam = buildSearchQuery();
            const limit = getUserQueryLimit();
            const [alertResp, sigmaResp] = await Promise.all([
                fetch(`/api/events?md5=${encodeURIComponent(currentMd5)}&type=alert&acknowledged=only&limit=${limit}${qParam}&t=${Date.now()}`),
                fetch(`/api/sigma-alerts?md5=${encodeURIComponent(currentMd5)}&acknowledged=only&limit=${limit}${qParam}&t=${Date.now()}`)
            ]);
            acknowledgedAlertsCache = {
                alert: await alertResp.json(),
                sigmaalert: await sigmaResp.json(),
            };
            renderAcknowledgedAlertsGroups();
        }

        // When only one of the two types has any acknowledged rows, show it
        // as a single plain table - sortable/paginated via
        // renderPaginatedTable, the exact same renderer/columns the real
        // Network Alerts/Sigma Alerts tab itself uses - instead of the
        // two-group layout below, which would otherwise pair it with an
        // empty "No acknowledged ..." group for no reason. Safe to reuse
        // renderPaginatedTable here (unlike the both-groups case just
        // below) since exactly one table is ever on screen at a time in
        // this branch, so there's no fight over the shared
        // currentPage/currentSort state (see renderPaginatedTable's own
        // sectionKey handling) the way two simultaneously-visible tables
        // would cause. rerender re-renders from the already-fetched
        // acknowledgedAlertsCache, not a fresh server round-trip - a
        // sort/page click never needs new data, just a different slice of
        // what buildAcknowledgedAlertsSection already loaded.
        function renderAcknowledgedSingleTypeTable(eventType) {
            const sectionEl = document.getElementById('section-acknowledged');
            const isSigma = eventType === 'sigmaalert';
            sectionEl.innerHTML = '<div class="section-content">' + renderPaginatedTable({
                sectionKey: 'section-acknowledged',
                columns: getColumnsForType(eventType),
                items: isSigma ? acknowledgedAlertsCache.sigmaalert : acknowledgedAlertsCache.alert,
                extractFn: isSigma ? extractSigmaValue : extractValue,
                rowRenderer: isSigma ? buildSigmaAlertRow : buildRowForEvent,
                rerender: () => renderAcknowledgedSingleTypeTable(eventType),
            }) + '</div>';
        }

        // Both-groups (or neither) layout - deliberately NOT
        // renderPaginatedTable() here, since this branch shows two tables
        // side by side, which would fight over renderPaginatedTable's one
        // shared currentPage/currentSort (two distinct sectionKeys
        // wouldn't fix it - paging one table would still move the other's
        // currentPage out from under it). Rendering both groups in full
        // instead - a reasonable scope for what's meant to be a small
        // review list once both types are present, not a primary
        // high-volume table the way Network Alerts/Sigma Alerts
        // themselves are.
        function renderAcknowledgedAlertsGroups() {
            const sectionEl = document.getElementById('section-acknowledged');
            if (!sectionEl) return;
            const hasAlerts = acknowledgedAlertsCache.alert.length > 0;
            const hasSigma = acknowledgedAlertsCache.sigmaalert.length > 0;
            if (hasAlerts && !hasSigma) {
                renderAcknowledgedSingleTypeTable('alert');
                return;
            }
            if (hasSigma && !hasAlerts) {
                renderAcknowledgedSingleTypeTable('sigmaalert');
                return;
            }
            // tableHeaderCellsHtml(cols, null) - same shared helper
            // renderPaginatedTable itself uses (see
            // renderAcknowledgedSingleTypeTable above), with a null
            // sectionKey so it never highlights a sort column (neither
            // group here is sortable - see this function's own comment).
            // Reused rather than hand-rolled specifically for its
            // FIXED_COLUMN_WIDTHS styling, so column widths in this
            // two-group view match every other table in the app instead of
            // drifting to whatever width each column's content happens to
            // need.
            const alertCols = getColumnsForType('alert');
            const alertHeaderHtml = tableHeaderCellsHtml(alertCols, null) + '<th style="width:32px;"></th>';
            const alertHtml = hasAlerts
                ? `<div class="table-scroll-wrapper"><table><thead><tr>${alertHeaderHtml}</tr></thead><tbody>${acknowledgedAlertsCache.alert.map(buildRowForEvent).join('')}</tbody></table></div>`
                : '<div class="no-matches">No acknowledged network alerts</div>';
            const sigmaCols = getColumnsForType('sigmaalert');
            const sigmaHeaderHtml = tableHeaderCellsHtml(sigmaCols, null) + '<th style="width:32px;"></th>';
            const sigmaHtml = hasSigma
                ? `<div class="table-scroll-wrapper"><table><thead><tr>${sigmaHeaderHtml}</tr></thead><tbody>${acknowledgedAlertsCache.sigmaalert.map(buildSigmaAlertRow).join('')}</tbody></table></div>`
                : '<div class="no-matches">No acknowledged Sigma alerts</div>';
            sectionEl.innerHTML = `
                <div class="section-content">
                    <div class="section-header">Network Alerts</div>
                    ${alertHtml}
                    <div class="section-header">Sigma Alerts</div>
                    ${sigmaHtml}
                </div>
            `;
        }

        async function buildAggregationsSectionAll() {
            const aggContainer = document.getElementById('aggregations');
            if (!aggContainer) return;

            if (!advancedMode) {
                aggContainer.innerHTML = AGG_COLLAPSED_HTML;
                return;
            }

            const allColumns = ALL_EVENTS_COLUMNS;
            const sectionId = 'section-all';

            if (canUseServerAggregation('all')) {
                const [data, totals] = await Promise.all([
                    fetchAggregationData('all'),
                    fetchAggregationTotals('all'),
                ]);
                aggTotalsCache[sectionId] = totals;
                const countsByColumn = {};
                for (const [col, entries] of Object.entries(data)) {
                    countsByColumn[col] = {};
                    for (const { value, count } of entries) countsByColumn[col][value] = count;
                }
                const html = '<div class="agg-grid">' + _renderAggTablesHtml(countsByColumn, allColumns, sectionId, totals) + '</div>';
                aggContainer.innerHTML = _wrapAggPanel(html);
                return;
            }

            const sortedAll = [...allEvents].filter(e => e.event_type !== 'stats').sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
            let filteredEvents = sortedAll;
            if (Object.keys(currentFilters).length > 0) {
                filteredEvents = sortedAll.filter(e => matchesCurrentFilters(e, (ev, col) => extractAllValue(ev, col, allColumns.indexOf(col))));
            }

            aggContainer.innerHTML = _wrapAggPanel(buildAggregationTablesAll(filteredEvents, allColumns));
        }
        
        function extractAllValue(e, col, colIndex) {
            // 'Type' means something different here (the event_type itself,
            // e.g. "DNS"/"ANOMALY") than it does on a per-type tab (a DNS
            // record type, dnp3's type field, etc.) - this override is
            // real and must stay. 'Command' and 'Message' used to be
            // overridden here too, but both were stale: 'Command' predates
            // pgsql/enip/pop3 gaining their own real command fields (this
            // always returned '' for them, ignoring extractValue's own
            // already-correct per-protocol handling), and 'Message' read
            // e.anomaly?.message, a field that has never existed in
            // Suricata's eve.json anomaly schema (real field is 'event') -
            // also, no column has been labeled 'Message' since anomaly
            // gained real columns (Event/Type/Layer/App Proto). Both are
            // removed; extractValue's own switch already handles every
            // real per-type column correctly.
            if (col === 'Type') return (e.event_type || '').toUpperCase();
            return extractValue(e, col, colIndex);
        }
        
        function buildAggregationTablesCore(events, columns, sectionId, extractFn) {
            if (!events || events.length === 0) return '';

            const excludeCols = ['Time'];
            const aggCols = columns.filter(c => !excludeCols.includes(c) && !hiddenAggregations.has(sectionId + ':' + c));

            const counts = {};
            aggCols.forEach(col => { counts[col] = {}; });
            for (const col of aggCols) {
                const colIndex = columns.indexOf(col);
                for (const e of events) {
                    const val = extractFn(e, col, colIndex);
                    const key = val || '(empty)';
                    counts[col][key] = (counts[col][key] || 0) + 1;
                }
            }

            return '<div class="agg-grid">' + _renderAggTablesHtml(counts, aggCols, sectionId) + '</div>';
        }
        
        function buildAggregationTablesAll(events, columns) {
            return buildAggregationTablesCore(events, columns, 'section-all', extractAllValue);
        }
        
        function extractValue(e, col, colIndex) {
            switch(col) {
                case 'Protocol': return e.proto || '';
                case 'Source IP': return e.src_ip || '';
                case 'Source Port': return String(e.src_port || '');
                case 'Dest IP': return e.dest_ip || '';
                case 'Dest Port': return String(e.dest_port || '');
                case 'Alert': return e.alert?.signature || '';
                case 'Category': {
                    if (e.event_type === 'modbus') return e.modbus?.request?.category || '';
                    return e.alert?.category || '';
                }
                case 'Severity': return 'Sev ' + (e.alert?.severity || 0);
                case 'Ruleset': return classifyRuleset(e.alert?.signature_id);
                case 'Type': {
                    if (e.event_type === 'dnp3') return e.dnp3?.type || '';
                    if (e.event_type === 'anomaly') return e.anomaly?.type || '';
                    if (e.event_type === 'mdns') return e.mdns?.queries?.[0]?.rrtype || '';
                    // See the 'Query' case above for why both the old flat
                    // field and the new Suricata 8 V3 queries[0] path are
                    // read here.
                    return e.dns?.rrtype || e.dns?.queries?.[0]?.rrtype || '';
                }
                case 'Method': return e.http?.http_method || '';
                case 'Host': return e.http?.hostname || '';
                case 'URL': return e.http?.url || '';
                case 'Status': {
                    if (e.event_type === 'enip') return e.enip?.response?.status || e.enip?.request?.status || '';
                    if (e.event_type === 'pop3') return e.pop3?.response?.status || '';
                    return String(e.http?.status || '');
                }
                case 'User-Agent': return (e.http?.http_user_agent || '').slice(0, CONFIG.USER_AGENT_MAX_LENGTH);
                case 'SNI / Host': return e.tls?.sni || '-';
                case 'Version': {
                    if (e.event_type === 'ntp') return e.ntp?.version !== undefined ? String(e.ntp.version) : '';
                    return e.tls?.version || '-';
                }
                case 'Subject': return (e.tls?.subject || '-').slice(0, CONFIG.TLS_SUBJECT_MAX_LENGTH);
                case 'Issuer': return (e.tls?.issuerdn || '-').slice(0, CONFIG.TLS_SUBJECT_MAX_LENGTH);
                case 'Pkts →': return String(e.flow?.pkts_toserver || 0);
                case 'Pkts ←': return String(e.flow?.pkts_toclient || 0);
                case 'Bytes →': return String(e.flow?.bytes_toserver || 0);
                case 'Bytes ←': return String(e.flow?.bytes_toclient || 0);
                case 'State': return e.flow?.state || '';
                case 'Alerted': return e.flow?.alerted ? 'Yes' : 'No';
                case 'Filename': {
                    if (e.event_type === 'smb') return e.smb?.filename || '';
                    if (e.event_type === 'ftp_data') return e.ftp_data?.filename || '';
                    if (e.event_type === 'nfs') return e.nfs?.filename || '';
                    return e.fileinfo?.filename || '';
                }
                case 'Rule Name': return e.filealerts?.rule_name || '';
                case 'Tags': return (e.filealerts?.tags || []).join(', ');
                case 'Author': return e.filealerts?.author || '';
                case 'Function': {
                    if (e.event_type === 'modbus') return e.modbus?.request?.function_code || '';
                    if (e.event_type === 'dnp3') {
                        return e.dnp3?.application?.function_code !== undefined ? String(e.dnp3.application.function_code) :
                               (e.dnp3?.request?.application?.function_code !== undefined ? String(e.dnp3.request.application.function_code) :
                               (e.dnp3?.response?.application?.function_code !== undefined ? String(e.dnp3.response.application.function_code) : ''));
                    }
                    return '';
                }
                case 'Unit ID': return e.modbus?.request?.unit_id !== undefined ? String(e.modbus.request.unit_id) : '';
                case 'Access Type': return e.modbus?.request?.access_type || '';
                case 'Error Flags': return e.modbus?.request?.error_flags || '';
                case 'Source Addr': return e.dnp3?.src !== undefined ? String(e.dnp3.src) : (e.dnp3?.request?.src !== undefined ? String(e.dnp3.request.src) : '');
                case 'Dest Addr': return e.dnp3?.dst !== undefined ? String(e.dnp3.dst) : (e.dnp3?.request?.dst !== undefined ? String(e.dnp3.request.dst) : '');
                case 'Query': {
                    if (e.event_type === 'pgsql') return e.pgsql?.request?.simple_query || '';
                    if (e.event_type === 'mdns') return e.mdns?.queries?.[0]?.rrname || '';
                    // dns.rrname/rrtype are the pre-Suricata-8 flat shortcut
                    // fields for "the query this transaction is about". As
                    // of Suricata 8's V3 DNS logging format (the new
                    // default - see rust/src/dns/log.rs), those flat fields
                    // are gone entirely and the same info lives at
                    // dns.queries[0].rrname/rrtype instead - confirmed
                    // against real Suricata 8.0.6 output, which silently
                    // rendered every DNS row's Query/Type as empty before
                    // this fix. Falling back to the old flat fields too
                    // keeps any previously-stored Suricata 7 analyses
                    // working.
                    return e.dns?.rrname || e.dns?.queries?.[0]?.rrname || '';
                }
                case 'Command': {
                    if (e.event_type === 'pgsql') return e.pgsql?.response?.command_completed || '';
                    if (e.event_type === 'enip') return e.enip?.request?.command || e.enip?.response?.command || '';
                    if (e.event_type === 'pop3') return e.pop3?.request?.command || '';
                    return e.ftp?.command || '';
                }
                case 'Rows': return e.pgsql?.response?.data_rows !== undefined ? String(e.pgsql.response.data_rows) : '';
                case 'SSL': return e.pgsql?.response?.ssl_accepted !== undefined ? (e.pgsql.response.ssl_accepted ? 'Yes' : 'No') : '';
                case 'SNI': return e.quic?.sni || '';
                case 'QUIC Version': return e.quic?.version || '';
                case 'JA3': return e.quic?.ja3?.hash || '';
                case 'JA3S': return e.quic?.ja3s?.hash || '';
                case 'DHCP Type': return e.dhcp?.dhcp_type || e.dhcp?.type || '';
                case 'Client MAC': return e.dhcp?.client_mac || '';
                case 'Assigned IP': return e.dhcp?.assigned_ip || '';
                case 'Hostname': return e.dhcp?.hostname || '';
                case 'FTP Command': return e.ftp_data?.command || '';
                case 'SMB Command': return e.smb?.command || '';
                case 'Share': return e.smb?.share || '';
                case 'SMB User': return e.smb?.ntlmssp?.user || e.smb?.kerberos?.cname || '';
                case 'Client Version': {
                    if (e.event_type === 'rfb') {
                        const cpv = e.rfb?.client_protocol_version;
                        return cpv ? `${cpv.major}.${cpv.minor}` : '';
                    }
                    return e.ssh?.client?.software_version || '';
                }
                case 'Server Version': {
                    if (e.event_type === 'rfb') {
                        const spv = e.rfb?.server_protocol_version;
                        return spv ? `${spv.major}.${spv.minor}` : '';
                    }
                    return e.ssh?.server?.software_version || '';
                }
                case 'Client': return e.krb5?.cname || '';
                case 'Service': return e.krb5?.sname || '';
                case 'Realm': return e.krb5?.realm || '';
                case 'Error Code': return e.krb5?.error_code || '';
                case 'SIP Method': return e.sip?.method || '';
                case 'URI': return e.sip?.uri || '';
                case 'SIP Code': return String(e.sip?.code || '');
                case 'Reason': return e.sip?.reason || '';
                case 'SNMP Version': return String(e.snmp?.version || '');
                case 'PDU Type': return e.snmp?.pdu_type || '';
                case 'Community': return e.snmp?.community || '';
                case 'MQTT Type': return e.mqtt ? (Object.keys(e.mqtt)[0] || '') : '';
                case 'Topic': {
                    const mqttType = e.mqtt ? Object.keys(e.mqtt)[0] : '';
                    const mqttSub = (mqttType && e.mqtt[mqttType]) || {};
                    return mqttSub.topic || (mqttSub.topics || []).map(t => t.topic || t).join(', ') || '';
                }
                case 'Client ID': {
                    const mqttType = e.mqtt ? Object.keys(e.mqtt)[0] : '';
                    return ((mqttType && e.mqtt[mqttType]) || {}).client_id || '';
                }
                case 'Interface UUID': return (e.dcerpc?.interfaces || [])[0]?.uuid || '';
                case 'Opnum': return String(e.dcerpc?.req?.opnum ?? e.dcerpc?.request?.opnum ?? '');
                case 'Call ID': return String(e.dcerpc?.call_id ?? '');
                case 'RDP Event': return e.rdp?.event_type || '';
                case 'Cookie': return e.rdp?.cookie || '';
                case 'Client Name': return e.rdp?.client_name || '';
                case 'Packet': return e.tftp?.packet || '';
                case 'File': return e.tftp?.file || '';
                case 'Mode': {
                    if (e.event_type === 'ntp') return e.ntp?.mode !== undefined ? String(e.ntp.mode) : '';
                    return e.tftp?.mode || '';
                }
                case 'Exchange Type': return e.ike?.exchange_type || '';
                case 'IKE Version': return e.ike?.version_major !== undefined ? `${e.ike.version_major}.${e.ike.version_minor || 0}` : '';
                case 'Init SPI': return e.ike?.init_spi || '';
                case 'Procedure': return e.nfs?.procedure || '';
                case 'Security Type': return String(e.rfb?.authentication?.security_type ?? '');
                case 'Request Type': return e.bittorrent_dht?.request_type || e.bittorrent_dht?.request?.request_type || '';
                case 'Info Hash': return e.bittorrent_dht?.info_hash || e.bittorrent_dht?.request?.info_hash || '';
                case 'Helo': return e.smtp?.helo || '';
                case 'Mail From': return e.smtp?.mail_from || '';
                case 'Rcpt To': return (e.smtp?.rcpt_to || []).join(', ');
                case 'Command Data': return e.ftp?.command_data || '';
                case 'Completion Code': return (e.ftp?.completion_code || []).join(', ');
                case 'Reply': return (e.ftp?.reply || []).join(' | ');
                case 'Event': return e.anomaly?.event || '';
                case 'Layer': return e.anomaly?.layer || '';
                case 'App Proto': return e.anomaly?.app_proto || '';
                case 'Stratum': return e.ntp?.stratum !== undefined ? String(e.ntp.stratum) : '';
                case 'Reference ID': return e.ntp?.reference_id || '';
                case 'Opcode': {
                    if (e.event_type === 'arp') return e.arp?.opcode || '';
                    return e.websocket?.opcode || '';
                }
                case 'Src MAC': return e.arp?.src_mac || '';
                case 'Dest MAC': return e.arp?.dest_mac || '';
                case 'Fin': return e.websocket?.fin !== undefined ? String(e.websocket.fin) : '';
                case 'Payload': return (e.websocket?.payload_printable || e.websocket?.payload_base64 || '').slice(0, 100);
                case 'Args': return (e.pop3?.request?.args || []).join(' ');
                case 'Operation': return e.ldap?.request?.operation || e.ldap?.responses?.[0]?.operation || '';
                case 'Message ID': {
                    const req = e.ldap?.request;
                    if (req?.message_id !== undefined) return String(req.message_id);
                    const resp = e.ldap?.responses?.[0];
                    return resp?.message_id !== undefined ? String(resp.message_id) : '';
                }
                case 'Result Code': {
                    for (const r of (e.ldap?.responses || [])) {
                        for (const key in r) {
                            if (r[key] && typeof r[key] === 'object' && 'result_code' in r[key]) return r[key].result_code;
                        }
                    }
                    return '';
                }
                case 'Channel': {
                    try { const jd = _parseLogEventJson(e); return jd.Channel || jd.Provider_Name || e.app_proto || ''; } catch(e2) { return e.app_proto || ''; }
                }
                case 'EventID': {
                    try { const jd = _parseLogEventJson(e); return String(jd.EventID || ''); } catch(e2) { return ''; }
                }
                case 'Computer': {
                    try { const jd = _parseLogEventJson(e); return jd.Computer || ''; } catch(e2) { return ''; }
                }
                case 'Detail': {
                    const etype = e.event_type || '';
                    if (etype === 'alert') return e.alert?.signature || '';
                    if (etype === 'protocol_decode') return e.alert?.signature || '';
                    if (etype === 'dns') return e.dns?.rrname || e.dns?.queries?.[0]?.rrname || '';
                    if (etype === 'mdns') return e.mdns?.queries?.[0]?.rrname || '';
                    if (etype === 'http') return (e.http?.http_method || '') + ' ' + (e.http?.url || '');
                    if (etype === 'tls') return e.tls?.sni || '';
                    if (etype === 'flow') return `${e.src_ip || ''}:${e.src_port || ''} → ${e.dest_ip || ''}:${e.dest_port || ''}`;
                    if (etype === 'ftp') return e.ftp?.command || (e.ftp?.reply || [])[0] || '';
                    // BUGFIX: was e.anomaly?.message, a field that has never
                    // existed in Suricata's eve.json anomaly schema (real
                    // field is 'event', e.g. "APPLAYER_DETECT_PROTOCOL_ONLY_
                    // ONE_DIRECTION") - always silently returned '' before.
                    if (etype === 'anomaly') return e.anomaly?.event || '';
                    if (etype === 'fileinfo') return e.fileinfo?.filename || '';
                    if (etype === 'modbus') return e.modbus?.request?.function_code || '';
                    if (etype === 'dnp3') return e.dnp3?.type || e.dnp3?.request?.type || e.dnp3?.response?.type || '';
                    if (etype === 'pgsql') return e.pgsql?.request?.simple_query || e.pgsql?.response?.command_completed || '';
                    if (etype === 'enip') return e.enip?.request?.command || e.enip?.response?.command || '';
                    if (etype === 'ntp') return e.ntp?.version !== undefined ? `v${e.ntp.version} mode ${e.ntp?.mode ?? ''}` : '';
                    if (etype === 'websocket') return e.websocket?.opcode || '';
                    if (etype === 'pop3') return e.pop3?.request?.command || e.pop3?.response?.status || '';
                    if (etype === 'ldap') return e.ldap?.request?.operation || e.ldap?.responses?.[0]?.operation || '';
                    if (etype === 'arp') return `${e.arp?.opcode || ''} ${e.arp?.src_mac || ''} → ${e.arp?.dest_mac || ''}`.trim();
                    if (etype === 'quic') return e.quic?.sni || '';
                    if (etype === 'dhcp') return `${e.dhcp?.dhcp_type || e.dhcp?.type || ''} ${e.dhcp?.assigned_ip || ''}`.trim();
                    if (etype === 'ftp_data') return `${e.ftp_data?.command || ''} ${e.ftp_data?.filename || ''}`.trim();
                    if (etype === 'smb') return `${e.smb?.command || ''} ${e.smb?.filename || ''}`.trim();
                    if (etype === 'ssh') return e.ssh?.client?.software_version || e.ssh?.server?.software_version || '';
                    if (etype === 'krb5') return `${e.krb5?.cname || ''} → ${e.krb5?.sname || ''}`;
                    if (etype === 'sip') return e.sip?.method ? `${e.sip.method} ${e.sip?.uri || ''}` : `${e.sip?.code || ''} ${e.sip?.reason || ''}`;
                    if (etype === 'snmp') return e.snmp?.pdu_type || '';
                    if (etype === 'mqtt') return e.mqtt ? (Object.keys(e.mqtt)[0] || '') : '';
                    if (etype === 'dcerpc') return (e.dcerpc?.interfaces || [])[0]?.uuid || '';
                    if (etype === 'rdp') return e.rdp?.event_type || '';
                    if (etype === 'tftp') return `${e.tftp?.packet || ''} ${e.tftp?.file || ''}`.trim();
                    if (etype === 'ike') return e.ike?.exchange_type || '';
                    if (etype === 'nfs') return `${e.nfs?.procedure || ''} ${e.nfs?.filename || ''}`.trim();
                    if (etype === 'rfb') return e.rfb?.authentication?.security_type ?? '';
                    if (etype === 'bittorrent_dht') return e.bittorrent_dht?.request_type || e.bittorrent_dht?.request?.request_type || '';
                    if (etype === 'smtp') return e.smtp?.mail_from || '';
                    if (etype === 'log') {
                        try {
                            const jd = _parseLogEventJson(e);
                            return getLogEventSmartDetail(jd);
                        } catch(e2) { return ''; }
                    }
                    return '';
                }
                default: {
                    // Generic fallback for log analysis dynamic columns
                    const field = _getFieldForLabel(col);
                    if (field) {
                        const v = getLogColumnValue(e, field);
                        if (v !== '') return v;
                    }
                    return '';
                }
            }
        }
        
        function buildAggregationTables(events, eventType) {
            return buildAggregationTablesCore(events, getColumnsForType(eventType), 'section-' + eventType, extractValue);
        }
        
        let allEvents = [];
        let baseAllEvents = [];
        // Tracks which eventTypes' currently-cached tabDataCache/allEvents data is
        // known to be a partial (capped) result - i.e. the real total exceeds
        // getUserQueryLimit()'s current value. Cleared whenever those caches
        // themselves are reset (new file load, search change).
        // NOTE: must stay `var` (not let/const) so it attaches to the global
        // object - the JSDOM test harness assigns/reads it via separate
        // script evaluations, same reason as currentFilters/advancedMode below.
        var truncatedTypes = new Set();
        let eventTypes = [];
        // NOTE: these must stay `var` (not let/const) so they attach to the
        // global object - the JSDOM test harness assigns/reads them via
        // separate script evaluations, same reason as truncatedTypes above
        // and currentFilters/advancedMode below.
        var currentMd5 = '';
        var currentFileName = '';
        var currentNotes = '';
        // Non-null while #notesModal is editing a row-scoped note instead
        // of the whole-analysis one - {table, rowId} identifying which row.
        // Reset to null on close so a stray reopen via the header icon
        // can't inherit stale row scope.
        var currentRowNoteScope = null;
        // NOTE: these must stay `var` (not let/const) so they attach to the
        // global object — the JSDOM test harness and inline handlers assign
        // them via separate script evaluations.
        var currentFilters = {};
        let currentSearch = [];
        var advancedMode = false;
        let diagramMode = true;

        // Pagination/sort state for the currently-visible data table. A single
        // set (not per-tab) is sufficient because loadTabData always fully
        // rebuilds whichever one section is visible at a time.
        let currentPage = 1;
        let currentSort = null;       // { sectionKey, colIndex, asc } | null
        let activeTableRender = null; // { sectionKey, rerender } - set each render

        function resetPagination() {
            currentPage = 1;
            currentSort = null;
        }

        // Whether the row table for the current view can be fetched a page at
        // a time directly from the server (arbitrarily large datasets), rather
        // than needing the whole filtered/sorted array in memory. Only true
        // when there's no active column filter and no active client-side sort
        // - both require the full array to be correct, since neither is
        // supported server-side yet.
        function canUseScalableFetch() {
            return Object.keys(currentFilters).length === 0 && currentSort === null;
        }

        // Guards against out-of-order async renders (tab switched, or
        // Prev/Next/sort clicked again, while a previous fetch is in flight).
        // Every scalable-mode fetch captures the generation at call time and
        // checks it's still current immediately before touching the DOM.
        let fetchGeneration = 0;
        function bumpFetchGeneration() { return ++fetchGeneration; }
        function isStaleFetch(gen) { return gen !== fetchGeneration; }

        // Sankey gets its own, separate generation counter rather than
        // sharing fetchGeneration above. REGRESSION (recurring): every
        // unrelated caller of bumpFetchGeneration() (pagination, sort, a
        // filter/search change, loadAnalysis, ...) invalidates whichever
        // Sankey fetch happens to still be in flight from a just-prior tab
        // load or filter change - if that caller's own chain doesn't
        // itself end in a fresh updateSankeyDiagram() call (easy to miss,
        // and already missed at least twice: loadAnalysis and
        // sortCurrentTable both needed a dedicated follow-up call added
        // after being caught stranding the panel on "Loading Sankey
        // diagram..." forever), nothing ever repaints it. Since sort order
        // and pagination have no bearing on the diagram's own content
        // anyway (see sortCurrentTable's own comment), Sankey never needed
        // to share staleness tracking with table fetches in the first
        // place - an isolated counter means only another Sankey render can
        // ever invalidate an in-flight one, so this whole bug class can no
        // longer recur no matter what future code bumps fetchGeneration for.
        let sankeyFetchGeneration = 0;
        function bumpSankeyFetchGeneration() { return ++sankeyFetchGeneration; }
        function isStaleSankeyFetch(gen) { return gen !== sankeyFetchGeneration; }

        // Fetches exactly one page (CONFIG.TABLE_PAGE_SIZE rows) of a per-type
        // or merged "all events" table directly from the server, plus the true
        // total via /api/count - both already support offset/limit and q.
        // eventType null/'all' -> merged multi-type query (no &type= param).
        async function fetchEventsPage(eventType) {
            const gen = bumpFetchGeneration();
            const qParam = buildSearchQuery();
            const typeParam = (eventType && eventType !== 'all') ? `&type=${eventType}` : '';
            const offset = (currentPage - 1) * CONFIG.TABLE_PAGE_SIZE;
            const sortParam = (currentSort && currentSort.sectionKey === `section-${eventType}` && canServerSortEventType(eventType))
                ? `&order_by=${encodeURIComponent(getColumnsForType(eventType)[currentSort.colIndex])}&sort_dir=${currentSort.asc ? 'asc' : 'desc'}`
                : '';
            const [rowsResp, countResp] = await Promise.all([
                fetch(`/api/events?md5=${encodeURIComponent(currentMd5)}${typeParam}&offset=${offset}&limit=${CONFIG.TABLE_PAGE_SIZE}${qParam}${sortParam}&t=${Date.now()}`),
                fetch(`/api/count?md5=${encodeURIComponent(currentMd5)}${typeParam}${qParam}&t=${Date.now()}`)
            ]);
            const items = await rowsResp.json();
            const { count } = await countResp.json();
            return { items, serverTotal: count, gen };
        }

        async function fetchSigmaAlertsPage() {
            const gen = bumpFetchGeneration();
            const qParam = buildSearchQuery();
            const offset = (currentPage - 1) * CONFIG.TABLE_PAGE_SIZE;
            const [rowsResp, countResp] = await Promise.all([
                fetch(`/api/sigma-alerts?md5=${encodeURIComponent(currentMd5)}&offset=${offset}&limit=${CONFIG.TABLE_PAGE_SIZE}${qParam}&t=${Date.now()}`),
                fetch(`/api/sigma-count?md5=${encodeURIComponent(currentMd5)}${qParam}&t=${Date.now()}`)
            ]);
            const items = await rowsResp.json();
            const { count } = await countResp.json();
            return { items, serverTotal: count, gen };
        }

        // Fetches an already-aggregated {nodes, links} Sankey payload (top-N
        // per column + Other bucketing computed server-side), so the diagram
        // can stay visible by default without needing the full capped batch.
        async function fetchSankeyData(eventType) {
            const qParam = buildSearchQuery();
            const typeParam = (eventType && eventType !== 'all') ? `&type=${eventType}` : '';
            const resp = await fetch(`/api/sankey-data?md5=${encodeURIComponent(currentMd5)}${typeParam}${qParam}&t=${Date.now()}`);
            return await resp.json();
        }

        // Whether the Sankey diagram can use the lightweight server-aggregated
        // fetch above instead of needing the full capped batch - only true
        // when there's no active column filter (search is already reflected
        // server-side). Deliberately not canUseScalableFetch(), which also
        // checks currentSort - sort has no bearing on the diagram.
        function canUseServerSankey(eventType) {
            return !!eventType && eventType !== 'sigmaalert' && eventType !== 'log'
                && Object.keys(currentFilters).length === 0;
        }

        // Whether the aggregation tables (the "advanced" per-column top-10
        // view) can be computed server-side via /api/aggregation-data
        // instead of needing the full capped batch. True for the 10 pcap
        // per-type tabs (sharing the generic buildAggregationTablesCore
        // /extractValue code path) plus the merged 'all' view (its 'Type'/
        // 'Detail' columns now have SQL equivalents too - db.py's
        // _all_events_detail_expr/UPPER(event_type)). sigmaalert/log stay
        // excluded (MITRE-Technique array-parse / entire column set being
        // data-dependent/untrusted, respectively) - and only when there's no
        // active column filter (the server endpoint is read-only/unfiltered).
        function canUseServerAggregation(eventType) {
            // 'mqtt'/'ldap' are excluded alongside sigmaalert/log/binary:
            // their fields are dynamically keyed by message/operation
            // subtype (connect/publish/subscribe/... for mqtt;
            // bind_request/search_request/modify_request/... for ldap),
            // which has no static JSON path representation server-side
            // (see db.py's AGGREGATION_JSON_PATHS) - falling back to
            // client-side computation here, like log/sigmaalert already do,
            // instead of hitting an always-empty server result.
            return !!eventType && eventType !== 'sigmaalert'
                && eventType !== 'log' && eventType !== 'binary'
                && eventType !== 'mqtt' && eventType !== 'ldap'
                && Object.keys(currentFilters).length === 0;
        }

        // Whether column-header sort can be performed server-side (via
        // /api/events' order_by/sort_dir params) for eventType. Same scope
        // as canUseServerAggregation - every column of the 10 pcap per-type
        // tabs plus the merged 'all' view now has a safe SQL expression via
        // db.py's _sort_expr (reusing the exact same mapping
        // /api/aggregation-data uses). sigmaalert/log/binary each have at
        // least one column with no server-side equivalent (sigmaalert's
        // MITRE-Technique array-parse, log's entire column set being
        // data-dependent/untrusted, binary having no scalable path at all),
        // so they keep the existing full-batch-then-client-sort fallback.
        function canServerSortEventType(eventType) {
            // 'mqtt'/'ldap' excluded for the same reason as
            // canUseServerAggregation: their column-specific fields have no
            // static JSON path server-side, so _sort_expr() returns None for
            // anything but 'Time' - fall back to full client-side sort,
            // which handles every column correctly.
            return !!eventType && eventType !== 'sigmaalert'
                && eventType !== 'log' && eventType !== 'binary'
                && eventType !== 'mqtt' && eventType !== 'ldap';
        }

        // Whether buildSection's scalable (per-page) fetch remains valid
        // given the CURRENT currentFilters/currentSort state - true when
        // unfiltered and either no sort is active, or the active sort is one
        // the server can perform for this eventType.
        function canUseScalableFetchForSort(eventType) {
            return Object.keys(currentFilters).length === 0
                && (currentSort === null || canServerSortEventType(eventType));
        }

        // column/page omitted -> the original bulk "every column, page 1"
        // fetch. column+page together restrict to just that one column's
        // one page - used by changeAggPage so paging one table doesn't
        // reset every other column in the section back to page 1. Always
        // sends the current AGG_PAGE_SIZE (the "Items per page" selector) -
        // the server has its own fallback default, but every real request
        // must be explicit so a page-size change and a page-navigation
        // fetch can never disagree on how many rows a "page" is.
        async function fetchAggregationData(eventType, column, page) {
            const qParam = buildSearchQuery();
            const typeParam = (eventType && eventType !== 'all') ? `&type=${eventType}` : '';
            const columnParam = column ? `&column=${encodeURIComponent(column)}` : '';
            const pageParam = page ? `&page=${page}` : '';
            const resp = await fetch(`/api/aggregation-data?md5=${encodeURIComponent(currentMd5)}${typeParam}${columnParam}${pageParam}&page_size=${AGG_PAGE_SIZE}${qParam}&t=${Date.now()}`);
            return await resp.json();
        }

        // Distinct-value COUNT per column, for the Prev/Next page-count math
        // in _renderOneAggTableHtml - fetched once per section open/filter
        // change (see buildAggregationsSection/buildAggregationsSectionAll),
        // not on every Prev/Next click. See get_aggregation_totals_sqlite's
        // own docstring for why this is a separate request from the page
        // data itself.
        async function fetchAggregationTotals(eventType) {
            const qParam = buildSearchQuery();
            const typeParam = (eventType && eventType !== 'all') ? `&type=${eventType}` : '';
            const resp = await fetch(`/api/aggregation-totals?md5=${encodeURIComponent(currentMd5)}${typeParam}${qParam}&t=${Date.now()}`);
            return await resp.json();
        }

        // Whether the (still fully client-side, for log/sigmaalert/binary/'all')
        // aggregation tables and/or the Sankey diagram need the full capped
        // batch loaded, independent of whatever mode the row table itself is
        // using.
        function needsFullBatch(eventType) {
            // The aggregation view only needs the full batch when it can't use
            // the lightweight server-aggregated fetch - i.e. for log/sigmaalert
            // (bespoke dynamic columns) or when a column filter is active
            // (canUseServerAggregation mirrors this same condition).
            if (advancedMode && (eventType === 'sigmaalert' || eventType === 'log'
                || !canUseServerAggregation(eventType))) return true;
            // The diagram only needs the full batch when it can't use the
            // lightweight server-aggregated fetch - i.e. when a column filter
            // is active (canUseServerSankey mirrors this same condition).
            if (eventType !== 'sigmaalert' && eventType !== 'log' && diagramMode
                && Object.keys(currentFilters).length > 0) return true;
            return false;
        }

        // Ensures tabDataCache[eventType] (or allEvents for 'all') is
        // populated, fetching at today's existing capped limit if not already
        // cached. No-op if already cached - safe to call redundantly. This is
        // the one fetch that feeds aggregation tables/Sankey (unchanged from
        // today) and is also what a mode transition into filtered/sorted
        // fallback rendering needs before it can render correctly.
        async function ensureCappedBatch(eventType) {
            const qParam = buildSearchQuery();
            if (eventType === 'all') {
                if (allEvents.length > 0) return;
                const [resp, countResp] = await Promise.all([
                    fetch(`/api/events?md5=${encodeURIComponent(currentMd5)}&limit=${getUserQueryLimit()}${qParam}&t=${Date.now()}`),
                    fetch(`/api/count?md5=${encodeURIComponent(currentMd5)}${qParam}&t=${Date.now()}`)
                ]);
                allEvents = await resp.json();
                const { count } = await countResp.json();
                if (allEvents.length < count) truncatedTypes.add('all'); else truncatedTypes.delete('all');
                return;
            }
            if (tabDataCache[eventType]) return;
            const limit = getUserQueryLimit();
            const endpoint = eventType === 'sigmaalert' ? '/api/sigma-alerts' : '/api/events';
            const countEndpoint = eventType === 'sigmaalert' ? '/api/sigma-count' : '/api/count';
            const typeParam = eventType === 'sigmaalert' ? '' : `&type=${eventType}`;
            const [resp, countResp] = await Promise.all([
                fetch(`${endpoint}?md5=${encodeURIComponent(currentMd5)}${typeParam}&limit=${limit}${qParam}&t=${Date.now()}`),
                fetch(`${countEndpoint}?md5=${encodeURIComponent(currentMd5)}${typeParam}${qParam}&t=${Date.now()}`)
            ]);
            tabDataCache[eventType] = await resp.json();
            const { count } = await countResp.json();
            if (tabDataCache[eventType].length < count) truncatedTypes.add(eventType); else truncatedTypes.delete(eventType);
        }

        // Fetches only the two event types binary-file analysis ever produces
        // (fileinfo: exactly one row, guaranteed by create_file_analysis_db's
        // insert-once call in db.py; filealerts: one row per YARA match) in
        // parallel, instead of every event type via ensureCappedBatch('all').
        // Binary-mode databases (routed here only when detectedType ===
        // 'binary') never contain any other event type, so this is a strict
        // narrowing with no fallback-loss risk.
        async function fetchBinaryEvents(qParam) {
            const q = qParam || '';
            const [fileAlertsResp, fileInfoResp] = await Promise.all([
                fetch(`/api/events?md5=${encodeURIComponent(currentMd5)}&type=filealerts&limit=${getUserQueryLimit()}${q}&t=${Date.now()}`),
                fetch(`/api/events?md5=${encodeURIComponent(currentMd5)}&type=fileinfo&limit=1${q}&t=${Date.now()}`)
            ]);
            const [fileAlerts, fileInfo] = await Promise.all([fileAlertsResp.json(), fileInfoResp.json()]);
            return [...fileInfo, ...fileAlerts];
        }

        // Cache-aware wrapper mirroring ensureCappedBatch('all')'s "no-op if
        // already populated" contract, for call sites (initial load,
        // applyFilters, clearFilter) that want to reuse an already-fetched
        // allEvents instead of forcing a fresh fetch on every column-filter
        // change.
        async function ensureBinaryEventsBatch() {
            if (allEvents.length > 0) return;
            allEvents = await fetchBinaryEvents(buildSearchQuery());
        }

        var hiddenAggregations = new Set();
        // sectionId+':'+col -> current 1-indexed page for that one table's
        // Prev/Next pagination. Reset alongside hiddenAggregations at every
        // site that resets it - same "starts fresh each time the panel
        // (re)opens" lifecycle.
        var aggPage = {};
        // sectionId -> {col: {value: count}} - the full, unpaged counts map
        // for client-computed sections only (log/sigmaalert/binary/'all'
        // client-fallback). Stashed by _renderAggTablesHtml so changeAggPage
        // can re-slice a new page locally instead of recomputing from
        // events/tabDataCache on every click.
        var aggFullCountsCache = {};
        // sectionId -> {col: totalDistinctValueCount} - for server-aggregated
        // sections, whose countsByColumn only ever holds the current page
        // (see fetchAggregationTotals/get_aggregation_totals_sqlite).
        var aggTotalsCache = {};
        let baseEventStats = {};
        var isLogAnalysisMode = false;
        const ALL_EVENTS_COLUMNS = ['Time', 'Type', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Detail'];

        // Columns whose content is short and structurally identical across every
        // table (pcap per-type, All Events, Sigma Alerts). Fixed widths keep them
        // the same size everywhere, regardless of how many other columns a given
        // table has - table-layout:fixed otherwise splits width evenly by column
        // count alone, so the same field ends up a different width per tab.
        const FIXED_COLUMN_WIDTHS = {
            'Time': '170px',
            'Type': '130px',
            'Protocol': '110px',
            'Source IP': '150px',
            'Dest IP': '150px',
            'Source Port': '120px',
            'Dest Port': '120px',
            'Severity': '150px',
        };

        function tableHeaderCellsHtml(columns, sectionKey) {
            return columns.map((h, i) => {
                const w = FIXED_COLUMN_WIDTHS[h];
                const styleAttr = w ? ` style="width:${w}"` : '';
                let cls = '', arrow = '';
                if (sectionKey && currentSort && currentSort.sectionKey === sectionKey && currentSort.colIndex === i) {
                    cls = ` class="${currentSort.asc ? 'sort-asc' : 'sort-desc'}"`;
                    arrow = `<span class="sort-arrow">${currentSort.asc ? '▲' : '▼'}</span>`;
                }
                return `<th${styleAttr}${cls}>${escapeHtml(h)}${arrow}</th>`;
            }).join('');
        }

        // Sorts a copy of `items` by columns[colIndex], reusing the caller's
        // existing (label, colIndex) => value extractor. Numeric-aware, same
        // rule the old DOM-based sortTable used.
        function sortItemsByColumn(items, columns, extractFn, colIndex, asc) {
            const col = columns[colIndex];
            return [...items].sort((a, b) => {
                const aStr = String(extractFn(a, col, colIndex) ?? '').trim();
                const bStr = String(extractFn(b, col, colIndex) ?? '').trim();
                if (aStr !== '' && bStr !== '' && !isNaN(aStr) && !isNaN(bStr)) {
                    return asc ? parseFloat(aStr) - parseFloat(bStr) : parseFloat(bStr) - parseFloat(aStr);
                }
                return asc ? aStr.localeCompare(bStr) : bStr.localeCompare(aStr);
            });
        }

        // Shared paginated-table renderer used by every data table (per-type
        // pcap tables, All Events, Sigma Alerts, Binary/YARA, Log Events).
        // `items` is the full already-filtered array for the current tab (not
        // yet sliced to a page). `rowRenderer` maps one item to its row HTML.
        // `rerender` re-invokes the exact call that produced `items`, so
        // Prev/Next and column-sort clicks know how to redraw.
        function renderPaginatedTable({ sectionKey, columns, items, extractFn, rowRenderer, rerender, serverTotal }) {
            activeTableRender = { sectionKey, rerender };

            let sortedItems = null, totalItems;
            if (serverTotal !== undefined) {
                // Scalable mode: `items` is already exactly one page, fetched
                // and ordered by the server - no local sort/slice needed.
                totalItems = serverTotal;
            } else {
                sortedItems = items;
                if (currentSort && currentSort.sectionKey === sectionKey) {
                    sortedItems = sortItemsByColumn(items, columns, extractFn, currentSort.colIndex, currentSort.asc);
                }
                totalItems = sortedItems.length;
            }

            const totalPages = Math.max(1, Math.ceil(totalItems / CONFIG.TABLE_PAGE_SIZE));
            currentPage = Math.min(Math.max(currentPage, 1), totalPages);
            const start = (currentPage - 1) * CONFIG.TABLE_PAGE_SIZE;
            const pageItems = sortedItems === null ? items : sortedItems.slice(start, start + CONFIG.TABLE_PAGE_SIZE);

            let html = '<div class="table-scroll-wrapper"><table><thead><tr>';
            html += tableHeaderCellsHtml(columns, sectionKey);
            // Fixed, unlabeled trailing column for the per-row note icon -
            // not one of `columns` (those are index-correlated with
            // currentSort.colIndex; inserting a sortable header here would
            // shift every other column's sort index).
            html += '<th style="width:32px;"></th>';
            html += '</tr></thead><tbody>';
            pageItems.forEach(item => { html += rowRenderer(item); });
            html += '</tbody></table></div>';
            html += buildPaginationControlsHtml(totalItems, start, pageItems.length, totalPages);

            return html;
        }

        function buildPaginationControlsHtml(totalItems, start, pageCount, totalPages) {
            if (totalItems <= CONFIG.TABLE_PAGE_SIZE) return '';
            const end = start + pageCount;
            return `<div class="pagination-bar">
                <span class="pagination-info">Showing ${start + 1}-${end} of ${totalItems}</span>
                <div class="pagination-controls">
                    <button class="pagination-btn" data-action="change-table-page" data-delta="-1" ${currentPage <= 1 ? 'disabled' : ''}>&larr; Prev</button>
                    <span class="pagination-page">Page
                        <input type="number" id="paginationPageInput" class="pagination-page-input" min="1" max="${totalPages}" value="${currentPage}" data-enter-action="jump-to-page">
                        of ${totalPages}
                    </span>
                    <button class="pagination-btn" data-action="jump-to-page">Go</button>
                    <button class="pagination-btn" data-action="change-table-page" data-delta="1" ${currentPage >= totalPages ? 'disabled' : ''}>Next &rarr;</button>
                </div>
            </div>`;
        }

        async function jumpToPage() {
            if (!activeTableRender) return;
            const input = document.getElementById('paginationPageInput');
            if (!input) return;
            const page = parseInt(input.value, 10);
            if (!isNaN(page)) {
                currentPage = page; // renderPaginatedTable clamps to the valid [1, totalPages] range
                await activeTableRender.rerender();
            } else {
                input.value = currentPage;
            }
        }

        async function changeTablePage(delta) {
            if (!activeTableRender) return;
            currentPage += delta;
            await activeTableRender.rerender();
        }

        // For the 10 pcap per-type tabs (canServerSortEventType), sort is
        // performed server-side - fetchEventsPage picks up the new
        // currentSort and re-fetches just one page in the new order, so no
        // full-batch fetch is needed here. For everything else ('all',
        // sigmaalert, log, binary), clicking a column header while in
        // scalable mode must first fetch the full capped batch (a no-op if
        // already cached for aggregations/Sankey) before currentSort takes
        // effect - canUseScalableFetch() becomes false the moment it's set,
        // so the next rerender() naturally takes the fallback (full-batch,
        // client-side sort) path through the same top-level build function.
        async function sortCurrentTable(colIndex) {
            if (!activeTableRender) return;
            const { sectionKey } = activeTableRender;
            const eventType = sectionKey.replace('section-', '');
            bumpFetchGeneration();
            if (!(Object.keys(currentFilters).length === 0 && canServerSortEventType(eventType))) {
                await ensureCappedBatch(eventType);
            }
            const sameCol = currentSort && currentSort.sectionKey === sectionKey && currentSort.colIndex === colIndex;
            currentSort = { sectionKey, colIndex, asc: sameCol ? !currentSort.asc : true };
            currentPage = 1;
            await activeTableRender.rerender();
            updateFilterBarVisibility();
            // Sort order has no bearing on the diagram's own content, so
            // this is a resync rather than something sorting itself
            // requires - Sankey now tracks its own staleness independently
            // (see bumpSankeyFetchGeneration's comment), so the
            // bumpFetchGeneration() above can no longer strand an in-flight
            // Sankey fetch the way it used to. Kept anyway (cheap - the
            // panel already shows a diagram for this exact eventType, so
            // there's nothing to visibly change) as a resync in case
            // something upstream ever needs it. applyFilters()/clearFilter()
            // call updateSankeyDiagram() too, for the same reason.
            //
            // Skipped for log/sigmaalert - loadTabData never calls
            // updateSankeyDiagram for either (they're the only two tabs
            // reachable in log-analysis mode, where #sankeyPanel stays
            // display:none for the whole session, set by
            // clearAnalysisContainers() - see its comment). Calling it
            // here anyway would be pure wasted work behind a hidden
            // panel at best, since neither tab's data has the src_ip/
            // dest_ip/dest_port shape a Sankey diagram needs.
            if (eventType !== 'log' && eventType !== 'sigmaalert') {
                await updateSankeyDiagram();
            }
        }

        const EMPTY_FILTER_STATE_HTML = `<div style="padding: 40px; text-align: center; color: var(--text-muted); font-size: 0.95rem;">${SEARCH_ICON_SVG} No events match the current filters</div>`;
        const AGG_COLLAPSED_HTML = '<div class="agg-panel"><div class="section-toggle-bar" data-action="toggle-aggregations">▸ Aggregation Tables</div></div>';

        function hideAggregationTable(sectionId, col) {
            hiddenAggregations.add(sectionId + ':' + col);
            // col can contain quotes (attacker-controlled log field names), so
            // compare attributes directly instead of building a CSS selector.
            document.querySelectorAll('.agg-section').forEach(el => {
                if (el.getAttribute('data-col') === col) {
                    el.style.display = 'none';
                }
            });
            const anyVisible = document.querySelectorAll('.agg-section:not([style*="display: none"])').length > 0;
            if (!anyVisible) {
                advancedMode = false;
                const aggContainer = document.getElementById('aggregations');
                if (aggContainer) {
                    aggContainer.innerHTML = AGG_COLLAPSED_HTML;
                }
            }
        }

        // Prev/Next for one table: server-aggregated sections fetch just
        // that one column's new page (its own single-column request - see
        // fetchAggregationData's column param); client-computed sections
        // re-slice the full counts map _renderAggTablesHtml already stashed
        // in aggFullCountsCache. Either way this patches only that one
        // table's DOM node in place (via _renderOneAggTableHtml), not a
        // full section rebuild - the whole point of paging in place is to
        // keep the surrounding layout (and the user's scroll position)
        // completely stable across clicks.
        async function changeAggPage(sectionId, col, delta) {
            const key = sectionId + ':' + col;
            const newPage = (aggPage[key] || 1) + delta;
            if (newPage < 1) return;

            const eventType = sectionId.replace('section-', '');
            let entries, total;
            if (sectionId !== 'section-binary' && canUseServerAggregation(eventType)) {
                const data = await fetchAggregationData(eventType, col, newPage);
                entries = (data[col] || []).map(e => [e.value, e.count]);
                const totals = aggTotalsCache[sectionId] || {};
                total = totals[col] || 0;
            } else {
                const fullCounts = (aggFullCountsCache[sectionId] || {})[col] || {};
                const sorted = Object.entries(fullCounts).sort((a, b) => b[1] - a[1]);
                total = sorted.length;
                const start = (newPage - 1) * AGG_PAGE_SIZE;
                entries = sorted.slice(start, start + AGG_PAGE_SIZE);
            }
            // Guards against a stale double-click landing past the last
            // page (e.g. Next clicked twice before the first response
            // returns) - Prev/Next are disabled at the true last page in
            // the rendered controls, so this should be unreachable in
            // practice, not just a cosmetic clamp.
            if (newPage > Math.max(1, Math.ceil(total / AGG_PAGE_SIZE))) return;

            aggPage[key] = newPage;
            const newTableHtml = _renderOneAggTableHtml(sectionId, col, entries, total, newPage);
            // A keyboard-driven Prev/Next (Enter on a keyboard-selected
            // button, via activateKeyboardSelection's generic .click()
            // fallback) has verticalNavSelection pointing at the very
            // button outerHTML below destroys - without re-pointing it at
            // the replacement, isConnected goes false and the next arrow
            // press would self-heal onto the top of the whole flat nav
            // list (the stat-card grid) instead of staying right where the
            // user just was (real bug report).
            const hadFocus = verticalNavSelection && verticalNavSelection.isConnected
                && verticalNavSelection.classList.contains('agg-page-btn')
                && verticalNavSelection.closest('.agg-section')?.getAttribute('data-col') === col;
            // col can contain quotes (attacker-controlled log field names),
            // so compare attributes directly instead of building a CSS
            // selector - same technique as hideAggregationTable.
            document.querySelectorAll('.agg-section').forEach(el => {
                if (el.getAttribute('data-col') === col) {
                    el.outerHTML = newTableHtml;
                }
            });
            if (hadFocus) {
                const replacementTable = Array.from(document.querySelectorAll('.agg-section')).find(t => t.getAttribute('data-col') === col);
                const buttons = replacementTable ? Array.from(replacementTable.querySelectorAll('.agg-page-btn')) : [];
                // Same button just pressed (index 1 = Next for delta > 0,
                // index 0 = Prev for delta < 0) - stays there even if that
                // button is now disabled (e.g. Next after reaching the
                // last page), rather than guessing the user wants Prev
                // instead; Left/Right (navigateAggPaginationButtons) is
                // already how they'd move off a disabled button.
                const target = buttons[delta > 0 ? 1 : 0];
                if (target) {
                    verticalNavSelection = target;
                    target.classList.add('keyboard-selected');
                    scrollKeyboardSelectionIntoView(target);
                }
            }
        }

        function getColumnNameFromSankeyColumn(col) {
            return ['Source IP', 'Dest IP', 'Dest Port'][col] || '';
        }

        async function refreshCurrentView(sectionId, eventType) {
            if (isLogAnalysisMode && eventType === 'log') {
                const events = tabDataCache['log'] || [];
                const filtered = getFilteredLogEvents(events);
                if (advancedMode) buildLogAggregations(filtered, sectionId);
                buildLogSectionContent(sectionId, filtered);
                return;
            }
            if (isLogAnalysisMode && eventType === 'sigmaalert') {
                const alerts = tabDataCache['sigmaalert'] || [];
                const filtered = getFilteredSigmaAlerts(alerts);
                if (advancedMode) buildSigmaAlertAggregations(filtered, sectionId);
                buildSigmaAlertSectionContent(sectionId, filtered);
                return;
            }
            if (eventType === 'all') {
                if (advancedMode) await buildAggregationsSectionAll();
                buildAllEvents();
                return;
            }
            const events = tabDataCache[eventType] || [];
            const filtered = getFilteredEvents(sectionId, events, eventType);
            if (advancedMode) {
                await buildAggregationsSection(eventType, filtered);
            }
            buildSection(eventType, events);
        }

        async function applyFilters(sectionId, filters) {
            resetPagination();
            for (const f of filters) {
                currentFilters[f.column] = f.value;
            }
            if (sectionId === 'section-binary') {
                await ensureBinaryEventsBatch();
                buildBinaryAnalysisView(allEvents);
                updateFilterBarVisibility();
                // Real user report: this early-return path (binary/file
                // analysis's own Include/Exclude/Only, from the YARA-match
                // table's pivot menu) was missing the same chip-focus fix
                // the normal path below already has - see
                // focusNewestFilterChip's own comment.
                focusNewestFilterChip();
                return;
            }
            const eventType = sectionId.replace('section-', '');
            bumpFetchGeneration();
            await ensureCappedBatch(eventType);
            await refreshCurrentView(sectionId, eventType);
            updateFilterBarVisibility();
            buildStats(await computeFilteredStats());
            await updateSankeyDiagram();
            focusNewestFilterChip();
        }

        // Real user report: a column filter added via the pivot menu
        // (Include/Exclude/Only - all routed through applyFilters() above,
        // not refreshAnalysisData()/huntFilterValue()) produced a chip
        // with no keyboard focus at all, unlike a typed search -
        // applyFilters() updates the current tab and stat cards in place
        // rather than tearing down and rebuilding #statsGrid/#sections
        // wholesale, so nothing ever disconnects the previous selection
        // for seedVerticalNavSelectionIfStale() to catch here either.
        // Always rings the LAST chip in the row (search terms render
        // first, then column filters, in buildFilterBarHtml()'s own
        // order) rather than trying to identify exactly which chip
        // Include/Exclude/Only just added - correct in the common case (a
        // single active filter) and a reasonable "whatever's newest reads
        // last" default otherwise. Shared with huntFilterValue(), which
        // calls this same helper after its own, differently-shaped
        // rebuild (refreshAnalysisData(), a full teardown) completes.
        function focusNewestFilterChip() {
            const chips = filterBarRowItems().filter(el => el.classList.contains('filter-chip'));
            const chip = chips[chips.length - 1];
            if (!chip) return;
            document.querySelectorAll('.keyboard-selected').forEach(el => el.classList.remove('keyboard-selected'));
            verticalNavSelection = chip;
            chip.classList.add('keyboard-selected');
            scrollKeyboardSelectionIntoView(chip);
        }

        // The clear-a-filter counterpart to focusNewestFilterChip() above -
        // real user report: after clearing search filters, keyboard focus
        // should go back to the first data type card (#statsGrid's own
        // first .stat-card, not necessarily whichever tab happens to be
        // active), mirroring how adding a filter focuses its own chip.
        // Falls back to ringing whatever chip remains when the clear was
        // only partial (e.g. clearFilterValue() removing one Include
        // among several) - the row is still the current position in that
        // case, not the top of the page.
        function focusFilterBarOrFirstCard() {
            const chips = filterBarRowItems().filter(el => el.classList.contains('filter-chip'));
            if (chips.length > 0) {
                focusNewestFilterChip();
                return;
            }
            const firstCard = document.querySelector('#statsGrid .stat-card');
            if (!firstCard) return;
            document.querySelectorAll('.keyboard-selected').forEach(el => el.classList.remove('keyboard-selected'));
            verticalNavSelection = firstCard;
            firstCard.classList.add('keyboard-selected');
            scrollKeyboardSelectionIntoView(firstCard);
        }

        async function clearFilter(columnName) {
            resetPagination();
            delete currentFilters[columnName];
            const visibleSection = document.querySelector('.section:not(.section-hidden):not(.agg-section)');
            if (!visibleSection) {
                // Binary analysis mode
                await ensureBinaryEventsBatch();
                buildBinaryAnalysisView(allEvents);
                updateFilterBarVisibility();
                // Real user report: same fix as the normal path below (see
                // focusFilterBarOrFirstCard's own comment) - this early-
                // return path was missing it.
                focusFilterBarOrFirstCard();
                return;
            }
            const eventType = visibleSection.id.replace('section-', '');
            await refreshCurrentView(visibleSection.id, eventType);
            updateFilterBarVisibility();
            buildStats(await computeFilteredStats());
            await updateSankeyDiagram();
            focusFilterBarOrFirstCard();
        }

        // Row-cell pivot menu (Include/Exclude/Only) support below. These
        // write the {include, exclude} object shape into currentFilters -
        // see matchesCurrentFilters()'s own comment for why that shape
        // coexists with the older plain-string shape applyFilters() above
        // still writes, rather than replacing it.

        // Normalizes currentFilters[column] to the {include, exclude}
        // shape, upgrading a pre-existing plain-string entry (e.g. left
        // over from an aggregation-row click on this same column) into an
        // equivalent one-item include list rather than clobbering it -
        // this is the only place a string-shape entry ever gets converted.
        function ensureFilterSpec(column) {
            const existing = currentFilters[column];
            if (existing && typeof existing === 'object') return existing;
            const spec = { include: existing !== undefined ? [existing] : [], exclude: [] };
            currentFilters[column] = spec;
            return spec;
        }

        // Broadens column to also match value (OR'd with whatever it
        // already allows), while every other column's filter is untouched -
        // "show me this too". Un-excludes value on the same column first,
        // since asking to include something just excluded is a clearer
        // signal than leaving it excluded.
        function includeFilterValue(sectionId, column, value) {
            const spec = ensureFilterSpec(column);
            if (!spec.include.includes(value)) spec.include.push(value);
            const idx = spec.exclude.indexOf(value);
            if (idx !== -1) spec.exclude.splice(idx, 1);
            applyFilters(sectionId, []);
        }

        // Narrows column to also deny value, while every other column's
        // filter is untouched - "hide this". Un-includes value on the same
        // column first, mirroring includeFilterValue's symmetry.
        function excludeFilterValue(sectionId, column, value) {
            const spec = ensureFilterSpec(column);
            if (!spec.exclude.includes(value)) spec.exclude.push(value);
            const idx = spec.include.indexOf(value);
            if (idx !== -1) spec.include.splice(idx, 1);
            applyFilters(sectionId, []);
        }

        // Resets every other filter (every other column, and any other
        // value already on this one) so column=value is the sole active
        // filter - "start over with just this". Deliberately leaves
        // currentSearch untouched: free-text search and column filters are
        // separate, independently-cleared mechanisms everywhere else in
        // this app (see clearAllFilters), and clearing a typed search query
        // as a side effect of a table-cell click would be surprising.
        function onlyFilterValue(sectionId, column, value) {
            currentFilters = {};
            currentFilters[column] = { include: [value], exclude: [] };
            applyFilters(sectionId, []);
        }

        // Replaces currentSearch (the whole-analysis free-text search - the
        // same mechanism the search box's performSearch() feeds, a
        // server-side FTS5 match against the entire event, not scoped to
        // the column it was clicked from) with just this one term, AND
        // clears currentFilters - "start completely over, search for this
        // and only this anywhere". Unlike onlyFilterValue() (which
        // deliberately leaves currentSearch alone, since it's narrowing
        // one specific field and a separately-typed search query is a
        // distinct, probably-still-wanted criterion), Hunt is framed as a
        // full reset: a lingering Include/Exclude/Only from earlier would
        // keep narrowing the results underneath the new search term,
        // which reads as "Hunt is combining with whatever I had before"
        // even though only currentSearch actually changed.
        async function huntFilterValue(value) {
            const term = String(value).trim();
            if (!term) return;
            resetPagination();
            currentSearch = [term];
            currentFilters = {};
            updateFilterBarVisibility();
            await refreshAnalysisData();
            // Real user report: performing a search is a deliberate
            // action, and its result should already visibly have keyboard
            // focus - see focusNewestFilterChip's own comment (shared with
            // applyFilters(), Include/Exclude/Only's own completion point)
            // for why this is a separate step from
            // seedVerticalNavSelectionIfStale() (already called inside
            // refreshAnalysisData() above), which only ever seeds
            // invisibly.
            focusNewestFilterChip();
        }

        // Generalized form of copyMd5ToClipboard() below (kept separate,
        // not refactored into a shared helper, since that function's own
        // tests assert its exact body/behavior) - same
        // secure-context-required handling, for the pivot menu's own Copy
        // to Clipboard entry.
        async function copyValueToClipboard(value) {
            if (!navigator.clipboard || !navigator.clipboard.writeText) {
                showToast('Clipboard access unavailable (requires HTTPS or localhost)');
                return;
            }
            try {
                await navigator.clipboard.writeText(value);
                showToast('Copied to clipboard');
            } catch (e) {
                showToast('Could not copy to clipboard');
            }
        }

        // CyberChef takes its input pre-filled via a base64 blob in the URL
        // fragment (#input=...), not a plain query string like the other
        // lookup sites - unescape(encodeURIComponent(...)) is the standard
        // idiom for UTF-8-safe btoa() (btoa() alone only accepts Latin1 and
        // throws on e.g. multi-byte characters in a log field's value).
        // Falls back to a bare (empty-input) CyberChef link on any encoding
        // failure rather than the whole menu action silently doing nothing.
        function cyberChefUrl(value) {
            try {
                const b64 = btoa(unescape(encodeURIComponent(String(value))));
                return `https://gchq.github.io/CyberChef/#input=${encodeURIComponent(b64)}`;
            } catch (e) {
                return 'https://gchq.github.io/CyberChef/';
            }
        }

        // OSINT/threat-intel lookup sites offered from the pivot menu -
        // naive general-purpose links (no field-type detection: the same
        // value is handed to every site regardless of whether it's
        // actually an IP/domain/hash that site's syntax implies), matching
        // this menu's own Include/Exclude/Only/Hunt pivots, which are
        // equally naive about field type. Opened via window.open with
        // noopener,noreferrer rather than a plain <a target="_blank">,
        // since these are constructed and opened programmatically rather
        // than rendered as real anchor elements.
        const PIVOT_LOOKUP_SITES = [
            { label: 'Google', urlTemplate: v => `https://www.google.com/search?q=${encodeURIComponent(v)}` },
            { label: 'VirusTotal', urlTemplate: v => `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}` },
            { label: 'Shodan', urlTemplate: v => `https://www.shodan.io/search?query=${encodeURIComponent(v)}` },
            { label: 'AbuseIPDB', urlTemplate: v => `https://www.abuseipdb.com/check/${encodeURIComponent(v)}` },
            { label: 'urlscan.io', urlTemplate: v => `https://urlscan.io/search/#${encodeURIComponent(v)}` },
            { label: 'CyberChef', urlTemplate: cyberChefUrl },
        ];

        // User-added lookup sites (Settings modal's "Custom Lookup Sites"
        // section) - stored as plain {label, urlTemplate} data (a string
        // template with a literal "{value}" placeholder), not a function
        // like PIVOT_LOOKUP_SITES' own entries, since these come from
        // localStorage/JSON rather than being written directly in this
        // file. applyCustomLookupUrlTemplate does the substitution;
        // showPivotMenu's click handler branches on typeof to call
        // whichever form a given site actually has.
        const CUSTOM_LOOKUP_SITES_KEY = 'socrates_customLookupSites';
        const MAX_CUSTOM_LOOKUP_SITES = 20;
        const MAX_CUSTOM_LOOKUP_LABEL_LENGTH = 40;
        const MAX_CUSTOM_LOOKUP_URL_LENGTH = 500;

        // null while adding a new site; the index being edited otherwise -
        // see resetCustomLookupForm/startEditCustomLookupSite in the
        // Settings modal section below.
        let editingCustomLookupIndex = null;

        function getCustomLookupSites() {
            const raw = safeStorageGet(localStorage, CUSTOM_LOOKUP_SITES_KEY);
            if (!raw) return [];
            try {
                const parsed = JSON.parse(raw);
                if (!Array.isArray(parsed)) return [];
                return parsed.filter(s => s && typeof s.label === 'string' && typeof s.urlTemplate === 'string');
            } catch (e) {
                return [];
            }
        }

        function setCustomLookupSites(sites) {
            safeStorageSet(localStorage, CUSTOM_LOOKUP_SITES_KEY, JSON.stringify(sites));
        }

        // http(s)-only, checked against the template with any "{value}"
        // placeholder substituted for a harmless stand-in - a stored
        // javascript:/data:/vbscript: URL would execute in this page's own
        // context once opened via window.open, and unlike the built-in
        // PIVOT_LOOKUP_SITES entries (fixed strings written directly in
        // this file), a custom site's URL is attacker-reachable input:
        // typed by whoever is at the keyboard, persisted to localStorage,
        // and replayed later without further review.
        function isSafeLookupUrlTemplate(template) {
            try {
                const parsed = new URL(String(template).replace(/\{value\}/g, 'x'));
                return parsed.protocol === 'http:' || parsed.protocol === 'https:';
            } catch (e) {
                return false;
            }
        }

        // No "{value}" placeholder is left as a fixed link (e.g. a static
        // internal dashboard bookmark) rather than an error - a deliberate
        // allowance, not an oversight.
        function applyCustomLookupUrlTemplate(template, value) {
            if (template.indexOf('{value}') === -1) return template;
            return template.replace(/\{value\}/g, encodeURIComponent(value));
        }

        // Shared validation for both add and edit (see
        // renderCustomLookupSitesSection) - returns {valid, error} rather
        // than throwing, so the caller can show the message inline instead
        // of a toast.
        function validateCustomLookupSite(label, urlTemplate) {
            const trimmedLabel = String(label || '').trim();
            const trimmedUrl = String(urlTemplate || '').trim();
            if (!trimmedLabel) return { valid: false, error: 'Name is required.' };
            if (trimmedLabel.length > MAX_CUSTOM_LOOKUP_LABEL_LENGTH) {
                return { valid: false, error: `Name must be ${MAX_CUSTOM_LOOKUP_LABEL_LENGTH} characters or fewer.` };
            }
            if (!trimmedUrl) return { valid: false, error: 'URL template is required.' };
            if (trimmedUrl.length > MAX_CUSTOM_LOOKUP_URL_LENGTH) {
                return { valid: false, error: `URL template must be ${MAX_CUSTOM_LOOKUP_URL_LENGTH} characters or fewer.` };
            }
            if (!isSafeLookupUrlTemplate(trimmedUrl)) {
                return { valid: false, error: 'URL template must be a valid http:// or https:// URL.' };
            }
            return { valid: true, label: trimmedLabel, urlTemplate: trimmedUrl };
        }

        // editIndex null adds a new entry; otherwise replaces the entry at
        // that index in place (so editing doesn't reorder the list).
        function saveCustomLookupSite(editIndex, label, urlTemplate) {
            const result = validateCustomLookupSite(label, urlTemplate);
            if (!result.valid) return result;
            const sites = getCustomLookupSites();
            if (editIndex === null || editIndex === undefined) {
                if (sites.length >= MAX_CUSTOM_LOOKUP_SITES) {
                    return { valid: false, error: `You can have at most ${MAX_CUSTOM_LOOKUP_SITES} custom lookup sites.` };
                }
                sites.push({ label: result.label, urlTemplate: result.urlTemplate });
            } else {
                if (editIndex < 0 || editIndex >= sites.length) return { valid: false, error: 'That entry no longer exists.' };
                sites[editIndex] = { label: result.label, urlTemplate: result.urlTemplate };
            }
            setCustomLookupSites(sites);
            return { valid: true };
        }

        function deleteCustomLookupSite(index) {
            const sites = getCustomLookupSites();
            if (index < 0 || index >= sites.length) return;
            sites.splice(index, 1);
            setCustomLookupSites(sites);
        }

        // Removes one value from one column's include/exclude list (the
        // filter-bar chip's own remove button) - NOT a thin wrapper around
        // clearFilter(column), which unconditionally deletes the whole
        // column's entry; this needs to leave any other still-active
        // value(s) on the same column alone. Duplicates clearFilter's own
        // refresh tail (visible-section detection, binary early return)
        // rather than factoring it out, since several existing tests slice
        // clearFilter's exact function body and assert those calls appear
        // directly inside it.
        async function clearFilterValue(column, kind, value) {
            resetPagination();
            const spec = currentFilters[column];
            if (spec && typeof spec === 'object') {
                const list = spec[kind] || [];
                const idx = list.indexOf(value);
                if (idx !== -1) list.splice(idx, 1);
                if (spec.include.length === 0 && spec.exclude.length === 0) {
                    delete currentFilters[column];
                }
            } else {
                delete currentFilters[column];
            }
            const visibleSection = document.querySelector('.section:not(.section-hidden):not(.agg-section)');
            if (!visibleSection) {
                await ensureBinaryEventsBatch();
                buildBinaryAnalysisView(allEvents);
                updateFilterBarVisibility();
                // Real user report: same fix as clearFilter()'s own binary
                // early-return above.
                focusFilterBarOrFirstCard();
                return;
            }
            const eventType = visibleSection.id.replace('section-', '');
            await refreshCurrentView(visibleSection.id, eventType);
            updateFilterBarVisibility();
            buildStats(await computeFilteredStats());
            await updateSankeyDiagram();
            focusFilterBarOrFirstCard();
        }

        async function clearAllFilters() {
            resetPagination();
            currentFilters = {};
            currentSearch = [];
            const input = document.getElementById('searchInput');
            if (input) input.value = '';
            updateFilterBarVisibility();
            await refreshAnalysisData();
            // Real user report: after clearing search filters, keyboard
            // focus should go back to the first data type card - see
            // focusFilterBarOrFirstCard's own comment. currentFilters/
            // currentSearch are both always empty here, so this always
            // lands on the first stat card, never a remaining chip.
            focusFilterBarOrFirstCard();
        }
        
        function getFilteredEvents(sectionId, events, eventType) {
            if (Object.keys(currentFilters).length === 0) return events;

            if (eventType === 'all') {
                const allColumns = ALL_EVENTS_COLUMNS;
                return events.filter(e => matchesCurrentFilters(e, (ev, col) => extractAllValue(ev, col, allColumns.indexOf(col))));
            }

            const columns = getColumnsForType(eventType);
            return events.filter(e => matchesCurrentFilters(e, (ev, col) => extractValue(ev, col, columns.indexOf(col))));
        }
        
        async function performSearch() {
            const input = document.getElementById('searchInput');
            const text = input ? input.value.trim() : '';
            if (!text) return;

            resetPagination();
            const terms = text.match(/"[^"]+"|\S+/g) || [];
            for (const t of terms) {
                const term = t.replace(/^"|"$/g, '').trim();
                if (term && !currentSearch.includes(term)) {
                    currentSearch.push(term);
                }
            }

            if (input) input.value = '';
            updateFilterBarVisibility();
            await refreshAnalysisData();
            // Same fix as huntFilterValue() (the search box's own "Hunt"
            // quick-action counterpart) - see focusNewestFilterChip's own
            // comment for why a search result should already visibly have
            // keyboard focus.
            focusNewestFilterChip();
        }

        async function clearSearchTerm(index) {
            resetPagination();
            currentSearch.splice(index, 1);
            updateFilterBarVisibility();
            await refreshAnalysisData();
            // Same fix as clearAllFilters()/clearFilter()/clearFilterValue() -
            // see focusFilterBarOrFirstCard's own comment. Falls back to
            // whichever chip remains (another search term, or a column
            // filter) when this was only a partial clear.
            focusFilterBarOrFirstCard();
        }

        // Fetch cheap log-event + sigma-alert *counts* in parallel, optionally
        // filtered by the current search terms. Deliberately does NOT fetch the
        // full arrays - _renderLogAnalysisView only needs counts to build the
        // stat cards and pick the default tab; the actual per-tab data is
        // fetched lazily, on-demand, by loadTabData when a tab is visited
        // (ensureCappedBatch('log') / buildSigmaAlertSectionContent's own
        // scalable fetch).
        async function _fetchLogAnalysisCounts(qParam) {
            const [logResp, sigmaResp] = await Promise.all([
                fetch(`/api/count?md5=${encodeURIComponent(currentMd5)}&type=log${qParam || ''}&t=${Date.now()}`),
                fetch(`/api/sigma-count?md5=${encodeURIComponent(currentMd5)}${qParam || ''}&t=${Date.now()}`)
            ]);
            const { count: logCount } = await logResp.json();
            const { count: sigmaCount } = await sigmaResp.json();
            return { log: logCount, sigmaalert: sigmaCount };
        }

        // Shared log-analysis view setup: records the (cheap) counts, builds
        // stat cards + sections, then loads the default tab. Deliberately does
        // NOT populate tabDataCache['log']/['sigmaalert'] - loadTabData
        // (defaultType) below does that lazily itself, and the non-default
        // tab's data is left uncached until (if ever) the user switches to it
        // via showTab().
        // Callers must set baseEventStats first (baseline or same-as-filtered).
        async function _renderLogAnalysisView(counts) {
            eventStats = counts;

            eventTypes = sortEventTypes(Object.keys(baseEventStats));
            buildStats(await computeFilteredStats());
            buildSections();

            const defaultType = counts.sigmaalert > 0 ? 'sigmaalert' : 'log';
            document.querySelectorAll('.section').forEach(s => s.classList.add('section-hidden'));
            const defaultSection = document.getElementById('section-' + defaultType);
            if (defaultSection) defaultSection.classList.remove('section-hidden');
            await loadTabData(defaultType, null);

            // loadTabData already builds the aggregation table itself when
            // advancedMode is true (for whichever type is defaultType) - the
            // only case it doesn't handle is collapsing the panel when
            // advancedMode is false.
            const aggContainer = document.getElementById('aggregations');
            if (aggContainer && !advancedMode) {
                aggContainer.innerHTML = AGG_COLLAPSED_HTML;
            }
        }

        async function refreshAnalysisData() {
            if (!currentMd5) return;
            // Marks the Acknowledged Alerts stat card's own count stale so
            // the next buildStats() call (this function's own, below)
            // re-fetches it - see acknowledgedAlertsCountStale's own
            // comment. Every acknowledge/un-acknowledge action already
            // calls this function, so this is the one hook that keeps
            // that card's count correct after them, without threading a
            // refresh through setAlertAcknowledged/acknowledgeAllInstances
            // themselves.
            acknowledgedAlertsCountStale = true;
            dnsHeuristicsCountStale = true;
            const gen = bumpFetchGeneration();
            showLoading(currentSearch.length > 0 ? 'Searching...' : 'Loading events...');

            try {
                const qParam = buildSearchQuery();

                const [statsResp, baseStatsResp] = await Promise.all([
                    fetch('/api/stats?md5=' + encodeURIComponent(currentMd5) + qParam + '&t=' + Date.now()),
                    fetch('/api/stats?md5=' + encodeURIComponent(currentMd5) + '&t=' + Date.now())
                ]);
                const statsCounts = (await statsResp.json()).counts;
                const baseStatsCounts = (await baseStatsResp.json()).counts;
                if (isStaleFetch(gen)) return;
                eventStats = statsCounts;
                baseEventStats = baseStatsCounts;

                const types = sortEventTypes(Object.keys(baseEventStats).filter(t => t !== 'stats' && t !== 'all'));
                eventTypes = types;

                // Invalidate any previously-cached full batch - the search
                // state just changed, so a stale array must not satisfy
                // ensureCappedBatch's cache guard. Whichever branch below
                // actually needs allEvents (binary mode, or stats when a
                // column filter is active) fetches it lazily on demand.
                allEvents = [];
                baseAllEvents = [];
                truncatedTypes.clear();

                // Use existing file-analysis class set during initial load
                const isFileOnly = document.body.classList.contains('file-analysis');
                const isLogFile = isLogAnalysisMode;

                if (isFileOnly) {
                document.querySelectorAll('.file-info-card').forEach(c => c.remove());
                document.getElementById('sections').innerHTML = '';
                tabDataCache = {};

                if (isLogFile) {
                    isLogAnalysisMode = true;

                    try {
                        // Unfiltered baseline counts (for totals) and, if a
                        // search is active, filtered counts - independent
                        // requests, fetched concurrently rather than back to
                        // back when both are needed.
                        let counts;
                        if (qParam) {
                            [baseEventStats, counts] = await Promise.all([
                                _fetchLogAnalysisCounts(''),
                                _fetchLogAnalysisCounts(qParam),
                            ]);
                        } else {
                            counts = baseEventStats = await _fetchLogAnalysisCounts('');
                        }
                        await _renderLogAnalysisView(counts);
                    } catch(e) {
                        console.error('Failed to load log analysis:', e);
                        document.getElementById('sections').innerHTML = '<div class="log-events-section"><h3>📋 Log Events</h3><div class="no-matches">Error loading log events</div></div>';
                    }
                } else {
                    // Binary file analysis: unified view with search + aggregations + file info + YARA table
                    const statsGrid = document.getElementById('statsGrid');
                    if (statsGrid) {
                        statsGrid.innerHTML = '';
                        statsGrid.style.display = 'none';
                    }
                    // Keep file info visible even when the current search filter
                    // excludes the fileinfo event by using unfiltered events.
                    // Both are independent requests, fetched concurrently
                    // rather than back to back when both are needed.
                    let baseEvents;
                    if (qParam) {
                        [allEvents, baseEvents] = await Promise.all([
                            fetchBinaryEvents(qParam),
                            fetchBinaryEvents(''),
                        ]);
                    } else {
                        allEvents = baseEvents = await fetchBinaryEvents(qParam);
                    }
                    baseAllEvents = baseEvents;
                    buildBinaryAnalysisView(allEvents, baseEvents);
                }
            } else {
                document.body.classList.remove('file-analysis');
                isLogAnalysisMode = false;
                const statsGrid = document.getElementById('statsGrid');
                if (statsGrid) statsGrid.style.display = '';
                buildStats(await computeFilteredStats());
                
                // Remember active section before rebuild
                const visibleSection = document.querySelector('.section:not(.section-hidden):not(.agg-section)');
                const activeType = visibleSection ? visibleSection.id.replace('section-', '') : '';

                document.getElementById('sections').innerHTML = '';
                tabDataCache = {};
                buildSections();

                // Restore active section after rebuild
                if (activeType && activeType !== eventTypes[0]) {
                    document.querySelectorAll('.section').forEach(s => s.classList.add('section-hidden'));
                    const sectionEl = document.getElementById('section-' + activeType);
                    if (sectionEl) {
                        sectionEl.classList.remove('section-hidden');
                        await loadTabData(activeType, null);
                        // Un-acknowledging the last remaining row (either
                        // type) empties the tab the user is currently
                        // looking at - staying there would just show its
                        // own "No acknowledged ..." empty state, which
                        // reads as "did that even work?" rather than the
                        // clear confirmation of landing back on Network
                        // Alerts and seeing the row reappear. section-alert
                        // is guaranteed to exist here: buildSections() above
                        // already re-ran off the fresh (post-un-acknowledge)
                        // /api/stats counts, so the row just un-acknowledged
                        // has already made 'alert' a real eventType again.
                        if (activeType === 'acknowledged' && acknowledgedAlertsCache.alert.length === 0
                                && acknowledgedAlertsCache.sigmaalert.length === 0 && document.getElementById('section-alert')) {
                            showTab('section-alert');
                        }
                    }
                } else if (eventTypes[0]) {
                    await loadTabData(eventTypes[0], null);
                }
            }

            updateFilterBarVisibility();
            // See seedVerticalNavSelectionIfStale's own comment - a filter/
            // search change, or any other action that routes through this
            // function (acknowledging an alert, changing the query limit,
            // ...), can destroy the DOM node the current keyboard selection
            // was pointing at (real user report: after applying a search
            // filter, the first Down landed ON the new chip instead of
            // past it). Only re-seeds when the old selection is actually
            // gone - a still-valid selection elsewhere is left alone.
            seedVerticalNavSelectionIfStale();
            hideLoading();
            } catch(err) {
                console.error('refreshAnalysisData error:', err);
                hideLoading();
                showError('Failed to load data: ' + (err.message || 'Unknown error'));
            }
        }

        // Click-to-rename for the header filename. Only one edit can be
        // active at a time (guarded by the existing <input> check below),
        // and blur commits the edit (matching common rename-in-place UIs
        // like a file manager) while Escape cancels it.
        async function copyMd5ToClipboard(md5) {
            // navigator.clipboard requires a secure context (HTTPS, or the
            // browser's localhost/127.0.0.1/::1 loopback exception) - a
            // real LAN deployment reached over plain http:// (a common way
            // to reach a container's published port from another machine)
            // won't have it at all, so fail with a clear toast rather than
            // a silent no-op either way.
            if (!navigator.clipboard || !navigator.clipboard.writeText) {
                showToast('Clipboard access unavailable (requires HTTPS or localhost)');
                return;
            }
            try {
                await navigator.clipboard.writeText(md5);
                showToast('MD5 copied to clipboard');
            } catch (e) {
                showToast('Could not copy to clipboard');
            }
        }

        async function startRenameAnalysis() {
            const el = document.getElementById('appHeaderFilename');
            if (!el || el.querySelector('input')) return;

            const originalName = currentFileName;
            const input = document.createElement('input');
            input.type = 'text';
            input.className = 'app-header-filename-input';
            input.value = originalName;
            input.maxLength = 255;
            el.onclick = null;
            el.style.cursor = 'default';
            el.innerHTML = '';
            el.appendChild(input);
            input.focus();
            input.select();

            let finished = false;
            async function finish(save) {
                if (finished) return;
                finished = true;
                const newValue = input.value.trim();
                if (save && newValue && newValue !== originalName) {
                    try {
                        const resp = await fetch('/api/rename-analysis', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ md5: currentMd5, name: newValue })
                        });
                        const result = await resp.json();
                        if (resp.ok && result.success) {
                            currentFileName = result.name;
                            document.title = 'SO-CRATES - ' + currentFileName;
                        } else {
                            showToast(result.error || 'Could not rename analysis');
                        }
                    } catch (e) {
                        showToast('Could not rename analysis');
                    }
                }
                el.innerHTML = `${FILE_ICON_SVG}${escapeHtml(currentFileName)}`;
                el.title = currentFileName;
                el.style.cursor = 'pointer';
                el.onclick = startRenameAnalysis;
            }

            input.addEventListener('keydown', function(e) {
                if (e.key === 'Enter') { e.preventDefault(); finish(true); }
                else if (e.key === 'Escape') { e.preventDefault(); finish(false); }
            });
            input.addEventListener('blur', function() { finish(true); });
            input.addEventListener('click', function(e) { e.stopPropagation(); });
        }

        // Cheap "has notes" signal in the header, without opening the modal.
        function notesIconHtml() {
            const color = currentNotes ? 'var(--accent)' : 'var(--text-muted)';
            const title = currentNotes ? 'View/edit notes' : 'Add notes';
            return `<span id="appHeaderNotesIcon" data-action="show-notes-modal" style="cursor: pointer; white-space: nowrap; color: ${color};" title="${title}">${NOTES_ICON_SVG}</span>`;
        }

        // Lets an analyst re-analyze the currently open sample without going
        // back to the welcome screen's previous-analyses list first -
        // openReanalyzeModal() is already self-contained (just md5/name), so
        // this reuses it as-is rather than a second reanalyze code path.
        function reanalyzeIconHtml() {
            return `<span data-action="open-reanalyze-modal" style="cursor: pointer; white-space: nowrap; color: var(--text-muted);" title="Re-analyze">${REFRESH_ICON_SVG}</span>`;
        }

        // Same reasoning as reanalyzeIconHtml() just above - openDeleteAnalysis()
        // is already self-contained (just md5/name) and confirmDelete() already
        // handles deleting the currently-open analysis (resets state, returns
        // to the welcome screen), so this reuses that as-is.
        function deleteIconHtml() {
            return `<span class="app-header-delete-icon" data-action="open-delete-analysis" style="cursor: pointer; white-space: nowrap;" title="Delete">${DELETE_ICON_SVG}</span>`;
        }

        function updateNotesCountHint() {
            const textarea = document.getElementById('analysisNotesInput');
            document.getElementById('notesCountHint').textContent =
                `${textarea.value.length.toLocaleString()} / ${textarea.maxLength.toLocaleString()}`;
        }

        // Called with no arguments for the existing whole-analysis note
        // (unchanged behavior). Called with (table, rowId, initialNote) to
        // edit a single row's note instead - same modal, same Save/Cancel
        // buttons, just re-scoped, rather than a second component with its
        // own focus/blur/escape/click-outside handling to build and test.
        function showNotesModal(table, rowId, initialNote) {
            closeOtherMenuModals('notesModal');
            const textarea = document.getElementById('analysisNotesInput');
            const titleEl = document.getElementById('notesModalTitle');
            if (table !== undefined) {
                currentRowNoteScope = { table, rowId };
                textarea.maxLength = ROW_NOTE_MAX_LENGTH;
                textarea.value = initialNote || '';
                titleEl.textContent = 'Row Note';
            } else {
                currentRowNoteScope = null;
                textarea.maxLength = NOTES_MAX_LENGTH;
                textarea.value = currentNotes;
                titleEl.textContent = 'Notes';
            }
            textarea.oninput = updateNotesCountHint;
            document.getElementById('notesError').style.display = 'none';
            updateNotesCountHint();
            document.getElementById('notesModal').classList.add('active');
            textarea.focus();
        }

        function closeNotesModal() {
            document.getElementById('notesModal').classList.remove('active');
            // Reset so a stray reopen via the header icon can't inherit
            // stale row scope from whatever was last edited.
            currentRowNoteScope = null;
        }

        // The note-icon/edit-link's data-row-id attribute is a string
        // (HTML attributes always are, and it goes through the same
        // escapeHtml discipline as the note text itself - see
        // rowNoteIconHtml/rowNoteDetailValueHtml). Parsed back to a real
        // number here before it's ever used as row-note state.
        function openRowNoteEditor(table, rowIdStr, note) {
            showNotesModal(table, parseInt(rowIdStr, 10), note);
        }

        async function saveAnalysisNotes() {
            const textarea = document.getElementById('analysisNotesInput');
            const errorEl = document.getElementById('notesError');
            const saveBtn = document.getElementById('notesSaveBtn');
            const rowScope = currentRowNoteScope;
            errorEl.style.display = 'none';
            saveBtn.disabled = true;
            try {
                if (rowScope) {
                    const resp = await fetch('/api/row-note', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ md5: currentMd5, table: rowScope.table, rowId: rowScope.rowId, note: textarea.value })
                    });
                    const result = await resp.json();
                    if (resp.ok && result.success) {
                        const rowEl = document.querySelector('tr[data-id="' + rowScope.rowId + '"]');
                        if (rowEl) {
                            const cell = rowEl.querySelector('.row-note-cell');
                            if (cell) cell.outerHTML = rowNoteIconHtml(rowScope.table, rowScope.rowId, result.note);
                            // The detail panel is rendered once and only
                            // toggled visible/hidden (see toggleRow), not
                            // re-rendered on expand - without this it would
                            // keep showing the pre-save Note value until the
                            // whole table next re-renders.
                            const detailRow = rowEl.nextElementSibling;
                            const valueEl = (detailRow && detailRow.classList.contains('detail-row'))
                                ? detailRow.querySelector('.row-note-detail-value')
                                : null;
                            if (valueEl) valueEl.outerHTML = rowNoteDetailValueHtml(rowScope.table, rowScope.rowId, result.note);
                        }
                        closeNotesModal();
                    } else {
                        errorEl.textContent = result.error || 'Could not save note';
                        errorEl.style.display = 'block';
                    }
                } else {
                    const resp = await fetch('/api/analysis-notes', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ md5: currentMd5, notes: textarea.value })
                    });
                    const result = await resp.json();
                    if (resp.ok && result.success) {
                        currentNotes = result.notes;
                        const iconEl = document.getElementById('appHeaderNotesIcon');
                        if (iconEl) iconEl.outerHTML = notesIconHtml();
                        closeNotesModal();
                    } else {
                        errorEl.textContent = result.error || 'Could not save notes';
                        errorEl.style.display = 'block';
                    }
                }
            } catch (e) {
                errorEl.textContent = rowScope ? 'Could not save note' : 'Could not save notes';
                errorEl.style.display = 'block';
            } finally {
                saveBtn.disabled = false;
            }
        }

        // Lets the notes icon in the Previous Analyses list jump straight to
        // that analysis's Notes modal, instead of just the normal overview -
        // loadAnalysis() must finish first so currentMd5/currentNotes (and
        // the DOM the modal reads from) reflect the newly-opened analysis.
        async function openAnalysisNotesFromList(md5) {
            await loadAnalysis(md5);
            showNotesModal();
        }

        async function loadAnalysis(md5) {
            const gen = bumpFetchGeneration();
            try {
                const resp = await fetch('/api/load-analysis?md5=' + encodeURIComponent(md5));
                const result = await resp.json();
                if (isStaleFetch(gen)) return;

                if (result.error) {
                    showError(result.error);
                    await showWelcome();
                    return;
                }

                if (result.success) {
                    currentMd5 = md5;
                    currentFileName = result.file_name || md5;
                    currentNotes = result.notes || '';
                    document.title = 'SO-CRATES - ' + currentFileName;
                    const urlParams = new URLSearchParams(window.location.search);
                    urlParams.set('file', md5);
                    const newUrl = window.location.pathname + '?' + urlParams.toString();
                    if (window.location.href !== window.location.origin + newUrl) {
                        history.replaceState({}, '', newUrl);
                    }
                    
                    allEvents = [];
                    baseAllEvents = [];
                    truncatedTypes.clear();
                    eventTypes = [];
                    currentFilters = {};
                    currentSearch = [];
                    resetPagination();
                    hiddenAggregations = new Set();
                    aggPage = {}; aggFullCountsCache = {}; aggTotalsCache = {};
                    tabDataCache = {};
                    clearAnalysisContainers();
                    document.getElementById('searchInput').value = '';
                    
                    showLoading('Loading events...');
                    
                    const statsResp = await fetch('/api/stats?md5=' + encodeURIComponent(md5) + '&t=' + Date.now());
                    const statsData = await statsResp.json();
                    if (isStaleFetch(gen)) return;
                    eventStats = statsData.counts;
                    baseEventStats = {...eventStats};

                    const types = sortEventTypes(Object.keys(baseEventStats).filter(t => t !== 'stats' && t !== 'all'));
                    // eventTypes should not include 'all' - it's added separately by buildStats()
                    eventTypes = types;

                    const dateDisplay = formatDateRange(statsData.date_range);

                    // Fetch analysis metadata for routing (supports ZIP uploads)
                    const statusResp = await fetch('/api/status?md5=' + encodeURIComponent(md5) + '&t=' + Date.now());
                    const analysisStatus = await statusResp.json();
                    const detectedType = analysisStatus.meta?.detected_type || detectFileType(currentFileName);

                    const isPcap = detectedType === 'pcap';
                    const isLogFile = detectedType === 'log';
                    const isFileOnly = !isPcap;
                    
                    if (isFileOnly) {
                        document.body.classList.add('file-analysis');
                    } else {
                        document.body.classList.remove('file-analysis');
                    }
                    
                    const appHeaderFilenameEl = document.getElementById('appHeaderFilename');
                    appHeaderFilenameEl.innerHTML = `${FILE_ICON_SVG}${escapeHtml(currentFileName)}`;
                    appHeaderFilenameEl.title = currentFileName;
                    appHeaderFilenameEl.style.cursor = 'pointer';
                    appHeaderFilenameEl.onclick = startRenameAnalysis;
                    document.getElementById('appHeaderMeta').innerHTML = `
                        <span id="appHeaderMd5" style="color: var(--text-muted); font-size: 0.85rem; white-space: nowrap; cursor: pointer;" title="Click to copy">${FOLDER_ICON_SVG}${escapeHtml(currentMd5)}</span>
                        <span style="color: var(--text-muted); font-size: 0.85rem; white-space: nowrap;">${CALENDAR_ICON_SVG}${escapeHtml(dateDisplay)}</span>
                        ${notesIconHtml()}
                        ${reanalyzeIconHtml()}
                        ${deleteIconHtml()}
                    `;
                    document.getElementById('appHeaderMd5').onclick = () => copyMd5ToClipboard(currentMd5);
                    document.getElementById('appHeaderRight').innerHTML = renderGearMenu();
                    updateThemeMenu();
                    showAnalysisUI();
                    updateFilterBarVisibility();
                    
                    if (isFileOnly) {
                        document.getElementById('sections').innerHTML = '';
                        const statsGrid = document.getElementById('statsGrid');
                        if (statsGrid) {
                            statsGrid.innerHTML = '';
                            statsGrid.style.display = 'none';
                        }
                        tabDataCache = {};

                        if (isLogFile) {
                            isLogAnalysisMode = true;
                            const statsGrid = document.getElementById('statsGrid');
                            if (statsGrid) statsGrid.style.display = '';
        
                            (async () => {
                                try {
                                    const counts = await _fetchLogAnalysisCounts('');
                                    baseEventStats = counts;
                                    await _renderLogAnalysisView(counts);
                                    // See seedVerticalNavSelectionIfStale's own
                                    // comment - this branch (log analysis'
                                    // own async IIFE, unlike the PCAP branch
                                    // below) was missing this call entirely,
                                    // so a freshly-opened log analysis's very
                                    // first Down press landed ON the default
                                    // tab's own card instead of past it (real
                                    // user report).
                                    seedVerticalNavSelectionIfStale();
                                } catch(e) {
                                    console.error('Failed to load log analysis:', e);
                                    document.getElementById('sections').innerHTML = '<div class="log-events-section"><h3>📋 Log Events</h3><div class="no-matches">Error loading log events</div></div>';
                                }
                            })();
                        } else {
                            // Binary file analysis: unified view with search + aggregations + file info + YARA table
                            await ensureBinaryEventsBatch();
                            baseAllEvents = allEvents;
                            buildBinaryAnalysisView(allEvents);
                            // See seedVerticalNavSelectionIfStale's own
                            // comment - same fix as the log-analysis branch
                            // above, for a freshly-opened binary/file
                            // analysis's own first Down press.
                            seedVerticalNavSelectionIfStale();
                        }
                    } else {

                        isLogAnalysisMode = false;
                        // currentFilters was just reset to {} above, so this is
                        // guaranteed to take computeFilteredStats' fast,
                        // fetch-free eventStats path (not ensureCappedBatch).
                        buildStats(await computeFilteredStats());
                        // PCAP analysis: full layout
                        buildSections();
                        const sankeyPanel = document.getElementById('sankeyPanel');
                        if (sankeyPanel) sankeyPanel.style.display = '';
                        if (eventTypes[0]) {
                            // Must be awaited: loadTabData's own fetchEventsPage call
                            // captures the shared fetchGeneration counter, and the
                            // updateSankeyDiagram() call below also bumps it - firing
                            // loadTabData without awaiting it left the two racing,
                            // silently dropping the row table's render (stuck on
                            // "Loading..."). loadTabData already ends by updating the
                            // Sankey diagram itself for this type, so no separate call
                            // is needed here in this branch.
                            await loadTabData(eventTypes[0]);
                        } else if (sankeyPanel) {
                            await updateSankeyDiagram();
                        }
                        // See seedVerticalNavSelectionIfStale's own comment -
                        // right after opening an analysis, nothing is
                        // keyboard-selected yet, so this seeds the starting
                        // position (no visible ring) rather than requiring
                        // an extra, wasted first arrow press.
                        seedVerticalNavSelectionIfStale();

                        // loadTabData(eventTypes[0]) above already builds the
                        // aggregation table itself when advancedMode is true,
                        // scoped to that default tab (e.g. Alerts) - same as
                        // _renderLogAnalysisView's equivalent comment. This
                        // used to also unconditionally rebuild the All-Events
                        // aggregation here, clobbering the per-type one above,
                        // so the only case left to handle here is collapsing
                        // the panel when advancedMode is false.
                        const aggContainer = document.getElementById('aggregations');
                        if (aggContainer && !advancedMode) {
                            aggContainer.innerHTML = AGG_COLLAPSED_HTML;
                        }
                    }

                    hideLoading();
                    
                    // Reset URL field for next analysis
                    const urlInput = document.getElementById('pcapUrl');
                    if (urlInput) {
                        urlInput.value = lastSampleUrl;
                    }
                }
            } catch(err) {
                console.error('loadAnalysis error:', err);
                console.error('loadAnalysis error stack:', err.stack);
                console.error('loadAnalysis error name:', err.name);
                hideLoading();
                showError('Failed to load analysis: ' + (err.message || 'Unknown error'));
            }
        }
        
        function loadSampleUrl(url) {
            closeHelpModal();
            lastSampleUrl = url;
            document.getElementById('pcapUrl').value = url;
            loadFromUrl();
        }

        async function loadFromUrl() {
            const urlInput = document.getElementById('pcapUrl');
            const url = urlInput.value.trim();
            
            if (!url) {
                showError('Please enter a URL');
                return;
            }
            
            // Remember this URL for future resets
            lastSampleUrl = url;
            
            showLoading('Downloading file... (0s)');
            const downloadStart = Date.now();
            let downloadInterval = setInterval(() => {
                const elapsedSec = Math.floor((Date.now() - downloadStart) / 1000);
                showLoading(`Downloading file... (${elapsedSec}s)`);
            }, 1000);

            try {
                const resp = await fetch('/api/load-url', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: url, maxUploadSize: getUserMaxUploadSizeMB() * 1024 * 1024})
                });
                const result = await resp.json();
                clearInterval(downloadInterval);
                notifyIfFilesSkipped(result);
                notifyIfAdditionalAnalyses(result);

                if (result.status === 'processing') {
                    await checkStatus(result.md5, result.phase || 'network');
                    urlInput.value = lastSampleUrl;
                } else if (result.status === 'ready') {
                    hideLoading();
                    await loadAnalysis(result.md5);
                    urlInput.value = lastSampleUrl;
                } else {
                    hideLoading();
                    showError(result.error || 'Unknown error');
                }
            } catch(err) {
                clearInterval(downloadInterval);
                hideLoading();
                showError(err.message);
            }
        }
        
        async function uploadPcap(droppedFile) {
            const fileInput = document.getElementById('pcapUpload');
            const file = droppedFile || fileInput.files[0];
            if (!file) return;

            // Fail fast client-side rather than uploading megabytes just
            // for the server to reject them - same limit the server
            // enforces via the X-Max-Upload-Size header below.
            const maxUploadMB = getUserMaxUploadSizeMB();
            if (file.size > maxUploadMB * 1024 * 1024) {
                showError(`File exceeds the maximum upload size (${maxUploadMB.toLocaleString()} MB). You can raise the limit in Settings.`);
                fileInput.value = '';
                return;
            }

            showLoading('Uploading file... (0s)');
            const uploadStart = Date.now();
            let uploadInterval = setInterval(() => {
                const elapsedSec = Math.floor((Date.now() - uploadStart) / 1000);
                showLoading(`Uploading file... (${elapsedSec}s)`);
            }, 1000);

            const formData = new FormData();
            formData.append('pcap', file);

            try {
                const resp = await fetch('/api/upload', {
                    method: 'POST',
                    headers: {'X-Max-Upload-Size': String(getUserMaxUploadSizeMB() * 1024 * 1024)},
                    body: formData
                });
                const result = await resp.json();
                clearInterval(uploadInterval);

                if (!resp.ok || result.error) {
                    hideLoading();
                    showError(result.error || 'Upload failed');
                    fileInput.value = '';
                    return;
                }
                notifyIfFilesSkipped(result);
                notifyIfAdditionalAnalyses(result);

                if (result.status === 'ready') {
                    hideLoading();
                    await loadAnalysis(result.md5);
                } else if (result.status === 'processing') {
                    await checkStatus(result.md5, result.phase || 'network');
                }
            } catch(err) {
                clearInterval(uploadInterval);
                hideLoading();
                showError(err.message);
            }
            
            fileInput.value = '';
        }
        
        function handleDragOver(e) {
            e.preventDefault();
            e.stopPropagation();
            document.getElementById('dropZone').classList.add('drop-zone-active');
        }
        
        function handleDragLeave(e) {
            e.preventDefault();
            e.stopPropagation();
            document.getElementById('dropZone').classList.remove('drop-zone-active');
        }
        
        function handleDrop(e) {
            e.preventDefault();
            e.stopPropagation();
            document.getElementById('dropZone').classList.remove('drop-zone-active');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                uploadPcap(files[0]);
            }
        }
        
        // Fun, theme-flavored loading phrases - every theme in THEMES's
        // 'fun' group gets its own pool here (see AGENTS.md's Theming
        // Conventions for the fun/dark/light group breakdown); every
        // non-fun theme just gets the plain default messages below - a
        // serious/professional theme shouldn't suddenly start joking
        // mid-analysis. One flat pool per theme, not a separate curated
        // set per checkStatus() phase (network/files/importing/logs) -
        // the phase itself isn't something a user actually watches for,
        // so tying a specific joke to a specific phase added authoring
        // effort without adding anything the user would notice.
        // getPhaseMessages() below draws independently for each of the
        // 4 phase slots (so a single load can show a couple of different
        // lines as it moves through phases), each draw fixed for that
        // phase's whole duration (not re-rolled every second) so the
        // message never flickers mid-phase.
        const THEMED_LOADING_PHRASES = {
            hacker: [
                'Bypassing the firewall...', 'Rerouting through the mainframe...', 'Tracing the IP address...',
                'Decrypting the stolen files...', 'Cracking the encryption...', 'Brute-forcing the login...',
                'Uploading to the mainframe...', 'Injecting the payload...', 'Compiling the exploit...',
                'Erasing the security footage...', 'Wiping the access logs...', 'Looping the security cameras...'
            ],
            'dos-blue': [
                'Formatting C:\\ ...', 'Running CHKDSK...', 'Loading MS-DOS...',
                'Defragging...', 'Scanning for viruses...', 'Compressing with DoubleSpace...',
                'Editing config.sys...', 'Setting up device drivers...', 'Expanding the memory manager...',
                'Editing autoexec.bat...', 'Writing to LPT1...', 'Buffering keyboard input...'
            ],
            vaporwave: [
                'Riding the information superhighway...', 'Connecting to the cyber sea...', 'Dialing into the grid...',
                'Rewinding the VHS tape...', 'Polishing the marble bust...', 'Adjusting the chrome...',
                'Downloading more RAM...', 'Loading the Windows 95 startup sound...', 'Rendering the sunset grid...',
                'Achieving aesthetic...', 'Applying the VHS filter...', 'Syncing the neon palm trees...'
            ],
            cga: [
                'Loading CGA graphics driver...', 'Dialing the BBS...', 'Initializing the modem...',
                'Reading from floppy disk...', 'Verifying the diskette...', 'Seeking track 0...',
                'Swapping diskette 2 of 5...', 'Loading interrupt handlers...', 'Copying to expanded memory...',
                'Beeping the PC speaker...', 'Writing to the printer buffer...', 'Flushing the keyboard buffer...'
            ],
            amber: [
                'Establishing terminal session...', 'Negotiating baud rate...', 'Connecting to the mainframe...',
                'Paging through the file system...', 'Reading tape drive 0...', 'Listing directory contents...',
                'Compiling FORTRAN...', 'Writing to core memory...', 'Running the batch job...',
                'Printing to the line printer...', 'Scrolling the CRT buffer...', 'Archiving to magnetic tape...'
            ],
            'breadbin-blue': [
                'LOAD "*",8,1...', 'Searching for tape...', 'Connecting the modem...',
                'PEEKing and POKEing...', 'Reading from disk drive 8...', 'Verifying the floppy...',
                'Running the BASIC program...', 'Loading from datasette...', 'Waiting for SYS 64738...',
                'Writing to the 1541 drive...', 'Printing to the dot matrix...', 'Saving before the power flickers...'
            ],
            'digital-frontier': [
                'Entering the Grid...', 'Riding the light cycle...', 'Scanning for the MCP...',
                'Derezzing corrupted programs...', 'Searching the data streams...', 'Decoding the identity disc...',
                'Compiling for the Grid...', 'Broadcasting across the network grid...', 'Rendering the light cycle trail...',
                'Reviewing the game grid...', 'Contacting Tron...', 'Bypassing the MCP...'
            ],
            'luna-blue': [
                'Connecting to the network...', 'Detecting new hardware...', 'Establishing dial-up connection...',
                'Emptying the Recycle Bin...', 'Indexing for Windows Search...', 'Cleaning up temporary files...',
                'Installing Windows updates...', 'Loading the Start menu...', 'Playing the startup chime...',
                'Writing to the Event Viewer...', 'Checking for updates...', 'Saving your preferences...'
            ],
            'retro-handheld': [
                'Linking up the Game Link cable...', 'Searching for a signal...', 'Syncing with the cartridge...',
                'Reading the save cartridge...', 'Checking the battery save...', 'Blowing on the cartridge...',
                'Loading level data...', 'Saving your progress...', 'Compressing sprite data...',
                'Showing the low battery warning...', 'Writing to save slot 1...', 'Pausing the game...'
            ],
            'mp3-player': [
                'Loading playlist...', 'Buffering...', 'Ripping the CD...',
                'Encoding to MP3...', 'Skinning the interface...', 'Scanning ID3 tags...',
                'Equalizing...', 'Crossfading...', 'Building the playlist...',
                'Visualizing...', 'Normalizing volume levels...', 'Updating the Now Playing display...'
            ]
        };

        function pickRandom(arr) {
            return arr[Math.floor(Math.random() * arr.length)];
        }

        function getPhaseMessages() {
            const pool = THEMED_LOADING_PHRASES[getCurrentTheme()];
            if (!pool) {
                return {
                    'network': 'Analyzing network traffic...',
                    'files': 'Analyzing files...',
                    'importing': 'Importing data...',
                    'logs': 'Analyzing log file...'
                };
            }
            return {
                network: pickRandom(pool),
                files: pickRandom(pool),
                importing: pickRandom(pool),
                logs: pickRandom(pool)
            };
        }

        // Gates purely-decorative fun-theme flourishes (the HUD
        // corner-bracket reticle in CSS, keyed off .fun-theme) behind the
        // same theme set THEMED_LOADING_PHRASES already defines, so "is
        // this a fun theme" stays single-sourced rather than maintaining a
        // second list in CSS.
        function updateFunThemeClass() {
            document.documentElement.classList.toggle('fun-theme', !!THEMED_LOADING_PHRASES[getCurrentTheme()]);
        }

        async function checkStatus(md5, initialPhase = 'network') {
            const phaseMessages = getPhaseMessages();

            const startTime = Date.now();
            let currentPhase = initialPhase;
            let elapsedInterval = null;
            
            // Show initial message immediately
            showLoading(`${phaseMessages[currentPhase]} (0s)`);
            
            // Local timer updates elapsed time every 1s without hitting the server
            elapsedInterval = setInterval(() => {
                const elapsedSec = Math.floor((Date.now() - startTime) / CONFIG.POLLING_INTERVAL_MS);
                const msg = phaseMessages[currentPhase] || 'Analyzing file...';
                showLoading(`${msg} (${elapsedSec}s)`);
            }, CONFIG.POLLING_INTERVAL_MS);
            
            for (let i = 0; i < CONFIG.MAX_POLLING_ATTEMPTS; i++) {
                await new Promise(r => setTimeout(r, 2000));
                
                try {
                    const resp = await fetch('/api/check-status', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({md5: md5})
                    });
                    const result = await resp.json();
                    
                    if (result.status === 'error') {
                        clearInterval(elapsedInterval);
                        hideLoading();
                        showError(result.message || 'Analysis failed');
                        return;
                    }

                    if (result.status === 'ready') {
                        clearInterval(elapsedInterval);
                        hideLoading();
                        // No fetch-generation guard here: if the user has
                        // since navigated to a different analysis (e.g. via
                        // notifyIfAdditionalAnalyses' "View Recent Analyses"
                        // link), this still unconditionally yanks them back
                        // to `md5` once it finishes. Pre-existing gap, not
                        // introduced by multi-pcap-zip support - just more
                        // reachable now.
                        await loadAnalysis(md5);
                        return;
                    }

                    if (result.status === 'processing') {
                        if (result.phase) {
                            currentPhase = result.phase;
                        }
                    }
                } catch(err) {
                    console.error('Status check error:', err);
                }
            }
            
            clearInterval(elapsedInterval);
            hideLoading();
            showError('Analysis is taking longer than expected. It may still finish in the background - check Previous Analyses in a few minutes.');
        }
        
        let pendingDelete = null;
        let pendingReanalyze = null;

        // Minimal focus management for the confirm/error modals (not a
        // full focus trap): on open, remember what was focused and move
        // focus to the modal's least-destructive button (Cancel/Close) so
        // keyboard users can't accidentally activate the destructive
        // action; on close, put focus back where it was.
        let modalReturnFocusEl = null;
        function focusModalDefault(buttonId) {
            const active = document.activeElement;
            if (active && active !== document.body) {
                modalReturnFocusEl = active;
            }
            const btn = document.getElementById(buttonId);
            if (btn) btn.focus();
        }
        function restoreModalFocus() {
            const el = modalReturnFocusEl;
            modalReturnFocusEl = null;
            if (el && el.isConnected && typeof el.focus === 'function') {
                el.focus();
            }
        }

        function openDeleteAnalysis(md5, name) {
            pendingDelete = { md5, name };
            document.getElementById('deleteFileName').textContent = name;
            document.getElementById('deleteConfirmModal').classList.add('active');
            focusModalDefault('deleteCancelBtn');
        }

        function closeDeleteModal() {
            pendingDelete = null;
            document.getElementById('deleteConfirmModal').classList.remove('active');
            restoreModalFocus();
        }
        
        function handleDeleteBackdropClick(event) {
            if (event.target.id === 'deleteConfirmModal') {
                closeDeleteModal();
            }
        }
        
        function showError(message) {
            document.getElementById('errorMessage').textContent = message;
            document.getElementById('errorModal').classList.add('active');
            focusModalDefault('errorCloseBtn');
        }

        function closeErrorModal() {
            document.getElementById('errorModal').classList.remove('active');
            restoreModalFocus();
        }

        async function confirmDelete() {
            if (!pendingDelete) return;
            
            const { md5, name } = pendingDelete;
            closeDeleteModal();

            try {
                const resp = await fetch('/api/delete-analysis', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ md5: md5 }),
                });
                const result = await resp.json();
                if (result.success) {
                    if (currentMd5 === md5) {
                        currentMd5 = '';
                        eventStats = {};
                        baseEventStats = {};
                        tabDataCache = {};
                    }
                    bumpFetchGeneration();
                    showWelcome();
                } else {
                    showError(result.error || 'Could not delete');
                }
            } catch(err) {
                showError(err.message);
            }
        }

        let pendingDeleteAllCount = 0;
        
        function openDeleteAllAnalyses(count) {
            // Now reachable from inside the Settings modal (Danger Zone) -
            // .modal all shares one z-index (see socrates.css), so with
            // both active at once, DOM order (Settings comes after this
            // modal in the HTML) would otherwise paint Settings on top and
            // visually hide this confirmation. A no-op if Settings isn't
            // open (e.g. if this ever gets a second call site).
            closeSettingsModal();
            pendingDeleteAllCount = count;
            document.getElementById('deleteAllCount').textContent = count;
            document.getElementById('deleteAllConfirmModal').classList.add('active');
            focusModalDefault('deleteAllCancelBtn');
        }

        function closeDeleteAllModal() {
            pendingDeleteAllCount = 0;
            document.getElementById('deleteAllConfirmModal').classList.remove('active');
            restoreModalFocus();
        }
        
        function handleDeleteAllBackdropClick(event) {
            if (event.target.id === 'deleteAllConfirmModal') {
                closeDeleteAllModal();
            }
        }
        
        async function confirmDeleteAll() {
            if (!pendingDeleteAllCount) return;
            closeDeleteAllModal();

            try {
                const resp = await fetch('/api/delete-all-analyses', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({}),
                });
                const result = await resp.json();
                if (result.success) {
                    currentMd5 = '';
                    eventStats = {};
                    baseEventStats = {};
                    tabDataCache = {};
                    bumpFetchGeneration();
                    showWelcome();
                } else {
                    showError(result.error || 'Could not delete analyses');
                }
            } catch(err) {
                showError(err.message);
            }
        }
        
        async function openReanalyzeModal(md5, name) {
            let phase = 'files';
            let hasRowNotes = false;
            try {
                const resp = await fetch('/api/status?md5=' + encodeURIComponent(md5) + '&t=' + Date.now());
                const status = await resp.json();
                const detectedType = status.meta?.detected_type || detectFileType(name);
                if (detectedType === 'log') phase = 'logs';
                else if (detectedType === 'pcap') phase = 'network';
                hasRowNotes = !!status.hasRowNotes;
            } catch(err) {
                // Fallback to filename-based detection if status API fails
                const detectedType = detectFileType(name);
                if (detectedType === 'log') phase = 'logs';
                else if (detectedType === 'pcap') phase = 'network';
            }
            pendingReanalyze = { md5, name, phase };
            document.getElementById('reanalyzeFileName').textContent = name;
            // Only shown when the analysis actually has row-level notes to
            // lose - matches this app's existing "hide irrelevant info
            // rather than show it as a no-op" convention (e.g. zero-count
            // stat cards).
            document.getElementById('reanalyzeRowNotesWarning').style.display = hasRowNotes ? 'block' : 'none';
            document.querySelector('.reanalyze-confirm-btn').classList.toggle('danger', hasRowNotes);
            document.getElementById('reanalyzeConfirmModal').classList.add('active');
            focusModalDefault('reanalyzeCancelBtn');
        }

        function closeReanalyzeModal() {
            pendingReanalyze = null;
            document.getElementById('reanalyzeConfirmModal').classList.remove('active');
            restoreModalFocus();
        }
        
        function handleReanalyzeBackdropClick(event) {
            if (event.target.id === 'reanalyzeConfirmModal') {
                closeReanalyzeModal();
            }
        }
        
        async function confirmReanalyze() {
            if (!pendingReanalyze) return;
            const { md5, name, phase } = pendingReanalyze;
            pendingReanalyze = null;
            closeReanalyzeModal();
            
            showLoading('Re-analyzing ' + name + '...');
            try {
                const resp = await fetch('/api/reanalyze', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({md5: md5})
                });
                const result = await resp.json();
                if (result.error) {
                    hideLoading();
                    showError(result.error);
                    return;
                }
                if (result.status === 'processing') {
                    await checkStatus(md5, phase || 'network');
                } else {
                    hideLoading();
                }
            } catch(err) {
                hideLoading();
                showError(err.message);
            }
        }
        
        let resizeTimeout;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(() => {
                if (diagramMode && currentMd5) {
                    updateSankeyDiagram();
                }
            }, CONFIG.SEARCH_DEBOUNCE_MS);
        });

        // Static-shell event wiring - socrates.html carries no inline on*=
        // handler attributes (CSP hardening: script-src without
        // 'unsafe-inline' forbids them). Elements declare a data-action
        // (plus an optional data-arg) and the delegated click listener
        // below dispatches to this registry. Delegation also keeps
        // re-rendered copies of the static markup wired (e.g.
        // renderGearMenu(), which rebuilds the header menu with the same
        // data-action attributes).
        const STATIC_ACTIONS = {
            'show-welcome': () => showWelcome(),
            'show-about-modal': () => showAboutModal(),
            'toggle-menu': () => toggleMenu(),
            'menu-help': () => { showHelpModal(); closeMenu(); },
            'menu-settings': () => { showSettingsModal(); closeMenu(); },
            'menu-themes': () => { showThemesModal(); closeMenu(); },
            'menu-rules': () => { showRulesModal(); closeMenu(); },
            'menu-about': () => { showAboutModal(); closeMenu(); },
            'close-error-modal': () => closeErrorModal(),
            'close-delete-modal': () => closeDeleteModal(),
            'close-delete-all-modal': () => closeDeleteAllModal(),
            'close-reanalyze-modal': () => closeReanalyzeModal(),
            'close-help-modal': () => closeHelpModal(),
            'close-settings-modal': () => closeSettingsModal(),
            'close-about-modal': () => closeAboutModal(),
            'close-security-onion-modal': () => closeSecurityOnionModal(),
            'close-themes-modal': () => closeThemesModal(),
            'close-notes-modal': () => closeNotesModal(),
            'close-rules-modal': () => closeRulesModal(),
            'close-autocomplete-modal': () => closeAutocompleteModal(),
            'confirm-delete': () => confirmDelete(),
            'confirm-delete-all': () => confirmDeleteAll(),
            'confirm-reanalyze': () => confirmReanalyze(),
            'save-custom-lookup-site': () => handleSaveCustomLookupSite(),
            'cancel-edit-custom-lookup-site': () => cancelEditCustomLookupSite(),
            // Reads settingsAnalysisCount at click time, not render time -
            // the real count only arrives after showSettingsModal()'s
            // async fetch (see the variable's own comment).
            'open-delete-all-analyses': () => openDeleteAllAnalyses(settingsAnalysisCount),
            'save-settings': () => saveSettings(),
            'save-notes': () => saveAnalysisNotes(),
            'check-app-update-now': () => checkForAppUpdateNow(),
            'update-ruleset': (el) => triggerRulesetUpdate(el.dataset.arg),
            'perform-search': () => performSearch(),
            // Modal backdrop: data-arg names the close action to run. A
            // click anywhere inside the modal bubbles up through the
            // backdrop div (the .modal-content stopPropagation shims are
            // gone), so close only when the click landed on the backdrop
            // itself - the same event.target === backdrop check the old
            // handleModalBackdropClick()/handle*BackdropClick() inline
            // handlers made.
            'backdrop': (el, e) => {
                if (e.target !== el) return;
                const closeFn = STATIC_ACTIONS[el.dataset.arg];
                if (closeFn) closeFn(el, e);
            },

            // ---- Generated-content actions ----
            // Everything below is referenced from HTML strings built at
            // runtime (welcome screen, data tables, modals' dynamic
            // bodies, ...) rather than the static socrates.html shell.
            // Same dispatch mechanism: the delegated listeners below run
            // the CLOSEST [data-action], so an inner element's action
            // naturally shadows its row/label ancestor's - which is how
            // the old inline event.stopPropagation() semantics (e.g. a
            // MITRE tag not toggling its row) are preserved. Scalar
            // arguments ride in escapeHtml'd data-* attributes (the HTML
            // parser decodes them before dataset reads them back);
            // structured payloads keep using the percent-encoded-JSON
            // idiom (see pivotDataAttrsHtml).

            // Modal openers for links generated into welcome/help/filter
            // content ('show-about-modal' above predates these).
            'show-settings-modal': () => showSettingsModal(),
            'show-themes-modal': () => showThemesModal(),
            'show-security-onion-modal': () => showSecurityOnionModal(),
            'show-rules-modal': (el) => showRulesModal(el.dataset.arg === 'expand-sources'),

            // Welcome screen: sample cards, URL import, upload drop zone,
            // previous-analyses rows.
            'load-sample-url': (el) => loadSampleUrl(el.dataset.url),
            'load-from-url': () => loadFromUrl(),
            'open-upload-picker': () => document.getElementById('pcapUpload').click(),
            // Real href (?file=md5) kept for copy-link/middle-click;
            // normal clicks stay in-app, same as the old inline
            // preventDefault + loadAnalysis() pair.
            'load-analysis': (el, e) => { e.preventDefault(); loadAnalysis(el.dataset.md5); },

            // Settings modal: custom lookup sites list.
            'edit-custom-lookup-site': (el) => startEditCustomLookupSite(Number(el.dataset.index)),
            'delete-custom-lookup-site': (el) => handleDeleteCustomLookupSite(Number(el.dataset.index)),

            // Themes modal tiles (hover/focus preview is delegated
            // separately below - only the commit is a click action).
            'commit-theme': (el) => commitTheme(el.dataset.themeOption),

            // Rules modal.
            'toggle-rule-log': (el) => toggleRuleLog(el.dataset.name),
            'toggle-suricata-sources': () => toggleSuricataSources(),
            'enable-all-suricata-sources': () => enableAllSuricataSources(),
            'reset-suricata-sources': () => resetSuricataSourcesToDefault(),
            // preventDefault keeps the wrapping <label> from toggling its
            // checkbox; stopPropagation matches the old inline handler.
            'show-source-note': (el, e) => { e.preventDefault(); e.stopPropagation(); showToast(el.dataset.note); },

            // An action that exists purely to SHADOW an ancestor's action
            // (closest() dispatch stops here), replacing the old inline
            // event.stopPropagation() on e.g. MITRE tags and the rules
            // modal's "(source)" links - external anchors, so no
            // preventDefault: the navigation must still happen.
            'stop-propagation': (el, e) => e.stopPropagation(),

            // Data-table rows + detail panels.
            'toggle-row': (el, e) => toggleRow(el, e),
            'toggle-log-row': (el, e) => toggleLogRow(el, el.dataset.detailId, e),
            'toggle-sigma-row': (el, e) => toggleSigmaRow(el, el.dataset.detailId, e),
            'toggle-playbook-questions': (el) => togglePlaybookQuestions(el),
            'toggle-packet': (el) => togglePacket(el),
            // this.parentNode.parentNode in the old inline form: the
            // button's .packet-controls bar's parent, i.e. the hexdump
            // container all the packet blocks live in.
            'expand-all-packets': (el) => expandAllPackets(el.parentNode.parentNode),
            'collapse-all-packets': (el) => collapseAllPackets(el.parentNode.parentNode),
            'switch-stream-view': (el, e) => {
                const p = el.closest('.stream-payload');
                if (p) switchStreamView(el.dataset.view, p.dataset.srcIp, p.dataset.srcPort, p.dataset.dstIp, p.dataset.dstPort, el);
            },
            'download-stream-pcap': (el) => {
                const p = el.closest('.stream-payload');
                if (p) downloadPcap(p.dataset.srcIp, p.dataset.srcPort, p.dataset.dstIp, p.dataset.dstPort);
            },
            // The note-icon <td>: clicks that miss the icon must do
            // nothing (not toggle the row) - shadowing handles that; the
            // preventDefault/stopPropagation mirror the old inline pair.
            'row-note-cell': (el, e) => { e.preventDefault(); e.stopPropagation(); },
            'open-row-note-editor': (el, e) => {
                e.preventDefault();
                e.stopPropagation();
                openRowNoteEditor(el.dataset.table, el.dataset.rowId, el.dataset.note);
            },
            'view-dns-heuristic-domain': (el) => viewDnsHeuristicDomain(el.dataset.id),
            'toggle-dns-heuristics-info': (el) => toggleDnsHeuristicsInfo(el),

            // Sankey / Aggregation panels.
            'toggle-diagram': () => toggleDiagram(),
            'toggle-aggregations': () => toggleAggregations(),
            'hide-agg-table': (el) => hideAggregationTable(el.dataset.sectionId, el.dataset.col),
            'change-agg-page': (el) => changeAggPage(el.dataset.sectionId, el.dataset.col, Number(el.dataset.delta)),

            // Filter bar chips.
            'clear-search-term': (el) => clearSearchTerm(Number(el.dataset.index)),
            'clear-filter': (el) => clearFilter(el.dataset.col),
            'clear-filter-value': (el) => clearFilterValue(el.dataset.col, el.dataset.kind, el.dataset.value),
            'clear-all-filters': () => clearAllFilters(),

            // Stat cards + table pagination.
            'show-tab': (el) => showTab(el.dataset.section, el),
            'change-table-page': (el) => changeTablePage(Number(el.dataset.delta)),
            'jump-to-page': () => jumpToPage(),

            // Analysis header icons - all read the current-analysis
            // globals at click time, same as the old inline handlers did.
            'show-notes-modal': () => showNotesModal(),
            'open-reanalyze-modal': () => openReanalyzeModal(currentMd5, currentFileName),
            'open-delete-analysis': () => openDeleteAnalysis(currentMd5, currentFileName),
        };

        // Change-event actions, dispatched from the delegated 'change'
        // listener below via data-change-action - kept in the same
        // registry object so action names stay unique app-wide.
        Object.assign(STATIC_ACTIONS, {
            'upload-pcap': () => uploadPcap(),
            'change-agg-page-size': (el) => changeAggPageSize(el.value),
            'suricata-source-toggle': (el) => handleSuricataSourceToggle(el.dataset.name, el.checked),
            'protocol-decode-toggle': (el) => handleShowProtocolDecodeAlertsToggle(el.checked),
        });

        document.addEventListener('click', e => {
            const el = e.target.closest('[data-action]');
            if (!el) return;
            const fn = STATIC_ACTIONS[el.dataset.action];
            // Unknown names are someone else's data-action (e.g. the
            // #previousAnalysesList notes buttons handled by their own
            // delegated listener above) - leave them alone.
            if (!fn) return;
            // In-page anchors (href="#" links like show-welcome /
            // show-about-modal) must not scroll-to-top/change the URL;
            // preventDefault replaces their old "return false;". Anchors
            // with a REAL href (MITRE tags, the rules modal's "(source)"
            // links) must keep navigating, so they're left alone - an
            // action that needs preventDefault despite a real href (e.g.
            // 'load-analysis') calls it itself.
            if (el.tagName === 'A' && el.getAttribute('href') === '#') e.preventDefault();
            fn(el, e);
        });

        // change/keydown/focus/mouse delegation for generated content -
        // each listener attached ONCE here at startup, so re-rendered
        // HTML stays wired with no per-render (or per-row) binding work.
        document.addEventListener('change', e => {
            const el = e.target.closest('[data-change-action]');
            if (!el) return;
            const fn = STATIC_ACTIONS[el.dataset.changeAction];
            if (fn) fn(el, e);
        });

        // Capture phase, so a focused card's Enter/Space activation runs
        // BEFORE the app-wide shortcut keydown handler (a bubble-phase
        // document listener registered earlier) - the same priority the
        // old inline onkeydown handlers had by running at the element and
        // calling stopPropagation, which the enter-space branch below
        // still does (capture-phase stopPropagation keeps the event from
        // ever reaching that bubble-phase handler).
        document.addEventListener('keydown', e => {
            if (e.key === 'Enter' || e.key === ' ') {
                // Keyboard activation for generated role="button" divs
                // (sample cards, the upload drop zone) - preventDefault/
                // stopPropagation mirror the old inline onkeydown added
                // in the accessibility work (Space must not scroll).
                const btn = e.target instanceof Element && e.target.closest('[data-key-activate="enter-space"]');
                if (btn) {
                    const fn = STATIC_ACTIONS[btn.dataset.action];
                    if (fn) {
                        e.preventDefault();
                        e.stopPropagation();
                        fn(btn, e);
                    }
                    return;
                }
            }
            if (e.key === 'Enter') {
                // Enter-to-submit inputs (URL import box, pagination page
                // input) - a separate attribute from data-action, since a
                // plain CLICK on these inputs must not trigger anything.
                // No preventDefault/stopPropagation, matching the old
                // inline onkeydown (the app-wide handler already ignores
                // keystrokes targeted at inputs).
                const input = e.target instanceof Element && e.target.closest('[data-enter-action]');
                if (input) {
                    const fn = STATIC_ACTIONS[input.dataset.enterAction];
                    if (fn) fn(input, e);
                }
            }
        }, true);

        // Theme-tile hover/focus preview - mouseover/mouseout +
        // relatedTarget checks emulate the old per-tile mouseenter/
        // mouseleave (enter/leave don't bubble, so they can't be
        // delegated directly), and focusin/focusout stand in for the
        // per-tile focus/blur the keyboard-accessibility work added.
        function _themeTileFromEvent(e) {
            const tile = e.target.closest('.theme-tile[data-theme-option]');
            if (!tile) return null;
            // Moving between descendants of the same tile is not a real
            // enter/leave.
            if (e.relatedTarget instanceof Node && tile.contains(e.relatedTarget)) return null;
            return tile;
        }
        document.addEventListener('mouseover', e => {
            const tile = _themeTileFromEvent(e);
            if (tile) previewTheme(tile.dataset.themeOption);
        });
        document.addEventListener('mouseout', e => {
            if (_themeTileFromEvent(e)) revertTheme();
        });
        document.addEventListener('focusin', e => {
            const tile = _themeTileFromEvent(e);
            if (tile) previewTheme(tile.dataset.themeOption);
            // Clear-on-focus inputs (the welcome screen's URL box, which
            // starts prefilled with the sample URL).
            const clearable = e.target.closest('[data-clear-on-focus]');
            if (clearable) clearable.value = '';
        });
        document.addEventListener('focusout', e => {
            if (_themeTileFromEvent(e)) revertTheme();
        });

        // Upload drop zone drag & drop (see showWelcome's #dropZone) -
        // delegated like everything else since the welcome screen is
        // re-rendered HTML.
        document.addEventListener('dragover', e => {
            if (e.target.closest('#dropZone')) handleDragOver(e);
        });
        document.addEventListener('dragleave', e => {
            if (e.target.closest('#dropZone')) handleDragLeave(e);
        });
        document.addEventListener('drop', e => {
            if (e.target.closest('#dropZone')) handleDrop(e);
        });

        // Inputs the static shell used to wire via inline on*= attributes,
        // bound directly by id - this script tag sits at the end of the
        // page, so the elements all exist by now.
        document.getElementById('searchInput').addEventListener('keydown', e => {
            if (e.key === 'Enter') performSearch();
        });
        document.getElementById('autocompleteInput').addEventListener('input', () => filterAutocomplete());
        document.getElementById('checkForUpdates').addEventListener('change', e => handleCheckForUpdatesChange(e.target));
        document.getElementById('syncThemeWithOS').addEventListener('change', e => handleSyncThemeWithOSChange(e.target));
        document.getElementById('checkForStaleRules').addEventListener('change', e => handleCheckForStaleRulesChange(e.target));
        document.getElementById('staleThresholdDaysInput').addEventListener('change', e => handleStaleThresholdDaysChange(e.target));

        async function init() {
            try {
                // Initialize theme state, ambient theme backgrounds, and favicon.
                updateThemeMenu();
                updateFunThemeClass();
                updateAllAmbientThemes();
                updateFavicon();
                startThemeSync();

                // Fetch and display version from server
                try {
                    const verResp = await fetch('/api/version');
                    if (verResp.ok) {
                        const verData = await verResp.json();
                        const link = document.getElementById('footerVersionLink');
                        if (link && verData.version) {
                            link.textContent = 'SO-CRATES ' + verData.version;
                        }
                    }
                } catch(verErr) {
                    // Ignore version fetch errors — footer shows placeholder
                }
                checkForAppUpdate();
                checkForMissingRules();

                // Check for file query parameter (backward compatible with ?pcap=)
                const urlParams = new URLSearchParams(window.location.search);
                const fileMd5 = urlParams.get('file') || urlParams.get('pcap');
                
                if (fileMd5) {
                    await loadAnalysis(fileMd5);
                } else {
                    await showWelcome();
                }
            } catch(err) {
                console.error('Init error:', err);
                
            }
        }
        
        init().catch(err => {
            console.error('Init error:', err);
            console.error('Init error stack:', err.stack);
            console.error('Init error names:', err.name);
        });
