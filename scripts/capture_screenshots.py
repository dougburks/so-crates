#!/usr/bin/env python3
"""Regenerate all docs/images/*.png screenshots against a locally running SO-CRATES server.

Requires: pip install -r requirements-screenshots.txt, and a running server
(default http://127.0.0.1:8000/socrates.html - override with --base-url).
Loads the URL box's default (DEFAULT_SAMPLE_URL in static/socrates.js - a
real infection's traffic on malware-traffic-analysis.net, richer than the
built-in Sample PCAP file) with its Go button, so it
needs no pre-existing local analysis or hardcoded MD5 - it works on a
clean checkout with an empty DATA_DIR. Its last two captures load other
captures the same way, for what that one lacks: GEO_SAMPLE_URL, internet
traffic from many countries for the Traffic Map, and TSHARK_SAMPLE_URL,
tshark's protocols and Findings.

Usage:
    python3 scripts/capture_screenshots.py [--base-url http://127.0.0.1:8000/socrates.html] [--only traffic-map|findings]
"""

import argparse
import asyncio
import os
import shutil
import sys

from playwright.async_api import async_playwright

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGES_DIR = os.path.join(REPO_ROOT, 'docs', 'images')
THEMES_DIR = os.path.join(IMAGES_DIR, 'themes')

THEMES = [
    'dark', 'sguil', 'hacker', 'cga', 'breadbin-blue', 'vaporwave', 'digital-frontier',
    'retro-handheld', 'matte-black', 'tokyo-night',
    'retro-82', 'ethereal', 'lumon', 'catppuccin', 'ohmydebn', 'catppuccin-latte', 'flexoki-light',
    'everforest', 'gruvbox', 'hackerman', 'kanagawa', 'miasma', 'nord',
    'osaka-jade', 'ristretto', 'rose-pine', 'vantablack', 'white', 'luna-blue', 'amber', 'dos-blue',
    'dracula', 'solarized-dark', 'monokai', 'mp3-player', 'jade-horse', 'last-horizon', 'lupine',
    'solitude', 'one-dark', 'thermal', 'big-board',
]

DEFAULT_VIEWPORT = {'width': 1600, 'height': 1000}

# The default sample is a malware infection's traffic - no protocol tshark
# adds there but Windows LAN chatter, and no Findings. This one, from the
# 4SICS ICS lab (Netresec), has S7comm and Telnet records, Findings for
# Telnet logins, S7 writes and expired and self-signed certificates, and
# TLS failures. 140 MB; Netresec's own share link.
TSHARK_SAMPLE_URL = 'https://share.netresec.com/s/camL59aoxbCRyyZ/download/4SICS-GeekLounge-151021.pcap'
# Suricata, the import and tshark together, on that capture
TSHARK_SAMPLE_TIMEOUT_MS = 15 * 60 * 1000

# The default sample's 10 flows reach four countries - too few to show the
# Traffic Map. A week of scans and probes hitting a web server, also from
# malware-traffic-analysis.net: 207,000 flows from 136 countries and 157
# alerts. A 16 MB zip (48 MB capture).
GEO_SAMPLE_URL = ('https://www.malware-traffic-analysis.net/2026/07/31/'
                  '2026-07-31-seven-days-of-scans-and-probes-and-web-traffic-hitting-my-web-server.pcap.zip')
GEO_SAMPLE_TIMEOUT_MS = 10 * 60 * 1000
# How long the map replays before the shot (of its default 1 minute) - far
# enough for routes from most countries, a full alerts list and arcs in flight
TRAFFIC_MAP_REPLAY_MS = 24000


def find_chromium():
    for name in ('chromium', 'chromium-browser', 'google-chrome'):
        path = shutil.which(name)
        if path:
            return path
    return None


async def capture_traffic_map(page, base_url):
    """The Traffic Map, part way through replaying GEO_SAMPLE_URL."""
    await page.set_viewport_size(DEFAULT_VIEWPORT)
    await page.goto(base_url, wait_until='networkidle')
    if await page.locator('#helpModal.active').count():
        await page.evaluate('closeHelpModal()')
    # the animated map, at its default speed, with the local network off the map
    await page.evaluate("""() => {
        for (const key of ['socrates_trafficMapAnimate', 'socrates_trafficMapSpeed', 'socrates_trafficMapLan']) {
            localStorage.removeItem(key);
        }
    }""")
    await page.fill('#pcapUrl', GEO_SAMPLE_URL)
    await page.click("button[data-action='load-from-url']")
    try:
        await page.wait_for_selector('#statsGrid .stat-card', timeout=GEO_SAMPLE_TIMEOUT_MS)
    except Exception:
        print('WARNING: the web server capture never finished - so-crates-traffic-map.png not updated',
              file=sys.stderr)
        return
    await page.wait_for_timeout(1000)
    await page.locator('#trafficMapPanel > .section-toggle-bar').click()
    try:
        await page.wait_for_selector('#trafficMapPanel .tm-stage', timeout=60000)
    except Exception:
        print('WARNING: the Traffic Map never loaded - so-crates-traffic-map.png not updated', file=sys.stderr)
        return
    panel = page.locator('#trafficMapPanel')
    # centered, clear of the fixed header and footer, which would cover its edges
    await panel.evaluate("el => el.scrollIntoView({ block: 'center' })")
    # off the map and its lists: no tooltip, and Top sources keeps updating
    await page.mouse.move(2, DEFAULT_VIEWPORT['height'] - 2)
    await page.wait_for_timeout(TRAFFIC_MAP_REPLAY_MS)
    await panel.screenshot(path=os.path.join(IMAGES_DIR, 'so-crates-traffic-map.png'))
    print('captured traffic-map')


async def capture_findings(page, base_url):
    """10. The stat cards' three sections with tshark's cards in them, and
    the Findings tab below, from TSHARK_SAMPLE_URL."""
    await page.set_viewport_size(DEFAULT_VIEWPORT)
    await page.goto(base_url, wait_until='networkidle')
    if await page.locator('#helpModal.active').count():
        await page.evaluate('closeHelpModal()')
    # The table, not the About card, is the point - and every section open
    await page.evaluate("""() => {
        localStorage.setItem('socrates_findingsInfoCollapsed', 'true');
        localStorage.removeItem('socrates_statGroupsCollapsed');
    }""")
    await page.fill('#pcapUrl', TSHARK_SAMPLE_URL)
    await page.click("button[data-action='load-from-url']")
    # tshark's cards don't join while the pointer is over the cards
    await page.mouse.move(2, DEFAULT_VIEWPORT['height'] - 2)
    try:
        await page.wait_for_function(
            "() => (document.getElementById('tsharkHeadingStatus') || {}).textContent?.includes('tshark parsed')",
            timeout=TSHARK_SAMPLE_TIMEOUT_MS)
    except Exception:
        print('WARNING: tshark never finished on the 4SICS capture - so-crates-findings.png not updated',
              file=sys.stderr)
        return
    # (its card appears once its count has come back)
    findings_card = page.locator('.stat-card[data-section="section-findings"]')
    try:
        await findings_card.wait_for(state='visible', timeout=60000)
    except Exception:
        print('WARNING: no Findings card on the 4SICS capture - so-crates-findings.png not updated', file=sys.stderr)
        return
    await findings_card.click()
    await page.wait_for_selector('#section-findings tbody tr[data-id]', timeout=30000)
    await page.mouse.move(2, DEFAULT_VIEWPORT['height'] - 2)
    await page.evaluate('window.scrollTo(0, 0)')
    await page.set_viewport_size({'width': DEFAULT_VIEWPORT['width'], 'height': 1560})
    await page.wait_for_timeout(800)
    await page.screenshot(path=os.path.join(IMAGES_DIR, 'so-crates-findings.png'))
    await page.set_viewport_size(DEFAULT_VIEWPORT)
    print('captured findings')


async def main(base_url, only=None):
    os.makedirs(THEMES_DIR, exist_ok=True)

    async with async_playwright() as p:
        launch_kwargs = {'headless': True}
        chromium_path = find_chromium()
        if chromium_path:
            launch_kwargs['executable_path'] = chromium_path
        browser = await p.chromium.launch(**launch_kwargs)
        page = await browser.new_page(viewport=DEFAULT_VIEWPORT)
        if only == 'findings':
            await capture_findings(page, base_url)
            await browser.close()
            return
        if only == 'traffic-map':
            await capture_traffic_map(page, base_url)
            await browser.close()
            return

        # 1. Welcome modal (fresh session -> auto-shows, Midnight/default theme)
        await page.goto(base_url, wait_until='networkidle')
        await page.wait_for_selector('#helpModal.active .modal-content', timeout=10000)
        await page.wait_for_timeout(500)
        modal = await page.query_selector('#helpModal .modal-content')
        await modal.screenshot(path=os.path.join(IMAGES_DIR, 'so-crates-welcome.png'))
        print('captured welcome')

        # 2. Main screen (modal closed, upload/previous-analyses view)
        await page.evaluate('closeHelpModal()')
        await page.wait_for_timeout(500)
        await page.screenshot(path=os.path.join(IMAGES_DIR, 'so-crates-main.png'))
        print('captured main')

        # 3. Load the URL box's default pcap (self-contained, no fixture needed)
        await page.click("button[data-action='load-from-url']")
        await page.wait_for_selector('#statsGrid .stat-card', timeout=60000)
        await page.wait_for_timeout(1000)
        print('sample pcap loaded')

        # Pin to the "All Events" tab explicitly - which tab loads active by
        # default is not deterministic across load paths, and a consistent
        # starting view keeps the theme screenshots consistent release to release.
        all_events_card = page.locator(".stat-card:has-text('All Events')")
        if await all_events_card.count() > 0:
            await all_events_card.first.click()
            await page.wait_for_timeout(500)

        # 4. Theme sweep, on the pinned "All Events" view
        for theme in THEMES:
            await page.evaluate('(t) => setTheme(t)', theme)
            await page.wait_for_timeout(400)
            await page.screenshot(path=os.path.join(THEMES_DIR, f'{theme}.png'))
        print(f'captured {len(THEMES)} theme screenshots')
        await page.evaluate("setTheme('dark')")
        await page.wait_for_timeout(300)

        # 5. Analysis screen - Network Alerts tab
        alerts_card = page.locator(".stat-card:has-text('Network Alerts')")
        if await alerts_card.count() > 0:
            await alerts_card.first.click()
            await page.wait_for_timeout(800)
        await page.screenshot(path=os.path.join(IMAGES_DIR, 'so-crates-analysis.png'))
        print('captured analysis')

        # Prefer the AgentTesla FTP exfil alert (rich Alert Details section,
        # real FTP session in the transcript, and a community_id so Correlate
        # shows up below); fall back to the first row / Flows tab if the
        # sample data ever changes and that specific alert isn't present.
        row_selector = '.section:not(.section-hidden):not(.agg-section) table tbody tr:not(.detail-row)'
        target_row = page.locator(
            f"{row_selector}:has-text('ET MALWARE AgentTesla Exfil via FTP')"
        ).first
        if await target_row.count() == 0:
            target_row = page.locator(row_selector).first

        # 5.5. Pivot menu - click a non-timestamp cell (Source IP) to open
        # it without expanding the row (see handleRowCellClick in
        # static/socrates.js). Shows Include/Exclude/Only alongside Hunt and
        # Correlate (community-id correlation, new in 4.1.0) together.
        await target_row.locator('.mono-fixed').first.click()
        pivot_menu = page.locator('.pivot-menu').first
        try:
            await pivot_menu.wait_for(state='visible', timeout=5000)
            await page.wait_for_timeout(200)
            await pivot_menu.screenshot(path=os.path.join(IMAGES_DIR, 'so-crates-pivot-menu.png'))
            print('captured pivot-menu')
            await page.keyboard.press('Escape')
            await page.wait_for_timeout(200)
        except Exception:
            print('WARNING: pivot menu did not open on the target row - '
                  'so-crates-pivot-menu.png not updated', file=sys.stderr)

        # 6/7/8. Expand that same alert -> Playbook, then ASCII Transcript,
        # then Hexdump.
        # Click the timestamp cell specifically, not the row's default
        # (center-of-bounding-box) click point - the pivot menu now opens
        # on a click anywhere else in the row (see static/socrates.js's
        # handleRowCellClick), so a plain .click() on the row locator can
        # land on a pivot-enabled cell and open that menu instead of
        # expanding the row, same as a real user now has to target the
        # timestamp column specifically to expand (or use the pivot menu's
        # own "Expand Row" entry).
        await target_row.locator('.timestamp').click()
        await page.wait_for_timeout(300)

        # Taller viewport for every capture in this block - the full detail
        # section (Timestamp through Rule, plus Playbook/Payload) runs well
        # past the default 1000px-tall viewport.
        await page.set_viewport_size({'width': DEFAULT_VIEWPORT['width'], 'height': 1800})
        await page.wait_for_timeout(300)

        def _scroll_row_below_header():
            return target_row.evaluate(
                "(row) => { "
                "const header = document.querySelector('.app-header'); "
                "const headerHeight = header ? header.getBoundingClientRect().height : 0; "
                "const rect = row.getBoundingClientRect(); "
                "window.scrollBy(0, rect.top - headerHeight - 8); }"
            )

        # Playbook section - only present on this alert row (has a
        # signature_id), not on the Flows-tab fallback row below.
        playbook_toggle = page.locator('.detail-row.visible .playbook-questions-toggle').first
        try:
            await playbook_toggle.wait_for(state='visible', timeout=6000)
            await _scroll_row_below_header()
            await page.wait_for_timeout(300)
            await page.screenshot(path=os.path.join(IMAGES_DIR, 'so-crates-playbook.png'))
            print('captured playbook')
            # Collapse the questions list back down so the Playbook section
            # doesn't push the Payload/transcript out of the next captures.
            await playbook_toggle.click()
            await page.wait_for_timeout(300)
        except Exception:
            print('WARNING: no playbook available on the target alert (nothing baked in?) - '
                  'so-crates-playbook.png not updated', file=sys.stderr)

        stream_payload = page.locator('.detail-row.visible .stream-payload').first
        if await stream_payload.count() == 0:
            flows_card = page.locator(".stat-card:has-text('Flows')")
            if await flows_card.count() > 0:
                await flows_card.first.click()
                await page.wait_for_timeout(800)
                target_row = page.locator(row_selector).first
                await target_row.locator('.timestamp').click()
                await page.wait_for_timeout(300)
                stream_payload = page.locator('.detail-row.visible .stream-payload').first

        if await stream_payload.count() > 0:
            await page.wait_for_timeout(1500)

            # Scroll so the alert's summary row sits just below the fixed
            # header, then take a plain viewport screenshot - matches what a
            # user actually sees when they drill in: header, summary row, and
            # the full detail (Connection info, Alert Details, and
            # Payload/ASCII Transcript) together, for context.
            await _scroll_row_below_header()
            await page.wait_for_timeout(300)
            await page.screenshot(path=os.path.join(IMAGES_DIR, 'so-crates-transcript.png'))
            print('captured transcript')

            await stream_payload.locator("button.view-tab:has-text('Hexdump')").click()
            await page.wait_for_timeout(1500)
            expand_all_btn = stream_payload.locator("button:has-text('Expand All')")
            if await expand_all_btn.count() > 0:
                await expand_all_btn.click()
                await page.wait_for_timeout(500)
            await page.screenshot(path=os.path.join(IMAGES_DIR, 'so-crates-hexdump.png'))
            print('captured hexdump')
        else:
            print('WARNING: no stream-payload found on either alert or flow rows - '
                  'so-crates-transcript.png / so-crates-hexdump.png not updated', file=sys.stderr)

        # Reset regardless of which captures above actually ran - the
        # viewport was already enlarged for the Playbook capture even if
        # stream_payload was never found.
        await page.set_viewport_size(DEFAULT_VIEWPORT)
        await page.wait_for_timeout(300)

        # 9. Aggregation Tables, expanded and actually filtered - click Source IP
        # and Dest Port values from the AgentTesla alert to demonstrate the
        # click-to-filter workflow, not just show the tables passively.
        agg_toggle = page.locator('.section-toggle-bar', has_text='Aggregation Tables').first
        if await agg_toggle.count() > 0:
            await agg_toggle.click()
            await page.wait_for_timeout(800)

            # Clicking an agg-row now opens the pivot menu rather than
            # applying a filter directly - "Only" for the first value
            # (clean start, replaces any existing filters) then "Include"
            # for the second (ANDs a second column's filter in on top,
            # rather than "Only"'s clear-and-replace, which would wipe out
            # the first one).
            source_ip_row = page.locator(
                ".agg-table:has(.agg-header:has-text('Source IP')) .agg-row:has-text('10.2.3.101')"
            ).first
            if await source_ip_row.count() > 0:
                await source_ip_row.click()
                await page.wait_for_timeout(300)
                await page.locator('[data-pivot-action="only"]').click()
                await page.wait_for_timeout(800)

            dest_port_row = page.locator(
                ".agg-table:has(.agg-header:has-text('Dest Port')) .agg-row:has-text('21')"
            ).first
            if await dest_port_row.count() > 0:
                await dest_port_row.click()
                await page.wait_for_timeout(300)
                await page.locator('[data-pivot-action="include"]').click()
                await page.wait_for_timeout(800)

            # Filtering rebuilds the data table, so re-expand the (now single,
            # filtered) row to show its detail below, same as the reference.
            # Click the timestamp cell specifically - see the transcript/
            # hexdump capture above for why a plain row click can open the
            # pivot menu instead of expanding.
            filtered_row = page.locator(row_selector).first
            if await filtered_row.count() > 0:
                await filtered_row.locator('.timestamp').click()
                await page.wait_for_timeout(500)

            # Collapse the Sankey Diagram (expanded by default) to leave room
            # for the Aggregation Tables and Data Table below it in one shot.
            sankey_toggle = page.locator('.section-toggle-bar', has_text='Sankey Diagram').first
            if await sankey_toggle.count() > 0:
                await sankey_toggle.click()
                await page.wait_for_timeout(300)

            await page.evaluate('window.scrollTo(0, 0)')
            await page.set_viewport_size({'width': DEFAULT_VIEWPORT['width'], 'height': 1250})
            await page.wait_for_timeout(300)
            await page.screenshot(path=os.path.join(IMAGES_DIR, 'so-crates-aggregation-filtering.png'))
            await page.set_viewport_size(DEFAULT_VIEWPORT)
            await page.wait_for_timeout(300)
            print('captured aggregation-filtering')
        else:
            print('WARNING: no aggregation toggle found - '
                  'so-crates-aggregation-filtering.png not updated', file=sys.stderr)

        await capture_traffic_map(page, base_url)
        await capture_findings(page, base_url)

        await browser.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', default='http://127.0.0.1:8000/socrates.html')
    parser.add_argument('--only', choices=['traffic-map', 'findings'],
                        help='capture just this one (traffic-map: the web server capture\'s Traffic Map; '
                             'findings: the 4SICS capture\'s sections and Findings tab)')
    args = parser.parse_args()
    asyncio.run(main(args.base_url, args.only))
