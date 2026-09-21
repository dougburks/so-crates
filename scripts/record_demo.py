#!/usr/bin/env python3
"""Record docs/videos/demo.mp4 against a locally running SO-CRATES server.

Requires: pip install -r requirements-screenshots.txt, plus a one-time
`playwright install ffmpeg` (Playwright's video muxing needs its own bundled
ffmpeg, separate from any system ffmpeg). Also needs a running server
(default http://127.0.0.1:8000/socrates.html - override with --base-url).
Uses the app's own default "Sample pcap file" (DEFAULT_SAMPLE_URL in
static/socrates.js - a one-click convenience link to an external pcap on
malware-traffic-analysis.net, not something bundled with the app), same as
scripts/capture_screenshots.py, so it needs no pre-existing local analysis
or hardcoded MD5 - it works on a clean checkout with an empty DATA_DIR.
Before recording starts, main() pre-warms that exact sample via a plain
/api/load-url POST (see _prewarm_sample_analysis) and blocks until it's
ready - so the recorded click hits _commit_file_or_return_ready's dedup
fast path (see socrates.py) instead of waiting through a real Suricata/
YARA/Sigma run on camera. Running against a container's fresh volume (see
AGENTS.md's Release Checklist) is also the only way to get real Playbook/
AI Summary content in the recording, since playbook_lookup.py/
ai_summary_lookup.py read from PLAYBOOKS_DIR//usr/share/playbooks and
AI_SUMMARIES_DIR//usr/share/ai-summaries (Docker-image-baked, not part of
DATA_DIR).

Each caption() call can optionally take a target (a Playwright Locator) -
see point_to()/DRAW_ARROW_JS - which draws an amber arrow from the caption
box to whatever it's currently describing, so a caption never leaves it
ambiguous which stat card/button/row it refers to. Caption styling uses a
solid on-brand blue rather than translucent black specifically so it stays
legible against the app's own near-black UI (see CAPTION_JS's own comment).

Playwright's own video muxing can only record to WebM, but that raw
recording is treated as a discarded intermediate, not a published asset -
it's immediately re-encoded to H.264/AAC MP4 via a system `ffmpeg` binary,
since MP4 is universally browser-supported (unlike WebM, whose Safari/iOS
support is spotty) and is also the format required to upload the same clip
directly to X/Instagram/LinkedIn/Facebook, none of which accept WebM. A
still frame is also extracted to docs/videos/demo-poster.jpg, used as the
<video poster> on the Home page so it doesn't show a blank white square
before playback. If ffmpeg isn't found on PATH, the raw WebM is saved to
docs/videos/demo.webm as a last-resort fallback instead, with a warning -
better than no video at all, but docs/index.md's <video> tag would need a
matching <source> added back until ffmpeg is available and this script is
re-run.

Usage:
    python3 scripts/record_demo.py [--base-url http://127.0.0.1:8000/socrates.html]
"""

import argparse
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

from playwright.async_api import async_playwright

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MP4_OUTPUT = os.path.join(REPO_ROOT, 'docs', 'videos', 'demo.mp4')
WEBM_FALLBACK_OUTPUT = os.path.join(REPO_ROOT, 'docs', 'videos', 'demo.webm')
POSTER_OUTPUT = os.path.join(REPO_ROOT, 'docs', 'videos', 'demo-poster.jpg')
POSTER_TIMESTAMP_SECONDS = 80  # lands on the full merged All Events Sankey diagram, pointer arrow included - re-tune this if the recorded workflow's timing shifts (e.g. steps added/removed/re-ordered)
# Playwright's raw recording's very first frame can be captured before the
# page has fully painted into the configured viewport - observed as a
# corrupted frame 0 showing only a small upper-left region of real content
# against an otherwise flat grey canvas, gone by the very next frame. Only
# matters for demo.mp4 itself (not docs/index.md's <video> embed, which
# uses POSTER_OUTPUT as its poster and never shows frame 0 at all) - but a
# viewer who downloads/re-uploads demo.mp4 directly (e.g. to social media)
# is at the mercy of whatever thumbnail that platform extracts from the
# file's own first frame. Trimmed off the front of the published MP4 here
# rather than relying on a manual release-checklist step to catch it by
# hand each time.
MP4_TRIM_START_SECONDS = 0.15
VIEWPORT = {'width': 1920, 'height': 1400}

# Solid on-brand blue (not translucent black) - a black/near-black caption
# box used to disappear into the app's own near-black UI (welcome screen,
# dark theme background) since rgba(0,0,0,0.85) barely differs from what's
# behind it. #1f6feb matches the app's own button/accent blue (see
# so-crates-welcome.png's "Got it!" button) so it reads as part of the UI's
# own visual language rather than a foreign overlay, while still being
# solid enough to contrast against literally any app background. The
# brighter border plus a two-layer shadow (soft ambient + a crisp 1px outer
# ring) keeps the box's edges legible even against similarly-dark page
# content directly behind it.
CAPTION_JS = """
(text) => {
    let el = document.getElementById('demoCaption');
    if (!el) {
        el = document.createElement('div');
        el.id = 'demoCaption';
        el.style.cssText = [
            'position:fixed', 'left:50%', 'transform:translateX(-50%)',
            'background:#1f6feb', 'color:#fff', 'padding:14px 30px',
            'border-radius:10px', 'font-family:system-ui,-apple-system,sans-serif',
            'font-size:24px', 'font-weight:600', 'z-index:2147483647',
            'box-shadow:0 8px 24px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.1)',
            'max-width:92vw', 'text-align:center', 'line-height:1.3', 'pointer-events:none',
            'white-space:pre-line', 'border:1px solid rgba(255,255,255,0.35)'
        ].join(';');
        document.body.appendChild(el);
    }
    const header = document.querySelector('.app-header');
    const headerHeight = header ? header.getBoundingClientRect().height : 0;
    el.style.top = (headerHeight + 16) + 'px';
    el.textContent = text;
}
"""

# Draws (or moves, if already present) an SVG line+arrowhead from whichever
# edge of the caption box is nearest the target to whichever edge of the
# target is nearest the caption box - not hardcoded to point straight down,
# since targets appear above/below/beside the caption depending on where
# they land on the page (a stat card near the top vs. a hexdump button far
# down the scrolled page). `rect` is a Playwright bounding_box() dict
# ({x, y, width, height}, viewport-relative, same coordinate space as
# getBoundingClientRect()) computed in Python right before this runs, not a
# selector re-resolved here - several targets (the currently-open pivot
# menu's own button, "the first alert row") aren't reliably re-selectable
# by a generic CSS selector the way the already-resolved Locator is.
# Amber, not the caption's own blue - so the arrow reads as a distinct
# annotation layer rather than blending into the caption box or the app's
# own blue accent/links.
#
# The arrowhead lands inside the target (its horizontal center, a quarter
# of the way down) rather than at the nearest edge point - REGRESSION: an
# earlier version pointed at the nearest edge, which for tightly-packed
# neighbors (e.g. the three "Sample ... file" cards sitting side by side)
# put the arrowhead right on the shared border between two cards, reading
# as ambiguous or pointing at the wrong one. Landing inside the target's
# own body instead of on any edge it might share with a neighbor is
# unambiguous regardless of what else is nearby.
DRAW_ARROW_JS = """
(rect) => {
    const captionEl = document.getElementById('demoCaption');
    if (!captionEl || !rect) return;
    const capRect = captionEl.getBoundingClientRect();
    const targetCenter = { x: rect.x + rect.width / 2, y: rect.y + rect.height / 2 };
    function nearestPoint(r, fx, fy) {
        return {
            x: Math.max(r.left, Math.min(fx, r.right)),
            y: Math.max(r.top, Math.min(fy, r.bottom))
        };
    }
    const start = nearestPoint(capRect, targetCenter.x, targetCenter.y);
    const end = { x: targetCenter.x, y: rect.y + Math.min(rect.height * 0.3, rect.height / 2) };
    let svg = document.getElementById('demoPointerArrow');
    if (!svg) {
        svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.id = 'demoPointerArrow';
        svg.style.cssText = 'position:fixed;top:0;left:0;width:100vw;height:100vh;pointer-events:none;z-index:2147483646;';
        svg.innerHTML = '<defs><marker id="demoArrowhead" markerWidth="10" markerHeight="9" refX="8" refY="4.5" orient="auto">' +
            '<polygon points="0 0, 9 4.5, 0 9" fill="#ffb300"/></marker></defs>' +
            '<line id="demoArrowLine" stroke="#ffb300" stroke-width="4" stroke-linecap="round" ' +
            'style="filter:drop-shadow(0 0 3px rgba(0,0,0,0.6))" marker-end="url(#demoArrowhead)"/>';
        document.body.appendChild(svg);
    }
    const line = svg.querySelector('#demoArrowLine');
    line.setAttribute('x1', start.x);
    line.setAttribute('y1', start.y);
    line.setAttribute('x2', end.x);
    line.setAttribute('y2', end.y);
}
"""

REMOVE_ARROW_JS = "() => { const el = document.getElementById('demoPointerArrow'); if (el) el.remove(); }"

CAPTION_REMOVE_JS = ("() => { "
                     "const el = document.getElementById('demoCaption'); if (el) el.remove(); "
                     "const arrow = document.getElementById('demoPointerArrow'); if (arrow) arrow.remove(); "
                     "}")

# Registered via page.add_init_script so it runs before the app's own scripts
# on the very first navigation - shows the caption from the first paint, over
# the real page as it loads in behind it (matching what a real user actually
# sees, rather than hiding the load behind an opaque cover - the app's own
# inline FOUC-prevention script in <head> already applies the right theme
# background before first paint, so there's nothing that needs covering).
# document.documentElement is null the instant this runs (before the HTML
# parser creates <html>), so it retries via setTimeout rather than assuming
# it already exists.
CAPTION_INIT_JS_TEMPLATE = """
(() => {
    // page.add_init_script() runs in every frame, not just the top-level
    // page - including the Themes modal's own #themePreviewFrame iframe
    // (a real, separately-navigated document). Without this guard, that
    // iframe gets its own "Welcome..." caption baked in at its own first
    // paint, which nothing ever updates afterward (every caption()/point_to()
    // call in this script only evaluates against the top-level `page`) - it
    // would sit there frozen, visible any time the live theme preview shows
    // through the modal later in the recording, long after the real
    // top-level caption has moved on to something else entirely.
    if (window.self !== window.top) return;
    function tryInit() {
        if (!document.documentElement) { setTimeout(tryInit, 0); return; }
        const el = document.createElement('div');
        el.id = 'demoCaption';
        el.style.cssText = [
            'position:fixed', 'left:50%', 'top:72px', 'transform:translateX(-50%)',
            'background:#1f6feb', 'color:#fff', 'padding:14px 30px',
            'border-radius:10px', 'font-family:system-ui,-apple-system,sans-serif',
            'font-size:24px', 'font-weight:600', 'z-index:2147483647',
            'box-shadow:0 8px 24px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.1)',
            'max-width:92vw', 'text-align:center', 'line-height:1.3', 'pointer-events:none',
            'white-space:pre-line', 'border:1px solid rgba(255,255,255,0.35)'
        ].join(';');
        el.textContent = __CAPTION_TEXT__;
        document.documentElement.appendChild(el);
    }
    tryInit();
})();
"""


def find_chromium():
    for name in ('chromium', 'chromium-browser', 'google-chrome'):
        path = shutil.which(name)
        if path:
            return path
    return None


async def caption(page, text, target=None):
    """Sets the caption text and, if target (a Playwright Locator) is
    given, points an arrow at it - otherwise clears any arrow left over
    from the previous caption, so a caption with no specific referent
    (e.g. a general status message) never inherits a stale, now-wrong
    arrow from whatever the last one pointed at."""
    await page.evaluate(CAPTION_JS, text)
    if target is not None:
        await point_to(page, target)
    else:
        await clear_pointer(page)


async def point_to(page, target):
    """(Re)draws the pointer arrow at target's current position, without
    touching the caption text - used when a target only becomes available
    partway through a caption's display (e.g. a Playbook/AI Summary section
    that's still being fetched when the caption first appears). Silently
    clears the arrow instead of drawing a wrong one if target isn't
    currently resolvable (e.g. no Playbook/AI Summary baked in for this
    rule/environment) - a missing arrow is fine, a stale one pointing at
    nothing is not."""
    try:
        box = await target.bounding_box()
    except Exception:
        box = None
    if box is None:
        await clear_pointer(page)
        return
    await page.evaluate(DRAW_ARROW_JS, box)


async def clear_pointer(page):
    await page.evaluate(REMOVE_ARROW_JS)


def _default_sample_url():
    """Read DEFAULT_SAMPLE_URL straight from static/socrates.js rather than
    hardcoding a second copy here - a second copy would silently drift out
    of sync with the real one if it ever changed, quietly pre-warming the
    wrong sample (or none at all) while the recorded click below still
    requests whatever the frontend's own constant actually says."""
    js_path = os.path.join(REPO_ROOT, 'static', 'socrates.js')
    with open(js_path, 'r') as f:
        content = f.read()
    match = re.search(r"const DEFAULT_SAMPLE_URL = '([^']+)'", content)
    if not match:
        raise RuntimeError('Could not find DEFAULT_SAMPLE_URL in static/socrates.js')
    return match.group(1)


def _prewarm_sample_analysis(base_url):
    """Trigger the same /api/load-url request the recorded 'Sample pcap
    file' click below will make, and block until Suricata/YARA/Sigma
    finish, before recording starts - so that click hits
    _commit_file_or_return_ready's dedup fast path (see socrates.py) and
    resolves in a second or two instead of however long the real analysis
    takes (real repro: several visible seconds of "Downloading file..."/
    analysis-in-progress spinner in the recorded video, dominated by
    Suricata parsing the sample and loading the full ruleset, not the
    small pcap's own download time). The download itself still happens
    twice - this request downloads the sample as a real prerequisite, and
    the recorded click downloads it again, since _fetch_url_safely has no
    cache - but a several-hundred-KB pcap download is fast; it's the
    Suricata/YARA/Sigma run this actually saves.

    Plain urllib, not Playwright - this must run before the recorded
    browser context is even created (see main() below), so none of it
    shows up in the video."""
    origin = base_url.rsplit('/socrates.html', 1)[0]
    sample_url = _default_sample_url()
    body = json.dumps({'url': sample_url}).encode('utf-8')
    req = urllib.request.Request(
        origin + '/api/load-url', data=body,
        headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req, timeout=90) as resp:
        result = json.loads(resp.read())
    if result.get('status') == 'error':
        raise RuntimeError(f"Pre-warm failed: {result.get('error')}")
    md5 = result['md5']
    print(f'Pre-warming sample analysis (md5={md5})...')
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        with urllib.request.urlopen(origin + '/api/status?md5=' + md5, timeout=10) as resp:
            status = json.loads(resp.read())
        if status.get('status') == 'ready':
            print('Pre-warm complete - the recorded run will hit the dedup fast path.')
            return
        if status.get('status') == 'error':
            raise RuntimeError(f"Pre-warm analysis failed: {status.get('message')}")
        time.sleep(1)
    raise RuntimeError('Pre-warm timed out waiting for analysis to become ready')


async def main(base_url):
    _prewarm_sample_analysis(base_url)
    os.makedirs(os.path.dirname(MP4_OUTPUT), exist_ok=True)
    tmp_video_dir = tempfile.mkdtemp(prefix='so-crates-demo-video-')

    async with async_playwright() as p:
        launch_kwargs = {'headless': True}
        chromium_path = find_chromium()
        if chromium_path:
            launch_kwargs['executable_path'] = chromium_path
        browser = await p.chromium.launch(**launch_kwargs)
        context = await browser.new_context(
            viewport=VIEWPORT,
            record_video_dir=tmp_video_dir,
            record_video_size=VIEWPORT,
        )
        page = await context.new_page()

        # Show the intro caption from the very first paint of the new
        # document, over the real page as it loads in behind it.
        welcome_caption = ("Welcome to the SO-CRATES recorded demo!\n\n"
                           "https://so-crates.org\n\n"
                           "When you first connect to SO-CRATES, you'll be greeted by a welcome "
                           "window that gives you an overview of what you can do with SO-CRATES.")
        caption_init_script = CAPTION_INIT_JS_TEMPLATE.replace(
            '__CAPTION_TEXT__', json.dumps(welcome_caption))
        await page.add_init_script(caption_init_script)

        # Welcome screen
        await page.goto(base_url, wait_until="networkidle")
        await page.wait_for_selector('#helpModal.active .modal-content', timeout=10000)
        welcome_modal = page.locator('#helpModal.active .modal-content')
        await caption(page, welcome_caption, welcome_modal)  # reposition now that the real header exists
        await page.wait_for_timeout(7000)  # two full sentences - the longest caption in the recording
        await page.evaluate("closeHelpModal()")
        # No target - the modal that was just closed is gone, and the
        # caption describes the main screen generally, not one widget on it.
        await caption(page, "When you dismiss the welcome window, you will see the main screen "
                            "where you can upload a new file or re-open a previous analysis")
        await page.wait_for_timeout(5800)

        # Select the sample pcap file
        sample_card = page.locator(".sample-card:has-text('Sample pcap file')")
        await caption(page, "Selecting the default sample pcap file", sample_card)
        await page.wait_for_timeout(2200)
        await sample_card.click()
        await page.wait_for_selector('#statsGrid .stat-card', timeout=60000)
        # No single target - "Analysis complete" is a general status, not a
        # reference to one specific element.
        await caption(page, "Analysis complete")
        await page.wait_for_timeout(2500)

        # Look at each of the individual data types
        card_count = await page.locator('.stat-card:not(.stat-disabled)').count()
        for i in range(card_count):
            card = page.locator('.stat-card:not(.stat-disabled)').nth(i)
            label = (await card.inner_text()).strip().split('\n')[-1]
            if label == 'ALL EVENTS':
                continue
            await card.click()
            await caption(page, f"Viewing {label}", card)
            await page.wait_for_timeout(3200)

            # Drill into a real Suricata alert to show the Playbook section -
            # only reachable from here, since Network Alerts is the one card
            # whose rows have a signature_id (see renderAlertDetails's own
            # playbook-section-placeholder in static/socrates.js).
            if label == 'NETWORK ALERTS':
                alert_row_selector = '.section:not(.section-hidden):not(.agg-section) table tbody tr:not(.detail-row)'
                # Prefer the ET MALWARE AgentTesla Exfil via FTP alert
                # specifically (sid:2029927) - its playbook has unusually
                # good, specific investigation questions to show off,
                # rather than whichever alert happens to sort first. Falls
                # back to the first alert row if this one isn't present
                # (e.g. a different/updated ruleset).
                targeted_alert_row = page.locator(
                    f"{alert_row_selector}:has-text('AgentTesla Exfil via FTP')"
                ).first
                alert_row = (
                    targeted_alert_row if await targeted_alert_row.count() > 0
                    else page.locator(alert_row_selector).first
                )
                if await alert_row.count() > 0:
                    await alert_row.scroll_into_view_if_needed()
                    await caption(page, "Drilling into a Suricata alert", alert_row)
                    await page.wait_for_timeout(2200)
                    # Click a value cell (not the timestamp) first, to show
                    # the pivot menu (Include/Exclude/Only/Hunt/...) that
                    # opens for any other cell in the row - see
                    # handleRowCellClick in static/socrates.js.
                    value_cell = alert_row.locator('.mono-fixed').first
                    await caption(page, "Clicking on a value opens the pivot menu.\n\n"
                                        "You can also click the timestamp to expand the row directly.", value_cell)
                    await page.wait_for_timeout(4200)
                    await value_cell.click()
                    await page.wait_for_timeout(700)
                    # "Expand Row" is the pivot menu's own entry point back
                    # to the same expand/collapse behavior a timestamp click
                    # triggers directly - see showPivotMenu's expandRowHtml.
                    # The menu is already open at this point (clicked above),
                    # so this locator resolves to a real, visible button.
                    expand_row_btn = page.locator('[data-pivot-action="expand-row"]')
                    await caption(page, 'Choosing "Expand Row" from the pivot menu', expand_row_btn)
                    await page.wait_for_timeout(2400)
                    await expand_row_btn.click()
                    await page.wait_for_timeout(600)
                    await alert_row.evaluate(
                        "(row) => { "
                        "const header = document.querySelector('.app-header'); "
                        "const headerHeight = header ? header.getBoundingClientRect().height : 0; "
                        "const rect = row.getBoundingClientRect(); "
                        "window.scrollBy(0, rect.top - headerHeight - 8); }"
                    )
                    await page.wait_for_timeout(600)

                    # AI Summary is fetched and inserted the moment the row
                    # expands (loadAiSummaryPlaceholders, triggered by the
                    # expand-row click above), same as Playbook below - no
                    # extra wait needed before the caption itself, but the
                    # arrow still waits for the row to confirm visible before
                    # pointing, same defensive shape as the Playbook arrow.
                    await caption(page, "SO-CRATES shows an AI-generated summary "
                                        "of what this rule detects")
                    ai_summary_label = page.locator(
                        '.detail-row.visible .detail-label', has_text='AI Summary'
                    ).first
                    try:
                        await ai_summary_label.wait_for(state='visible', timeout=4000)
                        await point_to(page, ai_summary_label)
                    except Exception:
                        pass  # no AI summary baked in for this rule/environment - caption still makes sense
                    await page.wait_for_timeout(4200)

                    await caption(page, "SO-CRATES shows a Playbook with guidance to help "
                                        "investigate this alert")
                    playbook_toggle = page.locator('.detail-row.visible .playbook-questions-toggle').first
                    try:
                        await playbook_toggle.wait_for(state='visible', timeout=6000)
                        await playbook_toggle.scroll_into_view_if_needed()
                        await point_to(page, playbook_toggle)
                    except Exception:
                        pass  # no playbook baked in for this rule/environment - caption still makes sense
                    await page.wait_for_timeout(5200)  # linger on the expanded section
                    # Collapse the row back before moving on, so its expanded
                    # state (and the ASCII-transcript fetch that toggleDetailRow
                    # kicks off for any alert row with a flow tuple) doesn't
                    # linger into later steps.
                    await clear_pointer(page)
                    await alert_row.locator('.timestamp').click()
                    await page.wait_for_timeout(400)

                    # Acknowledge this same alert to show how noisy,
                    # already-triaged signatures can be cleared out of
                    # view - re-open the pivot menu on the same row and
                    # commit "Acknowledge this alert".
                    await value_cell.click()
                    await page.wait_for_timeout(700)
                    acknowledge_btn = page.locator('[data-pivot-action="acknowledge"]')
                    await caption(page, 'Acknowledging this alert removes it from view - '
                                        'useful for noisy, already-triaged signatures', acknowledge_btn)
                    await page.wait_for_timeout(2400)
                    await acknowledge_btn.click()
                    await page.wait_for_timeout(2000)  # refreshAnalysisData()'s own re-fetch/re-render

                    # Acknowledged rows only reappear in the new
                    # Acknowledged Alerts tab, for review or undo.
                    acknowledged_card = page.locator(".stat-card:has-text('Acknowledged Alerts')").first
                    if await acknowledged_card.count() > 0:
                        await caption(page, "Acknowledged alerts move to their own "
                                            "Acknowledged Alerts tab", acknowledged_card)
                        await page.wait_for_timeout(2200)
                        await acknowledged_card.click()
                        await page.wait_for_timeout(1500)

                        acknowledged_row = page.locator(
                            '.section:not(.section-hidden):not(.agg-section) table tbody tr:not(.detail-row)'
                        ).first
                        if await acknowledged_row.count() > 0:
                            await acknowledged_row.scroll_into_view_if_needed()
                            ack_value_cell = acknowledged_row.locator('.mono-fixed').first
                            await caption(page, "Un-acknowledging brings it right back", ack_value_cell)
                            await page.wait_for_timeout(2200)
                            await ack_value_cell.click()
                            await page.wait_for_timeout(700)
                            unacknowledge_btn = page.locator('[data-pivot-action="unacknowledge"]')
                            await unacknowledge_btn.click()
                            # Un-acknowledging the only acknowledged row
                            # switches back to Network Alerts automatically
                            # (see refreshAnalysisData in static/socrates.js)
                            # - no explicit tab click needed here.
                            await page.wait_for_timeout(2200)

        # All Events
        all_events_card = page.locator(".stat-card:has-text('All Events')").first
        await all_events_card.click()
        await caption(page, "Switching to the merged All Events view", all_events_card)
        await page.wait_for_timeout(2800)

        # Collapse the Sankey Diagram via the keyboard, not a click - Down
        # selects the toggle bar (getVerticalNavItems in static/socrates.js)
        # and Enter activates it exactly like a click would
        # (activateKeyboardSelection's plain verticalNavSelection.click()
        # fallback for anything that isn't a data row/filter chip/previous-
        # analysis row) - so the Aggregation Tables and Data Table have room
        # to show, now that we're ready to expand them.
        selected = page.locator('.keyboard-selected')
        sankey_toggle = page.locator('.section-toggle-bar', has_text='Sankey Diagram').first
        if await sankey_toggle.count() > 0:
            await page.keyboard.press('ArrowDown')
            await page.wait_for_timeout(500)
            await caption(page, "Arrow keys navigate the whole page too - Down selects the "
                                "Sankey Diagram toggle, Enter collapses it to make room for "
                                "the Data Table", selected)
            await page.wait_for_timeout(3800)
            await page.keyboard.press('Enter')
            await page.wait_for_timeout(1400)

        # Expand Aggregation Tables the same way - Down moves to the next
        # toggle bar, Enter expands it.
        await page.keyboard.press('ArrowDown')
        await page.wait_for_timeout(500)
        await caption(page, "Down again, Enter again - expanding Aggregation Tables", selected)
        await page.wait_for_timeout(2800)
        await page.keyboard.press('Enter')
        await page.wait_for_timeout(600)
        await clear_pointer(page)

        # Clicking an aggregation value now opens the pivot menu (Include/
        # Exclude/Only/Hunt/...) rather than applying a filter directly -
        # "Only" is the one that matches "filter down to a single matching
        # event" (a fresh search scoped to just this value), so click that
        # from the menu rather than the row itself.
        detail_value_row = page.locator(
            ".agg-row:has-text('STOR PW_tyler-DESKTOP-W7F98GR_2026_02_03_16_13_59.html')"
        ).first
        # The Detail table pages 10 values at a time (deterministically
        # ordered by count desc, then value - see db.py's aggregation
        # tie-break), and this count-1 value sorts behind the digit-prefixed
        # FTP responses, landing on page 2. Page the Detail table forward
        # until the row is present rather than assuming page 1.
        for _ in range(5):
            if await detail_value_row.count() > 0:
                break
            next_btn = page.locator(
                ".agg-table:has(.agg-header:has-text('Detail')) .agg-page-btn:has-text('Next')"
            ).first
            if await next_btn.count() == 0 or not await next_btn.is_enabled():
                break
            await next_btn.click()
            await page.wait_for_timeout(900)
        await detail_value_row.scroll_into_view_if_needed()
        await caption(page, "Clicking a Detail value to filter down to a single matching event", detail_value_row)
        await page.wait_for_timeout(4200)
        await detail_value_row.click()
        await page.wait_for_timeout(400)
        await page.locator('[data-pivot-action="only"]').click()
        await page.wait_for_timeout(2600)

        # Drill into the single remaining row in the Data Table - click the
        # timestamp cell specifically, not the row's default click point:
        # clicking anywhere else in the row now opens the pivot menu too
        # (see static/socrates.js's handleRowCellClick), so a plain
        # .click() on the row can land on a pivot-enabled cell instead of
        # expanding it, same as a real user now has to target the
        # timestamp column (or use the pivot menu's own "Expand Row" entry).
        row_selector = '.section:not(.section-hidden):not(.agg-section) table tbody tr:not(.detail-row)'
        data_row = page.locator(row_selector).first
        await data_row.scroll_into_view_if_needed()
        timestamp_cell = data_row.locator('.timestamp')
        await caption(page, "Clicking directly on the timestamp immediately "
                            "expands the row, skipping the pivot menu", timestamp_cell)
        await page.wait_for_timeout(4400)
        await timestamp_cell.click()
        await page.wait_for_timeout(800)

        # Anchor the summary row just below the fixed header - the ASCII
        # Transcript/Hexdump content below it grows taller than the viewport
        # once expanded, so pin the top rather than scroll_into_view_if_needed
        # (which only guarantees the element's *edge* is visible, not that
        # there's room below it to actually see the payload).
        await data_row.evaluate(
            "(row) => { "
            "const header = document.querySelector('.app-header'); "
            "const headerHeight = header ? header.getBoundingClientRect().height : 0; "
            "const rect = row.getBoundingClientRect(); "
            "window.scrollBy(0, rect.top - headerHeight - 8); }"
        )
        await page.wait_for_timeout(600)

        # Show the ASCII Transcript (default view on expand)
        stream_payload = page.locator('.detail-row.visible .stream-payload').first
        ascii_tab = stream_payload.locator("button.view-tab:has-text('ASCII Transcript')")
        await caption(page, "Viewing the ASCII Transcript of the stream", ascii_tab)
        await page.wait_for_timeout(4000)  # let the transcript fetch finish + reading time

        # Click Hexdump
        hexdump_tab = stream_payload.locator("button.view-tab:has-text('Hexdump')")
        await hexdump_tab.click()
        await caption(page, "Switching to the Hexdump view", hexdump_tab)
        await page.wait_for_timeout(3200)

        # Click Expand All
        expand_all_btn = stream_payload.locator("button:has-text('Expand All')")
        await expand_all_btn.click()
        await caption(page, "Expanding all packets in the hexdump", expand_all_btn)
        await page.wait_for_timeout(2200)

        # Scroll down to reveal more of the expanded hexdump - the arrow is
        # cleared first since expand_all_btn scrolls out of view immediately
        # and a fixed-position arrow can't track a target that's moving
        # under continuous mouse-wheel scrolling.
        await clear_pointer(page)
        for _ in range(5):
            await page.mouse.wheel(0, 350)
            await page.wait_for_timeout(750)
        await page.wait_for_timeout(1500)

        # Command Palette - typing any letter/digit outside a text field
        # (isNavigableKeyContext/isAutocompleteTriggerKey in
        # static/socrates.js) opens a searchable list of commands, themes,
        # and data-type tabs. Closes out the tour with the newest
        # keyboard-first way to drive the whole app. Scrolled back to the
        # top first so the palette (a centered overlay) isn't shown against
        # whatever mid-scroll hexdump content the previous step left behind.
        await page.evaluate("window.scrollTo(0, 0)")
        await page.wait_for_timeout(600)
        await caption(page, "SO-CRATES also has a command palette - just "
                            "start typing anywhere outside a text field")
        await page.wait_for_timeout(2800)
        # page.keyboard.type() sends real keydown events - the first one
        # (isAutocompleteTriggerKey) opens the palette and seeds its input
        # with that character (openAutocompleteModal), so every character
        # after it lands as a normal keystroke in the now-focused input.
        await page.keyboard.type('e', delay=150)
        await page.wait_for_timeout(500)
        palette_results = page.locator('#autocompleteResults')
        await caption(page, 'Matching isn\'t limited to the start of a word - even a bare '
                            'fragment like "eme" finds "Themes" and every individual theme '
                            'by name', palette_results)
        await page.keyboard.type('me', delay=150)
        await page.wait_for_timeout(2800)
        # "eme" now matches dozens of commands (see autocompleteMatchScore's
        # own comment in static/socrates.js: every per-theme command's code
        # deliberately ends in " theme" so a "theme" fragment surfaces them
        # all) - Enter alone no longer commits with that many candidates
        # still ambiguous (activateAutocompleteSelection requires exactly
        # one match, or an explicit arrow-key selection first). "Themes"
        # itself sorts first among the tied score-0 matches (stable sort
        # preserves AUTOCOMPLETE_COMMANDS's own order, and "Themes" is
        # declared before the generated per-theme entries), so one ArrowDown
        # highlights it.
        await page.keyboard.press('ArrowDown')
        await page.wait_for_timeout(800)
        await caption(page, 'Arrow keys highlight a result - Down lands on "Themes", '
                            'first among the matches', palette_results)
        await page.wait_for_timeout(1800)
        await page.keyboard.press('Enter')
        await page.wait_for_timeout(1000)
        themes_modal = page.locator('#themesModal.active .modal-content')
        await caption(page, "Enter commits the highlighted command immediately - "
                            "here, opening the Themes modal", themes_modal)
        await page.wait_for_timeout(4000)

        # No target - the final sign-off caption describes nothing on
        # screen in particular.
        await caption(page, "Thanks for watching!\n\nhttps://so-crates.org")
        await page.wait_for_timeout(4000)

        await page.evaluate(CAPTION_REMOVE_JS)
        await page.wait_for_timeout(1000)

        await context.close()
        video_path = await page.video.path()
        await browser.close()

    # Playwright's raw recording is WebM-only; it's a discarded intermediate
    # (see module docstring), not what gets published, so it stays in the
    # temp dir rather than moving into docs/videos/.
    raw_webm_path = video_path

    ffmpeg_path = shutil.which('ffmpeg')
    if ffmpeg_path:
        subprocess.run(
            [ffmpeg_path, '-y', '-ss', str(POSTER_TIMESTAMP_SECONDS), '-i', raw_webm_path,
             '-frames:v', '1', '-q:v', '3', POSTER_OUTPUT],
            check=True, capture_output=True,
        )
        print('POSTER_SAVED_AT:', POSTER_OUTPUT)

        # crf 18 (not the more typical 23) plus preset slow - the source is
        # a screen recording dominated by large flat/near-black regions
        # (welcome screen, dark theme background), and crf 23's coarser
        # quantization on those regions was visible as banding (shade
        # shifting in what should be a single flat black) rather than the
        # blocking/blur crf differences usually show on natural video. This
        # is UI content with crisp text, not natural video, so a deband
        # filter was deliberately not used instead - it would soften the
        # exact text edges crf 18 already keeps sharp.
        # -ss placed after -i (output-seeking, not input-seeking) for
        # frame-accurate trimming rather than snapping to the nearest
        # keyframe - see MP4_TRIM_START_SECONDS's own comment for why this
        # trim exists. No extra decode cost from output-seeking here since
        # this is already a full re-encode (-c:v libx264), not a stream
        # copy, so every frame gets decoded regardless of where -ss sits.
        subprocess.run(
            [ffmpeg_path, '-y', '-i', raw_webm_path, '-ss', str(MP4_TRIM_START_SECONDS),
             '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-preset', 'slow', '-crf', '18',
             '-movflags', '+faststart', MP4_OUTPUT],
            check=True, capture_output=True,
        )
        print('MP4_SAVED_AT:', MP4_OUTPUT)
        if os.path.exists(WEBM_FALLBACK_OUTPUT):
            os.remove(WEBM_FALLBACK_OUTPUT)
    else:
        # Can't encode MP4 or extract a poster frame without ffmpeg - fall
        # back to publishing the raw WebM so there's still a video, with a
        # warning that docs/index.md's <video> tag needs a matching WebM
        # <source> added back until this is re-run with ffmpeg available.
        if os.path.exists(MP4_OUTPUT):
            os.remove(MP4_OUTPUT)
        shutil.move(raw_webm_path, WEBM_FALLBACK_OUTPUT)
        print('WEBM_FALLBACK_SAVED_AT:', WEBM_FALLBACK_OUTPUT)
        print('WARNING: ffmpeg not found on PATH - skipped generating '
              'docs/videos/demo.mp4 and docs/videos/demo-poster.jpg. Saved the raw '
              'WebM recording as a fallback instead; add a WebM <source> back to '
              "docs/index.md's <video> tag until ffmpeg is available and this "
              'script is re-run.',
              file=sys.stderr)

    shutil.rmtree(tmp_video_dir, ignore_errors=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', default='http://127.0.0.1:8000/socrates.html')
    args = parser.parse_args()
    asyncio.run(main(args.base_url))
