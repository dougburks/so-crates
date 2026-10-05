#!/usr/bin/env python3
"""Record docs/videos/story.mp4 - the Home page's "Follow an investigation"
video - against a locally running SO-CRATES server.

Walks through the Welcome screen's four built-in samples (samples.py) in
the order of the story they tell (docs/usage/sample-story.md): the
phishing email, the workstation's Sysmon log, its network traffic, and
the payload itself - showing email analysis, Sigma, Suricata with a
playbook, YARA, and CyberChef decoding values from the email and the log
along the way.

Everything comes from the built-in samples, so recording needs no
internet access. Same requirements as scripts/record_demo.py (whose
caption/arrow helpers this reuses): pip install -r
requirements-screenshots.txt, a one-time `playwright install ffmpeg`, a
system ffmpeg, and a running server - run it against a fresh container
per AGENTS.md's Release Checklist. The four samples are loaded once
through POST /api/load-sample before recording starts, so each click in
the video opens an already-finished analysis.

CyberChef opens in its own tab, and Playwright records each tab to its own
video file. So the SO-CRATES tab's recording is cut at each point a
CyberChef tab was on screen and that tab's recording spliced in (see
_stitch), giving one continuous video of what a user would actually see.

Usage:
    python3 scripts/record_story_demo.py [--base-url http://127.0.0.1:8000/socrates.html]
"""

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

from playwright.async_api import async_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from record_demo import (  # noqa: E402
    CAPTION_INIT_JS_TEMPLATE, CAPTION_REMOVE_JS, VIEWPORT, caption, clear_pointer, find_chromium,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MP4_OUTPUT = os.path.join(REPO_ROOT, 'docs', 'videos', 'story.mp4')
POSTER_OUTPUT = os.path.join(REPO_ROOT, 'docs', 'videos', 'story-poster.jpg')
SAMPLES = ('email', 'log', 'pcap', 'binary')
# Cut from the front of the video: the recording starts before the page's
# first paint, and those first frames are pure white - which X, LinkedIn
# and the like use as the thumbnail when the MP4 is uploaded directly.
TRIM_START_SECONDS = 0.5


def _prewarm_samples(origin):
    """Load each built-in sample and wait until its analysis is ready -
    plain urllib before the browser starts, so the Sample cards clicked in
    the video open finished analyses instantly."""
    for name in SAMPLES:
        req = urllib.request.Request(origin + '/api/load-sample', data=json.dumps({'name': name}).encode(),
                                     headers={'Content-Type': 'application/json'}, method='POST')
        with urllib.request.urlopen(req, timeout=60) as resp:
            md5 = json.loads(resp.read())['md5']
        print(f'Analyzing the {name} sample (md5={md5})...')
        deadline = time.monotonic() + 300
        while True:
            with urllib.request.urlopen(f'{origin}/api/status?md5={md5}', timeout=10) as resp:
                status = json.loads(resp.read())
            if status.get('status') == 'ready':
                break
            if status.get('status') == 'error':
                raise RuntimeError(f"The {name} sample's analysis failed: {status.get('message')}")
            if time.monotonic() > deadline:
                raise RuntimeError(f'Timed out waiting for the {name} sample')
            time.sleep(1)


async def _open_sample(page, label, hint):
    """From the Welcome screen, click one of the Sample cards."""
    card = page.locator('.sample-card', has_text=label)
    await caption(page, hint, card)
    await page.wait_for_timeout(3500)
    await clear_pointer(page)
    await card.click()
    # A binary analysis has no stat cards - its File Info card instead.
    await page.wait_for_selector('#statsGrid .stat-card, .file-info-card', timeout=60000)
    await page.wait_for_timeout(2500)


async def _back_to_welcome(page, hint):
    """Escape returns to the Welcome screen once nothing else is open."""
    await caption(page, hint)
    await page.wait_for_timeout(1800)
    await page.keyboard.press('Escape')
    await page.wait_for_selector('.sample-card', timeout=15000)
    await page.wait_for_timeout(1200)


async def _expand_row(page, tab_label, row_text):
    """Switch to a stat-card tab and expand the first row containing
    row_text (by its first cell - the timestamp, which expands without
    opening the pivot menu). Returns the expanded detail row."""
    await page.locator('.stat-card', has_text=tab_label).first.click()
    await page.wait_for_timeout(1500)
    row = page.locator('.section:not(.section-hidden) tbody tr[data-id]', has_text=row_text).first
    await row.scroll_into_view_if_needed()
    await row.locator('td').first.click()
    await page.wait_for_timeout(1500)
    return row.locator('xpath=following-sibling::tr[1]')


async def _drag_select(page, detail, label, start_marker, end_marker=None):
    """A real mouse drag across part of a detail-panel value - the one in
    detail whose text contains start_marker, from just after it to
    end_marker (or the end). Ending the drag opens the pivot menu for the
    selected text. Returns the selected text."""
    # Scroll first and let it settle, then measure - coordinates taken
    # mid-scroll put the drag's end somewhere else on the page.
    await detail.locator('.detail-value-pivot').evaluate_all(
        """(spans, start) => spans.find(s => s.textContent.includes(start)).scrollIntoView({ block: 'center' })""",
        start_marker)
    await page.wait_for_timeout(800)
    target = await detail.locator('.detail-value-pivot').evaluate_all(
        """(spans, [start, end]) => {
            const span = spans.find(s => s.textContent.includes(start));
            const node = span.firstChild, text = node.textContent;
            const from = text.indexOf(start) + start.length;
            const to = end ? text.indexOf(end, from) : text.length;
            const rect = (a, b) => { const r = document.createRange(); r.setStart(node, a); r.setEnd(node, b);
                                     const rs = r.getClientRects(); return rs[rs.length - 1]; };
            const first = rect(from, from + 1), last = rect(to - 1, to);
            return { text: text.slice(from, to), x1: first.left + 1, y1: (first.top + first.bottom) / 2,
                     x2: last.right - 1, y2: (last.top + last.bottom) / 2 };
        }""", [start_marker, end_marker])
    await caption(page, label)
    await page.wait_for_timeout(2500)
    await page.mouse.move(target['x1'], target['y1'])
    await page.mouse.down()
    await page.mouse.move(target['x2'], target['y2'], steps=30)
    await page.mouse.up()
    await page.wait_for_timeout(700)
    if await page.evaluate('getSelection().toString()') != target['text']:
        raise RuntimeError(f'The drag did not select exactly {target["text"]!r}')
    return target['text']


async def _show_in_cyberchef(context, page, captions, cyberchef_windows, start):
    """Choose CyberChef from the open pivot menu, then narrate the new
    CyberChef tab: captions[0] while Magic's suggestions are showing,
    captions[1] once its top suggestion is loaded and the output
    maximised. Records when the tab was on screen, for _stitch."""
    item = page.locator('.pivot-menu .pivot-menu-item', has_text='CyberChef')
    await caption(page, 'The pivot menu opens for the selection - choose CyberChef', item)
    await page.wait_for_timeout(3500)
    await clear_pointer(page)
    async with context.expect_page() as new_page:
        await item.click()
    cc = await new_page.value
    opened = time.monotonic() - start
    await cc.wait_for_load_state()
    await cc.wait_for_function(
        "() => document.querySelectorAll('#output-html table tr').length > 1", timeout=30000)
    top = cc.locator('#output-html table tr').nth(1).locator('a').first
    await caption(cc, captions[0], top)
    await cc.wait_for_timeout(4500)
    await top.click()
    await cc.wait_for_timeout(1000)
    await cc.locator('#maximise-output').click()
    # The decoded value is one short line - at CyberChef's normal size it's
    # a speck in the corner of the maximised pane, unreadable in a video.
    await cc.add_style_tag(content='#output-text, #output-text .cm-content, #output-text .cm-line '
                                   '{ font-size: 40px !important; line-height: 1.4 !important; }')
    await cc.wait_for_timeout(700)
    await caption(cc, captions[1])
    await cc.wait_for_timeout(5500)
    await cc.evaluate(CAPTION_REMOVE_JS)
    closed = time.monotonic() - start
    video = cc.video
    await cc.close()
    cyberchef_windows.append((opened, closed, await video.path()))
    await page.bring_to_front()
    await page.evaluate('getSelection().removeAllRanges()')


async def main(base_url):
    origin = base_url.rsplit('/socrates.html', 1)[0].rstrip('/')
    _prewarm_samples(origin)
    os.makedirs(os.path.dirname(MP4_OUTPUT), exist_ok=True)
    tmp_video_dir = tempfile.mkdtemp(prefix='so-crates-story-video-')
    poster_png = os.path.join(tmp_video_dir, 'poster.png')
    cyberchef_windows = []  # (opened, closed, video path), seconds from the main tab's start

    try:
        async with async_playwright() as p:
            launch_kwargs = {'headless': True}
            chromium_path = find_chromium()
            if chromium_path:
                launch_kwargs['executable_path'] = chromium_path
            browser = await p.chromium.launch(**launch_kwargs)
            context = await browser.new_context(viewport=VIEWPORT, record_video_dir=tmp_video_dir,
                                                record_video_size=VIEWPORT)
            page = await context.new_page()
            start = time.monotonic()

            intro = ("Follow an investigation\n\n"
                     "One phishing email, seen four ways - with SO-CRATES's four built-in samples")
            await page.add_init_script(CAPTION_INIT_JS_TEMPLATE.replace('__CAPTION_TEXT__', json.dumps(intro)))
            await page.goto(base_url, wait_until='networkidle')
            await page.wait_for_selector('#helpModal.active .modal-content', timeout=10000)
            await page.evaluate('closeHelpModal()')
            # Returning to the Welcome screen between samples shouldn't reopen
            # the Welcome window each time.
            await page.evaluate("localStorage.setItem('socrates_hideHelp', 'true')")
            await caption(page, intro)
            await page.wait_for_timeout(4500)

            # 1. The email.
            await _open_sample(page, 'Sample email file', 'It starts with an email - the Sample email file')
            detail = await _expand_row(page, 'Emails', 'ACTION REQUIRED')
            from_label = detail.locator('.detail-label', has_text='From').first
            await detail.locator('span', has_text='Warnings').first.scroll_into_view_if_needed()
            await page.evaluate('window.scrollBy(0, -120)')
            await page.wait_for_timeout(500)
            await caption(page, "\"Northbridge Payroll\" wants Jordan to confirm a direct deposit -\n"
                                "SO-CRATES lists the warning signs", from_label)
            await page.wait_for_timeout(2500)
            await page.evaluate(CAPTION_REMOVE_JS)
            await page.screenshot(path=poster_png)
            await caption(page, "Spoofed sender, failing SPF and DMARC, replies to a look-alike domain,\n"
                                "a link that lies, and a macro-enabled attachment")
            await page.wait_for_timeout(5500)

            detail = await _expand_row(page, 'Links', 'account-verify')
            await caption(page, "The \"portal\" link's text says portal.northbridgepay.example -\n"
                                "it really goes somewhere else, and carries a token", detail.locator('.detail-value-pivot').first)
            await page.wait_for_timeout(5000)
            await clear_pointer(page)
            await _drag_select(page, detail, 'Select the token after ?u= ...', '?u=')
            await _show_in_cyberchef(context, page, (
                "Magic recognizes base64", "Jordan's own address - the sender knows exactly who clicked"),
                cyberchef_windows, start)

            await caption(page, "Next: the attachment")
            await page.locator('.stat-card', has_text='File Alerts').first.click()
            await page.wait_for_timeout(1500)
            await caption(page, "YARA flags the macro document, Payroll_Adjustment_Form.docm",
                          page.locator('.section:not(.section-hidden) tbody tr[data-id]').first)
            await page.wait_for_timeout(4500)
            await clear_pointer(page)

            # 2. The log.
            await _back_to_welcome(page, 'Jordan opened it. What happened on the workstation?')
            await _open_sample(page, 'Sample log file', "The workstation's Sysmon log - the Sample log file")
            await caption(page, "Sigma flags each step: Word starting PowerShell, a download from the email's IP,\n"
                                "persistence, credential hunting", page.locator('.section:not(.section-hidden) tbody tr[data-id]').first)
            await page.wait_for_timeout(5500)
            await clear_pointer(page)
            # Through the alert's own matched event, not the Log Events tab:
            # that table is wider than the window, so the command line runs
            # off-screen there.
            await caption(page, "One alert - Base64 Encoded PowerShell. What did it run?")
            detail = await _expand_row(page, 'Sigma Alerts', 'Base64 Encoded PowerShell')
            await _drag_select(page, detail, 'Select the base64 it decodes ...', "FromBase64String('", "'")
            await _show_in_cyberchef(context, page, (
                "Magic decodes it", "certutil fetching update.bin from the email's sending IP - then running it"),
                cyberchef_windows, start)

            # 3. The pcap.
            await _back_to_welcome(page, 'And on the wire?')
            await _open_sample(page, 'Sample PCAP file', "The workstation's traffic - the Sample PCAP file")
            detail = await _expand_row(page, 'Network Alerts', 'AgentTesla')
            playbook = detail.locator('span', has_text='Playbook').first
            await playbook.wait_for(timeout=15000)
            await playbook.scroll_into_view_if_needed()
            await caption(page, "Suricata catches AgentTesla exfiltrating over FTP -\n"
                                "with an AI summary and a playbook to guide the investigation", playbook)
            await page.wait_for_timeout(6000)
            await clear_pointer(page)
            stor = detail.locator('.ascii-transcript div', has_text='STOR PW_').last
            await stor.wait_for(timeout=15000)
            await stor.scroll_into_view_if_needed()
            await caption(page, "The transcript shows what left: Jordan's harvested passwords", stor)
            await page.wait_for_timeout(5000)
            await clear_pointer(page)
            detail = await _expand_row(page, 'File Info', 'update.bin')
            sha = detail.locator('.detail-label', has_text='SHA256').first
            await sha.scroll_into_view_if_needed()
            await caption(page, "Suricata also extracted the payload, update.bin - note its SHA256", sha)
            await page.wait_for_timeout(5000)
            await clear_pointer(page)

            # 4. The binary.
            await _back_to_welcome(page, 'Finally, the payload itself')
            await _open_sample(page, 'Sample binary file', 'update.exe - the Sample binary file')
            sha = page.locator('.file-info-card .label', has_text='SHA256').first
            await caption(page, "The same SHA256 as the file Suricata extracted - and YARA flags it", sha)
            await page.wait_for_timeout(5500)
            await clear_pointer(page)

            await caption(page, "All four samples are built in and work offline -\n"
                              "try them from the Welcome screen.\n\nhttps://so-crates.org")
            await page.wait_for_timeout(5000)
            await page.evaluate(CAPTION_REMOVE_JS)
            await page.wait_for_timeout(800)
            total = time.monotonic() - start
            video = page.video
            await context.close()
            main_video = await video.path()
            await browser.close()

        _stitch(main_video, total, cyberchef_windows, tmp_video_dir, poster_png)
    finally:
        shutil.rmtree(tmp_video_dir, ignore_errors=True)


def _stitch(main_video, total, cyberchef_windows, tmp_dir, poster_png):
    """Splice each CyberChef tab's recording into the main tab's where that
    tab was on screen, then encode MP4 like record_demo.py does, and the
    email scene's screenshot as the poster JPEG.
    Each CyberChef recording starts when its tab was created, so it's used
    whole; the main tab's recording keeps running (on a view nobody sees)
    while a CyberChef tab is open, so that span is cut out of it."""
    ffmpeg = shutil.which('ffmpeg')
    if not ffmpeg:
        sys.exit('ffmpeg is required to stitch the CyberChef tabs into one video')
    parts, cursor = [], TRIM_START_SECONDS
    for opened, closed, cc_video in cyberchef_windows:
        parts.append((main_video, cursor, opened))
        parts.append((cc_video, 0.0, closed - opened))
        cursor = closed
    parts.append((main_video, cursor, total))
    segments = []
    for i, (src, begin, end) in enumerate(parts):
        seg = os.path.join(tmp_dir, f'seg{i:02d}.mp4')
        # record_demo.py's MP4 settings, but crf 20 to keep the file size
        # down for a longer video. Fixed frame rate so the segments
        # concatenate cleanly.
        subprocess.run([ffmpeg, '-y', '-ss', f'{begin:.3f}', '-i', src, '-t', f'{end - begin:.3f}',
                        '-r', '25', '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-preset', 'slow', '-crf', '20',
                        seg], check=True, capture_output=True)
        segments.append(seg)
    concat_list = os.path.join(tmp_dir, 'segments.txt')
    with open(concat_list, 'w') as f:
        f.writelines(f"file '{s}'\n" for s in segments)
    subprocess.run([ffmpeg, '-y', '-f', 'concat', '-safe', '0', '-i', concat_list, '-c', 'copy',
                    '-movflags', '+faststart', MP4_OUTPUT], check=True, capture_output=True)
    print('MP4_SAVED_AT:', MP4_OUTPUT)
    subprocess.run([ffmpeg, '-y', '-i', poster_png, '-q:v', '3', POSTER_OUTPUT],
                   check=True, capture_output=True)
    print('POSTER_SAVED_AT:', POSTER_OUTPUT)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', default='http://127.0.0.1:8000/socrates.html')
    args = parser.parse_args()
    asyncio.run(main(args.base_url))
