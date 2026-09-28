#!/usr/bin/env python3
"""Record docs/videos/cyberchef.mp4 - the Home page's "CyberChef, built in"
video - against a locally running SO-CRATES server.

Walks through the three ways SO-CRATES hands data to its bundled CyberChef,
each on a capture built for it by scripts/make_cyberchef_demo_pcap.py (see
that script for the story): sending a selection of an ASCII transcript,
sending one direction of a stream from the Payload panel, and sending an
extracted file from File Info. Every payload is base64(hex(hexdump(text))),
so each scene ends on CyberChef's Magic operation working that out and the
decoded message.

Same requirements as scripts/record_demo.py (whose caption/arrow helpers
this reuses): pip install -r requirements-screenshots.txt, a one-time
`playwright install ffmpeg`, a system ffmpeg, and a running server - run it
against a fresh container per AGENTS.md's Release Checklist. The capture is
generated and uploaded before recording starts, so the analysis is already
complete when the video begins.

CyberChef opens in its own tab, and Playwright records each tab to its own
video file. So the SO-CRATES tab's recording is cut at each point a
CyberChef tab was on screen and that tab's recording spliced in (see
_stitch), giving one continuous video of what a user would actually see.

Usage:
    python3 scripts/record_cyberchef_demo.py [--base-url http://127.0.0.1:8000/socrates.html]
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
import uuid

from playwright.async_api import async_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import make_cyberchef_demo_pcap  # noqa: E402
from record_demo import (  # noqa: E402
    CAPTION_INIT_JS_TEMPLATE, CAPTION_REMOVE_JS, VIEWPORT, caption, clear_pointer, find_chromium,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MP4_OUTPUT = os.path.join(REPO_ROOT, 'docs', 'videos', 'cyberchef.mp4')
POSTER_OUTPUT = os.path.join(REPO_ROOT, 'docs', 'videos', 'cyberchef-poster.jpg')
UPLOAD_NAME = 'cyberchef-demo.pcap'


def _upload_capture(origin):
    """Generate the demo capture, upload it and wait until its analysis is
    ready - plain urllib before the browser starts, so none of it is in
    the video. Returns the analysis md5."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, UPLOAD_NAME)
        make_cyberchef_demo_pcap.build(path)
        with open(path, 'rb') as f:
            data = f.read()
    boundary = uuid.uuid4().hex
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="pcap"; filename="{UPLOAD_NAME}"\r\n'
            'Content-Type: application/octet-stream\r\n\r\n').encode() + data + f'\r\n--{boundary}--\r\n'.encode()
    req = urllib.request.Request(origin + '/api/upload', data=body, method='POST',
                                 headers={'Content-Type': f'multipart/form-data; boundary={boundary}'})
    with urllib.request.urlopen(req, timeout=60) as resp:
        md5 = json.loads(resp.read())['md5']
    print(f'Analyzing the demo capture (md5={md5})...')
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        with urllib.request.urlopen(f'{origin}/api/status?md5={md5}', timeout=10) as resp:
            status = json.loads(resp.read())
        if status.get('status') == 'ready':
            return md5
        if status.get('status') == 'error':
            raise RuntimeError(f"Analysis failed: {status.get('message')}")
        time.sleep(1)
    raise RuntimeError('Timed out waiting for the demo capture to be analyzed')


async def _open_row(page, tab_label, cell_text):
    """Switch to a stat-card tab and expand the first data row with a cell
    containing cell_text. Returns that row's expanded detail row."""
    await page.locator('.stat-card', has_text=tab_label).first.click()
    await page.wait_for_timeout(1500)
    row = page.locator('tr[data-id]:visible').filter(has=page.locator('td', has_text=cell_text)).first
    await row.scroll_into_view_if_needed()
    await row.locator('td.timestamp').click()
    await page.wait_for_timeout(1500)
    return row.locator('xpath=following-sibling::tr[1]')


async def _show_in_cyberchef(context, page, trigger, captions, cyberchef_windows, start, poster_png=None):
    """Click trigger (a Send to CyberChef control), then narrate the new
    CyberChef tab: captions[0] while Magic's suggestions are showing,
    captions[1] once its top suggestion is loaded. Records when the tab was
    on screen, for _stitch. With poster_png, also screenshots the tab once
    the recipe is loaded - input, recipe and decoded output all in view,
    before the output is maximised - for the video's poster."""
    async with context.expect_page() as new_page:
        await trigger.click()
    cc = await new_page.value
    opened = time.monotonic() - start
    await cc.wait_for_load_state()
    await cc.wait_for_function(
        "() => document.querySelectorAll('#output-html table tr').length > 1", timeout=30000)
    top = cc.locator('#output-html table tr').nth(1).locator('a').first
    await caption(cc, captions[0], top)
    await cc.wait_for_timeout(6000)
    await top.click()
    await cc.wait_for_timeout(1200)
    if poster_png:
        await cc.evaluate(CAPTION_REMOVE_JS)
        await cc.screenshot(path=poster_png)
    # CyberChef's own "Maximise output pane" - the decoded message gets the
    # whole window instead of a corner of it.
    await cc.locator('#maximise-output').click()
    await cc.wait_for_timeout(800)
    # No arrow: the decoded message fills the pane and is the point.
    await caption(cc, captions[1])
    await cc.wait_for_timeout(7000)
    await cc.evaluate(CAPTION_REMOVE_JS)
    closed = time.monotonic() - start
    video = cc.video
    await cc.close()
    cyberchef_windows.append((opened, closed, await video.path()))
    await page.bring_to_front()


async def main(base_url):
    origin = base_url.rsplit('/socrates.html', 1)[0]
    md5 = _upload_capture(origin)
    os.makedirs(os.path.dirname(MP4_OUTPUT), exist_ok=True)
    tmp_video_dir = tempfile.mkdtemp(prefix='so-crates-cyberchef-video-')
    cyberchef_windows = []  # (opened, closed, video path), seconds from the main tab's start

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

        intro = ("New in SO-CRATES 4.3.0: CyberChef, built in\n\n"
                 "Send stream payloads, extracted files and transcript selections straight to CyberChef")
        await page.add_init_script(CAPTION_INIT_JS_TEMPLATE.replace('__CAPTION_TEXT__', json.dumps(intro)))
        await page.goto(base_url, wait_until='networkidle')
        await page.wait_for_selector('#helpModal.active .modal-content', timeout=10000)
        await page.evaluate('closeHelpModal()')
        await caption(page, intro)
        await page.evaluate(f"loadAnalysis('{md5}')")
        await page.wait_for_selector('td.timestamp', timeout=30000)
        await page.wait_for_timeout(4500)
        await caption(page, "This capture: an infected desktop talking to a fake C2 server.\n"
                            "Its three messages are \"military-grade encrypted\" - let's see.")
        await page.wait_for_timeout(5000)

        # Scene 1 - a selection of an ASCII transcript.
        await caption(page, "First: the infected desktop's HTTP check-in")
        detail = await _open_row(page, 'HTTP', '/api/v2/telemetry')
        transcript = detail.locator('.ascii-transcript')
        await transcript.wait_for(timeout=15000)
        await page.wait_for_function(
            "() => [...document.querySelectorAll('.ascii-transcript')].some(t => t.textContent.includes('\"telemetry\": \"'))",
            timeout=15000)
        blob_line = transcript.locator('div', has_text='"telemetry": "').last
        await blob_line.scroll_into_view_if_needed()
        await caption(page, "Its POST hides an encoded blob inside one JSON field", blob_line)
        await page.wait_for_timeout(4500)
        # A real mouse drag across exactly the blob - selecting it by hand
        # is what opens the pivot menu (on the mouseup), and the selection
        # growing is what the viewer should see. The drag's start and end
        # points come from the blob's first and last characters on screen.
        blob = await page.evaluate("""() => {
            const t = [...document.querySelectorAll('.ascii-transcript')].find(e => e.offsetParent && e.textContent.includes('"telemetry": "'));
            const w = document.createTreeWalker(t, NodeFilter.SHOW_TEXT);
            let n;
            while ((n = w.nextNode()) && !n.textContent.includes('"telemetry": "'));
            const from = n.textContent.indexOf('"telemetry": "') + 14;
            const to = n.textContent.indexOf('"', from);
            n.parentElement.scrollIntoView({ block: 'center' });
            const rect = (a, b) => { const r = document.createRange(); r.setStart(n, a); r.setEnd(n, b); const rs = r.getClientRects(); return rs[rs.length - 1]; };
            const first = rect(from, from + 1), last = rect(to - 1, to);
            return { text: n.textContent.slice(from, to),
                     x1: first.left + 1, y1: (first.top + first.bottom) / 2,
                     x2: last.right - 1, y2: (last.top + last.bottom) / 2 };
        }""")
        await page.wait_for_timeout(600)
        await clear_pointer(page)
        await page.mouse.move(blob['x1'], blob['y1'])
        await page.mouse.down()
        await page.mouse.move(blob['x2'], blob['y2'], steps=40)
        await page.mouse.up()
        await page.wait_for_timeout(600)
        if await page.evaluate('getSelection().toString()') != blob['text']:
            raise RuntimeError('The drag did not select exactly the telemetry blob')
        send_selection = page.locator('.pivot-menu .pivot-menu-item', has_text='CyberChef')
        await caption(page, "Select just the blob, and the pivot menu opens for it - choose CyberChef", send_selection)
        await page.wait_for_timeout(5000)
        await clear_pointer(page)
        await _show_in_cyberchef(context, page, send_selection, (
            "CyberChef opens with the selection - Magic has already worked out\n"
            "it's base64, then hex, then a hexdump",
            "One click loads that recipe - the stolen goods, decoded"), cyberchef_windows, start,
            poster_png=os.path.join(tmp_video_dir, 'poster.png'))
        await page.evaluate('getSelection().removeAllRanges()')

        # Scene 2 - one direction of a stream. Each scene sets its caption
        # before navigating, so the previous scene's never lingers over the
        # tab switch when the recording cuts back from CyberChef.
        await caption(page, "Next: a beacon on port 4444")
        detail = await _open_row(page, 'Flows', '4444')
        dest = detail.locator('[data-action="send-stream-to-cyberchef"][data-direction="dst"]')
        await dest.scroll_into_view_if_needed()
        await caption(page, "A raw beacon on port 4444 - the server's whole reply is encoded.\n"
                            "Send just what the server sent (Dest) to CyberChef", dest)
        await page.wait_for_timeout(5500)
        await clear_pointer(page)
        await _show_in_cyberchef(context, page, dest, (
            "The exact bytes of that direction - Magic spots the same three layers",
            "The implant's beacon acknowledgement"), cyberchef_windows, start)

        # Scene 3 - an extracted file.
        await caption(page, "Next: a file the C2 sent back")
        detail = await _open_row(page, 'File Info', 'tasking')
        send_file = detail.locator('[data-action="send-file-to-cyberchef"]')
        await send_file.scroll_into_view_if_needed()
        await caption(page, "Suricata extracted the C2's tasking file - send it from File Info", send_file)
        await page.wait_for_timeout(5000)
        await clear_pointer(page)
        await _show_in_cyberchef(context, page, send_file, (
            "The extracted file, byte for byte - and Magic again",
            "The C2's tasking - and a lesson in encoding vs. encryption"), cyberchef_windows, start)

        await caption(page, "CyberChef is bundled with SO-CRATES, so it works offline too.\n\n"
                            "https://so-crates.org")
        await page.wait_for_timeout(5000)
        await page.evaluate(CAPTION_REMOVE_JS)
        await page.wait_for_timeout(800)
        total = time.monotonic() - start
        video = page.video
        await context.close()
        main_video = await video.path()
        await browser.close()

    _stitch(main_video, total, cyberchef_windows, tmp_video_dir, os.path.join(tmp_video_dir, 'poster.png'))
    shutil.rmtree(tmp_video_dir, ignore_errors=True)


def _stitch(main_video, total, cyberchef_windows, tmp_dir, poster_png):
    """Splice each CyberChef tab's recording into the main tab's where that
    tab was on screen, then encode MP4 like record_demo.py does, and the
    first scene's CyberChef screenshot as the poster JPEG.
    Each CyberChef recording starts when its tab was created, so it's used
    whole; the main tab's recording keeps running (on a view nobody sees)
    while a CyberChef tab is open, so that span is cut out of it."""
    ffmpeg = shutil.which('ffmpeg')
    if not ffmpeg:
        sys.exit('ffmpeg is required to stitch the CyberChef tabs into one video')
    parts, cursor = [], 0.0
    for opened, closed, cc_video in cyberchef_windows:
        parts.append((main_video, cursor, opened))
        parts.append((cc_video, 0.0, closed - opened))
        cursor = closed
    parts.append((main_video, cursor, total))
    segments = []
    for i, (src, begin, end) in enumerate(parts):
        seg = os.path.join(tmp_dir, f'seg{i:02d}.mp4')
        # record_demo.py's MP4 settings (see its comment), but crf 20: these
        # scenes are dense walls of base64, which crf 18 made twice the
        # main demo's size for a shorter video. Fixed frame rate so the
        # segments concatenate cleanly.
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
