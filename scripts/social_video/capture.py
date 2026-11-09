#!/usr/bin/env python3
"""Capture the screens the release's social video shows (video.html), from
a running SO-CRATES - the release's own container is best, as for the docs'
screenshots (the Release Checklist).

It uploads attack-lab.pcap - attacks on Redis, MySQL, SQL Server, a Zabbix
agent and an IRC server, run in containers and re-addressed with
readdress.py - waits for tshark's records, and saves into <out>/shots:

- lab-findings.png: the analysis, Findings tab open, tall enough for every
  high-severity row (the lab scene and the Findings pan)
- lab-irc.png: the IRC bot's record expanded (the up-close scene)
- socrates.jpg: the mascot, from docs/images

video.html's highlight boxes sit at fixed places on these screens. If the
UI moved a row or a card, positions.py prints where they are now.

Usage: python3 scripts/social_video/capture.py [--base-url URL] [--out DIR]
"""
import argparse
import asyncio
import json
import os
import shutil
import sys
import time
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, '..', '..')
sys.path.insert(0, os.path.join(HERE, '..'))
VIEWPORT = {'width': 1600, 'height': 1000}


def default_out():
    sys.path.insert(0, ROOT)
    from socrates import VERSION
    return os.path.expanduser(f"~/Videos/so-crates-{'.'.join(VERSION.split('.')[:2])}-social")


def upload(api, path):
    """POST /api/upload the capture; its MD5 once tshark's records are in."""
    boundary = uuid.uuid4().hex
    with open(path, 'rb') as f:
        data = f.read()
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{os.path.basename(path)}"\r\n'
            'Content-Type: application/vnd.tcpdump.pcap\r\n\r\n').encode() + data + f'\r\n--{boundary}--\r\n'.encode()
    request = urllib.request.Request(f'{api}/api/upload', data=body,
                                     headers={'Content-Type': f'multipart/form-data; boundary={boundary}'})
    with urllib.request.urlopen(request, timeout=60) as r:
        md5 = json.loads(r.read())['md5']
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        with urllib.request.urlopen(f'{api}/api/shark-status?md5={md5}', timeout=30) as r:
            status = json.loads(r.read())
        if status.get('status') == 'ready' and status.get('merged'):
            return md5
        time.sleep(2)
    raise SystemExit('tshark never finished on the lab capture')


async def capture(base_url, md5, shots):
    from playwright.async_api import async_playwright
    from capture_screenshots import find_chromium
    async with async_playwright() as p:
        kwargs = {'headless': True}
        if find_chromium():
            kwargs['executable_path'] = find_chromium()
        browser = await p.chromium.launch(**kwargs)
        page = await browser.new_page(viewport=VIEWPORT, device_scale_factor=2)
        await page.goto(base_url, wait_until='networkidle')
        await page.evaluate("""() => {
            localStorage.setItem('socrates_findingsInfoCollapsed', 'true');
            localStorage.removeItem('socrates_statGroupsCollapsed');
            localStorage.setItem('socrates_welcomeSeen', 'true');
            localStorage.setItem('socrates-theme', 'dark');
        }""")

        async def open_card(section):
            await page.goto(f'{base_url}?file={md5}', wait_until='networkidle')
            if await page.locator('#helpModal.active').count():
                await page.evaluate('closeHelpModal()')
            await page.wait_for_selector('#statsGrid .stat-card', timeout=60000)
            await page.locator(f'.stat-card[data-section="{section}"]').first.click()
            await page.wait_for_selector(f'#{section} tbody tr', timeout=30000)
            await page.mouse.move(2, 2)
            await page.wait_for_timeout(1500)

        await open_card('section-findings')
        await page.set_viewport_size({'width': VIEWPORT['width'], 'height': 3600})
        await page.wait_for_timeout(700)
        await page.evaluate('window.scrollTo(0, 0)')
        await page.screenshot(path=os.path.join(shots, 'lab-findings.png'))
        print('captured lab-findings')

        await page.set_viewport_size(VIEWPORT)
        await open_card('section-irc')
        await page.set_viewport_size({'width': VIEWPORT['width'], 'height': 2600})
        # the bot's connection: its Nick cell opens the pivot menu, whose
        # Expand Row shows its details
        await page.locator('#section-irc tbody tr[data-id]', has_text='USA|83621').locator('td').nth(6).click()
        await page.locator('.pivot-menu-item', has_text='Expand Row').click()
        await page.wait_for_timeout(1500)
        await page.mouse.move(2, 2)
        await page.locator('#section-irc').screenshot(path=os.path.join(shots, 'lab-irc.png'))
        print('captured lab-irc')
        await browser.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--base-url', default='http://127.0.0.1:8000/socrates.html')
    parser.add_argument('--out', default=None, help='the release\'s video folder (default ~/Videos/so-crates-<version>-social)')
    args = parser.parse_args()
    out = args.out or default_out()
    shots = os.path.join(out, 'shots')
    os.makedirs(shots, exist_ok=True)
    shutil.copy(os.path.join(ROOT, 'docs', 'images', 'socrates.jpg'), shots)
    api = args.base_url.rsplit('/', 1)[0]
    md5 = upload(api, os.path.join(HERE, 'attack-lab.pcap'))
    print('lab capture analyzed:', md5)
    asyncio.run(capture(args.base_url, md5, shots))
    print('shots in', shots)


if __name__ == '__main__':
    main()
