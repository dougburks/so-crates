#!/usr/bin/env python3
"""Capture the screens the release's social video shows (video.html), from
a running SO-CRATES - the release's own container is best, as for the docs'
screenshots (the Release Checklist).

It uploads a lab capture, waits for tshark's records, and saves into
<out>/shots:

- lab-findings.png: the analysis, Findings tab open, tall enough for every
  row (the lab scene and the Findings pan)
- lab-record.png: one record expanded (the up-close scene)
- socrates.jpg: the mascot, from docs/images

The labs, one per release's video:

- building-lab.pcap (5.4, the default): a KNX gateway (knxd) and a
  WS-Discovery printer (wsdd2) on 10.20.60.x, and an attacker (.66) that
  searches for and describes the gateway, tunnels in to write group
  addresses, tunnels again to program and reset device 1.1.5, and probes
  the printer by multicast, straight to it, and with junk. The up-close
  record is that second tunnel's.
- attack-lab.pcap (5.3): attacks on Redis, MySQL, SQL Server, a Zabbix
  agent and an IRC server, run in containers and re-addressed with
  readdress.py. Its up-close record was the IRC bot's (--record irc).

video.html's highlight boxes sit at fixed places on these screens. If the
UI moved a row or a card, positions.py prints where they are now.

Usage: python3 scripts/social_video/capture.py [--base-url URL] [--out DIR] [--lab PCAP] [--record knxip|irc]
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


# The record each lab's up-close scene expands: its section, the text that
# picks its row, and the cell whose pivot menu has Expand Row
RECORDS = {'knxip': ('section-knxip', '41000', 6), 'irc': ('section-irc', 'USA|83621', 6)}


async def capture(base_url, md5, shots, record):
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

        section, row, cell = RECORDS[record]
        await page.set_viewport_size(VIEWPORT)
        await open_card(section)
        await page.set_viewport_size({'width': VIEWPORT['width'], 'height': 2600})
        # a cell's pivot menu has Expand Row, which shows the record's details
        await page.locator(f'#{section} tbody tr[data-id]', has_text=row).locator('td').nth(cell).click()
        await page.locator('.pivot-menu-item', has_text='Expand Row').click()
        await page.wait_for_timeout(1500)
        await page.mouse.move(2, 2)
        await page.locator(f'#{section}').screenshot(path=os.path.join(shots, 'lab-record.png'))
        print('captured lab-record')
        await browser.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--base-url', default='http://127.0.0.1:8000/socrates.html')
    parser.add_argument('--out', default=None, help='the release\'s video folder (default ~/Videos/so-crates-<version>-social)')
    parser.add_argument('--lab', default=os.path.join(HERE, 'building-lab.pcap'), help='the lab capture')
    parser.add_argument('--record', default='knxip', choices=sorted(RECORDS), help="the up-close scene's record")
    args = parser.parse_args()
    out = args.out or default_out()
    shots = os.path.join(out, 'shots')
    os.makedirs(shots, exist_ok=True)
    shutil.copy(os.path.join(ROOT, 'docs', 'images', 'socrates.jpg'), shots)
    api = args.base_url.rsplit('/', 1)[0]
    md5 = upload(api, args.lab)
    print('lab capture analyzed:', md5)
    asyncio.run(capture(args.base_url, md5, shots, args.record))
    print('shots in', shots)


if __name__ == '__main__':
    main()
