#!/usr/bin/env python3
"""Where video.html's highlight boxes belong on capture.py's screens, in
the CSS pixels video.html places them in - for when the UI moved a card or
a row. Prints the stat cards (the lab scene), every Findings row (the
Findings pan) and the up-close record's detail rows (the up-close scene), each
as left, top, width, height. Run it against the same server capture.py
used, with the lab capture already analyzed there.

Usage: python3 scripts/social_video/positions.py <md5> [--base-url URL] [--record knxip|irc]
"""
import argparse
import asyncio
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))


async def main(base_url, md5, record):
    from capture import RECORDS
    record_section, record_row, record_cell = RECORDS[record]
    from playwright.async_api import async_playwright
    from capture_screenshots import find_chromium
    async with async_playwright() as p:
        kwargs = {'headless': True}
        if find_chromium():
            kwargs['executable_path'] = find_chromium()
        browser = await p.chromium.launch(**kwargs)
        page = await browser.new_page(viewport={'width': 1600, 'height': 3600})
        await page.goto(base_url, wait_until='networkidle')
        await page.evaluate("() => { localStorage.setItem('socrates_findingsInfoCollapsed', 'true');"
                            " localStorage.setItem('socrates_welcomeSeen', 'true'); }")

        async def open_card(section):
            await page.goto(f'{base_url}?file={md5}', wait_until='networkidle')
            await page.wait_for_selector('#statsGrid .stat-card', timeout=60000)
            await page.locator(f'.stat-card[data-section="{section}"]').first.click()
            await page.wait_for_selector(f'#{section} tbody tr', timeout=30000)
            await page.mouse.move(2, 2)
            await page.wait_for_timeout(1500)

        await open_card('section-findings')
        found = await page.evaluate("""() => {
            const box = el => { const b = el.getBoundingClientRect(); return [b.left, b.top, b.width, b.height].map(Math.round); };
            return {
                cards: Object.fromEntries([...document.querySelectorAll('.stat-card')].map(c => [c.dataset.section, box(c)])),
                findings: [...document.querySelectorAll('#section-findings tbody tr[data-id]')].map(tr =>
                    [tr.children[1].textContent.trim(), tr.children[2].textContent.trim().slice(0, 60), ...box(tr)]),
            }; }""")
        print('Stat cards (lab-findings.png):')
        for section, b in found['cards'].items():
            print(f'  {section}: {b}')
        print('Findings rows (lab-findings.png): title, detail, left, top, width, height')
        for row in found['findings']:
            print('  ' + json.dumps(row))

        await open_card(record_section)
        await page.locator(f'#{record_section} tbody tr[data-id]', has_text=record_row).locator('td').nth(record_cell).click()
        await page.locator('.pivot-menu-item', has_text='Expand Row').click()
        await page.wait_for_timeout(1500)
        rows = await page.evaluate("""section => {
            const box = document.getElementById(section).getBoundingClientRect();
            // (the expanded record's: the others' details are there, hidden)
            return [...document.querySelectorAll(`#${section} .detail-label`)].filter(label => label.offsetHeight).map(label => {
                const a = label.getBoundingClientRect();
                const v = label.nextElementSibling ? label.nextElementSibling.getBoundingClientRect() : a;
                const top = Math.min(a.top, v.top), bottom = Math.max(a.bottom, v.bottom);
                return [label.textContent.trim(), Math.round(a.left - box.left), Math.round(top - box.top),
                        Math.round(v.right - a.left), Math.round(bottom - top)];
            }); }""", record_section)
        width = await page.evaluate("s => Math.round(document.getElementById(s).getBoundingClientRect().width)", record_section)
        print(f'Up-close record (lab-record.png, {width} px wide - its <img> width in video.html):')
        for row in rows:
            print('  ' + json.dumps(row))
        await browser.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('md5')
    parser.add_argument('--base-url', default='http://127.0.0.1:8000/socrates.html')
    parser.add_argument('--record', default='knxip', help="the up-close scene's record (capture.py's RECORDS)")
    args = parser.parse_args()
    asyncio.run(main(args.base_url, args.md5, args.record))
