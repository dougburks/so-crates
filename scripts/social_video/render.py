#!/usr/bin/env python3
"""Render the release's social video (video.html) frame by frame into MP4s,
from the screens capture.py saved in the same folder:

    so-crates-<version>-16x9.mp4   1920x1080, for X, Mastodon and Bluesky
    so-crates-<version>-1x1.mp4    1080x1080, for LinkedIn

60 seconds at 30 fps, H.264 with a silent AAC track (some platforms want
one), and a poster JPEG of each (poster-16x9.jpg, poster-1x1.jpg) for
platforms that ask for a cover. video.html is a deterministic timeline -
render(t) sets every element for time t - so a frame is the same however
fast it renders. Open it in a browser to watch it play (?t=12 freezes at
12 s; ?fmt=square for the square cut).

    render.py [--out DIR] [wide|square ...]            the videos
    render.py [--out DIR] wide --stills 3 12 30        PNG stills into <out>/prev

Needs ffmpeg, and Playwright's Chromium (or a system one).
"""
import argparse
import asyncio
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
FPS = 30
FORMATS = {'wide': ((1920, 1080), '16x9', ''), 'square': ((1080, 1080), '1x1', 'fmt=square')}


async def render(out, version, fmt, stills):
    from playwright.async_api import async_playwright
    from capture_screenshots import find_chromium
    (w, h), shape, query = FORMATS[fmt]
    url = f'file://{os.path.join(out, "video.html")}' + ('?' + query if query else '')
    async with async_playwright() as p:
        kwargs = {'headless': True}
        if find_chromium():
            kwargs['executable_path'] = find_chromium()
        browser = await p.chromium.launch(**kwargs)
        page = await browser.new_page(viewport={'width': w, 'height': h})
        await page.goto(url, wait_until='load')
        await page.evaluate('document.fonts.ready')
        await page.evaluate('Promise.all([...document.images].map(i => i.decode()))')
        if stills:
            os.makedirs(os.path.join(out, 'prev'), exist_ok=True)
            for t in stills:
                await page.evaluate(f'render({t})')
                await page.screenshot(path=os.path.join(out, 'prev', f'{fmt}-{t}.png'))
            await browser.close()
            return
        video = os.path.join(out, f'so-crates-{version}-{shape}.mp4')
        ff = subprocess.Popen([
            'ffmpeg', '-y', '-loglevel', 'error',
            '-f', 'image2pipe', '-framerate', str(FPS), '-c:v', 'png', '-i', '-',
            '-f', 'lavfi', '-i', 'anullsrc=channel_layout=stereo:sample_rate=48000',
            '-c:v', 'libx264', '-preset', 'slow', '-crf', '20', '-pix_fmt', 'yuv420p',
            '-profile:v', 'high', '-level', '4.1', '-r', str(FPS),
            '-c:a', 'aac', '-b:a', '128k', '-shortest', '-movflags', '+faststart', video,
        ], stdin=subprocess.PIPE)
        frames = int(await page.evaluate('DURATION') * FPS)
        for i in range(frames):
            await page.evaluate(f'render({i / FPS})')
            ff.stdin.write(await page.screenshot(type='png'))
            if i % 300 == 0:
                print(f'{fmt}: frame {i}/{frames}', flush=True)
        ff.stdin.close()
        ff.wait()
        await browser.close()
        # (the title card, once its subtitle is in)
        subprocess.run(['ffmpeg', '-y', '-loglevel', 'error', '-ss', '1.5', '-i', video, '-frames:v', '1', '-q:v', '3',
                        os.path.join(out, f'poster-{shape}.jpg')], check=True)
        print('wrote', video)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('formats', nargs='*', choices=list(FORMATS), help='wide, square or both (the default)')
    parser.add_argument('--out', default=None, help='the folder capture.py wrote to (default ~/Videos/so-crates-<version>-social)')
    parser.add_argument('--stills', nargs='+', type=float, help='times (s) to save as PNGs instead of rendering')
    args = parser.parse_args()
    from capture import default_out
    sys.path.insert(0, os.path.join(HERE, '..', '..'))
    from socrates import VERSION
    version = '.'.join(VERSION.split('.')[:2])
    out = args.out or default_out()
    if not os.path.exists(os.path.join(out, 'shots', 'lab-findings.png')):
        raise SystemExit(f'no shots in {out} - run capture.py first')
    shutil.copy(os.path.join(HERE, 'video.html'), out)
    for fmt in args.formats or list(FORMATS):
        asyncio.run(render(out, version, fmt, args.stills))


if __name__ == '__main__':
    main()
