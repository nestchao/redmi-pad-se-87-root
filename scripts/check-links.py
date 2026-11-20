"""Check that every relative Markdown link and image in this repo actually exists.

Usage: python scripts/check-links.py
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LINK = re.compile(r'!?\[([^\]]*)\]\(([^)]+)\)')
IMG = re.compile(r'<img\s+[^>]*src="([^"]+)"', re.I)
HREF = re.compile(r'<a\s+[^>]*href="([^"]+)"', re.I)
ANCHOR = re.compile(r'^#{1,6}\s+(.+)$', re.M)


def slug(s):
    s = s.strip().lower()
    s = re.sub(r'[`*_~\[\]()]', '', s)
    s = re.sub(r'[^\w\u4e00-\u9fff \-]', '', s)
    return s.replace(' ', '-')


def anchors(path):
    try:
        text = open(path, encoding='utf-8').read()
    except Exception:
        return set()
    return set(slug(m) for m in ANCHOR.findall(text))


def md_files():
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('build', 'recon')]
        for f in files:
            if f.endswith('.md'):
                yield os.path.join(base, f)


def main():
    broken = []
    checked = 0
    img_count = 0

    for path in md_files():
        rel = os.path.relpath(path, ROOT)
        text = open(path, encoding='utf-8').read()

        targets = []
        for m in LINK.finditer(text):
            targets.append((m.group(2), 'link'))
        for m in IMG.finditer(text):
            targets.append((m.group(1), 'img'))
        for m in HREF.finditer(text):
            targets.append((m.group(1), 'href'))

        for target, kind in targets:
            t = target.strip()
            if t.startswith(('http://', 'https://', 'mailto:')):
                continue
            if t.startswith('#'):
                if len(t) > 1:
                    checked += 1
                    if t[1:] not in anchors(path):
                        broken.append((rel, t, 'anchor'))
                continue

            frag = ''
            if '#' in t:
                t, frag = t.split('#', 1)

            resolved = os.path.normpath(os.path.join(os.path.dirname(path), t))
            checked += 1
            if kind == 'img':
                img_count += 1

            if not os.path.exists(resolved):
                broken.append((rel, target, 'missing'))
                continue

            if frag and resolved.endswith('.md'):
                if frag not in anchors(resolved):
                    broken.append((rel, target, 'anchor'))

    print('checked %d links/images (%d images)' % (checked, img_count))
    if not broken:
        print('ALL OK')
        return 0

    print('')
    print('found %d problems:' % len(broken))
    for rel, target, why in broken:
        print('  [%s] %s  ->  %s' % (why, rel, target))
    return 1


if __name__ == '__main__':
    sys.exit(main())
