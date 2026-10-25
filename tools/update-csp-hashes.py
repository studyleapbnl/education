#!/usr/bin/env python3
"""
Study LEAP - refresh the per-page Content-Security-Policy script hashes.

WHY: every page is allowed to run only its OWN inline <script> blocks (matched by SHA-256 hash).
An attacker-injected <script> tag has a different hash, so the browser refuses to run it.
(Inline event attributes such as onclick="..." are still allowed: script-src-attr 'unsafe-inline'.)

WHEN TO RUN: after ANY edit to an inline <script> block in ANY .html page, before you upload.
If you forget, that page's script is blocked and the page stops working - so always run it, then
upload. It is safe to run repeatedly (it replaces the old script-src-elem / script-src-attr).

HOW:   python3 tools/update-csp-hashes.py          (from the folder that holds index.html)
       python3 tools/update-csp-hashes.py --check  (report only, change nothing; exit 1 if stale)
"""
import base64, glob, hashlib, os, re, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CHECK = '--check' in sys.argv
DEFAULT_HOSTS = ['https://cdn.jsdelivr.net', 'https://www.clarity.ms', 'https://scripts.clarity.ms',
                 'https://www.googletagmanager.com', 'https://maps.googleapis.com',
                 'https://api.emailjs.com', 'https://challenges.cloudflare.com']
JS_TYPES = ('', 'text/javascript', 'application/javascript', 'module')

def inline_scripts(html):
    out = []
    for m in re.finditer(r'<script\b([^>]*)>(.*?)</script>', html, re.S | re.I):
        attrs, body = m.group(1), m.group(2)
        if re.search(r'\bsrc\s*=', attrs, re.I): continue
        t = re.search(r'\btype\s*=\s*["\']?([^"\'\s>]*)', attrs, re.I)
        if (t.group(1).lower() if t else '') not in JS_TYPES: continue    # JSON-LD etc. are data, not code
        if body.strip() == '': continue
        out.append(body)
    return out

def sha256(body):
    return "'sha256-" + base64.b64encode(hashlib.sha256(body.encode('utf-8')).digest()).decode() + "'"

def process(path):
    s = open(path, encoding='utf-8').read()
    hashes = sorted({sha256(b) for b in inline_scripts(s)})
    m = re.search(r'(<meta\s+http-equiv="Content-Security-Policy"\s+content=")([^"]*)(")', s, re.I)
    if m:
        csp = m.group(2)
        sm = re.search(r'(?<![\w-])script-src ([^;]*)', csp)
        hosts = [t for t in (sm.group(1).split() if sm else []) if t.startswith('https://')] or DEFAULT_HOSTS
        csp = re.sub(r';?\s*script-src-(elem|attr)\b[^;]*', '', csp).strip().rstrip(';')
    else:
        csp, hosts = '', DEFAULT_HOSTS
    elem = "script-src-elem 'self' " + ' '.join(hosts + hashes)
    new_csp = (csp + '; ' if csp else '') + elem + "; script-src-attr 'unsafe-inline'"
    if m:
        new = s[:m.start(2)] + new_csp + s[m.end(2):]
    else:
        tag = '<meta http-equiv="Content-Security-Policy" content="%s">\n' % new_csp
        cm = re.search(r'<meta\s+charset[^>]*>\s*', s, re.I) or re.search(r'<head[^>]*>\s*', s, re.I)
        new = s[:cm.end()] + tag + s[cm.end():]
    return s, new, len(hashes)

changed = stale = 0
for path in sorted(glob.glob(os.path.join(ROOT, '**', '*.html'), recursive=True)):
    rel = os.path.relpath(path, ROOT)
    if rel.startswith(('tools' + os.sep, 'node_modules')): continue
    old, new, n = process(path)
    if old != new:
        stale += 1
        if not CHECK:
            open(path, 'w', encoding='utf-8').write(new); changed += 1
print(('%d page(s) out of date' % stale) if CHECK else ('updated %d page(s)' % changed))
sys.exit(1 if (CHECK and stale) else 0)
