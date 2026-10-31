#!/usr/bin/env python3
"""Build one offline HTML with a hash-pinned upstream age implementation.

No npm install, CDN at runtime, credentials or secret-key generation at build time.
"""
from __future__ import annotations

import base64
import hashlib
import html
import os
from pathlib import Path
import re
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
URL = 'https://github.com/FiloSottile/typage/releases/download/v0.3.1/age-0.3.1.min.js'
DIGEST = '112306e7bc83bf28f47e45f632c5989c0ea979cdc7d0e5c71823b3eae7f086ae'
SIZE = 98093
NOTICES = '''Typage / age-encryption 0.3.1
https://github.com/FiloSottile/typage
Copyright 2023 The age Authors

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of the age project nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The complete upstream JavaScript bundle, including its dependency license
comments, is embedded unchanged apart from HTML end-tag escaping. This build
uses no custom cryptographic primitive. Typage uses the noble/scure libraries.
'''


def digest_policy(content: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(content.encode()).digest()).decode() + "'"


def main() -> None:
    request = Request(URL, headers={'User-Agent': 'security-review-helper-build'})
    with urlopen(request, timeout=40) as response:
        data = response.read(SIZE + 1)
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != DIGEST:
        raise SystemExit('Pinned browser encryption library verification failed.')
    library = data.decode('utf-8')
    # Preserve legal notices from the upstream bundle. Never use an unpinned fallback.
    if 'Paul Miller' not in library or 'MIT' not in library:
        raise SystemExit('Upstream dependency license notices require manual review.')
    template = (ROOT/'web/recovery.html').read_text(encoding='utf-8')
    if template.count('__AGE_LIBRARY__') != 1 or template.count('__CSP__') != 1:
        raise SystemExit('Unexpected browser-helper template.')
    library = re.sub(r'</script', r'<\\/script', library, flags=re.I)
    revision = os.environ.get('GITHUB_SHA', 'local-build')
    if revision != 'local-build' and not re.fullmatch(r'[a-f0-9]{40}', revision):
        raise SystemExit('Invalid build revision.')
    output = template.replace('__AGE_LIBRARY__', library).replace('__LICENSES__', html.escape(NOTICES)).replace('__REVISION__', revision)
    scripts = re.findall(r'<script>(.*?)</script>', output, re.S)
    styles = re.findall(r'<style>(.*?)</style>', output, re.S)
    if len(scripts) != 2 or len(styles) != 1:
        raise SystemExit('Unexpected inline resources.')
    csp = "default-src 'none'; connect-src 'none'; script-src " + ' '.join(map(digest_policy, scripts))
    csp += '; style-src ' + digest_policy(styles[0]) + "; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'; worker-src 'none'; media-src 'none'"
    output = output.replace('__CSP__', csp)
    if re.search(r'<(?:script|link)[^>]*(?:src|href)=', output, re.I):
        raise SystemExit('External resources are not allowed in the helper.')
    destination = ROOT/'dist'
    destination.mkdir(exist_ok=True)
    target = destination/'security-review.html'
    target.write_text(output, encoding='utf-8')
    (destination/'SHA256SUMS').write_text(hashlib.sha256(target.read_bytes()).hexdigest()+'  security-review.html\n')
    print('Built offline helper with verified upstream bundle and hash-based CSP.')


if __name__ == '__main__':
    main()
