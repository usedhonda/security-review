"""Real file:// browser integration. Disposable keys only; no OpenAI requests.

Run separately from the Python unit suite: requires Playwright and system Chrome.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
RUN_URL = 'https://github.com/usedhonda/security-review/actions/runs/123456789'


def main() -> None:
    chrome = shutil.which('google-chrome') or shutil.which('chromium')
    if not chrome:
        raise SystemExit('System Chrome/Chromium is required; do not skip browser tests.')
    with tempfile.TemporaryDirectory() as tmp, sync_playwright() as pw:
        temp = Path(tmp)
        browser = pw.chromium.launch(executable_path=chrome, headless=True)
        context = browser.new_context(accept_downloads=True)
        requests, errors = [], []
        context.on('request', lambda req: requests.append(req.url))
        context.route('https://**/*', lambda route: route.abort())
        context.route('http://**/*', lambda route: route.abort())
        page = context.new_page()
        page.on('pageerror', lambda exc: errors.append(str(exc)))
        page.goto((ROOT/'dist/security-review.html').as_uri())
        assert page.locator('#app').is_visible()
        assert page.locator('#open-report').is_disabled()
        with page.expect_download() as downloaded:
            page.locator('#generate').click()
        identity = temp/'identity.txt'
        downloaded.value.save_as(identity)
        key_text = identity.read_text()
        assert 'AGE-SECRET-KEY-1' in key_text
        assert 'AGE-SECRET-KEY-1' not in page.locator('body').inner_text()
        public_key = page.locator('#recipient').input_value()
        assert public_key.startswith('age1')
        assert page.locator('#generate').is_disabled()
        # Native CLI validates the browser-created identity independently.
        derived = subprocess.check_output(['age-keygen', '-y', str(identity)], text=True).strip()
        assert derived == public_key
        assert page.locator('#settings').get_attribute('href') == 'https://github.com/usedhonda/security-review/settings/secrets/actions/new'
        page.locator('#clear').click()
        assert page.locator('#recipient').input_value() == ''
        page.locator('#identity').set_input_files(identity)
        page.wait_for_function("document.getElementById('recipient').value.startsWith('age1')")
        assert page.locator('#recipient').input_value() == public_key
        provenance = {'repository': 'usedhonda/security-review', 'run_id': '123456789', 'run_attempt': '1', 'workflow_commit': 'a'*40, 'kind': 'probe', 'step_outcome': 'success', 'recipient_sha256': hashlib.sha256(public_key.encode()).hexdigest()}
        probe = {'format': 'security-review.age-bundle.v1', 'provenance': provenance, 'summary_json': json.dumps({'schema_version': 1, 'status': 'recovery_probe', 'api_calls': 0}), 'summary_markdown': 'Recovery succeeded'}
        cipher = temp/'report.json.age'
        def encrypt(bundle, destination=cipher):
            output = subprocess.run(['age','--encrypt','--recipient',public_key], input=json.dumps(bundle).encode(), capture_output=True, check=True).stdout
            destination.write_bytes(output)
        encrypt(probe)
        page.locator('#run-url').fill(RUN_URL+'?check_suite_focus=true#artifacts')
        page.locator('#cipher').set_input_files(cipher)
        page.locator('#open-report').click()
        page.wait_for_function("!document.getElementById('result').hidden")
        assert page.locator('#result-title').inner_text() == '回収テストに成功しました'
        for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            path = temp/'encrypted-review-123456789-1.zip'
            with zipfile.ZipFile(path, 'w', compression=method) as archive:
                archive.writestr('report.json.age', cipher.read_bytes())
            page.locator('#cipher').set_input_files(path)
            page.locator('#open-report').click()
            page.wait_for_function("!document.getElementById('result').hidden")
        # Wrong run, incorrect explicit SHA, wrong key and corrupt/truncated files fail closed.
        def expect_failure():
            page.locator('#open-report').click()
            page.wait_for_function("document.getElementById('report-status').classList.contains('error')")
            assert page.locator('#result').is_hidden()
        page.locator('#run-url').fill(RUN_URL+'0');expect_failure()
        page.locator('#run-url').fill(RUN_URL)
        page.locator('#expected-sha').fill('b'*40);expect_failure()
        page.locator('#expected-sha').fill('a'*40)
        damaged = temp/'damaged.age';damaged.write_bytes(cipher.read_bytes()[:-1])
        page.locator('#cipher').set_input_files(damaged);expect_failure()
        damaged.write_bytes(cipher.read_bytes()[:100]+b'bad'+cipher.read_bytes()[103:])
        page.locator('#cipher').set_input_files(damaged);expect_failure()
        foreign = temp/'other.txt'
        subprocess.run(['age-keygen','-o',str(foreign)],capture_output=True,check=True)
        page.locator('#identity').set_input_files(foreign)
        page.wait_for_function('(key) => document.getElementById("recipient").value !== key && document.getElementById("recipient").value.startsWith("age1")', arg=public_key)
        page.locator('#cipher').set_input_files(cipher);expect_failure()
        page.locator('#identity').set_input_files(identity)
        page.wait_for_function('(key) => document.getElementById("recipient").value === key', arg=public_key)
        multiple = temp/'multiple.zip'
        with zipfile.ZipFile(multiple,'w') as archive:
            archive.writestr('report.json.age',cipher.read_bytes());archive.writestr('../extra.txt','x')
        page.locator('#cipher').set_input_files(multiple);expect_failure()
        large = temp/'large.age';large.write_bytes(b'x'*4_600_000)
        page.locator('#cipher').set_input_files(large);expect_failure()
        # AI/model-provided HTML is rendered only as text, never as DOM or links.
        malicious = '<img src="https://example.invalid/leak" onerror="window.xss=true">'
        review = dict(probe, provenance={**provenance,'kind':'review'})
        review['summary_json'] = json.dumps({'schema_version':1,'status':'completed','cases':[{'repository':'owner/repo','status':'completed','cost_usd':'0.01','review':{'summary':malicious,'findings':[{'title':malicious,'file':'x.py','start_line':1,'end_line':2,'evidence':malicious,'fix':'Do not execute model output'}],'limitations':[]}}]})
        review['summary_markdown'] = malicious
        encrypt(review)
        page.locator('#cipher').set_input_files(cipher)
        page.locator('#open-report').click();page.wait_for_function("!document.getElementById('result').hidden")
        assert malicious in page.locator('#report-content').inner_text()
        assert page.locator('#report-content img').count() == 0
        assert page.evaluate('window.xss === undefined')
        assert not any(url.startswith(('https:','http:')) for url in requests), requests
        assert page.evaluate('localStorage.length') == 0
        assert page.evaluate('sessionStorage.length') == 0
        assert not errors, errors
        page.locator('#clear').click();assert page.locator('#result').is_hidden()
        assert page.locator('#open-report').is_disabled()
        browser.close()
    print('Browser checks passed: local key generation/import, native age compatibility, ZIP recovery, provenance, corruption, wrong key, size limits, XSS-safe rendering, no network/storage.')


if __name__ == '__main__':
    main()
