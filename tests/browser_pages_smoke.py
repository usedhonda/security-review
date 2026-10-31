"""Exercise the HTTPS viewer using synthetic identities, never the owner's keys."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
REPO = os.environ.get('GITHUB_REPOSITORY', 'usedhonda/security-review')
OWNER, NAME = REPO.split('/')
URL = f'https://{OWNER.lower()}.github.io/{NAME}/'
RUN, SHA = '123456789', 'a'*40


def main() -> None:
    executable = shutil.which('google-chrome') or shutil.which('chromium')
    if not executable:
        raise SystemExit('System Chrome required; do not skip HTTPS viewer tests.')
    document = (ROOT/'_pages/index.html').read_text(encoding='utf-8')
    with tempfile.TemporaryDirectory() as temporary, sync_playwright() as pw:
        root = Path(temporary)
        browser = pw.chromium.launch(executable_path=executable, headless=True)
        context = browser.new_context(accept_downloads=True)
        requests, errors = [], []
        context.on('request', lambda req: requests.append(req.url))
        # Serve the built HTML as an HTTPS navigation without contacting the web.
        permitted = {URL, 'https://untrusted.invalid/', f'http://{OWNER.lower()}.github.io/{NAME}/', URL+'unexpected/'}
        def serve(route):
            if route.request.is_navigation_request() and route.request.url in permitted:
                route.fulfill(status=200, content_type='text/html; charset=utf-8', body=document)
            else:
                route.abort()
        context.route('**/*', serve)
        page = context.new_page()
        page.on('pageerror', lambda err: errors.append(str(err)))
        page.goto(URL+f'#run={RUN}&attempt=1&sha={SHA}')
        expect(page.locator('#app')).to_be_visible()
        expect(page.locator('#run-url')).to_have_value(f'https://github.com/{REPO}/actions/runs/{RUN}')
        expect(page.locator('#expected-sha')).to_have_value(SHA)
        with page.expect_download() as saved:
            page.locator('#generate').click()
        identity = root/'identity.txt'
        saved.value.save_as(identity)
        public_key = subprocess.check_output(['age-keygen', '-y', str(identity)], text=True).strip()
        expect(page.locator('#recipient')).to_have_value(public_key)
        assert 'AGE-SECRET-KEY-1' not in page.locator('body').inner_text()
        # Reuse the same saved identity, not a new website-specific key.
        page.locator('#clear').click()
        page.locator('#identity').set_input_files(identity)
        expect(page.locator('#recipient')).to_have_value(public_key)
        bundle = {'format':'security-review.age-bundle.v1', 'provenance':{
            'repository':REPO, 'run_id':RUN, 'run_attempt':'1', 'workflow_commit':SHA,
            'kind':'probe', 'step_outcome':'success',
            'recipient_sha256':hashlib.sha256(public_key.encode()).hexdigest()},
            'summary_json':json.dumps({'schema_version':1, 'status':'recovery_probe', 'api_calls':0}),
            'summary_markdown':'Recovery succeeded'}
        cipher = subprocess.run(['age', '--encrypt', '--recipient', public_key], input=json.dumps(bundle).encode(), capture_output=True, check=True).stdout
        archive = root/f'encrypted-review-{RUN}-1.zip'
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as z:
            z.writestr('report.json.age', cipher)
        page.locator('#cipher').set_input_files(archive)
        page.locator('#open-report').click()
        expect(page.locator('#result-title')).to_have_text('回収テストに成功しました')
        expect(page.locator('#result')).to_be_visible()
        assert requests == [URL], 'Unexpected networking after document navigation'
        assert page.evaluate('localStorage.length') == 0
        assert page.evaluate('sessionStorage.length') == 0
        assert not errors, errors
        # Incorrect hosts, insecure HTTP and incorrect paths must never accept keys.
        for invalid in permitted - {URL}:
            rejected = context.new_page()
            rejected.goto(invalid)
            expect(rejected.locator('#app')).to_be_hidden()
            expect(rejected.locator('#fatal')).to_be_visible()
            rejected.close()
        browser.close()
    print('HTTPS viewer passed: fixed origin/path, deep link, existing identity, native-age ZIP recovery, no extra requests/storage; HTTP/foreign hosts rejected.')


if __name__ == '__main__':
    main()
