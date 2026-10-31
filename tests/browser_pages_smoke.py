"""Test the hosted entry point without keys or network credentials."""
import os
from pathlib import Path
import shutil
from playwright.sync_api import sync_playwright, expect

ROOT=Path(__file__).resolve().parents[1]
REPO=os.environ.get('GITHUB_REPOSITORY','usedhonda/security-review')
OWNER,NAME=REPO.split('/')
URL=f'https://{OWNER.lower()}.github.io/{NAME}/'


def main():
    chrome=shutil.which('google-chrome') or shutil.which('chromium')
    if not chrome:raise SystemExit('Chrome required; do not skip tests.')
    document=(ROOT/'_pages/index.html').read_text()
    with sync_playwright() as pw:
        browser=pw.chromium.launch(executable_path=chrome,headless=True)
        context=browser.new_context();requests=[]
        context.on('request',lambda req:requests.append(req.url))
        def serve(route):
            if route.request.is_navigation_request() and route.request.url==URL:
                route.fulfill(status=200,content_type='text/html; charset=utf-8',body=document)
            else:route.abort()
        context.route('**/*',serve)
        page=context.new_page();page.goto(URL)
        expect(page.locator('#start')).to_have_attribute('href',f'https://github.com/{REPO}/actions/workflows/account-review.yml')
        expect(page.locator('#results')).to_have_attribute('href',f'https://github.com/{REPO}/security/code-scanning')
        assert page.locator('input,textarea,script,iframe').count()==0
        assert page.evaluate('localStorage.length')==0
        assert page.evaluate('sessionStorage.length')==0
        assert requests==[URL],requests
        browser.close()
    print('Entry point passed: exact start/result links, no key inputs, no scripts/storage or extra requests.')


if __name__=='__main__':main()
