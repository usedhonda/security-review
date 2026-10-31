#!/usr/bin/env python3
"""Build a key-free HTTPS viewer from the verified offline helper.

Only the generated viewer, robots.txt and .nojekyll enter the publishing folder.
The original offline build is kept as a fixed, downloadable fallback.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import html
import json
import os
from pathlib import Path
import re
import runpy

ROOT = Path(__file__).resolve().parents[1]


def replace_once(text: str, before: str, after: str) -> str:
    if text.count(before) != 1:
        raise ValueError('Viewer template changed; review the hosted transformation.')
    return text.replace(before, after, 1)


def compile_hosted(offline: str, repository: str) -> str:
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}', repository):
        raise ValueError('Expected a GitHub owner/repository.')
    owner, name = repository.split('/')
    if name in ('.', '..'):
        raise ValueError('Invalid repository name.')
    origin = 'https://' + owner.lower() + '.github.io'
    path = '/' + name + '/'
    # Do not enable arbitrary websites or insecure HTTP. Preserve file: fallback.
    allowed = '(location.protocol===\'file:\'||(location.origin===' + json.dumps(origin) + '&&' + json.dumps([path, path+'index.html']) + '.includes(location.pathname)))'
    output = replace_once(offline, "location.protocol!=='file:'", '!' + allowed + '||window.top!==window')
    output = replace_once(output,
        'このHTMLを端末に保存し、Chromeでダブルクリックして開いてください。チャット内のプレビューやWebサイト上ではキーを読み込みません。',
        '正規のHTTPSページ、または保存済みHTMLをChromeで直接開いてください。埋め込み画面や別のサイトではキーを読み込みません。')
    output = replace_once(output, 'SECURITY REVIEW / LOCAL HELPER', 'SECURITY REVIEW / REPORT VIEWER')
    output = replace_once(output,
        'ターミナル・アプリのインストールは不要です。保存したこのHTMLをChromeで開いて使います。',
        'このページをブックマークするだけ。HTMLの保存やアプリのインストールは不要です。')
    output = replace_once(output,
        '初回だけ、ボタンを押してキーのファイルを保存します。すでにキーがあれば、下でそのファイルを選んでください。',
        '登録済みの方は、保存した読み取りキーを下で選び、そのまま③へ進んでください。キーの作り直し・GitHubへの再登録は不要です。初めての方だけキーを作成します。')
    output = replace_once(output, 'value="usedhonda/security-review"', 'value="' + html.escape(repository, quote=True) + '"')
    output = replace_once(output,
        '秘密鍵・レポートを送信する機能、アクセス解析、外部スクリプト読込、ブラウザへの永続保存はありません。GitHubを開く操作だけは別タブへ移動します。GitHubとOpenAIはレビュー中に平文を処理します。この画面は信頼できる配布元から取得してください。',
        'ページを開く際はGitHub Pagesへ通信しますが、選んだキー・ZIP・復号結果を送信する機能はありません。処理はブラウザ内だけで行い、外部スクリプト・アクセス解析・永続保存は使いません。GitHubリンクは別タブで開きます。サイトの配信コードとブラウザ拡張を信頼する必要があります。厳格な運用では、検証済みのオフライン版をご利用ください。GitHub runnerとOpenAIはレビュー中に平文を処理します。')
    # Public run information only. Fragment values never go in an HTTP request.
    initialization = '''  try {
    const p=new URLSearchParams(location.hash.slice(1));
    const run=p.get('run'), attempt=p.get('attempt')||'1', sha=p.get('sha')||'';
    if(location.hash.length<=256 && [...p.keys()].every(k=>['run','attempt','sha'].includes(k)) && ['run','attempt','sha'].every(k=>p.getAll(k).length<=1) && /^[1-9][0-9]{0,19}$/.test(run||'') && /^[1-9][0-9]{0,9}$/.test(attempt) && (!sha||/^[a-f0-9]{40}$/.test(sha))) {
      $('run-url').value='https://github.com/'+$('repository').value+'/actions/runs/'+run;
      $('attempt').value=attempt;$('expected-sha').value=sha;
    }
  } catch { /* Invalid links leave the manual run fields empty. */ }
  repoLinks();refresh();'''
    output = replace_once(output, '  repoLinks();refresh();', initialization)
    def digest(value: str) -> str:
        return "'sha256-" + base64.b64encode(hashlib.sha256(value.encode()).digest()).decode() + "'"
    scripts = re.findall(r'<script>(.*?)</script>', output, re.S)
    styles = re.findall(r'<style>(.*?)</style>', output, re.S)
    if len(scripts) != 2 or len(styles) != 1:
        raise ValueError('Unexpected inline resources.')
    csp = "default-src 'none'; connect-src 'none'; script-src " + ' '.join(map(digest, scripts))
    csp += '; style-src ' + digest(styles[0]) + "; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'; worker-src 'none'; media-src 'none'"
    output, count = re.subn(r'(<meta http-equiv="Content-Security-Policy" content=")[^"]*(">)', lambda m: m[1]+csp+m[2], output)
    if count != 1 or re.search(r'<(?:script|link)[^>]*(?:src|href)=', output, re.I):
        raise ValueError('Unexpected resources or CSP.')
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY', 'usedhonda/security-review'))
    args = parser.parse_args()
    runpy.run_path(str(ROOT/'scripts/build_browser_helper.py'), run_name='__main__')
    output = compile_hosted((ROOT/'dist/security-review.html').read_text(encoding='utf-8'), args.repository)
    destination = ROOT/'_pages'
    destination.mkdir(exist_ok=False)  # Refuse stale / additional files.
    (destination/'index.html').write_text(output, encoding='utf-8')
    (destination/'.nojekyll').write_text('')
    (destination/'robots.txt').write_text('User-agent: *\nDisallow: /\n')
    if set(p.name for p in destination.iterdir()) != {'index.html', '.nojekyll', 'robots.txt'}:
        raise ValueError('Unexpected publishing files.')
    print('Built HTTPS viewer. No keys, reports or API credentials are included.')


if __name__ == '__main__':
    main()
