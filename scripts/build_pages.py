#!/usr/bin/env python3
"""Build a small static launch page; no keys, report uploads or client-side crypto."""
from __future__ import annotations
import argparse
import base64
import hashlib
import html
import os
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
STYLE='''body{margin:0;background:#f5f7fa;color:#172b3d;font:16px/1.8 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{max-width:820px;margin:auto;padding:55px 24px}h1{font-size:34px;line-height:1.4}h2{font-size:22px}.lead{font-size:19px}.actions{display:flex;gap:16px;flex-wrap:wrap;margin:30px 0}.button{display:inline-block;padding:16px 24px;border-radius:10px;background:#173d59;color:#fff;font-weight:700;text-decoration:none}.secondary{background:#fff;color:#173d59;border:1px solid #b7c9d7}section{background:#fff;border:1px solid #dce4ec;border-radius:12px;padding:24px;margin:20px 0}.note{color:#4d6273;font-size:14px}.label{font-size:13px;letter-spacing:.1em}.warning{border-left:4px solid #bb861e;padding:12px 18px;background:#fff7e5}a{color:#175d92}code{overflow-wrap:anywhere}footer{font-size:13px;margin-top:30px}@media(max-width:600px){h1{font-size:27px}.button{width:100%;text-align:center}main{padding:30px 18px}}'''


def build(repository):
    if not re.fullmatch(r'[A-Za-z0-9-]+/[A-Za-z0-9_.-]+',repository) or repository.split('/')[1] in ('.','..'):
        raise ValueError('Invalid repository')
    repo=html.escape(repository,quote=True)
    base='https://github.com/'+repo
    style_hash=base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode()
    policy="default-src 'none'; script-src 'none'; connect-src 'none'; style-src 'sha256-"+style_hash+"'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'"
    return f'''<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="{policy}"><title>Security Review — 開始と結果</title><style>{STYLE}</style></head><body><main>
<div class="label">SECURITY REVIEW · 公開試験版</div><h1>自分の公開リポジトリを、<br>まとめてレビュー。</h1><p class="lead">リポジトリの選択は自動。結果はGitHubのSecurity画面に集約します。</p>
<div class="actions"><a id="start" class="button" href="{base}/actions/workflows/account-review.yml">チェックを始める</a><a id="results" class="button secondary" href="{base}/security/code-scanning">結果を読む</a></div>
<section><h2>登録済みなら、開始するだけ</h2><p>「チェックを始める」でGitHubを開き、<strong>Run workflow → 緑色のRun workflow</strong>を押します。鍵の作成、復号テスト、ZIPのダウンロード、リポジトリの選び直しは不要です。</p><p>終了後は「結果を読む」へ。GitHubにログインし、このリポジトリのセキュリティ結果を閲覧できる権限が必要です。</p><p class="note">実行先：<code>{repo}</code>。誰でもこの所有者のAPIを使える公開サービスではありません。</p></section>
<section><h2>どこまでチェックする？</h2><p>所有者の公開リポジトリを毎回取得します。Fork・アーカイブ・中央ツール自身を除き、未確認のものを優先して<strong>1回最大3件</strong>を選びます。前回と同じコードの確認済み対象はスキップします。</p><p><strong>各件最大16ファイル・160 KBの選択レビュー</strong>です。アカウント内の全ファイルを一度で監査するものではありません。今回の対象と未実施分は実行結果に表示します。</p><p>AIは<code>gpt-6.1-sol</code>。1回合計の見積予算は<strong>1 USD以内</strong>、自動再試行はありません。新しいリポジトリも自動取得します。</p></section>
<div class="warning"><strong>AIレビューは実 API での通し検証前です。</strong>初回は実行状態と費用を確認してください。失敗・未実施を「問題なし」とは扱いません。</div>
<section><h2>初めて使う方だけ</h2><p>自分の中央リポジトリのActions Secretに<code>OPENAI_API_KEY</code>を登録します。すでに保存した方は作り直さず、利用できないと表示された場合だけ保存先・名前・適用範囲を確認します。</p><p>他の方は自分のForkで利用し、自分のAPI利用分を負担します。追加のGitHub PATや全リポジトリへの書き込み許可は使いません。</p><p class="note">このページはキーを入力・保存する画面ではありません。APIキーや秘密鍵を貼り付ける欄はありません。</p></section>
<footer><a href="{base}">README・制限事項</a> · <a href="{base}/blob/main/docs/ACCOUNT_REVIEW.md">設計と運用</a><p>公開ページに詳細レポートは保存しません。GitHub runnerとOpenAIはレビュー中に平文を処理します。中央リポジトリの権限管理が結果の閲覧範囲になります。旧暗号化機能は任意の別経路として残ります。</p></footer>
</main></body></html>'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository',default=os.environ.get('GITHUB_REPOSITORY','usedhonda/security-review'))
    args=parser.parse_args()
    # Keep the existing offline helper available to its separate test/build flow.
    import runpy
    runpy.run_path(str(ROOT/'scripts/build_browser_helper.py'),run_name='__main__')
    destination=ROOT/'_pages';destination.mkdir(exist_ok=False)
    (destination/'index.html').write_text(build(args.repository),encoding='utf-8')
    (destination/'robots.txt').write_text('User-agent: *\nDisallow: /\n')
    (destination/'.nojekyll').write_text('')
    assert {p.name for p in destination.iterdir()}=={'index.html','robots.txt','.nojekyll'}
    print('Built the static launch page; no keys, reports or scripts included.')


if __name__=='__main__':main()
