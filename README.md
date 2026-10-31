# security-review

**自分の公開リポジトリを自動で見つけ、AIレビューの結果をGitHubのSecurity画面で読むツールです。公開試験版です。**

## 使う場所は2つだけ

### [チェックを始める](https://github.com/usedhonda/security-review/actions/workflows/account-review.yml)

GitHubの **Run workflow → 緑色のRun workflow** を押します。対象は自動選択です。通常の操作に、読み取りキーの生成・回収テスト・ZIPのダウンロード・GitHub PATの発行はありません。

### [結果を読む](https://github.com/usedhonda/security-review/security/code-scanning)

終了後、**中央の `security-review` の Security → Code scanning** で読みます。対象リポジトリ側ではなく、この中央リポジトリに集約します。GitHubへのログインと、このリポジトリのセキュリティ結果を見る権限が必要です。

[ブックマーク用の入口](https://usedhonda.github.io/security-review/)

## すでに設定した方

既存の `OPENAI_API_KEY` を使用します。APIキー・読み取りキーの作り直しは不要です。ただし、実行時にAPIキーが利用できないと表示された場合は、保存先・名前・適用範囲の確認が必要です。暗号化用のキー・Secretは残りますが、新しい標準手順では使用しません。

**2026-10-31の確認：** 中央の結果保存・認証付き読み出し・匿名APIアクセス拒否の実テストは成功しました。一方、そのActionsには `OPENAI_API_KEY` が空で渡されており、実APIレビューの完走はまだ確認できていません。「既にAIレビューまで動いた」という意味ではありません。

## 初めて使う方

この中央ツールを自分の公開リポジトリへFork/配置し、**自分の**OpenAI APIキーを `OPENAI_API_KEY` というRepository Actions Secretに一度登録します。Fork先のActionsを有効にし、**Review my public repositories** を実行してください。上の実行/結果リンクは作者のリポジトリ用なので、Forkでは自分のリポジトリのActionsとSecurityを開きます。自分のPagesを公開した場合は、その入口のリンクが自分用に生成されます。

作者のAPIキーを共用するサービスではありません。GitHub PATや全リポジトリへの書き込み許可は不要です。利用者ごとに自分のAPI利用料を負担します。

## チェック範囲と予算

公開・自分所有のリポジトリを毎回自動取得し、未確認のものを優先して**1回最大3件**を選びます。Fork、アーカイブ、中央ツール自身は対象外です。新しいリポジトリの個別登録は不要です。対象・除外・未実施をActionsのSummaryに表示します。

各件は**最大16ファイル・160 KBの選択レビュー**です。アカウント内の全ファイルを一度に監査するものではありません。認証・権限・外部入力などのファイル名を優先する限定的な選択方式です。前回と同じコミットで選択範囲のレビューが完了している対象はスキップします。

モデルは `gpt-6.1-sol`。1回合計の見積予算は**1 USD以内・最大3生成**です。APIの請求上限や月額上限ではありません。push/PRで有料AIは呼ばず、手動実行時だけ呼びます。API失敗時は自動再試行しません。標準公開runnerとOpenAI APIは別の料金体系です。

## 結果の安全性

詳細は中央のCode scanningへ送り、公開ログ・公開Artifact・PRコメントには出しません。原本のリポジトリ・コミット・ファイル位置は各アラート本文に記載します。集約用ドキュメントが表示上の位置になるため、対象ファイル上のネイティブな行内注釈や自動修正機能ではありません。

GitHub runnerとOpenAIは処理中に平文を扱います。中央リポジトリの管理者・書き込み権限・workflow変更管理は信頼境界です。配信失敗やrunner消失時の全文回収は保証しません。AIの指摘は仮説で、未実施・未完了・指摘ゼロは区別します。

[新しい方式の設計と制限](docs/ACCOUNT_REVIEW.md) / [Security方針](SECURITY.md)

## 以前の暗号化方式

既存のオフラインHTML・age鍵・`Security review pilot` は互換性のため残していますが、任意の旧方式です。新しい通常手順では使いません。旧ファイルや鍵を削除する必要はありません。[旧レポートの回収](docs/ENCRYPTED_RECOVERY.md)

## 開発

Python 3.11以上。既存の暗号化互換テストにはage CLIが必要です。

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

中核は `src/security_review/`、自動取得・中央配信は `scripts/account_review.py`、認証境界の合成テストは `scripts/hub_check.py` にあります。

MIT。対象コードは各リポジトリのライセンスに従います。
