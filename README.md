# security-review

**公開GitHubコードをAIでレビューし、コード量・指摘の品質・API費用を小さく実測するツールです。**

公開試験版です。自動PRレビュー製品や安全性の保証ではありません。対象はmanifestに明記した公開ファイルだけで、リポジトリ全体の監査ではありません。

## はじめに — 迷ったらここから

**料金と鍵の原則：ツールは公開・無料、実際のAIレビューを実行する利用者は各自のOpenAI APIキーでAPI料金を負担します。** Web画面の閲覧・レポートのローカル復号・APIを使わない回収テストにはOpenAI APIキーは不要です。Forkの有無ではなく、AIを実行するかどうかで区別します。上流の `usedhonda` のキーは他人への共用サービスではありません。


**[Webアプリを開く](https://usedhonda.github.io/security-review/)** · **[回収テストを実行する](https://github.com/usedhonda/security-review/actions/workflows/benchmark.yml)** · **[実行履歴を見る](https://github.com/usedhonda/security-review/actions/workflows/benchmark.yml)**

> このリポジトリは**公開試験版**です。対象は設定ファイルに記載した公開コードで、全体監査やPR自動レビューではありません。GitHub Actionsの標準公開ランナーは無料ですが、実際のOpenAI API呼び出しは別に費用が発生します。

| 利用状況 | 最初にすること |
| --- | --- |
| **はじめての方** | [Webアプリ](https://usedhonda.github.io/security-review/)で「読み取りキーを作って保存」→ 表示される公開の登録コードをGitHub Actions Secret `REVIEW_AGE_RECIPIENT` に一度登録 |
| **キー登録まで終わった方** | [Security review pilot](https://github.com/usedhonda/security-review/actions/workflows/benchmark.yml) の「Run workflow」から `recovery-check` を実行（API費用なし） |
| **回収テストが終わった方** | GitHub実行画面から暗号化ZIPを保存 → [Webアプリ](https://usedhonda.github.io/security-review/)で保存済みの読み取りキーとZIPを選ぶ。実行ページURLは実行結果に記載のリンクから開けば自動入力可能 |
| **本番相当のAIレビューを試す方** | 自分の `OPENAI_API_KEY` をActions Secretに登録して、回収確認後に `mode: review` を手動選択（1回の上限見積1 USD、最大3生成） |
| **自分でAIレビューを実行するすべての方** | Forkの有無にかかわらず、原則として自分のOpenAI APIキーと利用予算が必要です。自分のGitHubリポジトリに `OPENAI_API_KEY` を登録します。詳細結果を回収する場合は自分の復号鍵の公開部分を `REVIEW_AGE_RECIPIENT` に登録します。Forkには上流のSecretsは引き継がれません |

**秘密鍵（読み取りキーファイル）はGitHub・Gist・チャットへアップロードしないでください。** Web画面へのアクセスには通信が発生しますが、鍵や復号済みの詳細はアプリから送信しない設計です。より厳密に配布コードを固定したい場合は[オフライン版](docs/BROWSER_HELPER.md)を使用してください。安全性と制約は[こちら](docs/HOSTED_VIEWER.md)を参照してください。

## まずはURLで開く

**[レポート画面](https://usedhonda.github.io/security-review/)** をブックマークして使います。HTMLを毎回保存する必要はありません。初回の公開には **Settings → Pages → Source → GitHub Actions** の設定と、**Report viewer website** のdeploy成功が必要です。まだ開けない場合は[公開手順](docs/HOSTED_VIEWER.md)を確認してください。Forkでは自分の `https://OWNER.github.io/REPOSITORY/` を使用します。

**すでに登録済みの方：保存した読み取りキーとレポートのZIPを選ぶだけです。キーの作り直し・GitHubへの再登録は不要です。** 実行情報入りリンクから開けば実行ページURLも自動入力されます。通常のリンクから開いた場合は、GitHubの実行ページURLを貼ってください。

初めて使う方だけ、画面の「読み取りキーを作って保存」を押し、案内に従って公開の登録コードを自分のGitHubへ `REVIEW_AGE_RECIPIENT` として登録します。キー本体をGitHubやチャットへアップロードしないでください。

画面取得時はGitHub Pagesへ通信しますが、キー・ZIP・復号結果はアプリから送信せず、ブラウザ内で処理します。Web版は、その時点でサイトから配信されるコードを信頼する必要があります。より厳格な運用には、従来のオフラインHTMLも残しています。

オフライン版は、Actionsの **Offline browser helper → mainの成功した実行 → offline-browser-helper** を保存・展開し、`security-review.html` をChromeで開きます。

[URL版の公開・利用・信頼条件](docs/HOSTED_VIEWER.md) / [オフライン画面操作](docs/BROWSER_HELPER.md) / [暗号化の設計・CLI手順](docs/ENCRYPTED_RECOVERY.md)

## 回収テスト → 実レビュー

**Security review pilot** は手動実行だけです。

最初は既定の **recovery-check** でテスト用レポートを作ります。OpenAI APIは呼ばず、APIキーも不要です。実行ページのArtifact `encrypted-review-…` を保存し、画面で読み取りキー、ZIP、実行ページURLを指定して開いてください。番号や長いコマンドの入力は不要です。

自分のキーで「回収テストに成功しました」と表示されたら、同じworkflowで **mode: review / recovery_confirmed: true** を選びます。専用のOpenAI APIキーを自分のリポジトリのActions Secret `OPENAI_API_KEY` に登録しておく必要があります。上流リポジトリのAPIキー・SecretsはForkへ引き継がれません。

**公開されるのは費用等の計測値と暗号文です。詳細な指摘は、URL版の画面・ローカルHTML・CLIで端末内に復号して読みます。** 生の指摘本文・取得ソース・秘密鍵を公開Artifactに置きません。

## 実測の対象と費用

初期manifest `benchmarks/pilot.json` は固定コミットから選択した次の3組です。

| 対象 | 選択ファイル数 | 選択ソース量 |
| --- | ---: | ---: |
| usedhonda/statusline | 3 | 6,190 bytes |
| usedhonda/muse-agent-bridge | 7 | 51,074 bytes |
| usedhonda/openclaw-artist-runtime | 8 | 137,577 bytes |

モデルは `gpt-6.1-sol`、手動で `gpt-6-astra` も選択可能です。**1回の実行につき見積予算1 USD以下、最大3生成、自動再試行なし**です。生成前に公式入力トークン数と最大出力料金で予約します。価格は記録済みの公表単価に基づく見積もりで、請求書やクレジット残高ではありません。

公開リポジトリの標準 `ubuntu-24.04` runnerを使用します。Actions実行とOpenAI APIは別の費用です。利用可能なAPIクレジットの有効化・残高・適用範囲は本人のOpenAIアカウントで確認してください。Artifactの保持・保存枠にもGitHubの条件が適用されます。無制限の無料保存やAPI無料利用を保証するツールではありません。

アプリの上限は**1回単位**で、月間・アカウント全体の予算ではありません。失敗やタイムアウトで使用量が不明なら未解決の予約額を残し、後続を止めます。不明をゼロや安全と扱わず、盲目的に再実行しないでください。

## 現状と安全性

通常のpush/PRではAPIを呼ばずテストと画面のビルドを行い、mainの画面変更はPagesへ配信します。対象コードを実行せず、固定コミット・ハッシュを検証してテキストとして送ります。選択範囲の欠落、読み取り先の不正、課金条件不明などでは処理を止めます。プロンプトインジェクションや秘匿化対策はbest effortです。

暗号化はage。秘密鍵は端末に残し、公開Artifactには固定名の暗号文だけを保存します。配信失敗やrunner消失時の回収までは保証しません。暗号化は、レビュー中に平文を処理するGitHub runner/OpenAIや、コードを書き換えられる管理者からの保護ではありません。ブランチ保護・権限管理も必要です。

**テスト成功は、本人の実鍵でのGitHub回収や実APIレビュー成功を意味しません。** まず自分の鍵で回収を確認し、その後に実際の品質・費用を評価してください。PR自動実行・PRコメント・再利用workflow・月次予算管理はまだ未実装です。

[セキュリティ方針](SECURITY.md) / [実装修正の記録](docs/SECURITY_AUDIT.md)

## 開発者向けCLI

Python 3.11以上。基本部分は標準ライブラリ、暗号化回収にはage CLIを使用します。

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/fetch_cases.py --manifest benchmarks/pilot.json
PYTHONPATH=src python3 -m security_review plan --manifest benchmarks/pilot.json --output-dir reports/plan-001
```

`plan` はAPIなしの規模見積もりです。実レビューは、専用キーを環境変数に安全に設定した上で `plan` を `run` に変更し、`--model gpt-6.1-sol --max-cost-usd 1.00 --max-calls 3` を指定します。APIキーをコードやシェル履歴へ書かないでください。既存出力の再利用は拒否します。

| パス | 内容 |
| --- | --- |
| src/security_review/ | 入力検証・API・予算・レポート・暗号化回収 |
| web/recovery.html | 画面のビルド前ソース |
| scripts/build_browser_helper.py | SHA固定のageライブラリを内蔵するオフラインHTMLビルド |
| scripts/build_pages.py | 許可したHTTPS配信先向けの画面ビルド |
| benchmarks/pilot.json | 固定コミット・ファイル選択 |
| tests/ | オフライン・暗号化・ブラウザ検証 |

## License

MIT。対象コードは各リポジトリのライセンスに従い、ソースを同梱しません。ブラウザ用Typageと依存ライブラリのライセンスは配布HTMLに同梱します。
