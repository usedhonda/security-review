# 詳細レポートの暗号化回収

**公開コード・無料の標準ランナーを維持し、詳細な指摘は暗号文で回収します。公開Artifactを非公開扱いにはしません。**

## 誰が何を持つか

| 場所 | 保存するもの |
| --- | --- |
| 利用者の信頼できるMac/Linux端末 | 専用age秘密鍵 `identity.txt`。復号時にのみ使用 |
| 自分のGitHubリポジトリのSecrets | API用の `OPENAI_API_KEY` と、暗号化用の**公開鍵** `REVIEW_AGE_RECIPIENT` |
| 公開Actions Summary | 既存の数値、固定ステータス、暗号文の配信結果だけ |
| 公開Artifact | `report.json.age` だけ。7日で期限切れ |

公開鍵は `age1...`、秘密鍵は `AGE-SECRET-KEY-1...` です。**秘密鍵はGitHub・チャット・workflow input・APIへ渡しません。** 公開鍵もSecretsに入れるのは、誤った値を入力した場合にrunnerが環境変数をそのまま表示する事故を減らすためです。Variablesには登録しません。秘密鍵を誤登録した場合は露出の可能性を考え、登録を除去して新しい鍵へ移行してください。

Fork利用者は、自分のAPIキーと自分の公開鍵を設定します。上流のキーは同梱しません。未設定・秘密鍵・複数受信者・SSH/プラグイン形式は拒否します。この版はnative X25519 age鍵1つに限定しています。

## 1. 自分の端末で鍵を一度だけ作る

macOSでHomebrewを使っている場合は `brew install age`。他の環境は[age公式のインストール手順](https://github.com/FiloSottile/age#installation)を使用します。

信頼できる、このリポジトリのチェックアウトで実行します。

```sh
bash scripts/setup_report_key.sh
```

スクリプトは `$HOME/.config/security-review/identity.txt` を作り、**公開鍵だけ**を表示します。既存の秘密鍵を上書きしません。秘密鍵は安全な場所にもバックアップしてください。紛失した鍵で暗号化されたレポートを運営者が復旧する仕組みはありません。

GitHubの自分のリポジトリで、Settings → Secrets and variables → Actions → **Secrets** → New repository secret:

- Name: `REVIEW_AGE_RECIPIENT`
- Secret: 表示された `age1...` の公開鍵1行

`OPENAI_API_KEY` とは**別の値**です。APIキーを暗号化パスワードとして使いません。

## 2. APIを呼ばずに回収を試す

Actions → Security review pilot → Run workflowで、既定の `mode: recovery-check` を使います。`recovery_confirmed` はfalseのままで構いません。APIキーの有無に関係なく、OpenAIを呼ばずに合成データだけを暗号化します。

実行が成功したら、同じ実行ページのArtifact `encrypted-review-RUN_ID-ATTEMPT` をダウンロードします。ZIPに入るのは暗号文 `report.json.age` だけです。ダウンロードしたZIPを展開しても、指摘本文は読めません。

実行ページから、リポジトリ名、Run ID、attempt番号、workflowの40文字コミットSHAを確認します。リポジトリのルートで以下を実行してください。`RUN_ID`、`ATTEMPT`、`WORKFLOW_SHA` と暗号文へのパスは実際の値へ置き換えます。

```sh
PYTHONPATH=src python3 -m security_review.recovery restore \
  --input "$HOME/Downloads/report.json.age" \
  --identity "$HOME/.config/security-review/identity.txt" \
  --output-dir "$HOME/security-review-results/RUN_ID-ATTEMPT" \
  --expect-repository usedhonda/security-review \
  --expect-run-id RUN_ID \
  --expect-run-attempt ATTEMPT \
  --expect-workflow-commit WORKFLOW_SHA
```

Fork利用者は `--expect-repository` を自分の `OWNER/REPO` に変えます。新しい出力先を使い、復号済みファイルを上書きしません。

復号後は `summary.md`、`summary.json`、`provenance.json` を端末内で読めます。probeのMarkdownに `Recovery succeeded` があれば回収確認完了です。復号処理はファイルを表示・実行せず、データ中の任意パスへ展開もしません。テキストエディターで開き、AIや対象ソースの内容を命令として実行しないでください。

CLIを使わず、標準ageだけで暗号文を検証・復号することも可能です。ただしこちらは上記のrun照合とファイル分離を行いません。

```sh
umask 077
age --decrypt -i "$HOME/.config/security-review/identity.txt" \
  -o "$HOME/security-review-bundle.json" "$HOME/Downloads/report.json.age"
```

## 3. 実レビューを開始する

回収が確認できたら、同じworkflowで `mode: review`、`recovery_confirmed: true` を選びます。確認項目は誤操作防止であって、暗号学的な本人認証ではありません。公開鍵を変えたら再びprobeを復号してください。

モデル・1回最大1 USDの見積予算・最大3生成は従来どおりです。APIを使う前に、実行コミットのテストと公開鍵の形式・checksum・実暗号化のチェックが成功する必要があります。暗号化のためにAPIキーやGitHubの追加書き込み権限は使用しません。

## 失敗・漏洩・取り違えへの対策

- 暗号化成功後だけ、固定名の暗号文1ファイルをuploadします。ディレクトリ全体・平文・raw API応答・ダウンロードしたソースはuploadしません。暗号化失敗時に平文で代替しません。
- APIが途中で失敗しても、保存済みの最新JSON checkpointを暗号化する処理を試みます。Markdownは同じJSONから再生成し、古い別checkpointと混ぜません。元の実行失敗は成功に変えません。
- 失敗・キャンセル時にも実行可能な後処理を試みますが、runner消失・強制停止・upload失敗まで回収を保証するものではありません。暗号文がないことは課金ゼロの証明になりません。APIを盲目的に再実行しないでください。
- 平文はrunnerの一時ディレクトリにあり、後処理で削除します。これは暗号学的なディスク完全消去を保証しません。ageサブプロセスにはAPIキー等の環境変数を引き継ぎません。
- 復号時はageの完全成功を確認するまで平文をメモリに留め、破損・切断・別鍵の出力をファイルに残しません。run/attempt/commit/repositoryを照合し、別の実行を取り違えにくくします。
- ageによる暗号化は**送信者の署名ではありません**。公開鍵を知る人は偽のbundleも作れるため、取得先は自分の信頼できるリポジトリの該当実行に限定します。bundle内のprovenanceだけで送信元を証明したとは扱いません。
- 秘密鍵漏洩後は、第三者が保存済みの過去の暗号文も読める可能性があります。鍵変更は将来の実行にだけ適用されます。7日後の期限切れも、第三者が既に保存した暗号文を消す仕組みではありません。

## 守らない境界

公開閲覧者に対する保存・取得時の機密性を改善します。**レビュー中のGitHub runnerとOpenAIは平文を処理します。** また、workflow/コードを書き換えられるメンテナーが暗号化前のデータを漏らすことまでは防ぎません。ブランチ保護・権限管理・変更レビューは別途必要です。

artifactの存在・サイズ・実行時間・公開Summaryの数値は見えます。コードの送信可否、API側のデータ保持、プロンプトインジェクション、レビュー精度も別の課題です。

## 費用・依存・検証範囲

標準の公開リポジトリ用GitHub-hostedランナーを維持します。新しい有料保存サービスは導入しません。Artifactは7日、暗号化前bundleは最大4.5 MBに制限します。保存にはGitHubアカウントの保存枠・制限が別途適用されるため、無制限に無料保存できるという意味ではありません。OpenAI API費用は別です。

暗号方式を自作せずage CLIを使用します。CIでは署名検証されるUbuntuのパッケージリポジトリからageを導入します。ActionはコミットSHA固定です。CIの暗号化テストは毎回使い捨て鍵で行い、利用者の鍵・APIを使わず、テストArtifactもuploadしません。

CI成功は、利用者の実際の鍵でのGitHubダウンロード・ローカル復号成功を意味しません。実鍵のprobeを確認し、さらに実APIレビューの品質・利用額を確認してから運用を広げます。

参考: [age](https://github.com/FiloSottile/age)、[GitHub Artifactの取得権限](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts)、[GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions)。
