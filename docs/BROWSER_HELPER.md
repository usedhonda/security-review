# ターミナルなしで設定・レポート確認

`security-review.html` をMacに保存してChromeで開く方式です。brew、Python、ageのインストールや長いコマンドは利用者に不要です。**キーは利用者のブラウザで初めて作成されます。配布HTMLやビルド成果物に誰かのキーは入っていません。**

## 最初の一度

1. `Offline browser helper` のmainで成功した実行から `offline-browser-helper` を保存・展開し、中の `security-review.html` をChromeで開きます。チャットで同じビルド済みHTMLが渡された場合は、それを保存して開けます。`web/recovery.html` はビルド前のソースなので直接使いません。
2. 「読み取りキーを作って保存」を押します。ダウンロードされた `security-review-key-….txt` を安全に保管します。既存のnative age鍵も読み込めます。ブラウザを閉じたらキーは次回選び直します。
3. 画面の「GitHubの登録画面を開く」で、自分のリポジトリのActions Secretへ、Nameと登録コードをコピーします。Nameは `REVIEW_AGE_RECIPIENT`。**渡すのは公開鍵です。秘密鍵ファイルではありません。** OpenAIのキーは既存の `OPENAI_API_KEY` のままです。

登録後は画面の「登録後のテストはどうする？」にあるボタンから `recovery-check` を実行します。これはAPI費用を使いません。テストを自分の鍵で読めたら `review` と `recovery_confirmed` を使います。

## レポートを読む

同じHTMLを開き、保存した読み取りキー、GitHubからのZIP（または展開済み `report.json.age`）、ダウンロード元の実行ページURLを指定して「レポートを開く」を押します。通常はRun ID、コミットSHA、コマンドの入力は不要です。再実行時のattemptは標準ZIP名かURLから取得し、必要なら詳細設定で直せます。

URLは通信に使いません。リポジトリ・Run ID・attemptを照合します。暗号文内の公開鍵fingerprintも読み込んだキーと照合します。workflow SHAは画面に表示し、追加照合用の入力もあります。CLIの厳密なSHA照合は引き続き利用できます。

## 安全性の境界

- HTMLはローカルの `file:` でのみ動作します。暗号化ライブラリを内蔵し、通信・外部リソース・フォーム送信をCSPで禁止します。GitHubへのリンクだけは利用者が別タブで開きます。
- 秘密鍵をlocalStorage、sessionStorage、URL、ログ、clipboardへ保存・転送しません。保存ボタンは利用者の端末へ秘密鍵ファイルをダウンロードします。ファイルを失うと復号できず、他人に渡すと過去の暗号文を読まれる可能性があります。
- キーを作っただけではGitHub登録やバックアップが完了したことにはなりません。ダウンロードの保存先を確認してください。
- ageの公式TypeScript実装Typageを固定バージョン・SHA-256で検証して同梱します。暗号プリミティブは自作しません。ブラウザ用の小さなZIP読み取りは固定名1ファイル・サイズ制限・CRC検証を行い、任意パスへ展開しません。ZIP64、複数ファイル、未知の形式は拒否します。
- 復号が完全成功し、形式と実行情報が一致するまで内容を表示しません。モデルの文章は `textContent` だけで描画し、HTML・画像・リンク・コードとして解釈しません。
- ageは送信者署名ではありません。実行URLとの照合は取り違え対策であって、偽造されたbundleの送信者認証ではありません。取得先は自分の信頼するGitHub実行に限定してください。
- 端末やブラウザ拡張・配布HTML・リポジトリ管理者が悪意を持つ場合まで守る仕組みではありません。GitHub runner/OpenAIによる平文処理も従来どおりです。

## 開発・検証

`python3 scripts/build_browser_helper.py` は、固定のupstream bundleを検証し、CSPのscript/style hashを計算して `dist/security-review.html` とSHA256SUMSを生成します。ブラウザUI用CIは利用者のキーやAPIを使わず、使い捨て鍵でnative ageとの互換性、ZIP、誤鍵、破損、実行取り違え、XSS、外部通信・永続保存の不在をテストします。キー・合成レポートはArtifactに含めません。

HTML配布物のArtifactは14日保持です。利用者の暗号化レポートの7日保持とは別です。一般公開のためのPages設定変更、新しい有料サービス、API自動実行は追加しません。

詳しい暗号化回収設計とCLI手順は [ENCRYPTED_RECOVERY.md](ENCRYPTED_RECOVERY.md) を参照してください。
