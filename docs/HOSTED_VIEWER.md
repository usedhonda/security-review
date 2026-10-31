# URLからレポート画面を開く

HTMLを毎回保存する必要はありません。GitHub Pagesへ画面だけを公開します。

## 初回だけ：Pagesを有効にする

リポジトリの **Settings → Pages → Build and deployment → Source** を **GitHub Actions** にします。

公開URLは `https://OWNER.github.io/REPOSITORY/` です。このリポジトリでは `https://usedhonda.github.io/security-review/`。**URLが使えるのは「Report viewer website」のdeployが成功した後です。** 設定前にdeployが失敗していた場合は、その実行の「Re-run failed jobs」を押します。新しいAPIキーや有料ホスティングは不要です。

## 普段の使い方

URLをブックマークし、保存済みの読み取りキーと暗号化レポートのZIPを選びます。作成済みのキー・`REVIEW_AGE_RECIPIENT`は変更不要です。キーを作り直さないでください。

通常はGitHubの実行ページURLを貼ります。公開の実行情報をリンクに添えると自動入力できます：

```text
https://OWNER.github.io/REPOSITORY/#run=RUN_ID&attempt=1&sha=40_HEX_COMMIT
```

`run`は必須、`attempt`と`sha`は任意です。このリンクにAPIキーや読み取りキーを含めないでください。リンクは実行の取り違え防止であり、送信者を暗号学的に認証するものではありません。

## 公開・送信しないもの

公開対象は、ビルドされた画面・robots.txt・.nojekyllだけです。ユーザーの秘密鍵・レポート・取得ソース・APIキーはデプロイに入りません。APIキーの入力欄もありません。

ページの取得にはGitHub Pagesへの通信が発生します。キー選択・ZIP読込・復号・表示はブラウザ内の処理で、アプリはこれらを送信しません。CSPはconnect-src 'none'、外部スクリプト/CDN/画像・worker等を許可しません。キーをブラウザの永続ストレージには保存しません。GitHubへのリンクを押すと別タブへ移動します。

## Web配信により増える信頼条件

固定URLは便利ですが、**その時点で配信されるコードを信頼する必要があります**。サイトやworkflowを変更できる人・侵害された配信元・悪意あるブラウザ拡張からキーを保護するものではありません。CSPのハッシュも、HTMLを書き換えられる管理者に対する署名ではありません。GitHub Pages上の同一オリジンの他サイトも信頼境界に含まれます。厳格な運用では、検証済みのオフラインHTMLを引き続き利用できます。

この版は、ビルドした所有者のHTTPS GitHub Pagesオリジンと対象リポジトリのパスだけで有効になります。HTTP・別サイト・iframeではキー入力画面を無効化します。カスタムドメインは未対応です。

デプロイはAPIレビューとは別の、秘密情報を渡さないworkflowです。PRではビルドとテストだけを行い、mainのみ公開します。Pages書込/OIDC権限はデプロイjobだけに限定し、そこでリポジトリのコードは実行しません。

参考：[GitHub Pagesの設定](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site)、[カスタムworkflow](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)。
