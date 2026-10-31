# security-review

Bounded AI security-review experiments with encrypted report recovery.

公開GitHubコードを対象に、**コード量・指摘の品質・API利用額を小さく検証する**ための実験的なツールです。まだPR自動レビュー製品ではありません。指摘は人が検証する仮説であり、結果が空でも安全性の証明にはなりません。

## 最初はAPIなしで、安全に回収できることを確認

1. このリポジトリを自分のアカウントにForkし、Actionsを有効にします。標準hosted-runner用workflowは公開リポジトリでのみ実行します。
2. 信頼できる自分のMac/Linux端末でageを導入し、`bash scripts/setup_report_key.sh` を実行します。秘密鍵は端末に保存し、表示された**公開鍵だけ**を自分のリポジトリのActions Secret `REVIEW_AGE_RECIPIENT` に登録します。
3. Actions → **Security review pilot** → Run workflowを、既定の **`recovery-check`** で実行します。これはOpenAI APIを呼ばず、APIキーも不要です。
4. 実行ページから暗号文Artifactを取得して、自分の端末で復号します。詳しいコマンドと失敗時の扱いは **[暗号化回収ガイド](docs/ENCRYPTED_RECOVERY.md)** にあります。
5. 復号確認後、自分のOpenAI APIキーをActions Secret `OPENAI_API_KEY` に登録し、`mode: review` と `recovery_confirmed: true` を選びます。初期モデル・予算は `gpt-6.1-sol`、1回最大1 USDの見積予算です。

**自分のAPIキー＋自分の回収用公開鍵**を使う構成です。上流のキーを共有するサービスではありません。秘密鍵 `identity.txt` はGitHub、チャット、workflow inputに渡しません。公開鍵もSecretsへ登録するのは、入力ミス時のログ露出を抑えるためです。

## 結果はどこに残るか

| 情報 | 保存先 |
| --- | --- |
| コード量・トークン使用量・利用額・指摘件数 | 公開Actions Summary |
| 詳しい指摘・根拠・修正案 | **ageで暗号化したArtifact**。7日保持 |
| 復号したMarkdown/JSON | 利用者の端末だけ |
| 復号用秘密鍵 | 利用者の端末と安全なバックアップだけ |

公開Artifactは非公開ストレージではありません。第三者が暗号文を取得する可能性を前提にします。暗号化失敗時に平文で代替することはなく、raw API応答や取得ソースもuploadしません。暗号文のサイズや公開Summaryの数値は見えます。

API失敗後も、残っている最新JSON checkpointの暗号化を試みます。ただしrunner消失・強制停止・upload失敗時まで回収を保証しません。レポート未取得を課金ゼロや脆弱性ゼロとは扱いません。

## 比較する対象

`benchmarks/pilot.json` は、コミットSHAとファイルを明示した3つの公開サンプルです。**リポジトリ全体の監査ではありません。** Forkして別の対象をレビューする場合は、自分が送信してよい公開コードをmanifestに設定します。

| 対象 | 選択ファイル | ソース量 |
| --- | ---: | ---: |
| `usedhonda/statusline` | 3 | 6,190 bytes |
| `usedhonda/muse-agent-bridge` | 7 | 51,074 bytes |
| `usedhonda/openclaw-artist-runtime` | 8 | 137,577 bytes |

固定コミットの公開ソースを取得し、Git blob/SHA-256を確認します。取得コードの実行や依存ライブラリのインストールは行いません。欠けた選択範囲はAPIを呼ぶ前に拒否します。manifestは信頼できる設定としてレビューしてください。任意の第三者manifestを安全に実行するsandboxではありません。

## 費用と制限

公開リポジトリの標準 `ubuntu-24.04` runnerを使用します。新しい有料保存サービスは追加しません。暗号文Artifactは最大約4.51 MB/実行、保持7日で、GitHubアカウントの保存枠・制限に従います。**無制限の無料保存や、OpenAI APIが常に無料になることは保証しません。**

| 項目 | 設定 |
| --- | --- |
| API予算 | **1回につき最大1.00 USDの見積予算**。月額/アカウント全体の上限ではありません |
| 生成 | 最大3回、自動再試行なし |
| 出力 | 1生成あたり最大6,000 tokens（推論を含む） |
| 入力 | 最大128,000 tokens、生成前の公式token count必須 |
| API失敗/課金情報不明 | 予約額を維持して後続を停止。ゼロ円とは扱わない |
| 実行条件 | 既定ブランチ・手動のみ。回収確認の明示が必要 |
| モデルのツール/応答保存 | ツールなし、`store: false` |

料金表は日付付きの公表単価です。API応答のモデル・サービス区分・推論モード・usageを確認し、費用を計算します。公表単価からの利用額であり、請求額やクレジット残高の実測ではありません。サービス側の予算設定・クレジット適用は利用者が別途確認してください。`store: false` もAPI提供元のすべてのログ保持をゼロにする保証ではありません。

## ローカル実行

コアはPython 3.11+の標準ライブラリのみです。暗号化回収には別途age CLIが必要です。CIはageをインストールし、実際の暗号化/復号テストを必須にします。

```sh
# APIなしのテスト
PYTHONPATH=src python3 -m unittest discover -s tests -v

# 固定した公開ソースの取得（GitHubへの通信あり）
python3 scripts/fetch_cases.py --manifest benchmarks/pilot.json

# APIなしの規模見積もり
PYTHONPATH=src python3 -m security_review plan \
  --manifest benchmarks/pilot.json --output-dir reports/plan-001

# APIキーを環境変数へ安全に設定した後の実レビュー
PYTHONPATH=src python3 -m security_review run \
  --manifest benchmarks/pilot.json --output-dir reports/pilot-001 \
  --model gpt-6.1-sol --max-cost-usd 1.00 --max-calls 3
```

ローカルCLIの完全レポートは `summary.json` / `summary.md` です。出力先の再利用は拒否します。`planned` はAPI未実行、`completed` は選択範囲の処理完了であって「安全」の意味ではありません。未知のusage/費用は `null` / `unknown` です。

## 信頼境界と開発状況

暗号化は公開閲覧者から保存済み指摘を守るためのものです。**GitHub runnerとOpenAIはレビュー中に平文を処理します。** workflowを書き換えられるメンテナーの悪意や、秘密鍵の漏洩を解決するものではありません。ブランチ保護・変更レビュー・最小権限は別に必要です。ageは送信者の署名でもないため、暗号文は自分の信頼する実行から取得してください。

通常のpush/PRはAPIなしのテストのみです。PRへの自動推論・コメント、再利用workflow、月間予算の統合管理は未実装です。回収テスト、実APIの品質/費用比較を終えてから広げます。CI成功だけで実鍵での回収・実APIの互換性・検出品質を検証済みとは扱いません。

- [暗号化回収と鍵の管理](docs/ENCRYPTED_RECOVERY.md)
- [セキュリティ方針](SECURITY.md)
- [PR #1時点の実装監査と残課題](docs/SECURITY_AUDIT.md)（その後の回収方式は暗号化回収ガイドを参照）
- [GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions)

## License

MIT。サンプルの対象コードは各リポジトリのライセンスに従います。対象コードや利用者の鍵は同梱しません。
