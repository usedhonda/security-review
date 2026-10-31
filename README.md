# security-review

Small, bounded experiments for AI security review of public GitHub code.

GitHubアカウント全体へセキュリティレビューを導入する前に、**コード量・レビュー内容・API利用額を小さく実測する**ための試作です。Python 3.11以上の標準ライブラリだけで動きます。

公開リポジトリの標準GitHub-hostedランナーを使い、Actionsの実行料金をかけずに計測できる構成です。現段階は手動の検証用で、他のリポジトリへの自動導入やマージの制御は行いません。AIの指摘は人が確認する仮説です。結果が空でも、安全性の証明にはなりません。

## 最初に行うこと

1. このプロジェクトをGitHubの**公開**リポジトリに配置します。既存の非公開リポジトリを公開へ切り替える場合は、コミット履歴と過去のActionsログも公開対象になるため、内容を確認してから変更します。
2. そのリポジトリで **Settings → Secrets and variables → Actions → New repository secret** を開きます。
3. Nameに **`OPENAI_API_KEY`**、Secretに専用のOpenAI APIキーを登録します。キーをソースやチャットに記載する必要はありません。
4. **Actions → Security review pilot → Run workflow** で、既定ブランチ、モデル `gpt-6.1-sol`、予算 `1.00` を選びます。
5. 実行後のSummaryでコード量・カバー率・トークン使用量・利用額・指摘件数を確認します。指摘本文、ファイル別の箇所、モデルの自由記述は公開Summaryに出しません。Artifactのアップロードとキャッシュ保存は行いません。

APIキーにはResponses APIの作成と入力トークン数の取得が必要です。GitHub側のキーはこの専用リポジトリのSecretに限定します。公開リポジトリのコード取得にはGitHubトークンを使いません。

通常のpushとpull requestではオフラインのユニットテストだけが動き、OpenAI APIを呼びません。APIを使用するのは、メンテナーが明示的に開始した `Security review pilot` だけです。

### ActionsとAPIの費用

公開リポジトリで標準GitHub-hostedランナーを使うActions実行は無料です。このworkflowは標準の `ubuntu-24.04` を指定し、大型ランナー、Artifact保存、キャッシュ保存は使いません。両workflowはリポジトリが公開の場合だけジョブを実行します。非公開のまま試す場合はローカルCLIを使えます。非公開リポジトリのActions実行には一般にアカウント共有の月間無料枠と課金・予算制限が適用されます。公開された再利用workflowを非公開リポジトリから呼ぶ場合も、課金条件は呼び出し側のリポジトリに従います。

OpenAI APIの利用額はActionsとは別に計測します。対象プランのChatGPT APIクレジットが有効で残高があれば、そのクレジットが適用されます。初期設定のアプリ側API予算は1回につき最大1 USDです。

GitHub公式情報（2026-10-31確認）: [Billing and usage](https://docs.github.com/en/actions/concepts/billing-and-usage)。公開へ切り替えても、アカウント自体の実行制限などがあれば別途確認が必要です。

## 何を比較するか

`benchmarks/pilot.json` で対象・コミット・ファイルを固定しています。現在の比較対象は次の3組です。KBは1,000 bytesで表記しています。

| 比較対象 | 公開リポジトリ | 選択ファイル数 | 選択ソース量 | 対象範囲 |
| --- | --- | ---: | ---: | --- |
| Small | `usedhonda/statusline` | 3 | 6,190 bytes | インストーラー、CI、パッケージ定義 |
| Medium | `usedhonda/muse-agent-bridge` | 7 | 51,074 bytes | 設定、入力受付、リスナー、通信、ワーカー |
| Large | `usedhonda/openclaw-artist-runtime` | 8 | 137,577 bytes | HTTPルート、SSRF対策、設定、Telegram認証・ルーティング |

これは**選択したファイルの比較**です。リポジトリ全体を監査したという意味ではありません。未取得の呼び出し先、デプロイ環境、実行時の挙動は判断できない場合があります。レポートは選択範囲に対するファイル・行・バイトのカバー率を記録します。

ソースは固定した40桁のコミットSHAから取得し、各ファイルをGit blob SHAで照合します。取得したコードをimport・実行せず、そのリポジトリの依存パッケージもインストールしません。

## 予算の扱い

| 設定 | 初期値・制限 |
| --- | --- |
| モデル | `gpt-6.1-sol`。手動で `gpt-6-astra` も選択可能 |
| API予算 | **1回の実験全体で最大1.00 USD**。小さくすることは可能 |
| 生成回数 | **最大3回** |
| 出力上限 | 1回あたり6,000 tokens。推論トークンを含む |
| 入力上限 | 1回あたり128,000 tokens |
| 再試行 | 自動再試行なし |
| キャッシュ | 明示モード・breakpointなしで読み書きを無効化 |
| モデルのツール | なし。コードの実行、URL取得、外部ツール操作なし |
| API応答保存 | `store: false` |
| Workflow | 手動のみ、既定ブランチのみ、同時実行1件 |

生成前に、公式の `/v1/responses/input_tokens` でプロンプト・ソース・出力スキーマを含む入力数を数えます。その入力数と最大出力数の料金を予算から予約できた場合だけ、Responses APIを呼びます。数えられなければ生成を中止します。Astraで予約額が予算を超えるケースはスキップされます。

成功後はAPIが返したusageと記録済み単価から費用を計算します。出力トークンに含まれる推論トークンを二重加算しません。タイムアウトなどでusageが不明な呼び出しは、予約額を残して後続の実行を止めます。料金表と異なるモデル・サービス設定・予期しないキャッシュ利用も未完了として扱います。

**この1ドルは1回のCLI実行に対するアプリ側の制限です。** 複数回実行した合計やアカウント全体の上限ではありません。継続利用には専用OpenAIプロジェクトのhard limitも設定してください。GitHub Actionsのランナー料金や税金は、このAPI費用計算には含みません。

ChatGPTの対象プランにはAPIクレジット特典がありますが、適用先の組織・有効化・残高の確認が必要です。レポートのUSD値は**クレジット適用前の利用額**で、請求額や追加支払い額ではありません。このツールから課金設定やクレジット残高は取得しません。

公式情報（2026-10-31確認）:

- [API pricing](https://developers.openai.com/api/docs/pricing)
- [API credits for ChatGPT subscribers](https://developers.openai.com/api/docs/guides/chatgpt-api-credits)
- [Counting tokens](https://developers.openai.com/api/docs/guides/token-counting)
- [Prompt caching](https://developers.openai.com/api/docs/guides/prompt-caching)
- [Spend limits](https://developers.openai.com/api/docs/guides/spend-limits)

## ローカルで試す

追加パッケージのインストールは不要です。リポジトリのルートで実行します。

### 1. テスト

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

ネットワークアクセスやAPIキーは不要です。予算・中断時の会計・不完全な結果・パス境界・ハッシュ検証・秘匿化などを検証します。

### 2. 公開ソースを取得

```sh
python3 scripts/fetch_cases.py --manifest benchmarks/pilot.json
```

GitHubへのネットワーク接続が必要です。取得先は `.work/sources/` 以下に限定されます。manifestに記載したファイルだけを取得し、リダイレクト、パスの逸脱、シンボリックリンク、ハッシュ不一致やサイズ超過は拒否します。ソースはgit管理対象外です。

### 3. APIを呼ばずに規模を確認

```sh
PYTHONPATH=src python3 -m security_review plan \
  --manifest benchmarks/pilot.json \
  --output-dir reports/plan-001
```

`plan` はファイル数・行数・バイト数と、UTF-8サイズに基づく保守的な入力見積もりを出します。**APIのトークン実測ではありません。** APIキーは不要で、OpenAIへの通信もありません。

### 4. 実際にレビューする

専用APIキーを環境変数 `OPENAI_API_KEY` に安全に設定した上で実行します。シェル履歴やコードにキーを書かないようにします。指摘の詳細を読みたい場合は、このローカル実行の `summary.json` と `summary.md` を使用します。Actionsの公開Summaryは計測値だけを表示し、完全レポートはアップロードしません。

```sh
PYTHONPATH=src python3 -m security_review run \
  --manifest benchmarks/pilot.json \
  --output-dir reports/pilot-001 \
  --model gpt-6.1-sol \
  --max-cost-usd 1.00 \
  --max-calls 3
```

既存のレポートを上書きする実行は拒否します。再実行すると再びAPIを呼び、追加の利用額が発生するため、前の実行状態を確認してから新しい出力先を指定してください。

## 結果の読み方

| 項目 | 内容 |
| --- | --- |
| Source coverage | 選択ファイル、送ったファイル、行数、バイト数、各ファイルのSHA-256 |
| Provenance | 対象リポジトリ、固定したコミットSHA、選択モード |
| Token usage | 入力・出力・推論・キャッシュのAPI報告値 |
| Cost | 公表単価からの利用額、未解決の予約額、予算残額 |
| Findings | 深刻度、確信度、ファイルと行、入口、入力の流れ、影響、修正案 |
| Limitations | 未取得の文脈、モデルが確認できなかった点 |

`completed` は処理と選択範囲のレビューが完了した状態であり、「脆弱性なし」ではありません。内容や請求情報が不完全なら `incomplete` / `failed` / `skipped_*` などを記録し、CLIは終了コード2を返します。`planned` はAPI未実行です。未計測の費用は `null` または `unknown` で記録し、ゼロと混同しません。

上の表はローカルCLIが生成する完全レポートの項目です。Actionsの公開Summaryは、対象番号・モデル・状態と、コード量・カバー率・使用量・費用・指摘件数に限定します。対象番号はmanifestの並び順です。未知の値は `null` / `unknown` のまま表示します。

生成前に予約額をレポートへ保存します。プロセスが強制終了された場合は `in_progress` のまま残ることがあります。GitHub自体の停止などではSummaryの保存も完了しない場合があるため、保存失敗を費用ゼロと見なさないでください。

## 安全性と信頼境界

- APIキーを渡すのは専用の手動レビューのステップだけです。forkからのPRでは使用しません。
- プロンプト、manifest、ツール自身の変更は、実行前にメンテナーが確認する前提です。
- ソース中の指示はデータとして扱います。モデルにはツールを渡さず、生成物も実行しません。プロンプトだけで誤判定を完全に防げるという意味ではありません。
- 典型的なキー・トークン・秘密鍵を送信前とレポート生成時に秘匿化します。検知はbest effortです。現在の対象を公開ソースに限定しています。
- 公開Summaryは許可した計測項目だけから組み立てます。モデルの説明・指摘・制約や、任意のエラー説明を転記しません。完全レポートにはソース由来の内容が含まれる可能性があるため、ローカルでも公開前に人が確認します。
- Actionsの権限は `contents: read` です。利用ActionはコミットSHA固定、checkoutは認証情報を残しません。
- ActionsからArtifactをアップロードせず、完全レポートは一時ランナー内だけに残ります。完全レポートや取得ソースはgit管理対象外です。指摘内容の検証にはローカルCLIを使います。

`store: false` はResponses APIで応答を保存しない指定です。OpenAI側のすべてのログ保持がゼロになる保証ではありません。[API data controls](https://developers.openai.com/api/docs/guides/your-data) を確認してください。

## 構成

| パス | 役割 |
| --- | --- |
| `src/security_review/` | CLI、入力制限、API通信、予算、レポート |
| `scripts/fetch_cases.py` | 固定コミットの公開ファイル取得・ハッシュ検証 |
| `benchmarks/pilot.json` | 比較する対象と範囲 |
| `.github/workflows/ci.yml` | push / PRのオフライン検証 |
| `.github/workflows/benchmark.yml` | 手動のAPI実測 |
| `.github/dependabot.yml` | Action更新の提案 |
| `tests/` | 会計・境界・未完了判定の検証 |

## 検証後に決めること

1. レビューの指摘が再現できるか、人による修正に役立つかを確認します。
2. Small / Medium / Largeの利用額と入力・出力トークンを比較します。初回の測定前に月額を断定しません。
3. 差分レビューにする範囲、SolとAstraを使い分ける条件、月間上限を決めます。
4. 結果が良ければ、再利用可能なworkflowとリポジトリごとの参加設定を追加します。Dependabot、Dependency Review、CodeQL、secret scanningと組み合わせます。
5. 他のプロジェクトへ展開する前に、説明・ライセンス・設定・例・取得元の扱い・結果の秘匿性を確認します。

将来のdiff入力用に `base_commit` とhead側の `line_ranges` を受け付けますが、差分の自動抽出やPRイベントへの接続は未実装です。このpilotはsnapshotのみを使用します。

## License

MIT。取得した対象コードは各リポジトリのライセンスに従います。このリポジトリ自体には対象コードを同梱しません。
