# Architecture v0.1 — 設計仕様、未実装部分を含む

## 1. 何を作るか

単一の巨大CSVではなく、型付きの多粒度データと履歴、測定の由来、実験台帳を組み合わせる。
第一段階はローカルの不変ファイル + Parquet + DuckDBを想定する。複数人の同時更新が必要になるまでは
分散基盤を必須にしない。メタデータと大きな本文/原本を分離し、全文を日次表へ複製しない。
DuckDB/Parquetの取得・保存アダプタとDB DDLは今後の実装対象であり、現時点の動作済み機能ではない。

```
合法的に取得できる原本/提供者snapshot
  → raw bytes + artifact manifest
  → source別の観測（元のラベル/文脈を維持）
  → 意味・時点・版を揃えた候補事実 / 不一致台帳
  → 課題別のPITビュー
  → 特徴量・結果ラベル（互いに分離）
  → 実験・予測・評価・反証台帳
```

## 2. データモデル（実装契約）

| テーブル群 | 粒度/キー | 必須情報 |
|---|---|---|
| source_registry | 提供元×契約/規約版 | 上流、取得方法、個人利用/学術/商用/再配布/モデル学習の可否、確認根拠 |
| source_artifacts | 取得したバイト列の版 | SHA-256、取得時刻、レスポンス種別、safe URI、提供者release/commit、内部保存先 |
| entities / securities | 法的主体 / 発行証券 | 内部ID、証券種類。1企業=1証券としない |
| identifier_history | 識別子×有効期間×記録版 | EDINET、法人番号、証券コード、valid_from/to、recorded_from/to、照合方法 |
| filings / filing_relations | 書類版 / 書類間関係 | doc_id、提出者、発行対象、公開時刻、親書類、訂正/取下げ履歴 |
| observations_numeric | 提供者×書類×要素×context×単位×次元×抽出版 | 原文字列、値、元単位/倍率、連結範囲、期間、抽出経路、根拠位置 |
| observations_text | 書類×section×block×抽出版 | 原文/HTML、オフセット、本文ハッシュ、抽出器、テキストモデル版 |
| canonical_facts | 意味の揃った指標×期間×範囲×次元×vintage | 正規化値、定義版、入力ID、採用ルール、品質分類 |
| reconciliation | 同じ意味とvintageの候補値の比較 | 差、理由、元書類の一致、優先理由、未解決状態。勝手に平均しない |
| market_bars / actions | 証券×市場日 / 企業行動 | 生価格、調整係数、調整版、配当、分割、併合、上場廃止、対価、売買可否 |
| events / exposures | 企業/証券×イベント / 関係×期間 | 公開時刻、株主/相手先/セグメント、関係の強さ、出所 |
| human_capital | 会社/子会社×年度×雇用区分×指標 | 分母、対象範囲、提出会社給与と連結従業員の区別 |
| coverage / exclusions | source×年×業種×document type / 個票 | 取得・抽出・意味整合の成功率、欠損理由、選択過程 |
| feature_definitions / feature_values | 定義版 / 主体×decision_at×定義版 | 入力、lookback、公開可能時刻、モデル/fit期間、適用範囲 |
| label_definitions / labels | 定義版 / episode×horizon | 入口出口、結果観測時刻、成熟/打切り、価格/TR/市場差/費用の定義 |
| hypothesis_registry / experiment_runs | 仮説版 / run | 目的、推定対象、全試行、分割、入力snapshot、コードSHA、環境、seed |
| predictions / evaluations | 予測個票 / 評価対象×手法 | モデル版、fit/calibration期間、OOF種別、尺度、CI、cluster数 |
| claims / claim_history | 旧報告または新結論の版 | reported_not_reproduced等の状態、原文根拠、run ID、訂正/棄却履歴 |

## 3. 数値の性質は1本の「信頼度スコア」にしない

少なくとも独立した軸を持つ。

- `representation`: reported / guidance / derived / proxy / imputed / model / legacy_claim。
- `extraction_method`: structured / deterministic / manual / text_parser / llm / none。
- `verification`: unverified / source_tied / recomputed。原本照合の対象、実施者/手法、時刻を別台帳にする。
- `synthetic`: 明示的boolean。合成テスト専用。
- `missing_reason`: not_reported / not_applicable / retrieval_failed / parse_failed / ambiguous_scope /
  unknown_availability / censored / not_matured / withdrawn等。

reportedは「企業がその値を報告した」という観測であり、経済的真実や粉飾の不存在を保証しない。
会社予想は予想として直接観測できるが、将来実績でも市場全体の期待でもない。
原本照合、別実装照合、独立ソース照合は別の検証行為として記録する。
派生値に親のproxy/合成/未検証状態を継承させるDAG検証をP3で実装する。
**現在のカーネルはDAG全体を検証しないため、既定のPIT選択はreportedだけを許可する。**

## 4. 時間は最低3本 + 対象期間

- `period_start/end`: 何についての情報か。
- `public_available_at`: 原資料が公開された、または保守的に利用可能とみなす時刻。
- `provider_available_at`: この提供者が配信した時刻。unknownを許し、原資料公開時刻と混同しない。
- `recorded_at`: 自分のシステムがこの版を記録した時刻。
- `decision_at` / `entry_at`: 判断と注文/約定の時点。処理遅延・市場カレンダーを含める。

`public_reconstruction`は「現在取得した原本から、当時公開済みの内容だけを再構成」。
`provider_replay`は配信時刻まで確認できる場合だけの別モード。
`system_replay`は当時の自システム取得ログも要求する。
初期カーネルにはpublic_reconstruction/system_replayだけを実装している。

公開情報の再構成で、現在の取得時刻を過去の判断時刻以下に要求すると過去の全データが消える。
逆に取得時刻を提出日時に置き換えると、当時そのシステムにデータがあったと偽装する。
両者を区別し、全runにモードとsnapshot_cutoffを保存する。

時刻が日単位しかない場合は翌日0時JSTを保守的な上限として付け、次の取引可能セッションへ送る。
これは推定規則であって実測時刻ではない。短期の場中分析には使わない。
厳密な主系列ではavailable_at < decision_at、label_available_at < fit_cutoffを使う。

有報に記載された過年度5年分は、その有報の公開日以降に初めて使える版である。
訂正で過去の数値を上書きせず、as-reported、as-of、latest-restatedを別ビューにする。
最新の訂正がnull/取下げ/抽出不能になった場合、黙って旧値へ戻さない。

## 5. 意味と粒度

売上・利益は期間flow、総資産・純資産はinstant。連結/単体、IFRS/JP GAAP、企業独自要素、
継続/非継続事業、セグメント、通貨、桁、比率0–1/0–100、従業員の雇用区分を保持する。
持株会社の給与を子会社込みの平均給与と解釈しない。

単独四半期は同一会計年度・範囲・基準の累計差分だけを許す。決算期変更や欠損を四半期の均等割りで埋めない。
`FCF=CFO+CFI`と`CFO-CapEx`は別定義。M&A、資産売却、投資有価証券を設備投資と同一にしない。
銀行・保険の売上/キャッシュフローを一般事業会社の単一定義へ無理に押し込まない。

株価と株数/EPS/BPSは同じ分割基準に統一する。分割調整済み株価×未調整株数は誤った時価総額になり得る。
株数の期末値、期中平均、自己株控除後、発行済、上場株数を別指標にする。
J-Quants V1のLocalCodeとV2のCodeはアダプタで対応付け、原列名を保存する。

## 6. ソースの役割

原本と変換済みデータのどちらが常に優れるという固定順位は置かない。
Queriaは整形済み財務とマスタの入口、youseiushidaは詳細XBRL/履歴、CUCは古い原本、
numadは文章、hiroshi/Corpusは人的資本の候補。CoARiJは重複期間の照合と歴史補完に使う。
利用条件・schema・実カバレッジを確認できるまでは、どの候補も本番採用済みにしない。

同じEDINET原本を加工した3提供者が一致しても3つの独立観測ではない。
`upstream_document_id`と原本ハッシュで重複を識別し、提供者は測定経路として扱う。
決算短信と有報の不一致はエラーだけでなく、公開時点・決算確定・対象範囲の違いでも起こり得る。

## 7. 保存と公開

rawは内容ハッシュ付き不変保存。URL、可変なlatestタグ、現在のDBだけに依存しない。
版固定のmanifestに行数/ファイル数/schema hash/取得結果を保存する。権利制約に応じてmanifestも私有にする。
正規化ルール変更は新snapshotを生成し、影響差分を残す。

公開Git：自作コード、仕様、空の契約、明示的な合成fixture。
私有保存：取得原本、市場データ、J-Quants結合物、非公開研究、契約、必要に応じモデル/特徴量。
派生データが自動的に再配布可能になるとは仮定しない。公開exportは権利審査後の明示的allowlistのみ。

## 8. 初期実装の限界

evidence_core.pyは小さな検査核であり、銘柄マスタの歴史的再構成、全訂正グラフ、
原本の真正性検証、再配布判定、売買シミュレータ、XBRL正規化、完全な交差検証器ではない。
これらを既に実装したようにREADMEやデータカードへ記述しない。
