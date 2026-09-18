# Codex backlog / acceptance gates

全市場データセットは未作成。各段階を別PRにし、実装・実行・実データ検証を分離する。
既存の私有研究を回収する場合は、公開コードとは別の私有作業領域で行う。

## P0 — ソース採用前の監査

候補の規約・ライセンス本文、schema、取得方法、実サンプルを確認する。
`registry/sources.json`のdocumentation_checkedをdata_validatedと誤読しない。
不明な期間や銘柄数はnull。ソフトウェアライセンスだけで再配布可能としない。

受入：source別にdocs_checked/file_fetched/schema_profiled/source_tied/rights_reviewedを別状態で保存。
権利不明・取得不能をBLOCKEDとして列挙し、成功率の分母から消さない。
アクセスキーを要求する場合はsecret設定名だけを指定し、チャットへの貼付を求めない。

## P1 — raw保管・書類マスタ・再開可能な取得

公式EDINETと最小限の公開アーカイブの取り込みを実装する。
原本バイト、SHA-256、取得日時、HTTP結果、safe URL、doc_id、provider releaseを記録。
rate limit/retry/backoff/resume、重複取得の冪等性、取り下げ/訂正差分を実装。
日付付き企業/証券/提出者/対象会社マスタを別に持つ。

受入：中断後に再開可能。同じ入力から同じmanifest。異なるバイトを同名ファイルで上書きしない。
5文字コード・英字・複数証券・社名変更・非上場提出者・大量保有の発行対象を区別するテスト。
可変なlatestのリリース名だけでなくバイトhashを固定。rawの公開pushはしない。

## P2 — 小規模で難例を含む受入標本

最初の目安は30発行体/300書類程度。これは研究標本数ではなく、工学上の初期検査予算である。
固定seed/選択SQLで選び、JP GAAP/IFRS、連結/単体、訂正、赤字、決算期変更、
金融、REIT、複数segment、株式分割、上場廃止を層化する。
入手できない難例を合成例で「実データ検証済み」に置き換えない。

受入：書類数・企業数・年度・書類種別・成功/失敗を実測報告し、原本との照合標本を保存。
代表性のない難例標本から全体エラー率を外挿しない。全量監査には別の確率標本を使う。

## P3 — 財務標準化とPITの最小一貫処理

売上/OP/NP/資産/株主資本/CFO/CFI/株数/EPS/BPSを、元の要素/context/範囲を保持して正規化。
実績・会社予想・将来対象年度、単独四半期と累計、分割基準を分離する。
直接報告と計算派生のlineage、synthetic/proxy/未検証の伝播を検証するDAGを追加する。
訂正系列は明示的に組み、同じ企業年度というだけで結び付けない。

受入：全特徴量から元値・原本・定義版へ戻れる。孤立lineage、循環、未知単位はエラー。
available_at、snapshot_cutoff、system replay、訂正、取下げ、null更新の異常系を検査。
貸借一致等は会計基準/丸めの許容範囲付きで検査し、任意の数字を加えて一致させない。

## P4 — J-Quants結合・ラベルの定義

契約で利用できるデータだけを私有保存。V2公式仕様でCode/DiscDate/DiscTime等を確認する。
市場日カレンダー、分割/配当/合併対価/上場廃止、取引不能、コストの各定義を版管理する。
特徴量とラベルを別経路にする。20セッションと20暦日、イベント反応と取引収益を分ける。

受入：価格と株数の調整基準整合。全対象の除外理由。未成熟ラベルが学習に入らない。
配当情報不足ならprice returnのみと明記。TRを推定して実測扱いしない。
上場廃止や値幅制限を黙ってdropして利益を過大にしない。

## P5 — 多様な情報ブロック

現在の限定実装は[派生3ソースの受入と原本比較](P5.md)。Queria・youseiushida・numadから既存ID/lineageへ接続する段階であり、以下の増分研究評価や人的資本等は未実施。

numad/CUC/詳細XBRLの本文、人的資本、投資内訳、株主/政策保有、segmentを順に追加。
各追加ソースについてP0の受入手続きを再実施。指標だけでなく抽出根拠と範囲を移植する。

受入：baselineと同一標本での増分評価。公開時点・対象範囲・出所の対応率。
同じ原本のmirrorを独立観測として水増ししない。LLM経路は明示的opt-in。
本文/画像の公開や外部モデルへの送信は、利用条件とユーザー承認を確認してから行う。

## P5.5 — 私有snapshotの利用契約と照会

[利用ガイド](CHATGPT_DATA_USAGE.md)と機械可読table契約を入口に、P3–P5のID・時点・BLOCKED・lineageを保持したprivate packageを生成する。
immutable snapshotのhash/row count/schema/lineageと入力保存を検査してからCURRENTだけを切り替える。
公開Gitにはコード・仕様・合成テストのみ。Drive upload・新規金融値・return・研究評価は行わない。

## P5.6 — 既存privateデータのcoverageと展開準備

[棚卸し契約](P5_6.md)に従い、実bytes・実rowから2016〜2026のcoverageを測定する。
欠損・UNKNOWNを残すpartition queueと、実行前固定の年跨ぎ標本を使う。
既存定義・raw・snapshot・CURRENTは不変。全量財務処理や研究検証には進まない。

## P6 — 仮説・実験台帳と時間分割

registryの研究仕様を機械可読にし、全試行と状態遷移をappend-onlyで保存する。
暦時点ベースwalk-forward、label成熟、重複窓purge、内側のモデル選択/校正を実装する。
既に参照された期間はdevelopment扱い。過去の試行数不明は不明のまま記録。

受入：全runがsnapshot/コード/定義/環境hashへ接続。負の分散で推論が停止。
企業×時間依存、年別効果、標本変化、長期ラベル成熟を含む評価。
旧集計値はclaimsへ保存し、元個票へ逆生成しない。

## P7 — 仮説を一件ずつ検証

STATISTICAL_RESEARCH.mdから観測可能性の高い1件を選び、予測対象と比較を事前固定する。
結果を見て閾値を修正したら新run/新specにし、旧runを消さない。

受入：支持/null/逆転のいずれでも同じ評価書を生成。効果量/区間/依存/コスト/範囲を明記。
「新しい仮説を考えた」「実データで測定した」「未使用期間で再現した」を別に報告する。

## P8 — 全市場へ拡張・公開可否

取得対象母集団を固定し、年・業種・会計基準・書類種別別にカバレッジとエラー率を測る。
コード/データカード/公開可能な情報だけをexportする。最初はexport禁止を既定値にする。

受入：source別rights review、再現manifest、欠損/訂正/抽出失敗の一覧、私有データ漏洩検査。
完了は「ダウンロードが終わった」ではなく、適用範囲と失敗率を説明できる状態。

## Codex環境の使い分け

ローカルCodex：私有データ、認証付き取得、大きなraw/Parquetの処理。
クラウドCodex：公開コード、単体テスト、設計・レビューを中心にする。
権限が認められる場合だけ承認されたデータを投入する。公開CIに認証情報や私有DBを渡さない。
公式のクラウド説明ではsecretsはsetup段階のみで、agent段階のnetworkは既定off。
運用時点の公式文書を再確認し、secretを通常環境変数やファイルへコピーして制限を迂回しない。

参考：
https://developers.openai.com/codex/guides/agents-md
https://developers.openai.com/codex/cloud/environments
https://developers.openai.com/codex/cloud/internet-access
