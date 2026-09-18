# P2後のmetadata欠損監査（P3は未実施）

PR #3をmainへmergeし、Issue #1をcloseした後の限定修正。
凍結済みP2母集団30,283 ZIPのうちmetadata未対応102件と、拒否された日次一覧1ファイルだけを調べた。
P2 challenge 20件・probability 15件の選択・結果・manifestは変更していない。
任意のarchive全体について完全対応を保証する実装ではない。

## 原因と最小修正

2023-03-31の日次一覧は762行で、件数とJSON構造は整合していた。
確認書類（type 135）の1行の`parentDocID`に小文字が1字あり、旧parserの
`S[0-9A-Z]{7}`検査がファイル全体を拒否していた。102件はすべてこの一覧に存在した。

[EDINET API仕様書Version 2（2026年6月）](https://disclosure2dl.edinet-fsa.go.jp/guide/static/disclosure/download/ESE140206.pdf)
3-1-2-2、No.30、本文47頁は親書類管理番号を半角8文字の文字列とし、大文字限定とは記載していない。
4-1、本文87頁に親書類との関係の説明がある。今回は`parentDocID`の後続7文字だけASCII英大小文字・数字を許可する。
先頭`S`、長さ、他の識別子、件数・型・status・日次sequenceの検査は維持する。

原値を大文字化・補正せず、`parent_reference_case_unverified`警告と値のhashをschema profileへ追加する。
これは親参照の実在確認ではない。問題の135書類は今回の102 ZIPの対象外で、親参照の解決は`unresolved`のまま。
この警告と102件のmetadata欠損解消は別に集計する。

## 実測結果（2026-09-18）

新規の私有snapshot `metadata-gap-20260918-v1`を作成した。

| 検査 | 結果 |
|---|---:|
| 全対象への歴史的欠損reason記録 | 102 / 102 |
| `daily_file_rejected_by_parent_case_guard` | 102 |
| metadata行・提出日・原本DEI提出者コードの一致 | 102 / 102 |
| ZIPバイト整合性・XBRL parse | 各102 / 102 |
| 拒否された日次一覧の再parse | 1 / 1 |
| 対象ZIPの未解決metadata対応 | 0 |
| 別書類の未確認の親参照 | 1 |

原本hash/bytesは既存取得ログと一致し、現在の観測時刻と過去の取得ログ上の時刻を分離した。
live APIへ通信していない。原本や過去snapshotは再生成せず、新しい監査台帳から参照する。
監査前後でP2成果物151ファイルの名前・hash・bytes・mtimeが一致した。
今回観測したZIP102・日次一覧1・各取得ログの計206ファイルもhash・bytes・mtimeが一致した。

## 偏りの記述

分母は凍結P2 ZIP母集団。既存metadataに今回復元した行の属性を加えた記述集計であり、全市場へ外挿しない。

| 属性 | 該当ZIP数 | 旧欠損数 | 旧欠損割合 |
|---|---:|---:|---:|
| 提出年2023 | 4,621 | 102 | 2.207% |
| 他の提出年合計 | 25,662 | 0 | 0% |
| 提出日2023-03-31 | 102 | 102 | 100% |
| 有価証券報告書（120） | 26,132 | 86 | 0.329% |
| 訂正有価証券報告書（130） | 4,151 | 16 | 0.385% |
| periodEndの暦年2022 | 3,817 | 86 | 2.253% |
| periodEnd不明 | 4,151 | 16 | 0.385% |

今回の欠損は1つの提出日に集中した。有報・訂正有報の両方が影響を受けており、訂正に固有の障害とは解釈しない。
訂正16件は`periodEnd=null`を維持し、親書類から年度を補完しない。提出年と対象期間末の暦年を別集計し、後者を標準化済み決算年度とは呼ばない。
私有集計には全提出年・全periodEnd暦年・提出日・書類type・訂正区分・parent有無の分母、旧欠損数、未解決数を保存した。

## 再現方法と出力

```sh
python metadata_gap_audit.py --edinet-local-root /absolute/private/edinet --p2-snapshot /absolute/private/p2/frozen-snapshot --private-dir /absolute/private/metadata-gaps --snapshot new-unique-snapshot --expected-missing-count 102
python -m unittest discover -s tests -v
```

入力は明示したGit外rootと凍結P2 snapshot。対象件数、重複ID、archive rootの一致を検査する。
選び直し・新規取得は行わず、元の`metadata_events`が空の全件と`inventory_failures`だけを処理する。
原本DEIとmetadataの不一致、metadata候補の競合、日付不一致、raw欠損・破損はPASSへ昇格しない。
原因を特定できない場合は`unresolved`を残す。出力済みsnapshot、原本配下、P2 snapshot配下、Git checkout内への出力を拒否する。

私有出力は`audit_plan.json`、`daily_file_diagnostics.jsonl`、`metadata_gap_records.jsonl`、
`bias_summary.json`、`preservation_proof.json`、`summary.json`と既存adapter形式のlocal manifest/checkpoint。
主成果物にはsnapshot ID、P2 snapshot ID、syntheticフラグ、UTF-8/LF Pythonソース9ファイルのhash一覧から計算した`code_sha`を記録する。
個票はdoc_id、historical_missing_reason、現在のmissing_reason/状態、原本hash、metadataファイルhash/日次sequence、DEI根拠を保持する。
公開Gitへ実doc_id・原本・metadata個票・私有絶対pathを追加しない。

127 offline unit tests成功（既存112＋今回15）。GitHub Actionsも同じ合成テストだけを実行する。
rights reviewはBLOCKED、`export_allowed=false`。全市場代表性はNOT ESTABLISHED。
J-Quants・財務標準化・P3・投資/成績研究はNOT RUN。
