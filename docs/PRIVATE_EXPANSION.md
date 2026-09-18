# Available private archive expansion

P5.6で実ファイルから固定した母集団を、原本→P3→P4→P5→P5.5へ展開する。
対象年は2016〜2026。全市場の完全性、投資成績、system replayを認定する工程ではない。
rights reviewはBLOCKED、export_allowed=false。新規API取得、Drive変更、P6は行わない。

## 入力と定義

`expansion_archive.py`は明示したGit外rootの、棚卸し済みSHA・bytes・mtimeを再確認する。
ZIPと日次metadataを別rootから参照できるが、コピー原本や新しい取得日時を生成しない。
同一bytesのaliasは1原本として参照し、異なるZIP bytesは曖昧性として残す。
元rootのartifactと仮想locatorを両方保持する。SQLiteは検索indexであり、原本の代用ではない。
利用時は実際のZIPと日次JSONを再読込する。

訂正の双方向closureは既存`revision_series`の規則を共有する。
未取得の子訂正、branch、cycle、主体不一致を省かない。系列をジョブ間で分割しない。
securityの別主体候補も、同じジョブ内だけでなく全metadata indexから探し、
公式metadataの実bytesで確認してから既存のdecision cutoffを適用する。

`financial_extensions_v2.json`はv1をhash固定した追加allowlistである。
実原本に存在するexact QNameについて、公式schemaのtype/period、公式日本語label、
既存metricの意味との一致をレビューした項目だけを追加する。
企業独自要素や未知年度へ名前の類似だけで拡張しない。
v1で存在したcandidate/ruleのfact IDは維持し、適用したdefinition versionを別に記録する。
taxonomyのZIP・member SHAと取得証拠、実原本のレビュー証拠は私有領域に保存する。

参照した公式taxonomy：
[2016年版](https://www.fsa.go.jp/search/20160314.html)、
[2025年版](https://www.fsa.go.jp/search/20241112.html)、
[2026年版](https://www.fsa.go.jp/search/20251111.html)。
追加QNameごとのschema属性・version・hashは公開registryに記載する。

## 実行と再開

1. `expansion_archive.build_index`でP5.6 inventoryから原本/metadataのreadonly indexを作る。
2. `expansion_sources.build_derived_index`で保存済みprovider bytesをdecodeする。
   読めないrangeは台帳へ残す。従来のsource row IDと全行の一致を検査する。
3. `expansion_runner.plan_expansion`で入力hash、コードhash、全doc ID、系列単位のジョブを固定する。
4. `expansion_runner.run`を実行する。完了checkpointもartifact hashを再検査する。
   同じplanの入力・コード変更を受け付けない。中断した出力を成功扱いしない。
5. 全ジョブのCOMPLETE/BLOCKED、固定年跨ぎ標本、元入力不変、テスト/CIを確認し、
   `partitioned_dataset.publish_federation`で新しい私有rootのCURRENT候補を作る。

```console
python expansion_archive.py --inventory /PRIVATE/inventory --output /PRIVATE/new-index
python expansion_runner.py --output /PRIVATE/new-expansion --workers 3
python query_dataset.py --root /PRIVATE/new-expansion company --code SYNTHETIC_CODE
python query_dataset.py --root /PRIVATE/new-expansion facts --entity edinet:SYNTHETIC --as-of 2026-08-01T00:00:00+09:00
python query_dataset.py --root /PRIVATE/new-expansion lineage --fact-id SYNTHETIC_FACT_ID
python -m unittest discover -s tests -v
```

実データ処理のoptional runtimeは既存lockのPyArrowを使用する。公開CIはstdlibの合成testのみ。
最大3 worker。共有J-Quants cacheは親processで全行を元CSVへ往復確認してから読ませる。
cacheは選択を高速化するだけであり、利用するたび元ファイルとcacheをhash確認する。
カレンダーは既存アルゴリズムが参照し得るdecisionの15日前〜14日後を保持する。
価格の選択、利用可能時刻、予定entry、事後outcomeの定義は変えない。

## 私有packageと容量

全ジョブのpackageは独立した既存P5.5形式で検証する。最終rootは
`private-partitioned-query-v1`を宣言し、`dataset_index.json → CURRENT.json → manifest`
から、readonly SQLiteのID/主体index、必要なジョブのParquet、lineageへ進む。
主体のas-of queryは、その主体の全partitionを集めて既存`fact_view`を実行する。
ジョブ境界を利用可能時点や訂正系列の境界と解釈しない。
同一market/provider rowの複数partitionへの出現数とunique ID数は別集計にする。

物理Parquetの`private_payload_codec=column_projection_v1`は、同一文字列が
query列とpayloadに重複するとき、payload内の参照先列を保存する可逆圧縮である。
`ParquetCodec.decode`が元payloadを復元してからschema・値・lineageを検査する。
数値型、文字列コード、元ID、null、nested evidenceは変更しない。
標準codecで書いた旧packageも引き続き読める。

新規ジョブの一時stageは`evidence.zip`と`evidence_manifest.json`へ保存する。
packageのpayloadから**全ファイルbytesとSHAが完全一致で再構成できる**JSONLだけは、
重複保存せず再構成記述をmanifestへ置く。`replay_stage_file`が行順・LF・hashまで検査する。
本文を省略した行など再構成できないファイルはZIPに残す。
今回のprocessが作った一時directoryだけを片付け、rawや既存snapshotは削除しない。

元P5.5 CURRENTには書き込まない。新rootにも既存snapshotを上書きしない。
canonical/PIT合格、source tie、rights、研究利用可否を混同しない。
詳細な件数・年別状態・欠損・保存証明は最終snapshotの機械可読成果物を正とする。

最終`document_coverage.jsonl.gz`は元inventoryの全doc IDを保持する。
原本なし、未完了partition、原本照合済み候補、canonical view適格、PIT適格、rightsを別状態にする。
旧inventoryの理由は`prior_inventory_missing_reasons`へ分離し、古い「未監査」を新しい結果の理由と混ぜない。
`expansion_queue.jsonl.gz`のCOMPLETEは`execution_scope`に記した工程の完了である。
metadata/source inventory完了をPIT完了に読み替えない。元のUNKNOWN/BLOCKEDも`prior_status`で保持する。
P4対象外のTOPIXや、原本がない加工行の依存不足を消さない。

`source_catalog.json`は全ローカルmetadata・加工行index・検証済みJ-Quants cacheへの私有参照を持つ。
PITに結合されなかったsource行も所在とhashを追跡できるが、canonical/PIT値へ昇格しない。
publication前にoffline tests、CI、固定標本、全入力の保存証明をhash固定したacceptance gateが必要。
