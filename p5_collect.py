"""Explicit bounded collection of published derived views; no EDINET API/secrets.

Collection is separate from admission. Cached byte ranges are individual artifacts,
not a fabricated digest of a whole release. Only fixed P3/numad-overlap IDs are read.
"""
import argparse
from collections import Counter
import io
import json
from pathlib import Path
from urllib.error import HTTPError, URLError

from evidence_core import ContractError
from local_edinet import LocalArchive
from p5_acquisition import fetch, tar_index, RangeFile, parquet_rows
from source_acquisition import PrivateStore, encoded, sha256, utcnow

QUERIA_COMMIT='4844ff654235d087d2cbd7521cd3c05af481ac15'
YOUSEI_COMMIT='70f9a20ddc685283b06e68ef15132e6b81ea59c3'
NUMAD_COMMIT='e1dd7e00d5de82aa1b00cf7a28c829d327a93ca7'
TAR_URL='https://github.com/youseiushida/edinet/releases/download/dataset-v2/edinet-2022-H1.tar'
CATALOG_URL='https://data.queria.io/datasets/queria/edinet/ducklake.duckdb'
VERSION='dataset-v2/asset-375969107'
TABLES=('filings','line_items','contexts','text_blocks','dei','calc_edges','def_parents')


def collect(p3_snapshot, numad_store, directory):
    import duckdb
    for p in (p3_snapshot,numad_store):LocalArchive._outside_git(Path(p).resolve())
    store=PrivateStore(directory)
    if any(Path(directory).resolve()==Path(p).resolve() or Path(p).resolve() in Path(directory).resolve().parents
           for p in (p3_snapshot,numad_store)):raise ContractError('output_inside_input')
    # Record all choices before comparing any facts. A restart reuses byte checkpoints.
    docs=[json.loads(x) for x in (Path(p3_snapshot)/'documents.jsonl').read_bytes().splitlines()]
    available={d['doc_id']:d for d in docs if d.get('doc_type')=='120' and
               '2022-01-01'<=d.get('submit_datetime','')[:10]<='2022-06-30'}
    ns=PrivateStore(numad_store)
    manifests=[json.loads(x.read_bytes()) for x in (ns.root/'manifests').glob('*.json')]
    manifests=[m for m in manifests if m['provider_version']==NUMAD_COMMIT and m['safe_url'].endswith('/yuho-2022.jsonl')]
    if len(manifests)!=1:raise ContractError('numad_manifest_ambiguous')
    nm=manifests[0];raw=ns.read_raw(nm);numad=[]
    complete=raw.splitlines() if raw.endswith(b'\n') else raw.splitlines()[:-1]
    for i,line in enumerate(complete,1):
        row=json.loads(line)
        numad.append({'provider_fields':row,'locator':{'line_number':i,'row_sha256':sha256(encoded(row))}})
    ids=sorted(available.keys() & {r['provider_fields']['doc_id'] for r in numad})[:3]
    if not ids:raise ContractError('no_fixed_p3_numad_overlap')
    plan={'selection_rule':'first 3 sorted doc_ids in frozen P3 annual reports submitted 2022-H1 intersect complete rows of pinned numad prefix',
          'doc_ids':ids,'p3_document_sha256':sha256((Path(p3_snapshot)/'documents.jsonl').read_bytes()),
          'numad_byte_sha256':nm['byte_sha256'],'numad_complete_rows':len(complete),'max_docs':3,
          'financial_file_budget':600,'range_budget_per_file':128*1024*1024}
    store.publish('selection.json',encoded(plan))
    sources={};assets=[];rows=[];failures=[]

    def accept_table(source,table,result,evidence,scope=ids,method='provider_parquet'):
        asset={'source_id':source,'table':table,'evidence':evidence,'doc_scope':scope,
               **{k:v for k,v in result.items() if k!='rows'}}
        asset['asset_id']=sha256(encoded(asset));assets.append(asset)
        for row in result['rows']:
            r=dict(row,source_id=source,table=table,asset_id=asset['asset_id'],extraction_method=method)
            r['source_row_id']=sha256(encoded(r));rows.append(r)
        return asset

    # Pin source documentation separately from measured data; code commit != data release.
    for source,repo,commit,files in [
        ('queria','queria-io/dataset-edinet',QUERIA_COMMIT,['README.md','dataset.yml','models/main/mart/mart_business_results.sql','models/main/stg/stg_financial_facts.sql']),
        ('youseiushida','youseiushida/edinet',YOUSEI_COMMIT,['README.md','LICENSE','src/edinet/extension/_schema.py'])]:
        documentation=[]
        for file in files:
            b,a=fetch(store,f'https://raw.githubusercontent.com/{repo}/{commit}/{file}',commit)
            documentation.append(dict(a,document=file))
        sources[source]={'source_id':source,'source_class':'derived_from_edinet','code_reference_commit':commit,
                         'documentation':documentation,'rights_review':'BLOCKED','export_allowed':False}
    card_url=f'https://huggingface.co/datasets/numad/yuho-text-2014-2022/raw/{NUMAD_COMMIT}/README.md'
    _,card=fetch(store,card_url,NUMAD_COMMIT)
    sources['numad']={'source_id':'numad','source_class':'derived_from_edinet','provider_version':NUMAD_COMMIT,
                     'documentation':[card],'rights_review':'BLOCKED','export_allowed':False}
    store.publish('raw/'+nm['byte_sha256'],raw) # copy only into another private store; original remains read-only
    accept_table('numad','text_blocks',{'schema':sorted(numad[0]['provider_fields']),
        'file_row_count':None,'complete_prefix_rows':len(complete),'selected_count':sum(r['provider_fields']['doc_id'] in ids for r in numad),
        'rows':[r for r in numad if r['provider_fields']['doc_id'] in ids]}, {'artifacts':[nm],
        'scope':'complete JSONL rows in byte prefix, not full 2022 file'},method='pinned_jsonl')

    # Published half-year release: fetch metadata and only selected row groups.
    entries,headers=tar_index(store,TAR_URL,VERSION,1723453440)
    sources['youseiushida'].update(provider_version=VERSION,release_tag='dataset-v2',
        release_asset_bytes=1723453440,provider_claimed_release_sha256='ce38d86eddd8cb405172da28cac613bc674fb68e3508f4dd9321ec91fdd82c8c',
        whole_release_byte_verification='NOT RUN',coverage_scope='120 / 2022-H1 / fixed doc_ids')
    for table in TABLES:
        e=next(x for x in entries if x['name']=='120_2022-01-01_2022-06-30_'+table+'.parquet')
        f=RangeFile(store,TAR_URL,VERSION,e['offset'],e['size'],expected_etag=e['header']['etag'])
        result=parquet_rows(f,ids)
        accept_table('youseiushida',table,result,{'member':e['name'],'member_offset':e['offset'],
            'member_size':e['size'],'tar_header':e['header'],'artifacts':f.artifacts,
            'scope':'hashed ranges; whole tar and whole parquet hash unverified'})
        print('collected youseiushida',table,result['selected_count'],flush=True)

    # Queria catalog is fixed by complete bytes; data build commit is not inferred.
    _,catalog=fetch(store,CATALOG_URL,'queria-observed-20260918')
    c=duckdb.connect(str(store.root/'raw'/catalog['byte_sha256']),read_only=True)
    latest=c.execute('select max(snapshot_id) from ducklake_snapshot').fetchone()[0]
    sources['queria'].update(provider_version=f'ducklake-snapshot-{latest}',catalog_artifact=catalog,
        data_build_commit=None,data_build_commit_missing_reason='not_in_provider_catalog')
    base='https://data.queria.io/datasets/queria/edinet/ducklake.duckdb.files/'
    target_entities={available[d]['edinet_code'] for d in ids}
    query="""select t.table_id,t.table_name,s.path,t.path,f.path,f.file_size_bytes from ducklake_table t
        join ducklake_schema s using(schema_id) join ducklake_data_file f using(table_id)
        where t.end_snapshot is null and s.end_snapshot is null and f.end_snapshot is null
        and t.table_name in ('mart_companies','mart_documents','mart_business_results') order by t.table_name,f.path"""
    tables=c.execute(query).fetchall()
    if {r[1] for r in tables}!={'mart_companies','mart_documents','mart_business_results'}:raise ContractError('queria_catalog_table_missing')
    for tid,table,sp,tp,fp,size in tables:
        if c.execute('select count(*) from ducklake_delete_file where end_snapshot is null and table_id=?',[tid]).fetchone()[0]:
            raise ContractError('queria_delete_vectors_unsupported')
        b,a=fetch(store,base+sp+tp+fp,f'ducklake-snapshot-{latest}')
        if len(b)!=size:raise ContractError('queria_catalog_size_mismatch')
        result=parquet_rows(io.BytesIO(b),target_entities if table=='mart_companies' else ids,
                            'edinet_code' if table=='mart_companies' else 'doc_id')
        accept_table('queria',table,result,{'artifacts':[a],'catalog_artifact':catalog,'scope':'complete parquet file'})
        print('collected queria',table,result['selected_count'],flush=True)
    # One-to-one stg value/context projection, with explicit links to source rows.
    raw_table=c.execute("select table_id,path,schema_id from ducklake_table where table_name='financial_facts' and end_snapshot is null").fetchall()
    if len(raw_table)!=1:raise ContractError('queria_raw_table_ambiguous')
    tid,tp,sid=raw_table[0];sp=c.execute('select path from ducklake_schema where schema_id=? and end_snapshot is null',[sid]).fetchone()[0]
    if c.execute('select count(*) from ducklake_delete_file where end_snapshot is null and table_id=?',[tid]).fetchone()[0]:raise ContractError('queria_delete_vectors_unsupported')
    inlined=c.execute('select table_name from duckdb_tables() where table_name like ?',[f'ducklake_inlined_data_{tid}_%']).fetchall()
    if any(c.execute('select count(*) from "'+name+'"').fetchone()[0] for (name,) in inlined):raise ContractError('queria_inlined_data_unsupported')
    col=c.execute("select column_id from ducklake_column where table_id=? and column_name='doc_id' and end_snapshot is null",[tid]).fetchone()[0]
    file_rows=c.execute('''select f.path,f.file_size_bytes,s.min_value,s.max_value from ducklake_data_file f
        left join ducklake_file_column_stats s on f.data_file_id=s.data_file_id and f.table_id=s.table_id and s.column_id=?
        where f.table_id=? and f.end_snapshot is null order by f.path''',[col,tid]).fetchall()
    selected=[r for r in file_rows if r[2] is None or r[3] is None or any(r[2]<=d<=r[3] for d in ids)]
    if len(selected)>plan['financial_file_budget']:raise ContractError('queria_financial_file_budget_exceeded')
    sources['queria']['financial_file_inventory']={'total':len(file_rows),'candidate_files':len(selected),
        'selection':'catalog exact doc_id min/max then parquet row groups then exact doc_id; no missing-stats exclusion'}
    # Save compiled SQL as provenance; do not execute arbitrary remote SQL.
    sql=c.execute("select sql from ducklake_view where view_name='stg_financial_facts' and end_snapshot is null").fetchone()[0]
    sources['queria']['stg_view_sql']=sql;sources['queria']['stg_view_sql_sha256']=sha256(sql.encode())
    for n,(fp,size,_,__) in enumerate(selected):
        f=RangeFile(store,base+sp+tp+fp,f'ducklake-snapshot-{latest}',0,size)
        result=parquet_rows(f,ids)
        accept_table('queria','stg_financial_facts',result,{'artifacts':f.artifacts,'catalog_artifact':catalog,
            'member':fp,'member_size':size,'stg_view_sql_sha256':sha256(sql.encode()),
            'scope':'hashed ranges; raw financial value/context projection underlying provider stg view'},method='provider_stg_source_projection')
        if n%25==0:print('inspected queria financial files',n+1,'of',len(selected),flush=True)
    c.close()
    bundle={'selection':plan,'sources':sources,'assets':assets,'rows':rows,'failures':failures,
            'created_at':utcnow(),'rights_review':'BLOCKED','export_allowed':False}
    # Immutable name: acquisition checkpoints can resume; completed bundle cannot change.
    path=store.root/'bundle.json'
    if not path.exists():store.publish('bundle.json',encoded(bundle))
    else:
        prior=json.loads(path.read_bytes());bundle['created_at']=prior['created_at'];store.publish('bundle.json',encoded(bundle))
    print('collection complete',dict(Counter((r['source_id']+'.'+r['table']) for r in rows)),flush=True)
    return bundle


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--p3-snapshot',required=True);p.add_argument('--numad-store',required=True);p.add_argument('--private-dir',required=True)
    a=p.parse_args();collect(a.p3_snapshot,a.numad_store,a.private_dir)
