"""Verified local row caches; source bytes are rechecked before every partition use."""
from collections import defaultdict
from datetime import date
import json
import io
from pathlib import Path
import sqlite3
import zlib

from coverage_inventory import file_hash,private_path
from evidence_core import ContractError
from jquants_local import JQuantsArchive,DATASETS,csv_rows,code
from source_acquisition import PrivateStore,encoded,sha256


def source_observation(artifact,index,row,dataset,synthetic=False):
    digest=sha256(encoded(row))
    return {'observation_id':sha256(encoded([artifact['byte_sha256'],index,digest])),
        'dataset':dataset,'provider_fields':row,'source':{'artifact':artifact,'record_index':index,
        'record_index_basis':'one_based_data_record_excluding_header','row_sha256':digest},'synthetic':synthetic}


class CachedJQuants(JQuantsArchive):
    """Parquet accelerates selection only; it never provides new price/identity evidence."""
    def __init__(self,root,store,*,cache_root,synthetic=False):
        super().__init__(root,store,synthetic=synthetic)
        self.cache_root=private_path(cache_root)
        if self.cache_root==self.root or self.root in self.cache_root.parents or self.cache_root in self.root.parents:
            raise ContractError('cache_overlaps_source')
        self.query_codes=set();self.query_windows={};self.used={}

    def _cache(self,f):
        import pyarrow as pa
        import pyarrow.parquet as pq
        raw,artifact=self.evidence(f['relative_path'])
        if (artifact['byte_sha256'],len(raw))!=(f.get('expected_sha256'),f.get('expected_bytes')):
            raise ContractError('jquants_byte_integrity_failed')
        root=self.cache_root/artifact['byte_sha256'];store=PrivateStore(root)
        parquet=root/'rows.parquet';manifest=root/'manifest.json'
        if manifest.is_file():
            m=json.loads(manifest.read_bytes())
            if m['source_sha256']!=artifact['byte_sha256'] or file_hash(parquet)!=m['parquet_sha256']:
                raise ContractError('row_cache_integrity_failed')
            return m,parquet
        if parquet.exists():raise ContractError('interrupted_row_cache')
        schema=pa.schema([('code',pa.string()),('day',pa.string()),('record_index',pa.int64()),('provider_json',pa.string())])
        count=0;days=set();invalid=0;buffer=[];fields=[];dataset=f['dataset']
        with pq.ParquetWriter(parquet,schema,compression='zstd') as writer:
            for fields,n,row in csv_rows(raw,f['relative_path'].endswith('.gz')):
                if not DATASETS[dataset]<=set(fields):raise ContractError('unsupported_jquants_schema')
                day=row['DiscDate' if dataset=='fins_summary' else 'Date'];date.fromisoformat(day)
                days.add(day);count+=1
                if 'Code' in row:
                    try:code(row['Code'])
                    except ContractError:invalid+=1
                buffer.append({'code':row.get('Code'),'day':day,'record_index':n,'provider_json':encoded(row).decode()})
                if len(buffer)==10000:
                    writer.write_table(pa.Table.from_pylist(buffer,schema=schema));buffer=[]
            if buffer:writer.write_table(pa.Table.from_pylist(buffer,schema=schema))
        if not count:raise ContractError('empty_jquants_csv')
        profile=dict(f,artifact=artifact,row_count=count,row_count_basis='csv_records_recounted',date_range=[min(days),max(days)],
            fields=fields,schema_sha256=sha256(encoded(fields)),code_schema='string_4_or_5_ASCII_uppercase_alphanumeric',
            invalid_code_rows=invalid,api_schema_profile='jquants_v2_bulk_observed_v1',
            price_columns=[x for x in fields if x in {'O','H','L','C','AdjO','AdjH','AdjL','AdjC'}],
            corporate_action_columns=[x for x in fields if x in {'AdjFactor','ExRT'}],
            price_basis='reported_unadjusted' if dataset=='equities_bars_daily' else None,
            adjustment_basis='ex_date_factor_not_cumulative_not_total_return' if dataset=='equities_bars_daily' else None)
        # Roundtrip EVERY decoded cache row, before any cache is accepted.
        replay=(r for batch in pq.ParquetFile(parquet).iter_batches() for r in batch.to_pylist())
        for _,n,row in csv_rows(raw,f['relative_path'].endswith('.gz')):
            r=next(replay)
            if r['record_index']!=n or r['provider_json']!=encoded(row).decode():raise ContractError('row_cache_roundtrip_failed')
        if next(replay,None) is not None:raise ContractError('row_cache_count_mismatch')
        m={'source_sha256':artifact['byte_sha256'],'parquet_sha256':file_hash(parquet),'profile':profile,
            'row_count':count,'roundtrip':'PASS','rights_review':'BLOCKED','export_allowed':False}
        store.publish('manifest.json',encoded(m))
        return m,parquet

    def inspect(self,f,keep):
        import pyarrow.parquet as pq
        m,path=self._cache(f);dataset=f['dataset']
        if dataset=='markets_calendar':filters=None
        else:
            if not self.query_codes:return dict(m['profile'],retained_rows=0),[]
            filters=[[('code','in',sorted(self.query_codes)),('day','>=',lo),('day','<=',hi)] for lo,hi in self.query_windows[dataset]]
        table=pq.read_table(path,filters=filters)
        rows=[]
        for r in table.to_pylist():
            provider=json.loads(r['provider_json'])
            if keep(provider):rows.append(source_observation(m['profile']['artifact'],r['record_index'],provider,dataset,self.synthetic))
        self.used[f['relative_path']]=(f,m,path)
        return dict(m['profile'],retained_rows=len(rows),row_cache_roundtrip='PASS'),rows

    def verify_rows(self,observations):
        import pyarrow.parquet as pq
        grouped=defaultdict(list)
        for r in observations:grouped[r['source']['artifact']['relative_path']].append(r)
        for relative,rows in grouped.items():
            f,m,path=self.used[relative]
            raw,_=self._bytes(relative)
            if sha256(raw)!=m['source_sha256'] or file_hash(path)!=m['parquet_sha256']:
                raise ContractError('row_cache_integrity_failed')
            wanted=sorted({r['source']['record_index'] for r in rows})
            original={r['record_index']:json.loads(r['provider_json']) for r in pq.read_table(path,filters=[('record_index','in',wanted)]).to_pylist()}
            for r in rows:
                expected=source_observation(m['profile']['artifact'],r['source']['record_index'],original[r['source']['record_index']],r['dataset'],self.synthetic)
                if expected!=r:raise ContractError('jquants_row_reverse_lookup_mismatch')
        return {'status':'PASS','observations':len(observations),'files':len(grouped),
            'basis':'all cache rows roundtripped to original CSV at cache creation; original and cache bytes rehashed now'}


def derived_row(asset,provider,locator):
    row={'asset_id':asset['asset_id'],'source_id':asset['source_id'],'table':asset['table'],
         'provider_fields':provider,'locator':dict(locator,row_sha256=sha256(encoded(provider))),
         'extraction_method':('pinned_jsonl' if asset['source_id']=='numad' else
             'provider_stg_source_projection' if asset['source_id']=='queria' and asset['table']=='stg_financial_facts' else 'provider_parquet')}
    row['source_row_id']=sha256(encoded(row));return row


def build_derived_index(source,output):
    """Read every accessible saved row group, retain unavailable ranges in the ledger."""
    import pyarrow.parquet as pq
    from p5_audit import RecordedRanges
    from p5_acquisition import json_value
    source,output=private_path(source),private_path(output)
    if source==output or source in output.parents or output in source.parents:raise ContractError('cache_overlaps_source')
    store=PrivateStore(output);inputs=PrivateStore(source)
    if any(output.iterdir()):raise ContractError('snapshot_already_exists')
    raw=(source/'bundle.json').read_bytes();bundle=json.loads(raw)
    db=sqlite3.connect(output/'derived.sqlite')
    db.executescript('CREATE TABLE rows (id TEXT PRIMARY KEY,doc TEXT,entity TEXT,asset TEXT,payload BLOB); CREATE INDEX row_doc ON rows(doc); CREATE INDEX row_entity ON rows(entity);')
    failures=[];count=0;known={r['source_row_id']:r for r in bundle['rows']};retained=set()
    for a in bundle['assets']:
        e=a['evidence']
        def add(provider,locator):
            nonlocal count
            row=derived_row(a,provider,locator)
            if row['source_row_id'] in known:
                if row!=known[row['source_row_id']]:raise ContractError('source_row_identity_changed')
                retained.add(row['source_row_id'])
            db.execute('INSERT INTO rows VALUES (?,?,?,?,?)',(row['source_row_id'],provider.get('doc_id'),
                provider.get('edinet_code') if a['table']=='mart_companies' else None,a['asset_id'],zlib.compress(encoded(row))))
            count+=1
        if a['source_id']=='numad':
            b=inputs.read_raw(e['artifacts'][0]);rows=b.splitlines() if b.endswith(b'\n') else b.splitlines()[:-1]
            for n,line in enumerate(rows,1):add(json.loads(line),{'line_number':n})
        else:
            stream=io.BytesIO(inputs.read_raw(e['artifacts'][0])) if e['scope']=='complete parquet file' else RecordedRanges(inputs,e)
            parquet=pq.ParquetFile(stream)
            for g in range(parquet.num_row_groups):
                try:values=parquet.read_row_group(g)
                except (ContractError,OSError):
                    failures.append({'source_id':a['source_id'],'asset_id':a['asset_id'],'row_group':g,'reason':'recorded_range_missing'});continue
                for n,row in enumerate(values.to_pylist()):add(json_value(row),{'row_group':g,'row_index':n})
        db.commit()
    if retained!=set(known):raise ContractError('prior_derived_rows_not_preserved')
    db.close()
    if (source/'bundle.json').read_bytes()!=raw:raise ContractError('source_bundle_changed')
    manifest={'source_root':str(source),'source_bundle_sha256':sha256(raw),'database_sha256':file_hash(output/'derived.sqlite'),
        'rows':count,'prior_ids_preserved':len(retained),'failures':failures,'rights_review':'BLOCKED','export_allowed':False}
    store.publish('manifest.json',encoded(manifest));return manifest


def indexed_bundle(index,p3,selected,output):
    from metadata_gap_audit import guard_output
    index,p3,output=private_path(index),private_path(p3),private_path(output)
    m=json.loads((index/'manifest.json').read_bytes())
    source=private_path(m['source_root'])
    guard_output(output, [index,p3,source], 'bundle_output_overlap')
    store=PrivateStore(output)
    if any(output.iterdir()):raise ContractError('bundle_already_exists')
    if file_hash(index/'derived.sqlite')!=m['database_sha256']:raise ContractError('derived_cache_corrupt')
    raw=(source/'bundle.json').read_bytes()
    if sha256(raw)!=m['source_bundle_sha256']:raise ContractError('source_bundle_changed')
    bundle=json.loads(raw)
    docs=[json.loads(line) for line in (p3/'documents.jsonl').read_bytes().splitlines()]
    entities={d['edinet_code'] for d in docs if d['doc_id'] in selected and d.get('edinet_code')}
    db=sqlite3.connect((index/'derived.sqlite').as_uri()+'?mode=ro',uri=True)
    rows={}
    for column,keys in [('doc',selected),('entity',sorted(entities))]:
        for key in keys:
            for rid,payload in db.execute('SELECT id,payload FROM rows WHERE '+column+'=?',(key,)):
                rows[rid]=json.loads(zlib.decompress(payload))
    db.close();assets={r['asset_id'] for r in rows.values()}
    bundle.update(rows=list(rows.values()),assets=[a for a in bundle['assets'] if a['asset_id'] in assets],
        selection={'doc_ids':list(selected),'p3_document_sha256':file_hash(p3/'documents.jsonl'),
        'selection_rule':'fixed partition IDs, exact doc_id and exact filer EDINET code, no outcome selection',
        'original_bundle_sha256':m['source_bundle_sha256']},failures=m['failures'])
    store.publish('bundle.json',encoded(bundle))
    return source
