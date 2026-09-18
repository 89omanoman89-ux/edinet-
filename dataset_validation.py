"""Read-only package integrity and ID/lineage validation; no external content fetch."""
import csv
from datetime import datetime
import io
import json
from pathlib import Path

from dataset_contract import VERSION, TABLES, SCHEMA, CHAT_COLUMNS, ParquetCodec, discovery_index, payload, safe_path
from evidence_core import ContractError
from financial_views import validate_lineage
from local_edinet import LocalArchive
from source_acquisition import encoded, sha256


def table_key(name, row):
    value=payload(row)
    key=tuple(row.get(k) if row.get(k) is not None else value.get(k) for k in TABLES[name][0].split(','))
    if any(v is None or v=='' for v in key): raise ContractError('table_primary_key_missing:'+name)
    return key


def validate_tables(tables):
    indices={}
    for name,rows in tables.items():
        index={}
        for row in rows:
            if set(row)!=set(k for k,_,_ in SCHEMA): raise ContractError('table_columns_mismatch')
            value=payload(row)
            for key in row:
                v=value.get(key)
                if isinstance(v,(str,int)) and not isinstance(v,bool) and key!='payload_json' and row[key]!=str(v):
                    raise ContractError('projected_column_mismatch')
            key=table_key(name,row)
            if key in index: raise ContractError('duplicate_primary_key:'+name)
            index[key]=value
        indices[name]=index
    edges={tuple(payload(r)[k] for k in ('from_table','from_id','to_table','to_id','relation')) for r in tables['lineage']}
    for a,aid,b,bid,_ in edges:
        if a not in indices or b not in indices or (aid,) not in indices[a] or (bid,) not in indices[b]:
            raise ContractError('orphan_lineage_edge')
    def require(a,aid,b,bid,relation):
        if (a,aid,b,bid,relation) not in edges: raise ContractError('required_lineage_edge_missing')
    facts=list(indices['canonical_facts'].values())
    verified=set()
    for f in facts:
        fid=f['fact_id'];doc=indices['documents'].get((f['doc_id'],))
        if doc is None or doc['edinet_code']!=f['edinet_code']: raise ContractError('fact_document_identity_mismatch')
        require('canonical_facts',fid,'documents',f['doc_id'],'reported_in')
        if f['representation']=='derived':
            for pid in f['input_ids']: require('canonical_facts',fid,'canonical_facts',pid,'derived_from')
        else:
            require('canonical_facts',fid,'original_locators',f['candidate_id'],'original_element')
            anchor=indices['original_locators'][(f['candidate_id'],)]
            for k in ('doc_id','original_qname','contextRef','unitRef','source_artifact_sha256','xbrl_member_sha256','xbrl_member','element_index'):
                if anchor.get(k)!=f.get(k): raise ContractError('original_locator_mismatch')
            if f['normalized_value'] is not None:
                if not all(f.get(k) is not None for k in ('source_artifact_sha256','xbrl_member_sha256','xbrl_member','element_index','original_qname','contextRef')):
                    raise ContractError('original_locator_incomplete')
                if (doc.get('artifact') or {}).get('byte_sha256')!=f['source_artifact_sha256']: raise ContractError('original_artifact_mismatch')
                verified.add(fid)
    validate_lineage(facts,verified)
    for j in indices['pit_join_rows'].values():
        key=j['research_row_id'];fid=j['edinet_fact_id']
        require('pit_join_rows',key,'canonical_facts',fid,'financial')
        f=indices['canonical_facts'][(fid,)]
        if j['doc_id']!=f['doc_id'] or j['entity_id']!='edinet:'+f['edinet_code']: raise ContractError('join_identity_mismatch')
        if j['status']=='PASS':
            for table,field,relation in [('securities','mapping_id','identity'),('market_observations','market_observation_id','prior_market'),('edinet_identity_evidence','identity_evidence_id','filer_code')]:
                require('pit_join_rows',key,table,j[field],relation)
            m=indices['securities'][(j['mapping_id'],)];p=indices['market_observations'][(j['market_observation_id'],)]
            if j['normalized_value']!=f['normalized_value'] or j['price']!=p['close']: raise ContractError('join_value_mismatch')
            if j['security_id']!=m['security_id'] or j['entity_id']!=m['entity_id'] or j['jquants_code']!=p['jquants_code']:
                raise ContractError('join_mapping_mismatch')
            decision=datetime.fromisoformat(j['decision_at'])
            if any(datetime.fromisoformat(x)>=decision for x in (f['public_available_at'],p['public_available_at'])): raise ContractError('future_information_leakage')
            if j.get('execution_claim') is not False or j.get('system_replay')!='NOT ESTABLISHED': raise ContractError('evidence_promotion')
    for c in indices['derived_source_links'].values():
        if c['independent_evidence_increment']!=0 or c['source_class']!='derived_from_edinet' or c['canonical_mapping_promoted']:
            raise ContractError('mirror_evidence_promoted')
        require('derived_source_links',c['comparison_id'],'derived_source_rows',c['source_row_id'],'provider_row')
        for oid in c['origin_ids']: require('derived_source_links',c['comparison_id'],'original_facts',oid,'original_element')
        for fid in c['canonical_fact_ids']: require('derived_source_links',c['comparison_id'],'canonical_facts',fid,'canonical_candidate')
    return {'status':'PASS','lineage_edges':len(edges),'fact_ids':len(facts),
        'research_row_ids':len(indices['pit_join_rows']),'source_row_ids':len(indices['derived_source_rows'])}


def read_snapshot(root, *, codec=None, allow_synthetic=False):
    root=Path(root).resolve();LocalArchive._outside_git(root)
    codec=codec or ParquetCodec();manifest=json.loads(safe_path(root,'manifest.json').read_bytes())
    if manifest['contract_version']!=VERSION: raise ContractError('unsupported_contract_version')
    if manifest['synthetic'] and not allow_synthetic: raise ContractError('synthetic_not_empirical')
    if codec.format!='parquet' and not manifest['synthetic']: raise ContractError('synthetic_codec_not_empirical')
    if manifest['rights_status']!='BLOCKED' or manifest['export_allowed'] is not False: raise ContractError('rights_promotion')
    artifacts={a['relative_path']:a for a in manifest['artifacts']}
    required={name+codec.extension for name in TABLES}|{'chat/'+n+'.csv' for n in CHAT_COLUMNS}|{'dataset_index.json','preservation_proof.json'}
    if set(artifacts)!=required or len(artifacts)!=len(manifest['artifacts']): raise ContractError('manifest_artifact_set_mismatch')
    actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    if actual!=required|{'manifest.json'}: raise ContractError('unmanifested_artifact')
    tables={};extras={}
    for relative,a in artifacts.items():
        raw=safe_path(root,relative).read_bytes()
        if sha256(raw)!=a['sha256'] or len(raw)!=a['byte_count']: raise ContractError('artifact_integrity_failed:'+relative)
        if sha256(encoded(a['schema']))!=a['schema_hash']: raise ContractError('schema_hash_mismatch')
        if relative.endswith(codec.extension):
            if a['format']!=codec.format or a['schema']!=SCHEMA: raise ContractError('table_schema_mismatch')
            rows=codec.decode(raw);tables[Path(relative).stem]=rows;count=len(rows)
        elif a['format']=='csv':
            reader=csv.DictReader(io.StringIO(raw.decode('utf-8')))
            if reader.fieldnames!=a['schema'] or reader.fieldnames!=list(CHAT_COLUMNS[Path(relative).stem]): raise ContractError('csv_schema_mismatch')
            count=sum(1 for _ in reader)
        elif a['format']=='json':
            value=json.loads(raw);extras[relative]=value;count=1
            if sorted(value)!=a['schema']: raise ContractError('json_schema_mismatch')
        else: raise ContractError('artifact_format_unsupported')
        if count!=a['row_count']: raise ContractError('row_count_mismatch')
    index=extras['dataset_index.json'];proof=extras['preservation_proof.json']
    if index['snapshot_id']!=manifest['snapshot_id'] or index['snapshot_cutoff']!=manifest['snapshot_cutoff']: raise ContractError('snapshot_identity_mismatch')
    if index['coverage']!={n:len(v) for n,v in tables.items()}: raise ContractError('coverage_count_mismatch')
    if not proof['unchanged'] or proof['before']!=proof['after']: raise ContractError('preservation_failed')
    for rows in tables.values():
        for row in rows:
            if not row.get('input_stage'): continue
            expected=proof['before'][row['input_stage']].get(row['input_file'])
            if not expected or expected['byte_sha256']!=row['input_file_sha256']: raise ContractError('source_reference_hash_mismatch')
    return manifest,index,tables


def validate_snapshot(root, **kwargs):
    manifest,index,tables=read_snapshot(root,**kwargs)
    return dict(validate_tables(tables),artifacts=len(manifest['artifacts']),snapshot_id=index['snapshot_id'])


def resolve_current(root):
    root=Path(root).resolve();LocalArchive._outside_git(root)
    if json.loads(safe_path(root,'dataset_index.json').read_bytes())!=discovery_index(): raise ContractError('discovery_contract_mismatch')
    current=json.loads(safe_path(root,'CURRENT.json').read_bytes())
    expected='snapshots/'+current['snapshot_id']+'/manifest.json'
    if current['manifest']!=expected: raise ContractError('current_pointer_mismatch')
    path=safe_path(root,current['manifest']);raw=path.read_bytes()
    if sha256(raw)!=current['manifest_sha256'] or len(raw)!=current['manifest_byte_count']: raise ContractError('manifest_hash_mismatch')
    if json.loads(raw)['snapshot_id']!=current['snapshot_id']: raise ContractError('current_snapshot_mismatch')
    return path.parent
