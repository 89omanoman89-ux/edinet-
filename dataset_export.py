"""Build a private, immutable query package from read-only P3/P4/P5 snapshots."""
import argparse
from collections import Counter, defaultdict
from copy import deepcopy
import csv
from datetime import datetime
import io
import json
import os
from pathlib import Path
import re
import tempfile

from dataset_contract import (VERSION, TABLES, SCHEMA, CHAT_COLUMNS, ParquetCodec,
    catalog, discovery_index, pack, payload, safe_path)
from evidence_core import ContractError
from financial_views import fact_view
from local_edinet import LocalArchive
from metadata_gap_audit import snapshot_fingerprints
from source_acquisition import PrivateStore, encoded, sha256, utcnow


def build_tables(roots, fingerprints, plans):
    tables = {name: [] for name in TABLES}
    loaded = {}

    def source(stage, filename):
        key = (stage, filename)
        if key not in loaded:
            raw = safe_path(roots[stage], filename).read_bytes()
            digest = sha256(raw)
            if digest != fingerprints[stage][filename]['byte_sha256']: raise ContractError('input_changed')
            loaded[key] = [(json.loads(line), {'input_stage': stage, 'input_file': filename,
                'input_line': str(i), 'input_snapshot_id': plans[stage]['snapshot_id'],
                'input_file_sha256': digest, 'input_row_sha256': sha256(encoded(json.loads(line)))})
                for i, line in enumerate(raw.splitlines(), 1)]
        return loaded[key]

    def copy(table, stage, filename):
        tables[table] = [pack(row, ref) for row, ref in source(stage, filename)]

    for table, stage, filename in (
        ('documents','p3','documents.jsonl'), ('canonical_facts','p3','canonical_facts.jsonl'),
        ('securities','p4','security_identity_map.jsonl'), ('market_observations','p4','market_observations.jsonl'),
        ('pit_join_rows','p4','pit_join_rows.jsonl'), ('jquants_source_rows','p4','jquants_source_rows.jsonl'),
        ('edinet_identity_evidence','p4','edinet_identity_evidence.jsonl'), ('trading_calendar','p4','trading_calendar.jsonl'),
        ('derived_source_links','p5','comparison_ledger.jsonl')):
        copy(table, stage, filename)
    docs = {r['doc_id']: r for r, _ in source('p3','documents.jsonl')}
    entities = {}
    for doc in docs.values():
        code = doc['edinet_code']; eid = 'edinet:' + code
        entity = entities.setdefault(eid, {'entity_id': eid, 'edinet_code': code,
            'names': [], 'codes': [], 'document_ids': [], 'name_evidence': [], 'names_are_join_keys': False})
        entity['document_ids'].append(doc['doc_id'])
        if doc.get('secCode') and doc['secCode'] not in entity['codes']: entity['codes'].append(doc['secCode'])
        for loc in doc.get('metadata_locators', []):
            name = loc.get('provider_fields', {}).get('filerName')
            if name and name not in entity['names']:
                entity['names'].append(name)
                entity['name_evidence'].append({'doc_id': doc['doc_id'], 'name': name, 'metadata_locator': loc})
    tables['entities'] = [pack(e) for e in entities.values()]
    # Text stays in the source snapshot. This package contains only private references.
    for stage, filename, table, fields in (
        ('p5','derived_observations.jsonl','derived_source_rows',('text','value_text','value')),
        ('p5','official_observations.jsonl','original_facts',('value',))):
        for original, ref in source(stage, filename):
            row = deepcopy(original)
            target = row.get('provider_fields', row)
            omitted = {}
            for field in fields:
                value = target.get(field)
                is_text = row.get('table') == 'text_blocks' or field == 'text' or (isinstance(value,str) and len(value) > 1024)
                if is_text and isinstance(value, str):
                    omitted[field] = {'text_sha256': sha256(value.encode('utf-8')), 'byte_count': len(value.encode('utf-8')),
                        'private_content_reference': dict(ref, field=('provider_fields.' if 'provider_fields' in row else '')+field)}
                    target[field] = None
            if omitted: row['omitted_text'] = omitted
            tables[table].append(pack(row, ref))
            if table == 'derived_source_rows' and (omitted or row.get('table') == 'text_blocks'):
                doc = docs.get(target.get('doc_id'), {})
                tables['text_index'].append(pack({'source_row_id': row['source_row_id'], 'source_id': row['source_id'],
                    'doc_id': target.get('doc_id'), 'tag': target.get('tag') or target.get('concept') or target.get('element_id'),
                    'texts': omitted, 'source_locator': row['locator'],
                    'public_available_at': doc.get('public_available_at'), 'provider_available_at': None,
                    'availability_basis': 'original document time only; historical derived delivery unknown',
                    'missing_reason': None if omitted else 'text_not_reported', 'content_embedded': False}, ref))
    anchors = {}
    for fact, ref in source('p3','canonical_facts.jsonl'):
        if fact['representation'] == 'derived': continue
        anchor = {k: fact.get(k) for k in ('candidate_id','doc_id','original_qname','contextRef','unitRef',
            'original_unit','context_sha256','source_artifact_sha256','xbrl_member_sha256','xbrl_member','element_index','verification_state')}
        anchor['archive_reference'] = docs[fact['doc_id']].get('artifact')
        key = anchor['candidate_id']
        if key in anchors and payload(anchors[key]) != anchor: raise ContractError('ambiguous_original_locator')
        anchors.setdefault(key, pack(anchor, ref))
    tables['original_locators'] = list(anchors.values())
    for stage in roots:
        for filename in ('failure_ledger.jsonl', 'metric_coverage.jsonl'):
            if filename not in fingerprints[stage]: continue
            for row, ref in source(stage, filename):
                if filename == 'metric_coverage.jsonl' and not row.get('missing_reason'): continue
                tables['failures'].append(pack(dict(row, reason=row.get('reason') or row.get('missing_reason')), ref))
    for i, s in enumerate(json.loads((roots['p5']/'source_acceptance.json').read_bytes())['sources'],1):
        tables['failures'].append(pack({'source_id': s['source_id'], 'reason': 'rights_unresolved', 'status': 'BLOCKED',
            'source_acceptance': s}, {'input_stage':'p5','input_file':'source_acceptance.json','input_line':str(i),
            'input_snapshot_id':plans['p5']['snapshot_id'],'input_file_sha256':fingerprints['p5']['source_acceptance.json']['byte_sha256'],
            'input_row_sha256':sha256(encoded(s))}))
    edges = set()
    def edge(table, identifier, target, target_id, relation):
        if target_id is not None: edges.add((table, identifier, target, target_id, relation))
    for d in docs.values():
        edge('documents',d['doc_id'],'entities','edinet:'+d['edinet_code'],'filer')
        if d.get('parentDocID') in docs: edge('documents',d['doc_id'],'documents',d['parentDocID'],'revises')
    for r in tables['canonical_facts']:
        f = payload(r); fid = f['fact_id']
        edge('canonical_facts',fid,'documents',f['doc_id'],'reported_in')
        if f['representation'] == 'derived':
            for parent in f['input_ids']: edge('canonical_facts',fid,'canonical_facts',parent,'derived_from')
        else: edge('canonical_facts',fid,'original_locators',f['candidate_id'],'original_element')
    for r in tables['securities']:
        m = payload(r)
        edge('securities',m['mapping_id'],'entities',m['entity_id'],'dated_entity')
        edge('securities',m['mapping_id'],'edinet_identity_evidence',m['identity_evidence_id'],'filer_code')
        for o in m['date_observations']: edge('securities',m['mapping_id'],'jquants_source_rows',o['observation_id'],o['use'])
    for r in tables['pit_join_rows']:
        j = payload(r); key = j['research_row_id']
        for target, field, relation in [('canonical_facts','edinet_fact_id','financial'),('securities','mapping_id','identity'),
            ('market_observations','market_observation_id','prior_market'),('edinet_identity_evidence','identity_evidence_id','filer_code')]:
            edge('pit_join_rows',key,target,j.get(field),relation)
        for oid in (j.get('trading_session') or {}).get('calendar_observation_ids',[]): edge('pit_join_rows',key,'trading_calendar',oid,'scheduled_session')
    for name in ('market_observations','trading_calendar'):
        for r in tables[name]: edge(name,r['observation_id'],'jquants_source_rows',r['observation_id'],'source_row')
    for r in tables['derived_source_links']:
        c = payload(r); key = c['comparison_id']
        edge('derived_source_links',key,'derived_source_rows',c['source_row_id'],'provider_row')
        for oid in c['origin_ids']: edge('derived_source_links',key,'original_facts',oid,'original_element')
        for fid in c['canonical_fact_ids']: edge('derived_source_links',key,'canonical_facts',fid,'canonical_candidate')
        for sid in c['component_row_ids']: edge('derived_source_links',key,'derived_source_rows',sid,'normalization_component')
    tables['lineage'] = [pack(dict(zip(('from_table','from_id','to_table','to_id','relation'), e))) for e in sorted(edges)]
    return tables


def chat_views(tables, snapshot, cutoff, synthetic):
    values = lambda name: [payload(r) for r in tables[name]]
    views = {name: [] for name in CHAT_COLUMNS}
    for e in values('entities'):
        views['company_index'].append(dict(snapshot_id=snapshot,entity_id=e['entity_id'],edinet_code=e['edinet_code'],
            names_json=json.dumps(e['names'],ensure_ascii=False),codes_json=json.dumps(e['codes']),search_only='true'))
    for d in values('documents'):
        views['filing_index'].append(dict(snapshot_id=snapshot,doc_id=d['doc_id'],entity_id='edinet:'+d['edinet_code'],sec_code=d.get('secCode'),
            parent_doc_id=d.get('parentDocID'),public_available_at=d.get('public_available_at'),sample_kind=d.get('sample_kind'),
            status='BLOCKED' if d.get('document_failure') else 'CANDIDATE',missing_reason=d.get('document_failure')))
    view = fact_view(values('canonical_facts'),values('documents'), mode='latest_restated',
        snapshot_cutoff=datetime.fromisoformat(cutoff), allow_synthetic_for_tests=synthetic)
    for f in view['facts']:
        views['latest_financials'].append(dict(snapshot_id=snapshot,snapshot_cutoff=cutoff,view='latest_restated_within_snapshot',
            entity_id='edinet:'+f['edinet_code'],doc_id=f['doc_id'],fact_id=f['fact_id'],metric=f['metric'],value=f['normalized_value'],
            unit=f['normalized_unit'],scope=f['consolidation'],accounting_standard=f['accounting_standard'],period_start=f.get('period_start'),
            period_end=f.get('period_end'),instant_date=f.get('instant_date'),public_available_at=f['public_available_at'],status='PASS'))
    for b in view['blocked']:
        views['latest_financials'].append(dict(snapshot_id=snapshot,snapshot_cutoff=cutoff,view='latest_restated_within_snapshot',
            doc_id=b.get('doc_id'),fact_id=b.get('fact_id'),status='BLOCKED',missing_reason=b['reason']))
    for c in values('derived_source_links'):
        views['source_comparison'].append(dict(snapshot_id=snapshot,**{k:c.get(k) for k in CHAT_COLUMNS['source_comparison'] if k!='snapshot_id'}))
    return views


def csv_bytes(name, rows):
    stream=io.StringIO(newline=''); writer=csv.DictWriter(stream,fieldnames=CHAT_COLUMNS[name]);writer.writeheader()
    for row in rows:
        # CSV is a text search view; prevent names or provider labels becoming formulas.
        safe={k: ("'"+v if isinstance(v,str) and v.startswith(('=','+','@','\t','\r','-')) and not re.fullmatch(r'-?\d+(\.\d+)?',v) else v) for k,v in row.items()}
        writer.writerow(safe)
    return stream.getvalue().encode('utf-8')


def export_dataset(p3, p4, p5, root, snapshot, *, codec=None, synthetic=False):
    from dataset_validation import validate_snapshot
    if not re.fullmatch(r'[A-Za-z0-9_-]+',snapshot): raise ContractError('invalid_snapshot_id')
    roots={k:Path(p).resolve() for k,p in [('p3',p3),('p4',p4),('p5',p5)]};root=Path(root).resolve()
    for p in [root,*roots.values()]: LocalArchive._outside_git(p)
    if any(root==p or root in p.parents or p in root.parents for p in roots.values()): raise ContractError('export_input_overlap')
    codec=codec or ParquetCodec()
    if codec.format!='parquet' and not synthetic: raise ContractError('synthetic_codec_not_empirical')
    before={k:snapshot_fingerprints(p) for k,p in roots.items()}
    plans={k:json.loads((p/'audit_plan.json').read_bytes()) for k,p in roots.items()}
    if any(bool(p['synthetic'])!=synthetic for p in plans.values()): raise ContractError('synthetic_mode_mismatch')
    if any(plans[k]['p3_snapshot_id']!=plans['p3']['snapshot_id'] for k in ('p4','p5')): raise ContractError('parent_snapshot_mismatch')
    for stage in ('p4','p5'):
        proof=json.loads((roots[stage]/'preservation_proof.json').read_bytes())
        inherited=proof.get('p3_before',proof.get('before'))
        if inherited!=before['p3']: raise ContractError('p3_input_evidence_mismatch')
    store=PrivateStore(root);index=encoded(discovery_index())+b'\n'
    if (root/'dataset_index.json').exists() and (root/'dataset_index.json').read_bytes()!=index: raise ContractError('discovery_contract_conflict')
    lock=root/'.export.lock'
    try: fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY)
    except FileExistsError: raise ContractError('export_writer_active') from None
    os.close(fd)
    try:
        out=safe_path(root,'snapshots/'+snapshot)
        out.parent.mkdir(exist_ok=True)
        try: out.mkdir()
        except FileExistsError: raise ContractError('snapshot_already_exists') from None
        output=PrivateStore(out); tables=build_tables(roots,before,plans)
        cutoff=plans['p3']['created_at'];created=utcnow()
        artifacts=[]
        def write(path,raw,fmt,count,schema):
            output.publish(path,raw)
            artifacts.append({'relative_path':path,'sha256':sha256(raw),'byte_count':len(raw),'row_count':count,
                'schema_hash':sha256(encoded(schema)),'format':fmt,'schema':schema})
        for name,rows in tables.items(): write(name+codec.extension,codec.encode(rows),codec.format,len(rows),SCHEMA)
        for name,rows in chat_views(tables,snapshot,cutoff,synthetic).items():
            write('chat/'+name+'.csv',csv_bytes(name,rows),'csv',len(rows),list(CHAT_COLUMNS[name]))
        summary={'snapshot_id':snapshot,'created_at':created,'snapshot_cutoff':cutoff,'contract_version':VERSION,
            'dataset_name':'edinet-research','definition_versions':{k:p['definition_version'] for k,p in plans.items()},
            'input_snapshots':{k:p['snapshot_id'] for k,p in plans.items()},'tables':catalog(),
            'coverage':{k:len(v) for k,v in tables.items()},'join_states':dict(Counter(payload(r)['status'] for r in tables['pit_join_rows'])),
            'rights_status':'BLOCKED','export_allowed':False,'synthetic':synthetic,
            'system_replay':'NOT ESTABLISHED','original_bytes_rechecked':False,
            'known_limitations':discovery_index()['known_limitations']}
        for name,entry in summary['tables'].items(): entry['path']=name+codec.extension
        write('dataset_index.json',encoded(summary)+b'\n','json',1,sorted(summary))
        after={k:snapshot_fingerprints(p) for k,p in roots.items()}
        if before!=after: raise ContractError('read_only_input_changed')
        preservation={'unchanged':True,'before':before,'after':after,'input_paths_embedded':False}
        write('preservation_proof.json',encoded(preservation)+b'\n','json',1,sorted(preservation))
        code_files={name:sha256((Path(__file__).parent/name).read_text(encoding='utf-8').encode()) for name in
            ('dataset_contract.py','dataset_export.py','dataset_validation.py','query_dataset.py','financial_views.py','revision_series.py')}
        manifest={'snapshot_id':snapshot,'created_at':created,'contract_version':VERSION,'synthetic':synthetic,
            'rights_status':'BLOCKED','export_allowed':False,'artifacts':artifacts,'code_files':code_files,
            'code_sha':sha256(encoded(code_files)),'input_snapshots':summary['input_snapshots'],'snapshot_cutoff':cutoff}
        raw=encoded(manifest)+b'\n';output.publish('manifest.json',raw)
        result=validate_snapshot(out,codec=codec,allow_synthetic=synthetic)
        store.publish('dataset_index.json',index)
        current=encoded({'snapshot_id':snapshot,'created_at':created,'manifest':'snapshots/'+snapshot+'/manifest.json',
            'manifest_sha256':sha256(raw),'manifest_byte_count':len(raw),'contract_version':VERSION})+b'\n'
        fd,temp=tempfile.mkstemp(prefix='.CURRENT-',dir=root)
        try:
            with os.fdopen(fd,'wb') as f: f.write(current);f.flush();os.fsync(f.fileno())
            os.replace(temp,root/'CURRENT.json')
        finally: Path(temp).unlink(missing_ok=True)
        return dict(result,snapshot_id=snapshot,coverage=summary['coverage'],join_states=summary['join_states'])
    finally: lock.unlink()


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('p3','p4','p5','root','snapshot'): p.add_argument('--'+name,required=True)
    a=p.parse_args()
    print(json.dumps(export_dataset(a.p3,a.p4,a.p5,a.root,a.snapshot)))
