"""Immutable federation of independently validated P5.5 partitions.

The index routes queries; it does not choose between conflicting financial facts.
Repeated market/mirror evidence retains its partition occurrence and source ID.
"""
from collections import Counter,defaultdict
from datetime import datetime
import json
import gzip
from pathlib import Path
import re
import sqlite3

from coverage_inventory import private_path,file_hash
from dataset_contract import TABLES,payload,safe_path,catalog
from dataset_validation import table_key
from evidence_core import ContractError,aware
from expansion_runner import validate_checkpoint
from financial_views import fact_view
from query_dataset import Dataset
from source_acquisition import PrivateStore,encoded,sha256,utcnow

VERSION='private-partitioned-query-v1'
ROUTED=('documents','canonical_facts','pit_join_rows','derived_source_links','derived_source_rows','text_index')
EXCLUSIVE=ROUTED[:3]


def binary_key(identifier):
    if len(identifier)==64:
        try:return b'h'+bytes.fromhex(identifier)
        except ValueError:pass
    return b't'+identifier.encode()


def verify_frozen_inputs(inventory,output):
    """Final full rehash, including old snapshots and CURRENT; no digest reuse."""
    from coverage_inventory import verify_inventory_inputs
    inventory=private_path(inventory);output=private_path(output)
    plan=json.loads((inventory/'inventory_plan.json').read_bytes())['plan']
    roots={r['id']:private_path(r['path']) for r in plan['roots']}
    if any(output==p or p in output.parents or output in p.parents for p in (*roots.values(),inventory)):
        raise ContractError('preservation_output_overlap')
    proof=verify_inventory_inputs(inventory)
    PrivateStore(output).publish('preservation_proof.json',encoded(proof));return proof



def coverage_records(documents,processed):
    """Every inventoried document survives, including derived-only and metadata-only."""
    for d in documents:
        state=processed.get(d['doc_id']);reasons=[]
        original=bool(d.get('originals'))
        if not original:reasons.append('official_original_not_available')
        elif state is None:reasons.append('partition_not_completed')
        if state and state.get('document_failure'):reasons.append(state['document_failure'])
        if state:
            if not state['source_tied_facts']:reasons.append('no_source_tied_canonical_fact')
            if not state['canonical_eligible_facts']:reasons.append('canonical_view_blocked_or_no_accepted_mapping')
            if not state['pit_pass']:reasons.append('no_PIT_eligible_row')
        yield {'doc_id':d['doc_id'],'submit_date':d.get('submit_date'),'source_ids':d.get('sources',[]),
            'data_exists':True,'official_original_available':original,
            'pipeline_execution':'COMPLETE' if state else 'BLOCKED',
            'source_tied':'PASS' if state and state['source_tied_facts'] else 'BLOCKED',
            'canonical_eligible':'PASS' if state and state['canonical_eligible_facts'] else 'BLOCKED',
            'pit_eligible':'PASS' if state and state['pit_pass'] else 'BLOCKED',
            'research_ready':'BLOCKED','rights_review':'BLOCKED','export_allowed':False,
            'audit':state,'missing_reasons':sorted(set(reasons+['rights_unresolved'])),
            'prior_inventory_missing_reasons':d.get('missing_reasons',[])}


def write_expansion_coverage(plan,out,processed,job_results):
    from expansion_archive import lines
    inventory=Path(plan['inventory']);months=defaultdict(set);states=Counter();years=defaultdict(Counter)
    # Older undated partitions refer to source_files by ID; dated ones embed evidence.
    references={a for p in lines(inventory/'expansion_queue.jsonl') for a in p['input_artifacts'] if isinstance(a,str)}
    referenced={}
    if references:
        for f in lines(inventory/'source_files.jsonl'):
            if f['file_id'] in references:
                referenced[f['file_id']]={k:f[k] for k in ('file_id','root_id','relative_path','byte_sha256')}
    by_doc={d:r for r in job_results for d in r['doc_ids']}
    archive_manifest=json.loads((Path(plan['archive_index'])/'cross_archive_index.json').read_bytes())
    metadata_failures={r['relative_path'] for r in archive_manifest['failures']}
    for r in coverage_records(lines(inventory/'document_coverage.jsonl'),processed):
        year=r['submit_date'][:4] if r['submit_date'] else 'unknown'
        years[year]['observed_documents']+=1
        for key in ('official_original_available','source_tied','canonical_eligible','pit_eligible'):
            if r[key] is True or r[key]=='PASS':years[year][key]+=1
    def write_gzip(path,records):
        common={'snapshot_id':out.name,'code_sha':file_hash(Path(__file__))}
        expected=Counter();count=0
        shape=lambda r:json.dumps(sorted((k,type(v).__name__) for k,v in r.items()),separators=(',',':'))
        with Path(path).open('xb') as f,gzip.GzipFile(fileobj=f,mode='wb',mtime=0) as z:
            for r in records:
                value=dict(r,**common);z.write(encoded(value)+b'\n');expected[shape(value)]+=1;count+=1
        actual=Counter()
        with gzip.open(path,'rt',encoding='utf-8') as f:
            for line in f:
                value=json.loads(line)
                if any(value[k]!=v for k,v in common.items()) or value['export_allowed'] is not False:raise ContractError('coverage_envelope_mismatch')
                actual[shape(value)]+=1
        if expected!=actual:raise ContractError('coverage_schema_or_count_mismatch')
        return {'row_count':count,'schema_profiles':[{'fields':json.loads(s),'rows':n} for s,n in sorted(actual.items())],'roundtrip':'PASS'}
    # Input pass counts are independent of the yearly primary sample used for validation.
    profiles={'document_coverage.jsonl.gz':write_gzip(out/'document_coverage.jsonl.gz',coverage_records(lines(inventory/'document_coverage.jsonl'),processed))}
    for d in lines(inventory/'document_coverage.jsonl'):
        if d.get('originals'):
            for t in d.get('document_types',[]):months[(d.get('submit_date') or '')[:7],t].add(d['doc_id'])
    def queue():
        for p in lines(inventory/'expansion_queue.jsonl'):
            r=dict(p,prior_status=p['status'],rights_review='BLOCKED',export_allowed=False)
            source=p['source'];status='BLOCKED';reason=p.get('reason') or 'input_partition_not_available'
            artifacts=[referenced.get(a) if isinstance(a,str) else a for a in p['input_artifacts']]
            r['resolved_input_artifacts']=artifacts
            if any(a is None for a in artifacts):
                reason='artifact_reference_unresolved'
                r['execution_scope']='input_reference_validation'
            elif p['month']=='unknown' or (p['status']=='UNKNOWN' and not artifacts):
                status='UNKNOWN';reason=p.get('reason') or 'row_date_not_available'
                r['execution_scope']='undated_or_unobserved_input; no dated execution inferred'
            elif artifacts:
                if source=='edinet_original':
                    docs=months[p['month'],p['table'].removeprefix('ZIP:')]
                    outcomes=[by_doc.get(d) for d in docs]
                    status='COMPLETE' if docs and all(x and x['status']=='COMPLETE' for x in outcomes) else 'BLOCKED'
                    reason='all_available_documents_executed; consult row-level eligibility' if status=='COMPLETE' else 'document_partition_execution_blocked'
                    r['job_ids']=sorted({x['job_id'] for x in outcomes if x})
                    r['execution_scope']='P3_P4_P5_P55_for_available_originals'
                elif source=='edinet_metadata':
                    bad=any(a['root_id']+'/'+a['relative_path'] in metadata_failures for a in artifacts)
                    status='BLOCKED' if bad else 'COMPLETE';reason='metadata_index_rejected_input' if bad else 'read_only_cross_archive_metadata_index; raw absence retained'
                    r['execution_scope']='metadata_inventory_and_revision_discovery'
                elif source=='jquants':
                    if p['table']=='indices_topix_daily':reason='dataset_outside_existing_P4_contract'
                    else:
                        cached=all((Path(plan['row_cache'])/a['byte_sha256']/'manifest.json').is_file() for a in artifacts)
                        status='COMPLETE' if cached else 'BLOCKED'
                        reason='all_saved_rows_cached_and_roundtripped; PIT rows require EDINET and dated evidence' if cached else 'jquants_row_cache_missing_or_failed'
                    r['execution_scope']='source_inventory; EDINET-linked PIT outcomes are separate'
                elif source in ('queria','youseiushida','numad'):
                    status='COMPLETE';reason='available_saved_rows_indexed; original_overlap_required_for_comparison'
                    r['execution_scope']='saved_bytes_only; unavailable ranges and original dependencies remain BLOCKED'
                else:
                    status='COMPLETE';reason='prior_immutable_snapshot_preserved; not reclassified as new evidence'
                    r['execution_scope']='input_preservation_only'
            r.update(status=status,reason=reason,research_ready='BLOCKED',downstream_pipeline_status='see_document_coverage')
            states[status]+=1;yield r
    profiles['expansion_queue.jsonl.gz']=write_gzip(out/'expansion_queue.jsonl.gz',queue())
    PrivateStore(out).publish('coverage_artifact_profiles.json',encoded(profiles))
    return {'year_document_states':{k:dict(v) for k,v in sorted(years.items())},'source_partition_states':dict(states)}


def source_catalog(plan):
    """Expose saved source coverage without promoting unjoined rows to canonical/PIT."""
    result={'rights_review':'BLOCKED','export_allowed':False,'independent_evidence_increment':0,
        'source_inventory':plan['inventory'],'source_inventory_hashes':plan['input_hashes'],
        'raw_data_are_external_read_only':True,'sources':{}}
    for name,root,manifest_name,database,expected in (
        ('edinet',Path(plan['archive_index']),'cross_archive_index.json','archive.sqlite',plan['archive_manifest_sha256']),
        ('derived_from_edinet',Path(plan['derived_index']),'manifest.json','derived.sqlite',plan['derived_manifest_sha256'])):
        if file_hash(root/manifest_name)!=expected:raise ContractError('source_catalog_manifest_changed')
        m=json.loads((root/manifest_name).read_bytes())
        if file_hash(root/database)!=m['database_sha256']:raise ContractError('source_catalog_database_changed')
        result['sources'][name]={'index_root':str(root),'manifest':manifest_name,'manifest_sha256':expected,
            'database':database,'database_sha256':m['database_sha256'],'counts':m.get('counts',{'rows':m.get('rows')}),
            'canonical_eligibility':'requires original tie and P3 rules','pit_eligibility':'requires dated P4 evidence'}
    cache=Path(plan['row_cache']);files=[]
    for p in sorted(cache.glob('*/manifest.json')):
        m=json.loads(p.read_bytes());parquet=p.parent/'rows.parquet'
        if m['roundtrip']!='PASS' or file_hash(parquet)!=m['parquet_sha256']:raise ContractError('source_cache_changed')
        files.append({'manifest':str(p),'manifest_sha256':file_hash(p),'parquet_sha256':m['parquet_sha256'],
            'source_sha256':m['source_sha256'],'dataset':m['profile']['dataset'],'date_range':m['profile']['date_range'],'rows':m['row_count']})
    result['sources']['jquants']={'raw_root':plan['jquants_root'],'cache_root':str(cache),'files':files,
        'scope':'all decoded saved files within the existing P4 dataset contract; TOPIX is inventory only',
        'financial_independence':'NOT ESTABLISHED','pit_eligibility':'source presence alone is insufficient'}
    return result


def merge_entity(existing,incoming):
    if existing['entity_id']!=incoming['entity_id'] or existing['edinet_code']!=incoming['edinet_code']:
        raise ContractError('entity_identifier_conflict')
    result=dict(existing)
    for k in ('names','codes','document_ids'):
        result[k]=sorted(set(existing[k])|set(incoming[k]))
    evidence={sha256(encoded(r)):r for r in existing['name_evidence']+incoming['name_evidence']}
    result['name_evidence']=[evidence[k] for k in sorted(evidence)]
    result['names_are_join_keys']=False
    return result


def publish_federation(root,snapshot,*,codec=None,synthetic=False):
    if not re.fullmatch(r'[A-Za-z0-9_-]+',snapshot):raise ContractError('invalid_snapshot_id')
    root=private_path(root);plan_raw=(root/'expansion_plan.json').read_bytes();plan=json.loads(plan_raw)
    gate=None
    if not synthetic:
        if not (root/'acceptance_gate.json').is_file():raise ContractError('final_acceptance_gate_missing')
        gate=json.loads((root/'acceptance_gate.json').read_bytes())
        if gate.get('code_files')!=plan['code_files']:raise ContractError('acceptance_code_mismatch')
        for key in ('offline_tests','offline_CI','input_preservation','fixed_cross_year'):
            check=gate.get(key,{})
            if check.get('status')!='PASS':raise ContractError('acceptance_gate_blocked:'+key)
            path=private_path(check['evidence_path'])
            if file_hash(path)!=check['evidence_sha256']:raise ContractError('acceptance_evidence_changed')
    digest=sha256(plan_raw);out=safe_path(root,'snapshots/'+snapshot)
    store=PrivateStore(out)
    if any(out.iterdir()):raise ContractError('snapshot_already_exists')
    db=sqlite3.connect(out/'locator.sqlite')
    db.executescript('''CREATE TABLE entities (id TEXT PRIMARY KEY,payload BLOB);
        CREATE TABLE entity_shards (entity TEXT,shard INTEGER,PRIMARY KEY(entity,shard));
        CREATE TABLE exclusive_locations (kind INTEGER,id BLOB,shard INTEGER,PRIMARY KEY(kind,id)) WITHOUT ROWID;
        CREATE TABLE shared_locations (kind INTEGER,id BLOB,shard INTEGER,PRIMARY KEY(kind,id,shard)) WITHOUT ROWID;
        CREATE TABLE documents (id TEXT PRIMARY KEY,entity TEXT,shard INTEGER);
    ''')
    shards=[];entities={};totals=Counter();states=Counter();years=defaultdict(Counter);blocked=[];processed={};job_results=[]
    # WITHOUT ROWID enforces IDs without duplicating a multi-million-row index.
    for job in plan['jobs']:
        folder=root/'jobs'/job['job_id']
        if not (folder/'result.json').is_file():raise ContractError('unfinished_expansion_job')
        result=validate_checkpoint(folder,digest)
        job_results.append(dict(result,job_id=job['job_id'],doc_ids=job['doc_ids']))
        year=job['month'][:4];years[year][result['status']]+=1
        if result['status']!='COMPLETE':
            blocked.append({'job_id':job['job_id'],'doc_ids':job['doc_ids'],'month':job['month'],'reason':result['reason']});continue
        if not synthetic and not (folder/'evidence_manifest.json').is_file():raise ContractError('stage_evidence_manifest_missing')
        package=folder/'package';data=Dataset(package,codec=codec,allow_synthetic=synthetic)
        number=len(shards)
        entry={'number':number,'job_id':job['job_id'],'package':package.relative_to(root).as_posix(),
            'CURRENT_sha256':file_hash(package/'CURRENT.json'),'manifest_sha256':file_hash(data.path/'manifest.json'),
            'evidence_archive':(folder/'evidence.zip').relative_to(root).as_posix(),
            'evidence_sha256':result['artifacts']['evidence.zip'],'checkpoint':(folder/'result.json').relative_to(root).as_posix(),
            'evidence_manifest':(folder/'evidence_manifest.json').relative_to(root).as_posix() if (folder/'evidence_manifest.json').exists() else None,
            'evidence_manifest_sha256':file_hash(folder/'evidence_manifest.json') if (folder/'evidence_manifest.json').exists() else None,
            'checkpoint_sha256':file_hash(folder/'result.json'),'validation':data.verification,'coverage':data.index['coverage']}
        shards.append(entry)
        for name,rows in data.tables.items():
            totals[name]+=len(rows)
            if name not in ROUTED:continue
            kind=ROUTED.index(name)
            for row in rows:
                key=table_key(name,row)
                if len(key)!=1:raise ContractError('routing_key_not_scalar')
                table='exclusive_locations' if name in EXCLUSIVE else 'shared_locations'
                try:db.execute('INSERT INTO '+table+' VALUES (?,?,?)',(kind,binary_key(key[0]),number))
                except sqlite3.IntegrityError:raise ContractError('duplicate_cross_partition_id:'+name) from None
        for e in data.rows('entities'):
            entities[e['entity_id']]=merge_entity(entities[e['entity_id']],e) if e['entity_id'] in entities else e
            db.execute('INSERT INTO entity_shards VALUES (?,?)',(e['entity_id'],number))
        for d in data.rows('documents'):
            entity='edinet:'+d['edinet_code'] if d.get('edinet_code') else None
            db.execute('INSERT INTO documents VALUES (?,?,?)',(d['doc_id'],entity,number))
            processed[d['doc_id']]={'job_id':job['job_id'],'document_failure':d.get('document_failure'),
                'source_tied_facts':0,'canonical_eligible_facts':0,'pit_pass':0,'pit_blocked':0}
        for f in data.rows('canonical_facts'):
            if f.get('normalized_value') is not None and f.get('verification_state')=='source_tied':processed[f['doc_id']]['source_tied_facts']+=1
        view=fact_view(data.rows('canonical_facts'),data.rows('documents'),mode='latest_restated',
            snapshot_cutoff=datetime.fromisoformat(plan['created_at']),allow_synthetic_for_tests=synthetic)
        for f in view['facts']:processed[f['doc_id']]['canonical_eligible_facts']+=1
        for r in data.rows('pit_join_rows'):processed[r['doc_id']]['pit_pass' if r['status']=='PASS' else 'pit_blocked']+=1
        for r in data.rows('pit_join_rows'):states[r['status']]+=1;years[year]['PIT_'+r['status']]+=1
        db.commit()
    db.executemany('INSERT INTO entities VALUES (?,?)',[(k,encoded(v)) for k,v in sorted(entities.items())])
    # Occurrence counts are deliberately not mislabeled as unique upstream evidence.
    counts={name:db.execute('SELECT COUNT(DISTINCT id) FROM '+('exclusive_locations' if name in EXCLUSIVE else 'shared_locations')+
        ' WHERE kind=?',(ROUTED.index(name),)).fetchone()[0] for name in ROUTED}
    counts['entities']=len(entities)
    db.commit();db.close()
    expansion=write_expansion_coverage(plan,out,processed,job_results) if not synthetic else {}
    summary={'snapshot_id':snapshot,'snapshot_cutoff':plan['created_at'],'contract_version':VERSION,
        'created_at':utcnow(),'code_sha':file_hash(Path(__file__)),'coverage_unique_ids':counts,'table_occurrences':dict(totals),
        'join_states':dict(states),'year_states':{k:dict(v) for k,v in sorted(years.items())},'complete_partitions':len(shards),
        'blocked_partitions':len(blocked),'blocked_documents':plan['blocked_documents'],
        'rights_status':'BLOCKED','export_allowed':False,'full_market_representativeness':'NOT ESTABLISHED',
        'system_replay':'NOT ESTABLISHED','original_bytes_rechecked':'see input preservation proof',
        'query_policy':'full entity revision series across partitions; no name join or missing-value fallback',
        'stage_content_resolution':'checkpoint -> evidence_manifest (ZIP member or verified package reconstruction) -> stage snapshot/file/line -> original',
        **expansion}
    store.publish('coverage_summary.json',encoded(summary))
    store.publish('gap_ledger.jsonl',b''.join(encoded(r)+b'\n' for r in blocked+plan['blocked_documents']))
    if gate:store.publish('acceptance_gate.json',encoded(gate))
    if not synthetic:store.publish('source_catalog.json',encoded(source_catalog(plan)))
    # Chat views are existing shard CSVs, plus the global entity and filing indices in SQLite.
    manifest={'snapshot_id':snapshot,'contract_version':VERSION,'synthetic':synthetic,'shards':shards,
        'snapshot_cutoff':plan['created_at'],'plan_sha256':digest,'tables':list(TABLES),'rights_status':'BLOCKED','export_allowed':False,
        'artifacts':{p.relative_to(root).as_posix():{'sha256':file_hash(p),'byte_count':p.stat().st_size} for p in out.iterdir() if p.is_file()}}
    store.publish('manifest.json',encoded(manifest))
    tables=catalog()
    for spec in tables.values():spec['path_base']='each manifest.shards[].package -> CURRENT snapshot'
    index={'contract_version':VERSION,'CURRENT_snapshot':{'pointer':'CURRENT.json'},'tables':tables,
        'snapshot_id':{'resolve':'CURRENT.json','field':'snapshot_id'},
        'coverage':{'resolve':'CURRENT snapshot/coverage_summary.json'},
        'definition_versions':{'resolve':'each verified shard snapshot/dataset_index.json','field':'definition_versions'},
        'read_order':['dataset_index.json','CURRENT.json','snapshot manifest','locator.sqlite','selected partition package','lineage'],
        'rights_status':'BLOCKED','export_allowed':False,'system_replay':'NOT ESTABLISHED'}
    PrivateStore(root).publish('dataset_index.json',encoded(index))
    # New root only. A current pointer is created once, never overwrites legacy P5.5 CURRENT.
    PrivateStore(root).publish('CURRENT.json',encoded({'snapshot_id':snapshot,'manifest':(out/'manifest.json').relative_to(root).as_posix(),
        'manifest_sha256':file_hash(out/'manifest.json'),'manifest_byte_count':(out/'manifest.json').stat().st_size,
        'contract_version':VERSION}))
    return summary


class PartitionedDataset:
    def __init__(self,root,*,codec=None,allow_synthetic=False):
        self.root=private_path(root);self.codec=codec;self.synthetic=allow_synthetic
        current=json.loads((self.root/'CURRENT.json').read_bytes())
        if current['contract_version']!=VERSION or current['manifest']!='snapshots/'+current['snapshot_id']+'/manifest.json':
            raise ContractError('federation_pointer_mismatch')
        path=safe_path(self.root,current['manifest']);raw=path.read_bytes()
        if (sha256(raw),len(raw))!=(current['manifest_sha256'],current['manifest_byte_count']):raise ContractError('federation_manifest_changed')
        self.manifest=json.loads(raw)
        if (self.manifest['contract_version']!=VERSION or self.manifest['synthetic']!=allow_synthetic or
                self.manifest['snapshot_id']!=current['snapshot_id']):raise ContractError('federation_contract_mismatch')
        for relative,a in self.manifest['artifacts'].items():
            p=safe_path(self.root,relative)
            if p.stat().st_size!=a['byte_count'] or file_hash(p)!=a['sha256']:raise ContractError('federation_artifact_changed')
        self.index=json.loads((path.parent/'coverage_summary.json').read_bytes());self.shards=self.manifest['shards']
        self.db=sqlite3.connect((path.parent/'locator.sqlite').as_uri()+'?mode=ro',uri=True)

    def close(self):self.db.close()

    def shard(self,n):
        s=self.shards[n];root=safe_path(self.root,s['package'])
        if file_hash(root/'CURRENT.json')!=s['CURRENT_sha256']:raise ContractError('partition_pointer_changed')
        d=Dataset(root,codec=self.codec,allow_synthetic=self.synthetic)
        if file_hash(d.path/'manifest.json')!=s['manifest_sha256']:raise ContractError('partition_manifest_changed')
        return d

    def locate(self,table,key):
        source='exclusive_locations' if table in EXCLUSIVE else 'shared_locations'
        return [r[0] for r in self.db.execute('SELECT shard FROM '+source+' WHERE kind=? AND id=? ORDER BY shard',(ROUTED.index(table),binary_key(key)))]

    def entity_shards(self,entity):
        return [r[0] for r in self.db.execute('SELECT shard FROM entity_shards WHERE entity=? ORDER BY shard',(entity,))]

    def query(self,command,**args):
        if command=='company':
            rows=[]
            for (raw,) in self.db.execute('SELECT payload FROM entities ORDER BY id'):
                e=json.loads(raw)
                if args.get('entity') and e['entity_id']!=args['entity']:continue
                if args.get('code') and args['code'] not in e['codes']:continue
                if args.get('name') and not any(args['name'].casefold() in n.casefold() for n in e['names']):continue
                rows.append(e)
            return {'rows':rows,'names_are_join_keys':False}
        if command in ('facts','filings','joins'):
            entity=args['entity'];docs=[];facts=[];joins=[]
            for n in self.entity_shards(entity):
                d=self.shard(n)
                docs.extend(r for r in d.rows('documents') if r.get('edinet_code') and 'edinet:'+r['edinet_code']==entity)
                if command=='facts':facts.extend(r for r in d.rows('canonical_facts') if 'edinet:'+r['edinet_code']==entity)
                if command=='joins':joins.extend(r for r in d.rows('pit_join_rows') if r['entity_id']==entity)
            if command=='filings':return {'rows':docs}
            if command=='joins':return {'rows':joins,'execution_claim':False}
            at=datetime.fromisoformat(args['as_of']);aware(at)
            return fact_view(facts,docs,mode='as_of',decision_at=at,snapshot_cutoff=datetime.fromisoformat(self.index['snapshot_cutoff']),
                replay=args.get('replay','public_reconstruction'),allow_synthetic_for_tests=self.synthetic)
        if command in ('compare','failures'):
            if not args.get('doc_id'):raise ContractError('document_filter_required_for_partitioned_ledger')
            return {'rows':[r for n in self.locate('documents',args['doc_id']) for r in self.shard(n).query(command,**args)['rows']]}
        if command=='lineage':
            for field,table in [('fact_id','canonical_facts'),('research_row_id','pit_join_rows'),('source_row_id','derived_source_rows'),('comparison_id','derived_source_links')]:
                if args.get(field):
                    return {'occurrences':[{'partition':self.shards[n]['job_id'],'lineage':self.shard(n).query(command,**args),
                        'private_stage_archive':self.shards[n]['evidence_archive'],
                        'private_evidence_manifest':self.shards[n].get('evidence_manifest'),
                        'evidence_manifest_sha256':self.shards[n].get('evidence_manifest_sha256')} for n in self.locate(table,args[field])],
                        'independent_evidence_increment':0,'original_bytes_rechecked':False}
        if command=='validate':
            results=[]
            for n,s in enumerate(self.shards):
                d=self.shard(n)
                if file_hash(safe_path(self.root,s['evidence_archive']))!=s['evidence_sha256']:raise ContractError('partition_evidence_changed')
                if s.get('evidence_manifest') and file_hash(safe_path(self.root,s['evidence_manifest']))!=s['evidence_manifest_sha256']:
                    raise ContractError('partition_evidence_manifest_changed')
                results.append({'partition':s['job_id'],'validation':d.verification})
            return {'status':'PASS','partitions':results,'rights_status':'BLOCKED','export_allowed':False}
        raise ContractError('unknown_query')
