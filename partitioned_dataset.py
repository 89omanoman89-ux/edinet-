"""Immutable federation of independently validated P5.5 partitions.

The index routes queries; it does not choose between conflicting financial facts.
Repeated market/mirror evidence retains its partition occurrence and source ID.
"""
from collections import Counter,defaultdict
from datetime import datetime
import json
from pathlib import Path
import sqlite3

from coverage_inventory import private_path,file_hash
from dataset_contract import TABLES,payload,safe_path
from dataset_validation import table_key
from evidence_core import ContractError,aware
from expansion_runner import validate_checkpoint
from financial_views import fact_view
from query_dataset import Dataset
from source_acquisition import PrivateStore,encoded,sha256,utcnow

VERSION='private-partitioned-query-v1'
ROUTED=('documents','canonical_facts','pit_join_rows','derived_source_links','derived_source_rows','text_index')


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
    root=private_path(root);plan_raw=(root/'expansion_plan.json').read_bytes();plan=json.loads(plan_raw)
    digest=sha256(plan_raw);out=safe_path(root,'snapshots/'+snapshot)
    store=PrivateStore(out)
    if any(out.iterdir()):raise ContractError('snapshot_already_exists')
    db=sqlite3.connect(out/'locator.sqlite')
    db.executescript('''CREATE TABLE entities (id TEXT PRIMARY KEY,payload BLOB);
        CREATE TABLE entity_shards (entity TEXT,shard INTEGER,PRIMARY KEY(entity,shard));
        CREATE TABLE locations (kind INTEGER,id BLOB,shard INTEGER,PRIMARY KEY(kind,id,shard));
        CREATE TABLE documents (id TEXT PRIMARY KEY,entity TEXT,shard INTEGER);
    ''')
    shards=[];entities={};totals=Counter();states=Counter();years=defaultdict(Counter);blocked=[]
    unique_ids={name:set() for name in ('documents',)}
    # Enforce primary ID uniqueness with SQLite, without holding millions of IDs in RAM.
    db.execute('CREATE TABLE exclusive_ids (kind INTEGER,id BLOB,PRIMARY KEY(kind,id))')
    for job in plan['jobs']:
        folder=root/'jobs'/job['job_id']
        if not (folder/'result.json').is_file():raise ContractError('unfinished_expansion_job')
        result=validate_checkpoint(folder,digest)
        year=job['month'][:4];years[year][result['status']]+=1
        if result['status']!='COMPLETE':
            blocked.append({'job_id':job['job_id'],'doc_ids':job['doc_ids'],'month':job['month'],'reason':result['reason']});continue
        package=folder/'package';data=Dataset(package,codec=codec,allow_synthetic=synthetic)
        number=len(shards)
        entry={'number':number,'job_id':job['job_id'],'package':package.relative_to(root).as_posix(),
            'CURRENT_sha256':file_hash(package/'CURRENT.json'),'manifest_sha256':file_hash(data.path/'manifest.json'),
            'evidence_archive':(folder/'evidence.zip').relative_to(root).as_posix(),
            'evidence_sha256':result['artifacts']['evidence.zip'],'checkpoint':(folder/'result.json').relative_to(root).as_posix(),
            'checkpoint_sha256':file_hash(folder/'result.json'),'validation':data.verification,'coverage':data.index['coverage']}
        shards.append(entry)
        for name,rows in data.tables.items():
            totals[name]+=len(rows)
            if name not in ROUTED:continue
            kind=ROUTED.index(name)
            for row in rows:
                key=table_key(name,row)
                if len(key)!=1:raise ContractError('routing_key_not_scalar')
                identifier=key[0];binary=identifier.encode()
                if len(identifier)==64:
                    try:binary=bytes.fromhex(identifier)
                    except ValueError:pass
                if name in ('documents','canonical_facts','pit_join_rows'):
                    try:db.execute('INSERT INTO exclusive_ids VALUES (?,?)',(kind,binary))
                    except sqlite3.IntegrityError:raise ContractError('duplicate_cross_partition_id:'+name) from None
                db.execute('INSERT INTO locations VALUES (?,?,?)',(kind,binary,number))
        for e in data.rows('entities'):
            entities[e['entity_id']]=merge_entity(entities[e['entity_id']],e) if e['entity_id'] in entities else e
            db.execute('INSERT INTO entity_shards VALUES (?,?)',(e['entity_id'],number))
        for d in data.rows('documents'):
            entity='edinet:'+d['edinet_code'] if d.get('edinet_code') else None
            db.execute('INSERT INTO documents VALUES (?,?,?)',(d['doc_id'],entity,number))
        for r in data.rows('pit_join_rows'):states[r['status']]+=1;years[year]['PIT_'+r['status']]+=1
        db.commit()
    db.executemany('INSERT INTO entities VALUES (?,?)',[(k,encoded(v)) for k,v in sorted(entities.items())])
    # Occurrence counts are deliberately not mislabeled as unique upstream evidence.
    counts={name:db.execute('SELECT COUNT(DISTINCT id) FROM locations WHERE kind=?',(ROUTED.index(name),)).fetchone()[0] for name in ROUTED}
    counts['entities']=len(entities)
    db.commit();db.close()
    summary={'snapshot_id':snapshot,'snapshot_cutoff':plan['created_at'],'contract_version':VERSION,
        'created_at':utcnow(),'code_sha':file_hash(Path(__file__)),'coverage_unique_ids':counts,'table_occurrences':dict(totals),
        'join_states':dict(states),'year_states':{k:dict(v) for k,v in sorted(years.items())},'complete_partitions':len(shards),
        'blocked_partitions':len(blocked),'blocked_documents':plan['blocked_documents'],
        'rights_status':'BLOCKED','export_allowed':False,'full_market_representativeness':'NOT ESTABLISHED',
        'system_replay':'NOT ESTABLISHED','original_bytes_rechecked':'see input preservation proof',
        'query_policy':'full entity revision series across partitions; no name join or missing-value fallback',
        'stage_content_resolution':'checkpoint -> evidence.zip -> stage snapshot/file/one-based line -> original hash/locator'}
    store.publish('coverage_summary.json',encoded(summary))
    store.publish('gap_ledger.jsonl',b''.join(encoded(r)+b'\n' for r in blocked+plan['blocked_documents']))
    # Chat views are existing shard CSVs, plus the global entity and filing indices in SQLite.
    manifest={'snapshot_id':snapshot,'contract_version':VERSION,'synthetic':synthetic,'shards':shards,
        'snapshot_cutoff':plan['created_at'],'plan_sha256':digest,'tables':list(TABLES),'rights_status':'BLOCKED','export_allowed':False,
        'artifacts':{p.relative_to(root).as_posix():{'sha256':file_hash(p),'byte_count':p.stat().st_size} for p in out.iterdir() if p.is_file()}}
    store.publish('manifest.json',encoded(manifest))
    index={'contract_version':VERSION,'CURRENT_snapshot':{'pointer':'CURRENT.json'},'tables':list(TABLES),
        'read_order':['dataset_index.json','CURRENT.json','snapshot manifest','locator.sqlite','selected partition package','lineage'],
        'rights_status':'BLOCKED','export_allowed':False,'system_replay':'NOT ESTABLISHED'}
    PrivateStore(root).publish('dataset_index.json',encoded(index))
    # New root only. A current pointer is created once, never overwrites legacy P5.5 CURRENT.
    PrivateStore(root).publish('CURRENT.json',encoded({'snapshot_id':snapshot,'manifest':(out/'manifest.json').relative_to(root).as_posix(),
        'manifest_sha256':file_hash(out/'manifest.json'),'contract_version':VERSION}))
    return summary


class PartitionedDataset:
    def __init__(self,root,*,codec=None,allow_synthetic=False):
        self.root=private_path(root);self.codec=codec;self.synthetic=allow_synthetic
        current=json.loads((self.root/'CURRENT.json').read_bytes());path=safe_path(self.root,current['manifest'])
        if file_hash(path)!=current['manifest_sha256']:raise ContractError('federation_manifest_changed')
        self.manifest=json.loads(path.read_bytes())
        if self.manifest['contract_version']!=VERSION or self.manifest['synthetic']!=allow_synthetic:raise ContractError('federation_contract_mismatch')
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
        binary=key.encode()
        if len(key)==64:
            try:binary=bytes.fromhex(key)
            except ValueError:pass
        return [r[0] for r in self.db.execute('SELECT shard FROM locations WHERE kind=? AND id=? ORDER BY shard',(ROUTED.index(table),binary))]

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
                        'private_stage_archive':self.shards[n]['evidence_archive']} for n in self.locate(table,args[field])],
                        'independent_evidence_increment':0,'original_bytes_rechecked':False}
        if command=='validate':
            results=[]
            for n,s in enumerate(self.shards):
                d=self.shard(n)
                if file_hash(safe_path(self.root,s['evidence_archive']))!=s['evidence_sha256']:raise ContractError('partition_evidence_changed')
                results.append({'partition':s['job_id'],'validation':d.verification})
            return {'status':'PASS','partitions':results,'rights_status':'BLOCKED','export_allowed':False}
        raise ContractError('unknown_query')
