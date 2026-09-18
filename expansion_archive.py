"""Hash-pinned read-only cross-archive EDINET index. Never copy or modify raw inputs."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import re
import sqlite3
import zlib

from coverage_inventory import daily_path, file_hash, private_path
from evidence_core import ContractError
from filing_catalog import edinet_metadata
from local_edinet import LocalArchive
from revision_series import revision_closure
from source_acquisition import PrivateStore, encoded, sha256, utcnow


def lines(path):
    with Path(path).open(encoding='utf-8') as f:
        for line in f: yield json.loads(line)


def read_frozen(root, entry):
    path=(root/entry['relative_path']).resolve()
    if root not in path.parents: raise ContractError('input_path_escape')
    LocalArchive._outside_git(path)
    st=path.stat();raw=path.read_bytes();after=path.stat()
    if (st.st_size,st.st_mtime_ns,st.st_ino)!=(after.st_size,after.st_mtime_ns,after.st_ino):
        raise ContractError('input_changed_during_read')
    if (len(raw),sha256(raw),st.st_mtime_ns)!=(entry['byte_count'],entry['byte_sha256'],entry['mtime_ns']):
        raise ContractError('frozen_input_changed')
    return raw,st


def build_index(inventory, output):
    inventory,output=private_path(inventory),private_path(output)
    plan=json.loads((inventory/'inventory_plan.json').read_bytes())
    specs={r['id']:r for r in plan['plan']['roots'] if r['kind']=='edinet'}
    roots={k:private_path(v['path']) for k,v in specs.items()}
    if any(output==p or output in p.parents or p in output.parents for p in [inventory,*roots.values()]):
        raise ContractError('index_output_overlaps_input')
    store=PrivateStore(output)
    if any(output.iterdir()): raise ContractError('snapshot_already_exists')
    catalog=inventory/'source_files.jsonl';catalog_sha=file_hash(catalog)
    db=sqlite3.connect(output/'archive.sqlite')
    db.executescript('''
        CREATE TABLE files (locator TEXT PRIMARY KEY, root_id TEXT, relative_path TEXT,
          byte_sha256 TEXT, byte_count INTEGER, mtime_ns INTEGER, doc_id TEXT, kind TEXT);
        CREATE INDEX zip_document ON files(doc_id,kind);
        CREATE TABLE events (doc_id TEXT,parent TEXT,entity TEXT,doc_type TEXT,locator TEXT,seq INTEGER,payload BLOB);
        CREATE INDEX event_document ON events(doc_id);
        CREATE INDEX event_parent ON events(parent);
    ''')
    listings={};failures=[];seen_daily=set();observed=0
    for f in lines(catalog):
        if f['root_id'] not in roots:continue
        relative=f['relative_path'];path=Path(relative)
        doc=path.stem if path.suffix.lower()=='.zip' and re.fullmatch(r'S[0-9A-Z]{7}',path.stem) else None
        daily=daily_path(relative)
        if not (doc or daily or relative.endswith('.manifest.json')):continue
        raw,_=read_frozen(roots[f['root_id']],f)
        locator=f['root_id']+'/'+relative
        db.execute('INSERT INTO files VALUES (?,?,?,?,?,?,?,?)',(locator,f['root_id'],relative,f['byte_sha256'],f['byte_count'],f['mtime_ns'],doc,'zip' if doc else 'daily' if daily else 'sidecar'))
        observed+=1
        if not daily or f['byte_sha256'] in seen_daily:continue
        seen_daily.add(f['byte_sha256'])
        try:
            payload_rows,_=edinet_metadata(raw)
            day=json.loads(raw)['metadata']['parameter']['date']
            listings[locator]={'relative_path':locator,'day':day,'byte_sha256':f['byte_sha256'],
                'byte_count':len(raw),'mtime_ns':f['mtime_ns'],'row_count':len(payload_rows)}
            db.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?)',[(r['docID'],r.get('parentDocID'),r.get('edinetCode'),r.get('docTypeCode'),locator,r['seqNumber'],zlib.compress(encoded(r))) for r in payload_rows])
        except (ContractError,ValueError,KeyError,TypeError) as exc:
            failures.append({'relative_path':locator,'reason':str(exc) if isinstance(exc,ContractError) else 'metadata_schema_invalid'})
    db.commit()
    counts={k:db.execute(sql).fetchone()[0] for k,sql in {
        'metadata_doc_id_count':'SELECT COUNT(DISTINCT doc_id) FROM events',
        'zip_doc_id_count':"SELECT COUNT(DISTINCT doc_id) FROM files WHERE kind='zip'"}.items()}
    db.close()
    if file_hash(catalog)!=catalog_sha:raise ContractError('frozen_inventory_changed')
    manifest={'snapshot_id':output.name,'created_at':utcnow(),'code_sha':file_hash(Path(__file__)),
        'source_inventory':str(inventory),'source_files_sha256':catalog_sha,'roots':{k:str(v) for k,v in roots.items()},
        'database_sha256':file_hash(output/'archive.sqlite'),'files_verified':observed,
        'listings':list(listings.values()),'failures':failures,'counts':counts,
        'status':'BLOCKED' if failures else 'PASS','provenance_class':'preexisting_local_official_archive',
        'rights_review':'BLOCKED','export_allowed':False,
        'scope':'all frozen local archives; no claim of current official completeness; byte variants retained'}
    store.publish('cross_archive_index.json',encoded(manifest))
    return manifest


class SqlLinks:
    def __init__(self,db,children=False):self.db,self.children=db,children
    def get(self,key,default=()):return self[key]
    def __getitem__(self,key):
        if self.children:return {r[0] for r in self.db.execute('SELECT DISTINCT doc_id FROM events WHERE parent=?',(key,))}
        return {tuple(r) for r in self.db.execute('SELECT DISTINCT parent,entity,doc_type FROM events WHERE doc_id=?',(key,))}


class CrossArchive(LocalArchive):
    _identity_catalogs={}
    def __init__(self,root,store,**kwargs):
        super().__init__(str(Path(root).resolve()),store,**kwargs)
        self.manifest=json.loads((self.root/'cross_archive_index.json').read_bytes())
        if file_hash(self.root/'archive.sqlite')!=self.manifest['database_sha256']:raise ContractError('archive_index_corrupt')
        self.db=sqlite3.connect((self.root/'archive.sqlite').as_uri()+'?mode=ro',uri=True)
        self.db.row_factory=sqlite3.Row
        self.roots={k:private_path(v) for k,v in self.manifest['roots'].items()}
        self.observed={}
        self.listings={r['relative_path']:r for r in self.manifest['listings']}

    def close(self):self.db.close()

    def identity_peers(self,documents,*,synthetic=False):
        """Find other observed owners across ALL partitions, then re-read their metadata.

        The SQL payload is only a candidate index. It cannot itself authorize a join.
        Future evidence remains subject to dated_mapping's decision cutoff.
        """
        from p3_audit import metadata_document
        from dated_pit import edinet_identity_evidence
        key=self.manifest['database_sha256']
        if key not in self._identity_catalogs:
            owners=defaultdict(set)
            for e in self.db.execute("SELECT doc_id,entity,payload FROM events WHERE doc_type IN ('120','130')"):
                r=json.loads(zlib.decompress(e['payload']))
                if r.get('secCode'):owners[r['secCode']].add((e['entity'],e['doc_id']))
            self._identity_catalogs[key]=owners
        wanted=set()
        for d in documents:
            wanted.update(doc for entity,doc in self._identity_catalogs[key].get(d.get('secCode'),())
                          if entity!=d.get('edinet_code'))
        cache={};peers=[]
        for doc in sorted(wanted-{d['doc_id'] for d in documents}):
            events=[{'listing':self.listings[e['locator']],'provider_fields':json.loads(zlib.decompress(e['payload']))}
                for e in self.db.execute('SELECT locator,payload FROM events WHERE doc_id=? ORDER BY locator,seq',(doc,))]
            record={'doc_id':doc,'metadata_events':events}
            d=metadata_document(self,record,utcnow(),'identity_support',cache)
            d['synthetic']=synthetic
            peers.append(d)
        return edinet_identity_evidence(self,peers)

    def entry(self,relative):
        row=self.db.execute('SELECT * FROM files WHERE locator=?',(str(relative).replace('\\','/'),)).fetchone()
        if row is None:raise ContractError('unregistered_cross_archive_locator')
        return dict(row)

    def _path(self,relative):
        e=self.entry(relative);root=self.roots[e['root_id']];path=(root/e['relative_path']).resolve()
        if root not in path.parents:raise ContractError('input_path_escape')
        return path

    def _bytes(self,relative):
        e=self.entry(relative);raw,st=read_frozen(self.roots[e['root_id']],e)
        self.observed[str(relative)]=e
        return raw,st

    def file_exists(self,relative):return self._path(relative).is_file()

    def observe(self,relative,*,doc_id=None):
        e=self.entry(relative);self._bytes(relative)
        if doc_id is not None and e['doc_id']!=doc_id:raise ContractError('local_document_id_mismatch')
        side=Path(e['relative_path']).with_suffix('.manifest.json').as_posix()
        actual=self.roots[e['root_id']]/side
        if actual.exists():self._bytes(e['root_id']+'/'+side)
        original=LocalArchive(str(self.roots[e['root_id']]),self.store,provenance_class=self.provenance_class).observe(e['relative_path'],doc_id=doc_id)
        return dict(original,archive_root_id=self.root_id,relative_path=str(relative),origin_artifact=original,
                    cross_archive_index_sha256=self.manifest['database_sha256'])

    def read(self,artifact):
        if artifact['archive_root_id']!=self.root_id:raise ContractError('local_archive_root_mismatch')
        raw,_=self._bytes(artifact['relative_path'])
        if (sha256(raw),len(raw))!=(artifact['byte_sha256'],artifact['byte_count']):raise ContractError('local_byte_integrity_failure')
        return raw

    def zip_index(self,preferred_doc_id=None):
        result=defaultdict(list);seen=set()
        query="SELECT * FROM files WHERE kind='zip'"+(' AND doc_id=?' if preferred_doc_id else '')+' ORDER BY locator'
        for r in self.db.execute(query,(preferred_doc_id,) if preferred_doc_id else ()):
            identity=(r['doc_id'],r['byte_sha256'])
            if identity not in seen:result[r['doc_id']].append(r['locator']);seen.add(identity)
        return dict(result)

    def indexed_series(self,selection,frozen_frame,frozen_manifest,limit):
        primary=selection['challenge']+selection['probability']
        if not primary or len(primary)!=len(set(primary)):raise ContractError('invalid_primary_selection')
        if any(d not in frozen_frame for d in primary):raise ContractError('sample_not_in_frozen_frame')
        if frozen_manifest.get('archive_root_id')!=self.root_id:raise ContractError('archive_root_mismatch')
        selected,excluded=revision_closure(primary,SqlLinks(self.db),SqlLinks(self.db,True),limit)
        records={}
        for doc in sorted(selected):
            events=[]
            for e in self.db.execute('SELECT locator,payload FROM events WHERE doc_id=? ORDER BY locator,seq',(doc,)):
                events.append({'listing':self.listings[e['locator']],'provider_fields':json.loads(zlib.decompress(e['payload']))})
            events.sort(key=lambda e:(e['listing']['day'],e['provider_fields']['seqNumber'],e['listing']['relative_path']))
            zips=[]
            for relative in self.zip_index(doc).get(doc,[]):
                e=self.entry(relative)
                zips.append({'relative_path':relative,'byte_count':e['byte_count'],'mtime_ns':e['mtime_ns']})
            if doc in frozen_frame and frozen_frame[doc].get('zip_files') not in (None,[],zips):
                raise ContractError('frozen_cross_archive_zip_mismatch')
            records[doc]={'doc_id':doc,'zip_files':zips,'metadata_events':events}
        days=sorted({l['day'] for l in self.listings.values()})
        inventory={'status':self.manifest['status'],'failures':self.manifest['failures'],
            'scope':self.manifest['scope'],'listing_count':len(self.listings),
            'metadata_doc_id_count':self.manifest['counts']['metadata_doc_id_count'],
            'date_range':[days[0],days[-1]] if days else None,'listings':list(self.listings.values()),
            'cross_archive_database_sha256':self.manifest['database_sha256']}
        inventory['inventory_sha256']=sha256(encoded(inventory))
        plan={'primary':primary,'revision_support':sorted(selected-set(primary)),'all':sorted(selected),
            'selection_rule':'frozen_P2_bidirectional_recursive_parentDocID_closure_annual_reports_v1',
            'limit':limit,'metadata_inventory_sha256':inventory['inventory_sha256'],
            'excluded_non_revision_relations':[{'parentDocID':p,'doc_id':d,'doc_types':list(t),'reason':'non_revision_document_type'} for p,d,t in sorted(excluded)]}
        return inventory,plan,records

    def prove_unchanged(self):
        for relative in list(self.observed):self._bytes(relative)
        if file_hash(self.root/'archive.sqlite')!=self.manifest['database_sha256']:raise ContractError('archive_index_corrupt')
        return {'status':'PASS','file_count':len(self.observed),'files':self.observed,
                'cross_archive_database_sha256':self.manifest['database_sha256']}


def make_frame(archive,doc_ids,output):
    """Freeze exact primary IDs; child revisions remain independently discoverable."""
    if len(doc_ids)!=len(set(doc_ids)) or not doc_ids:raise ContractError('invalid_primary_selection')
    store=PrivateStore(private_path(output))
    if any(store.root.iterdir()):raise ContractError('snapshot_already_exists')
    selection={'challenge':list(doc_ids),'probability':[]}
    frozen={'archive_root_id':archive.root_id,'snapshot_id':store.root.name,
            'cross_archive_database_sha256':archive.manifest['database_sha256']}
    _,_,records=archive.indexed_series(selection,{d:{'zip_files':[]} for d in doc_ids},frozen,300)
    store.publish('selected_documents.json',encoded(selection))
    store.publish('universe_manifest.json',encoded(frozen))
    store.publish('universe_documents.jsonl',b''.join(encoded(r)+b'\n' for r in records.values()))
    audits=[]
    for d,r in records.items():
        if len(r['zip_files'])==1:audits.append({'doc_id':d,'zip_sha256':archive.entry(r['zip_files'][0]['relative_path'])['byte_sha256']})
    store.publish('document_audit.jsonl',b''.join(encoded(a)+b'\n' for a in audits))
    return records


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inventory',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    m=build_index(a.inventory,a.output)
    print(json.dumps({'status':m['status'],'files_verified':m['files_verified'],**m['counts']}))
