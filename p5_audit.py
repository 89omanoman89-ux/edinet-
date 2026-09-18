"""Offline private P5 audit, with byte/row replay and immutable P0-P4 inputs."""
import argparse
from collections import Counter, defaultdict
import io
import json
from pathlib import Path
import re

from derived_sources import (DEFINITION, DEI, DEI_FIELDS, MART_FIELDS, document_link, original_index,
    compare_fact, compare_context, compare_relation, mart_components, scalar_equal)
from evidence_core import ContractError
from financial_facts import reverse_verify
from filing_catalog import edinet_metadata
from local_edinet import LocalArchive
from metadata_gap_audit import ReadOnlyEvidence, snapshot_fingerprints
from p5_acquisition import json_value
from source_acquisition import PrivateStore, encoded, sha256
from source_documentation import acceptance_states, documentation_acceptance


def verify_document_metadata(archive,document):
    """Document identity also supports unlisted filers with null security codes."""
    proof={'doc_id':document['doc_id'],'status':'PASS','missing_reason':None,'locators':[]}
    try:
        if not document.get('metadata_locators'):raise ContractError('official_metadata_missing')
        for loc in document['metadata_locators']:
            raw,_=archive._bytes(loc['relative_path'])
            if sha256(raw)!=loc['source_artifact_sha256']:raise ContractError('official_metadata_integrity_failed')
            rows,_=edinet_metadata(raw)
            actual=[r for r in rows if r['docID']==document['doc_id'] and r['seqNumber']==loc['seqNumber']]
            if actual!=[loc['provider_fields']]:raise ContractError('official_metadata_row_mismatch')
            if actual[0]['edinetCode']!=document['edinet_code'] or actual[0]['secCode']!=document.get('secCode'):
                raise ContractError('official_metadata_identifier_mismatch')
            if json.loads(raw)['metadata']['parameter']['date']!=loc['day']:raise ContractError('official_metadata_day_mismatch')
            proof['locators'].append(loc)
    except (ContractError,KeyError,ValueError) as exc:
        proof.update(status='BLOCKED',missing_reason=str(exc) if isinstance(exc,ContractError) else 'official_metadata_schema_invalid')
    return proof


class RecordedRanges(io.RawIOBase):
    """Replay only saved, hash-checked ranges. Missing bytes never trigger networking."""
    def __init__(self,store,evidence):
        self.size=evidence['member_size'];self.offset=evidence.get('member_offset',0);self.position=0
        self.ranges=[];etags=set()
        for a in evidence['artifacts']:
            raw=store.read_raw(a)
            if a.get('range_start') is None:raise ContractError('range_locator_missing')
            self.ranges.append((a['range_start']-self.offset,raw));etags.add(a.get('etag'))
        if len(etags)!=1 or None in etags:raise ContractError('range_version_unverified')
        if evidence.get('tar_header',{}).get('etag',next(iter(etags))) not in etags:raise ContractError('range_version_changed')
    def readable(self):return True
    def seekable(self):return True
    def tell(self):return self.position
    def seek(self,offset,whence=0):
        pos=offset if whence==0 else self.position+offset if whence==1 else self.size+offset if whence==2 else -1
        if not 0<=pos<=self.size:raise ContractError('recorded_seek_outside_member')
        self.position=pos;return pos
    def read(self,size=-1):
        size=self.size-self.position if size<0 else min(size,self.size-self.position);pieces=[]
        while size:
            chunks=[(start,b) for start,b in self.ranges if start<=self.position<start+len(b)]
            if not chunks:raise ContractError('recorded_range_missing')
            start,raw=max(chunks,key=lambda x:x[0]+len(x[1]));n=min(size,start+len(raw)-self.position)
            pieces.append(raw[self.position-start:self.position-start+n]);self.position+=n;size-=n
        return b''.join(pieces)
    def readinto(self,buffer):
        b=self.read(len(buffer));buffer[:len(b)]=b;return len(b)


def verify_source_rows(store,bundle,synthetic=False):
    grouped=defaultdict(list)
    for row in bundle['rows']:grouped[row['asset_id']].append(row)
    verified=set();failures=[]
    for asset in bundle['assets']:
        rows=grouped.pop(asset['asset_id'],[])
        try:
            if sha256(encoded({k:v for k,v in asset.items() if k!='asset_id'}))!=asset['asset_id']:raise ContractError('asset_manifest_hash_mismatch')
            evidence=asset['evidence']
            if asset.get('format')=='synthetic_jsonl':
                if not synthetic:raise ContractError('synthetic_not_empirical')
                original=[json.loads(x) for x in store.read_raw(evidence['artifacts'][0]).splitlines()]
                retrieve=lambda r:original[r['locator']['line_number']-1]
            elif asset['source_id']=='numad':
                original=store.read_raw(evidence['artifacts'][0]).splitlines()
                retrieve=lambda r:json.loads(original[r['locator']['line_number']-1])
            else:
                import pyarrow.parquet as pq
                stream=io.BytesIO(store.read_raw(evidence['artifacts'][0])) if evidence['scope']=='complete parquet file' else RecordedRanges(store,evidence)
                parquet=pq.ParquetFile(stream);cache={}
                if str(parquet.schema_arrow)!=asset['schema']:raise ContractError('source_schema_mismatch')
                if parquet.metadata.num_rows!=asset['file_row_count']:raise ContractError('source_row_count_mismatch')
                def retrieve(r):
                    group=r['locator']['row_group']
                    if group not in cache:cache[group]=parquet.read_row_group(group)
                    return json_value(cache[group].slice(r['locator']['row_index'],1).to_pylist()[0])
            for row in rows:
                if row['source_id']!=asset['source_id'] or row['table']!=asset['table']:raise ContractError('source_asset_mismatch')
                if sha256(encoded({k:v for k,v in row.items() if k!='source_row_id'}))!=row['source_row_id']:raise ContractError('source_row_id_mismatch')
                original_row=retrieve(row)
                if original_row!=row['provider_fields'] or sha256(encoded(original_row))!=row['locator']['row_sha256']:
                    raise ContractError('source_row_reverse_mismatch')
            verified.update(r['source_row_id'] for r in rows)
        except (ContractError,ValueError,KeyError,IndexError,OSError,ImportError) as exc:
            failures.append({'asset_id':asset['asset_id'],'source_id':asset['source_id'],'table':asset['table'],
                'reason':str(exc) if isinstance(exc,ContractError) else 'source_replay_failed','status':'BLOCKED'})
    if grouped:raise ContractError('orphan_source_rows')
    return verified,failures


def run(edinet_root,p3_snapshot,input_dir,private_dir,snapshot,*,synthetic=False):
    if not re.fullmatch(r'[A-Za-z0-9_-]+',snapshot):raise ContractError('invalid_snapshot_id')
    p3,source=Path(p3_snapshot).resolve(),Path(input_dir).resolve();output=(Path(private_dir)/snapshot).resolve()
    for path in (p3,source,Path(edinet_root).resolve()):
        LocalArchive._outside_git(path)
        if path==output or path in output.parents:raise ContractError('output_inside_input')
    store=PrivateStore(output)
    if any(output.iterdir()):raise ContractError('snapshot_already_exists')
    before=snapshot_fingerprints(p3);source_before=snapshot_fingerprints(source)
    bundle=json.loads((source/'bundle.json').read_bytes());inputs=PrivateStore(source)
    selected=bundle['selection']['doc_ids']
    if not selected or len(selected)>10 or len(set(selected))!=len(selected):raise ContractError('invalid_p5_document_selection')
    code_files={name:sha256((Path(__file__).parent/name).read_text(encoding='utf-8').encode()) for name in
        ('derived_sources.py','p5_audit.py','p5_acquisition.py','p5_collect.py','financial_facts.py','original_tie.py',
         'dated_pit.py','metadata_gap_audit.py','local_edinet.py','source_acquisition.py',
         'source_documentation.py','registry/p5_documentation_reviews.json')}
    review_raw=(Path(__file__).parent/'registry/p5_documentation_reviews.json').read_bytes()
    review_registry=json.loads(review_raw)
    p3_plan=json.loads((p3/'audit_plan.json').read_bytes())
    common={'snapshot_id':snapshot,'p3_snapshot_id':p3_plan['snapshot_id'],'code_sha':sha256(encoded(code_files)),'definition_version':DEFINITION,
            'synthetic':synthetic,'rights_review':'BLOCKED','export_allowed':False}
    def save(name,obj):store.publish(name,encoded(dict(common,**obj))+b'\n')
    def lines(name,rows):store.publish(name,b''.join(encoded(dict(common,**r))+b'\n' for r in rows))
    documents=[json.loads(x) for x in (p3/'documents.jsonl').read_bytes().splitlines()]
    docs={d['doc_id']:d for d in documents if d['doc_id'] in selected}
    if set(docs)!=set(selected):raise ContractError('selected_document_not_in_p3')
    if any(d.get('synthetic') for d in docs.values()) and not synthetic:raise ContractError('synthetic_not_empirical')
    if sha256((p3/'documents.jsonl').read_bytes())!=bundle['selection']['p3_document_sha256']:raise ContractError('p3_selection_hash_mismatch')
    facts=[json.loads(x) for x in (p3/'canonical_facts.jsonl').read_bytes().splitlines() if json.loads(x)['doc_id'] in docs]
    config=json.loads((p3/'canonical_fact_definitions.json').read_bytes())['definitions']
    archive=ReadOnlyEvidence(str(Path(edinet_root).resolve()),store,provenance_class='synthetic_fixture' if synthetic else 'preexisting_local_official_archive')
    save('audit_plan.json',{'selection':bundle['selection'],'code_files':code_files,'input_bundle_sha256':sha256((source/'bundle.json').read_bytes()),
        'canonical_write_policy':'read_only_no_mapping_promotion','source_classes':['official_original','derived_from_edinet','independent_external']})
    save('definitions.json',{'provider_normalized_component_rules':MART_FIELDS,'dei_field_rules':DEI_FIELDS,
        'p3_canonical_definition_sha256':sha256(encoded(config)),
        'text_rule':'HTML data extraction then whitespace removal; retain each provider string/hash separately',
        'evidence_group_rule':'same doc_id + original ZIP hash is one upstream group; mirror adds zero independent evidence'})
    verified,failures=verify_source_rows(inputs,bundle,synthetic)
    save('documentation_review_registry.json',{'registry':review_registry,'registry_byte_sha256':sha256(review_raw)})
    anchors=[verify_document_metadata(archive,d) for d in docs.values()];anchor_by_doc={a['doc_id']:a for a in anchors}
    originals={};canonical_by_locator=defaultdict(list)
    for f in facts:canonical_by_locator[(f['doc_id'],f['xbrl_member'],f['element_index'])].append(f['fact_id'])
    for doc,d in docs.items():
        try:
            if anchor_by_doc[doc]['status']!='PASS':raise ContractError(anchor_by_doc[doc]['missing_reason'])
            raw,_=archive._bytes(d['artifact']['relative_path'])
            reverse_verify(raw,d['artifact'],d,config,[f for f in facts if f['doc_id']==doc])
            originals[doc]=original_index(raw,d['artifact'],d)
        except (ContractError,KeyError) as exc:
            failures.append({'doc_id':doc,'reason':str(exc) if isinstance(exc,ContractError) else 'original_artifact_missing','status':'BLOCKED'})
    rows=bundle['rows'];links={};link_rows=[]
    for provider,table in [('queria','mart_documents'),('youseiushida','filings')]:
        for doc in selected:
            match=[r for r in rows if r['source_id']==provider and r['table']==table and r['provider_fields'].get('doc_id')==doc]
            reason='source_document_metadata_missing' if not match else 'source_document_ambiguous' if len(match)>1 else None
            if not reason:
                r=match[0];p=r['provider_fields']
                if r['source_row_id'] not in verified:reason='source_row_unverified'
                elif not {'doc_id','edinet_code','sec_code','period_end'}<=p.keys() or not any(p.get(k) for k in ('submit_date_time','submit_datetime','submit_date')):reason='source_document_schema_incomplete'
                else:reason=document_link(p,docs[doc])
            if doc not in originals:reason='original_unverified'
            link={'source_id':provider,'doc_id':doc,'entity_id':'edinet:'+docs[doc]['edinet_code'],
                'edinet_sec_code':docs[doc].get('secCode'),'source_row_ids':[r['source_row_id'] for r in match],
                'status':'BLOCKED' if reason else 'PASS','missing_reason':reason,
                'public_available_at':docs[doc]['public_available_at'],'provider_available_at':None,
                'provider_available_at_missing_reason':'historical_provider_delivery_unknown',
                'date_matching':'shared_original_metadata_precision','name_join':False,
                'comparison_scope':'doc_id, provided identifiers, document period, shared submit precision, parent/status fields'}
            links[provider,doc]=link;link_rows.append(link)
    comparisons=[]
    origin_by_id={o['origin_id']:o for idx in originals.values() for kind in ('facts','contexts','relations') for o in idx[kind]}
    def emit(row,doc,kind,reason,origin_ids=(),*,field=None,components=(),representation='provider_extracted'):
        if kind not in {'exact_match','extraction_difference','context_difference','unit_difference','scope_difference','revision_difference','text_difference','missing_in_source','unresolved'}:raise ContractError('unknown_comparison_class')
        canonical=sorted({f for oid in origin_ids for f in canonical_by_locator.get((doc,origin_by_id[oid]['member'],origin_by_id[oid].get('element_index')),[])})
        record={'source_row_id':row['source_row_id'],'source_id':row['source_id'],'source_class':'derived_from_edinet','table':row['table'],
            'doc_id':doc,'entity_id':'edinet:'+docs[doc]['edinet_code'],'field':field,'comparison':kind,
            'status':'PASS' if kind=='exact_match' else 'BLOCKED','missing_reason':reason,'origin_ids':list(origin_ids),
            'canonical_fact_ids':canonical,'canonical_mapping_promoted':False,'representation':representation,
            'component_row_ids':list(components),'upstream_evidence_group':originals.get(doc,{}).get('upstream_evidence_group'),
            'independent_evidence_increment':0,'public_available_at':docs[doc]['public_available_at'],
            'provider_available_at':None,'provider_available_at_missing_reason':'historical_provider_delivery_unknown'}
        record['comparison_id']=sha256(encoded(record));comparisons.append(record)
    pending_marts=[]
    for r in rows:
        p=r['provider_fields'];provider,table=r['source_id'],r['table'];doc=p.get('doc_id')
        if table=='mart_companies':
            matches=[d for d in selected if docs[d]['edinet_code']==p.get('edinet_code')]
            for d in matches:
                reason=None if p.get('sec_code')==docs[d].get('secCode') else 'current_master_code_differs'
                if d not in originals:reason='original_unverified'
                if r['source_row_id'] not in verified:reason='source_row_unverified'
                emit(r,d,'unresolved' if reason else 'exact_match',reason,representation='current_entity_master_only')
            continue
        if doc not in docs:raise ContractError('source_row_outside_fixed_selection')
        reason='source_row_unverified' if r['source_row_id'] not in verified else None
        if doc not in originals:reason='original_unverified'
        if not reason:reason=document_link(p,docs[doc]) if provider=='numad' else links[provider,doc]['missing_reason']
        if not reason and any(k in p and p[k]!=docs[doc].get(target) for k,target in (('edinet_code','edinet_code'),('sec_code','secCode'))):reason='identifier_or_period_mismatch'
        if not reason and table=='mart_business_results':reason=document_link(p,docs[doc])
        if reason:emit(r,doc,'revision_difference' if reason=='revision_difference' else 'unresolved',reason);continue
        idx=originals[doc]
        if table in ('mart_documents','filings'):emit(r,doc,'exact_match',None,representation='document_metadata');continue
        if table=='mart_business_results':pending_marts.append(r);continue
        if table=='contexts':kind,why,loc=compare_context(p,idx);emit(r,doc,kind,why,loc);continue
        if table in ('calc_edges','def_parents'):kind,why,loc=compare_relation(table,p,idx);emit(r,doc,kind,why,loc);continue
        if table=='dei':
            for field,tag in DEI_FIELDS.items():
                matches=[f for f in idx['facts'] if f['qname']=='{'+DEI+'}'+tag]
                loc=[f['origin_id'] for f in matches];value=p.get(field)
                if isinstance(value,bool):value=str(value).lower()
                kind='exact_match' if len(matches)==1 and scalar_equal(value,matches[0]['value']) else 'missing_in_source' if value is None and matches else 'unresolved'
                emit(r,doc,kind,None if kind=='exact_match' else 'dei_field_missing_or_not_uniquely_matched',loc,field=field)
            continue
        kind,why,loc=compare_fact(provider,table,p,idx);emit(r,doc,kind,why,loc)
    by_row={c['source_row_id']:c for c in comparisons if c['table']=='stg_financial_facts'}
    stg=[r for r in rows if r['source_id']=='queria' and r['table']=='stg_financial_facts']
    for r in pending_marts:
        p=r['provider_fields'];doc=p['doc_id']
        for field in MART_FIELDS:
            components=mart_components(p,field,stg);cs=[by_row[x['source_row_id']] for x in components]
            loc=sorted({o for c in cs for o in c['origin_ids']})
            if p.get(field) is None:kind,why='missing_in_source','provider_normalized_value_null'
            elif len(cs)!=1:kind,why='unresolved','provider_normalization_components_missing_or_ambiguous'
            elif cs[0]['status']!='PASS':kind,why=cs[0]['comparison'],'normalization_component_not_source_tied'
            elif not scalar_equal(p[field],components[0]['provider_fields']['value']):kind,why='extraction_difference','normalized_view_value_differs'
            else:kind,why='exact_match',None
            emit(r,doc,kind,why,loc,field=field,components=[x['source_row_id'] for x in components],representation='provider_normalized_view')
    # A complete grid records absence rather than silently dropping missing providers/tables.
    expected={'queria':['mart_companies','mart_documents','mart_business_results','stg_financial_facts'],
              'youseiushida':['filings','line_items','contexts','text_blocks','dei','calc_edges','def_parents'],'numad':['text_blocks']}
    matrix=[]
    for doc in selected:
        for provider,tables in expected.items():
            for table in tables:
                actual=[c for c in comparisons if c['doc_id']==doc and c['source_id']==provider and c['table']==table]
                scoped=[a for a in bundle['assets'] if a['source_id']==provider and a['table']==table and doc in a['doc_scope']]
                reason=None if actual else 'missing_in_source' if scoped else 'source_table_not_acquired'
                matrix.append({'doc_id':doc,'source_id':provider,'table':table,'comparison_counts':dict(Counter(c['comparison'] for c in actual)),
                    'comparison_ids':[c['comparison_id'] for c in actual],'missing_reason':reason,'coverage_scope':'fixed selection only'})
                if reason:failures.append({'doc_id':doc,'source_id':provider,'table':table,'reason':reason,'status':'BLOCKED'})
    failures.extend({'doc_id':c['doc_id'],'source_id':c['source_id'],'comparison_id':c['comparison_id'],'reason':c['missing_reason'],
                     'classification':c['comparison'],'status':'BLOCKED'} for c in comparisons if c['status']!='PASS')
    acceptance=[]
    for provider in expected:
        src=bundle['sources'].get(provider,{});subset=[c for c in comparisons if c['source_id']==provider]
        provider_rows=[r['provider_fields'] for r in rows if r['source_id']==provider]
        dates={}
        for key in ('submit_date','submit_datetime','submit_date_time','period_start','period_end','period_instant'):
            values=sorted({r[key] for r in provider_rows if isinstance(r.get(key),str) and r[key]})
            dates[key]={'min':values[0],'max':values[-1]} if values else None
        states=acceptance_states(documentation_acceptance(inputs,provider,src.get('documentation',[]),review_registry),
            data_fetched='PASS' if any(r['source_id']==provider and r['source_row_id'] in verified for r in rows) else 'BLOCKED',
            schema_profiled='PASS' if any(a['source_id']==provider and a.get('schema') for a in bundle['assets']) else 'BLOCKED',
            original_tied='PASS' if any(c['status']=='PASS' and c['origin_ids'] for c in subset) else 'BLOCKED')
        acceptance.append(dict(src,**states,
            docs_checked=states['documentation_checked'],file_fetched=states['data_fetched'],original_fact_tied=states['original_tied'],
            source_class='derived_from_edinet',source_rows_verified=sum(r['source_id']==provider and r['source_row_id'] in verified for r in rows),
            acceptance_scope='bounded sample only; not full-source approval',production_approved=False,
            schema_profiles=[{k:v for k,v in a.items() if k not in ('evidence',)} for a in bundle['assets'] if a['source_id']==provider],
            comparison_counts=dict(Counter(c['comparison'] for c in subset)),
            rights_evidence={'queria':'dataset declares JP-FSA-EDINET; independent rights review unresolved',
                'youseiushida':'AGPL-3.0-or-later repository software license is not a verified dataset redistribution grant',
                'numad':'dataset card declares Apache-2.0; upstream EDINET rights kept separate'}[provider],
            upstream_terms_url='https://disclosure2.edinet-fsa.go.jp/',rights_review='BLOCKED',
            provider_replay='NOT ESTABLISHED',independent_primary_evidence=False,
            observed_date_ranges=dates,coverage_basis='selected documents and inspected physical tables; not full source validation',
            identifiers={'doc_id':len({r['doc_id'] for r in provider_rows if r.get('doc_id')}),
                         'edinet_code':len({r['edinet_code'] for r in provider_rows if r.get('edinet_code')})},
            known_limitations={'queria':['current company master is not dated identity history','corrections not reflected in financial view',
                'data build commit unknown','stg audit uses exact raw value/context projection; provider normalized values remain separate'],
                'youseiushida':['release sampled by table/doc_id; full archive digest not verified','flattened def_parents drops QName/role/path',
                'duplicate original members remain ambiguous'],
                'numad':['2022 JSONL byte prefix only','local tag may lack QName/context','day-only submit date; provider delivery time unknown']}[provider]))
    lines('derived_observations.jsonl',[dict(r,source_class='derived_from_edinet') for r in rows])
    lines('metadata_proofs.jsonl',anchors)
    lines('original_artifacts.jsonl',[{'doc_id':d['doc_id'],'artifact':d.get('artifact'),
        'public_available_at':d.get('public_available_at'),'provenance_class':d.get('provenance_class')} for d in docs.values()])
    linked_facts={f for c in comparisons for f in c['canonical_fact_ids']}
    lines('canonical_fact_references.jsonl',[{'fact_id':f['fact_id'],'doc_id':f['doc_id'],'p3_fact':f,
        'p3_fact_sha256':sha256(encoded(f)),'mapping_promoted':False} for f in facts if f['fact_id'] in linked_facts])
    lines('official_observations.jsonl',list(origin_by_id.values()));lines('document_links.jsonl',link_rows)
    lines('comparison_ledger.jsonl',comparisons);lines('source_matrix.jsonl',matrix);lines('failure_ledger.jsonl',failures)
    lines('lineage.jsonl',[{'comparison_id':c['comparison_id'],'source_row_id':c['source_row_id'],'origin_ids':c['origin_ids'],
        'component_row_ids':c['component_row_ids'],'canonical_fact_ids':c['canonical_fact_ids'],'upstream_evidence_group':c['upstream_evidence_group']} for c in comparisons])
    shared=defaultdict(list)
    for c in comparisons:
        for oid in c['origin_ids']:shared[oid].append(c)
    lines('shared_original_views.jsonl',[{'origin_id':oid,'doc_id':origin_by_id[oid]['doc_id'],
        'upstream_evidence_group':origin_by_id[oid]['upstream_evidence_group'],
        'source_views':[{'source_id':c['source_id'],'source_row_id':c['source_row_id'],'comparison_id':c['comparison_id'],
                        'comparison':c['comparison']} for c in cs],
        'canonical_fact_ids':sorted({f for c in cs for f in c['canonical_fact_ids']}),
        'independent_primary_evidence_count':1} for oid,cs in shared.items()])
    save('source_acceptance.json',{'sources':acceptance});save('source_artifacts.json',{'assets':bundle['assets']})
    # Re-read serialized edges and check no orphan or silent canonical write.
    serialized=[json.loads(x) for x in (output/'comparison_ledger.jsonl').read_bytes().splitlines()]
    for c in serialized:
        if c['status']=='PASS' and c['source_row_id'] not in verified:raise ContractError('unverified_source_admitted')
        if any(o not in origin_by_id for o in c['origin_ids']):raise ContractError('orphan_original_lineage')
        if any(f not in {x['fact_id'] for x in facts} for f in c['canonical_fact_ids']):raise ContractError('orphan_canonical_lineage')
        if c['canonical_mapping_promoted'] or c['independent_evidence_increment']:raise ContractError('mirror_promoted')
    after=snapshot_fingerprints(p3);source_after=snapshot_fingerprints(source)
    if before!=after or source_before!=source_after:raise ContractError('private_input_changed')
    save('preservation_proof.json',{'p3_unchanged':True,'p3_before':before,'p3_after':after,
        'derived_inputs_unchanged':True,'derived_before':source_before,'derived_after':source_after,'edinet':archive.prove_unchanged()})
    summary={'documents':len(selected),'entities':len({d['edinet_code'] for d in docs.values()}),'source_rows':len(rows),'verified_source_rows':len(verified),
        'comparison_counts':dict(Counter(c['comparison'] for c in comparisons)),
        'by_source':{s:dict(Counter(c['comparison'] for c in comparisons if c['source_id']==s)) for s in expected},
        'unique_official_evidence_groups':len(originals),'mirror_independent_evidence_increment':0,
        'original_locators_with_multiple_provider_views':sum(len({c['source_id'] for c in cs})>1 for cs in shared.values()),
        'original_locators_with_all_three_provider_views':sum(len({c['source_id'] for c in cs})==3 for cs in shared.values()),
        'canonical_facts_linked':len({f for c in comparisons for f in c['canonical_fact_ids']}),
        'failure_reasons':dict(Counter(f['reason'] for f in failures)),
        'p3_unchanged':True,'full_coverage_audit':'NOT RUN','performance_research':'NOT RUN','p6':'NOT RUN'}
    save('coverage_summary.json',summary);print(json.dumps(summary,ensure_ascii=False));return summary


if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ('edinet-local-root','p3-snapshot','input-dir','private-dir','snapshot'):p.add_argument('--'+name,required=True)
    a=p.parse_args();run(a.edinet_local_root,a.p3_snapshot,a.input_dir,a.private_dir,a.snapshot)
