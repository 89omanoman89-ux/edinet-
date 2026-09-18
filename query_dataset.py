"""Read-only queries over a verified private package. JSON output is private."""
import argparse
from collections import defaultdict, deque
from datetime import datetime
import json

from dataset_contract import payload
from dataset_validation import read_snapshot, resolve_current, table_key, validate_tables
from evidence_core import ContractError, aware
from financial_views import fact_view


class Dataset:
    def __init__(self, root, *, codec=None, allow_synthetic=False):
        self.path=resolve_current(root)
        self.manifest,self.index,self.tables=read_snapshot(self.path,codec=codec,allow_synthetic=allow_synthetic)
        self.verification=validate_tables(self.tables)
        self.synthetic=allow_synthetic

    def rows(self, table): return [payload(r) for r in self.tables[table]]

    def company(self, *, code=None, name=None, entity=None):
        # A name may return several entities; never use it to choose a mapping.
        return [r for r in self.rows('entities') if (code is None or code in r['codes'])
            and (entity is None or r['entity_id']==entity)
            and (name is None or any(name.casefold() in n.casefold() for n in r['names']))]

    def facts(self, entity, as_of, replay='public_reconstruction'):
        decision=datetime.fromisoformat(as_of);aware(decision)
        docs=[r for r in self.rows('documents') if 'edinet:'+r['edinet_code']==entity]
        facts=[r for r in self.rows('canonical_facts') if 'edinet:'+r['edinet_code']==entity]
        if not docs: return {'facts':[], 'blocked':[{'reason':'entity_not_in_snapshot'}]}
        return fact_view(facts,docs,mode='as_of',decision_at=decision,
            snapshot_cutoff=datetime.fromisoformat(self.index['snapshot_cutoff']),replay=replay,
            allow_synthetic_for_tests=self.synthetic)

    def lineage(self, table, identifier):
        indices={n:{table_key(n,r):payload(r) for r in rows} for n,rows in self.tables.items() if n not in ('lineage','failures')}
        if table not in indices or (identifier,) not in indices[table]: raise ContractError('lineage_start_not_found')
        adjacency=defaultdict(list)
        for e in self.rows('lineage'): adjacency[e['from_table'],e['from_id']].append(e)
        seen=set();queue=deque([(table,identifier)]);nodes=[];edges=[]
        while queue:
            t,key=queue.popleft()
            if (t,key) in seen: continue
            seen.add((t,key));nodes.append({'table':t,'id':key,'record':indices[t][(key,)]})
            for e in adjacency[t,key]: edges.append(e);queue.append((e['to_table'],e['to_id']))
        return {'nodes':nodes,'edges':edges,'original_bytes_rechecked':False,
            'external_content':'Locate using document artifact relative_path and hash; originals are not embedded'}

    def query(self, command, **args):
        if command=='company': return {'rows':self.company(**{k:args.get(k) for k in ('code','name','entity')})}
        if command=='facts': return self.facts(args['entity'],args['as_of'],args.get('replay','public_reconstruction'))
        if command=='compare': return {'rows':[r for r in self.rows('derived_source_links') if r['doc_id']==args['doc_id']]}
        if command=='filings': return {'rows':[r for r in self.rows('documents') if 'edinet:'+r['edinet_code']==args['entity']]}
        if command=='joins': return {'rows':[r for r in self.rows('pit_join_rows') if r['entity_id']==args['entity']],
            'scope':'Stored audited decisions only; entry outcome is not a decision feature; includes BLOCKED'}
        if command=='lineage':
            for field,table in [('fact_id','canonical_facts'),('research_row_id','pit_join_rows'),
                ('source_row_id','derived_source_rows'),('comparison_id','derived_source_links')]:
                if args.get(field):
                    if field=='source_row_id':
                        matches=[r for r in self.rows('derived_source_links') if r['source_row_id']==args[field]]
                        return {'comparisons':[self.lineage('derived_source_links',r['comparison_id']) for r in matches],
                            'source_rows':[r for r in self.rows('derived_source_rows') if r['source_row_id']==args[field]]}
                    return self.lineage(table,args[field])
        if command=='failures':
            return {'rows':[dict(payload(r),input_stage=r['input_stage'],input_file=r['input_file'],input_line=r['input_line'])
                for r in self.tables['failures'] if (not args.get('doc_id') or r['doc_id']==args['doc_id'])
                and (not args.get('reason') or payload(r).get('reason')==args['reason'])]}
        if command=='validate': return self.verification
        raise ContractError('unknown_query')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',required=True);p.add_argument('--limit',type=int,default=100);p.add_argument('--offset',type=int,default=0)
    sub=p.add_subparsers(dest='command',required=True)
    c=sub.add_parser('company');group=c.add_mutually_exclusive_group(required=True)
    for flag in ('code','name','entity'): group.add_argument('--'+flag)
    f=sub.add_parser('facts');f.add_argument('--entity',required=True);f.add_argument('--as-of',required=True)
    f.add_argument('--replay',choices=['public_reconstruction','system_replay'],default='public_reconstruction')
    for cmd in ('filings','joins'):
        c=sub.add_parser(cmd);c.add_argument('--entity',required=True)
    c=sub.add_parser('compare');c.add_argument('--doc-id',required=True)
    c=sub.add_parser('lineage');group=c.add_mutually_exclusive_group(required=True)
    for flag in ('fact-id','research-row-id','source-row-id','comparison-id'):group.add_argument('--'+flag)
    c=sub.add_parser('failures');c.add_argument('--doc-id');c.add_argument('--reason')
    sub.add_parser('validate');args=vars(p.parse_args())
    try:
        if not 1<=args['limit']<=1000 or args['offset']<0: raise ContractError('invalid_page')
        dataset=Dataset(args['root']);result=dataset.query(**args)
        totals={k:len(v) for k,v in result.items() if isinstance(v,list)}
        for k in totals: result[k]=result[k][args['offset']:args['offset']+args['limit']]
        print(json.dumps({'snapshot_id':dataset.index['snapshot_id'],'snapshot_cutoff':dataset.index['snapshot_cutoff'],
            'rights_status':'BLOCKED','export_allowed':False,'system_replay':'NOT ESTABLISHED',
            'offset':args['offset'],'limit':args['limit'],'total_counts':totals,
            'truncated':any(n>args['offset']+args['limit'] for n in totals.values()),'result':result},ensure_ascii=False))
    except (ContractError,ValueError,OSError,KeyError,ImportError):
        # Do not include local paths, private rows or parser excerpts in public logs.
        print(json.dumps({'status':'BLOCKED','reason':'package_or_query_validation_failed',
            'hint':'Validate package hashes, contract, dependency lock and timezone-aware query arguments locally.'}))
        raise SystemExit(2) from None


if __name__=='__main__': main()
