"""P5.6: offline, read-only coverage measurement, never financial expansion.

The input plan is private. All output paths are outside Git. Physical bytes,
decoded rows, dependent mirrors, accepted facts and research permission differ.
"""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import date
import hashlib
import json
from pathlib import Path
import re

from evidence_core import ContractError
from local_edinet import LocalArchive
from source_acquisition import PrivateStore, encoded, sha256, utcnow

VERSION = 'p56-coverage-v1'
YEARS = tuple(range(2016, 2027))
SEED = 'p56-cross-year-v1'


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def private_path(path):
    p = Path(path).resolve()
    LocalArchive._outside_git(p)
    return p


def bounded_map(function, values):
    """Bound pending work as well as worker count; retain deterministic input order."""
    with ThreadPoolExecutor(max_workers=8) as pool:
        for start in range(0, len(values), 256):
            yield from pool.map(function, values[start:start+256])


def day(value):
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value[:10]).isoformat()
    except ValueError:
        return None


def daily_path(relative):
    p=Path(relative)
    return (p.suffix=='.json' and not p.name.endswith('.manifest.json')
            and not any(x.startswith('.') for x in p.parts)
            and (p.parts[0]=='listings' or re.fullmatch(r'list_\d{4}-\d{2}-\d{2}\.json',p.name) is not None))


def freeze_selection(documents, years=YEARS, seed=SEED):
    """Use metadata and raw existence only; never inspect downstream outcomes."""
    result = []
    for year in years:
        candidates = [d for d in documents if d.get('submit_date', '').startswith(str(year))
                      and '120' in d.get('document_types', []) and d.get('originals')]
        ordered = sorted(candidates, key=lambda d: (sha256(encoded([seed, year, d['doc_id']])), d['doc_id']))
        chosen = ordered[0] if ordered else None
        result.append({'year': year, 'doc_id': chosen['doc_id'] if chosen else None,
                       'status': 'SELECTED' if chosen else 'BLOCKED',
                       'reason': None if chosen else 'annual_original_not_available',
                       'candidate_count': len(candidates), 'seed': seed,
                       'selection_rule': 'minimum SHA256(JSON [seed,year,doc_id]); annual 120 with raw; no outcome filter',
                       'originals': chosen['originals'] if chosen else [],
                       'metadata': chosen['metadata'] if chosen else []})
    return result


class Inventory:
    def __init__(self, plan, output):
        self.output = private_path(output)
        self.roots = {r['id']: private_path(r['path']) for r in plan['roots']}
        if len(self.roots) != len(plan['roots']):
            raise ContractError('duplicate_root_id')
        for root in self.roots.values():
            if self.output == root or root in self.output.parents or self.output in root.parents:
                raise ContractError('output_overlaps_input')
        roots = list(self.roots.values())
        if any(a == b or a in b.parents or b in a.parents for i, a in enumerate(roots) for b in roots[i+1:]):
            raise ContractError('overlapping_inventory_roots')
        self.store = PrivateStore(self.output)
        if any(self.output.iterdir()):
            raise ContractError('snapshot_already_exists')
        code = {p.name: file_hash(p) for p in Path(__file__).parent.glob('*.py')}
        code.update({p.as_posix().split('/registry/')[-1]: file_hash(p)
                     for p in (Path(__file__).parent/'registry').glob('*.json')})
        self.common = {'snapshot_id': plan['snapshot_id'], 'code_sha': sha256(encoded(code)),
                       'definition_version': VERSION, 'observed_at': utcnow(),
                       'rights_review': 'BLOCKED', 'export_allowed': False}
        self.plan = plan
        self.files = []
        self.by_path = {}
        self.groups = {}
        self.docs = {}
        self.gaps = []
        self.logical_seen = set()
        self.prior_acceptance = defaultdict(Counter)
        self.save('inventory_plan.json', dict(plan=plan, code_files=code, seed=SEED,
            years=list(YEARS), scope='only explicit roots; no remote or Drive discovery',
            row_count_policy='physical decoded records, byte-identical files deduplicated within source/table; snapshots separate'))

    def save(self, name, obj):
        self.store.publish(name, encoded(dict(self.common, **obj)) + b'\n')

    def lines(self, name, rows):
        # Stream to a new temporary file, publish once, never replace old snapshots.
        path = self.output/name
        with path.open('xb') as f:
            for r in rows:
                f.write(encoded(dict(self.common, **r)) + b'\n')

    def gap(self, reason, **fields):
        self.gaps.append(dict(reason=reason, status='BLOCKED', **fields))

    def observe_files(self):
        cached = {}
        if self.plan.get('hash_checkpoint'):
            checkpoint = private_path(self.plan['hash_checkpoint'])
            if file_hash(checkpoint) != self.plan.get('hash_checkpoint_sha256'):
                raise ContractError('hash_checkpoint_changed')
            with checkpoint.open(encoding='utf-8') as stream:
                cached = {(r['root_id'],r['relative_path']):r for r in map(json.loads,stream)}
        for spec in self.plan['roots']:
            root = self.roots[spec['id']]
            if not root.is_dir():
                self.gap('input_root_missing', root_id=spec['id'])
                continue
            def observe(path):
                if not path.is_file():
                    return None
                if root not in path.resolve().parents:
                    raise ContractError('input_path_escape')
                relative = path.relative_to(root).as_posix()
                st = path.stat()
                prior = cached.get((spec['id'],relative))
                if prior and (prior['byte_count'],prior['mtime_ns']) != (st.st_size,st.st_mtime_ns):
                    raise ContractError('checkpoint_input_changed')
                digest = prior['byte_sha256'] if prior else file_hash(path)
                if (st.st_size, st.st_mtime_ns) != (path.stat().st_size, path.stat().st_mtime_ns):
                    raise ContractError('input_changed_during_hash')
                item = dict(root_id=spec['id'], source=spec['source'], kind=spec['kind'],
                            relative_path=relative, byte_sha256=digest, byte_count=st.st_size,
                            mtime_ns=st.st_mtime_ns, file_id=sha256(encoded([spec['id'], relative])),
                            rows=None, row_count_basis='not_a_decoded_data_table', hash_checkpoint_reused=bool(prior),
                            acquisition_method='preexisting_local_inventory', original_provider_retrieved_at=None,
                            acquisition_time_missing_reason='not_inferred_from_mtime_or_data_date')
                return item
            for item in bounded_map(observe, sorted(root.rglob('*'))):
                if item is not None:
                    self.files.append(item)
                    self.by_path[(spec['id'], item['relative_path'])] = item
            print('hashed root', spec['id'], flush=True)
        # A failed later decoder can restart without losing the measured file frame.
        # Reused digests are NOT an integrity PASS until preserve rehashes every byte.
        self.lines('file_hash_checkpoint.jsonl', self.files)

    def artifact(self, root_id, relative):
        return self.by_path[(root_id, relative)]

    def row(self, source, table, artifact, *, when=None, axis='unknown', doc=None, entity=None, security=None,
            source_tied=False, canonical=False, pit=False):
        date_value = day(when)
        month = date_value[:7] if date_value else 'unknown'
        key = source, table, axis, month
        if key not in self.groups:
            self.groups[key] = dict(rows=0, days=set(), docs=set(), entities=set(), securities=set(),
                                    artifacts=set(), source_tied_rows=0, canonical_eligible_rows=0, pit_eligible_rows=0)
        g = self.groups[key]
        g['rows'] += 1
        if date_value: g['days'].add(date_value)
        if doc: g['docs'].add(str(doc))
        if entity: g['entities'].add(str(entity))
        if security: g['securities'].add(str(security))
        g['artifacts'].add(artifact['file_id'])
        g['source_tied_rows'] += bool(source_tied)
        g['canonical_eligible_rows'] += bool(canonical)
        g['pit_eligible_rows'] += bool(pit)

    def document(self, doc):
        return self.docs.setdefault(doc, {'doc_id': doc, 'submit_dates': set(), 'document_types': set(),
            'entities': set(), 'securities': set(), 'sources': set(), 'metadata': [], 'originals': [],
            'source_tied': False, 'canonical_eligible': False, 'pit_eligible': False})

    def edinet(self, spec):
        from filing_catalog import edinet_metadata
        root_id = spec['id']
        for f in [x for x in self.files if x['root_id'] == root_id]:
            relative = f['relative_path']
            path = self.roots[root_id]/relative
            if path.suffix.lower() == '.zip':
                f['attributed_sources'] = ['edinet_original']
                doc = path.stem
                if not re.fullmatch(r'S[0-9A-Z]{7}', doc):
                    self.gap('unrecognized_original_filename', file_id=f['file_id'])
                    continue
                self.document(doc)['originals'].append({k: f[k] for k in
                    ('root_id', 'relative_path', 'file_id', 'byte_sha256', 'byte_count', 'mtime_ns')})
                self.document(doc)['sources'].add('edinet_original')
            elif daily_path(relative):
                f['attributed_sources'] = ['edinet_metadata']
                try:
                    raw = path.read_bytes(); obj = json.loads(raw)
                    edinet_metadata(raw)
                    observed_day = obj['metadata']['parameter']['date']
                    if not day(observed_day): raise ContractError('invalid_daily_metadata_date')
                    f.update(rows=len(obj['results']), row_count_basis='decoded_official_metadata_rows',
                             metadata_day=observed_day)
                    duplicate = ('edinet_metadata', f['byte_sha256']) in self.logical_seen
                    self.logical_seen.add(('edinet_metadata', f['byte_sha256']))
                    for n, r in enumerate(obj['results'], 1):
                        doc = self.document(r['docID'])
                        for field, value in (('submit_dates', day(r.get('submitDateTime'))),
                                             ('document_types', r.get('docTypeCode')),
                                             ('entities', r.get('edinetCode')), ('securities', r.get('secCode'))):
                            if value: doc[field].add(value)
                        doc['sources'].add('edinet_metadata')
                        doc['metadata'].append(dict(root_id=root_id, relative_path=relative, file_id=f['file_id'],
                            row_index=n, row_sha256=sha256(encoded(r)), day=observed_day))
                        if not duplicate:
                            self.row('edinet_metadata', 'documents:'+str(r.get('docTypeCode')), f,
                                when=r.get('submitDateTime'), axis='submit_date', doc=r['docID'],
                                entity=r.get('edinetCode'), security=r.get('secCode'))
                    # Empty daily lists still provide observed date evidence.
                    self.row('edinet_metadata', 'daily_files', f, when=observed_day, axis='metadata_day')
                except (ContractError, ValueError, KeyError, TypeError):
                    self.gap('daily_metadata_schema_rejected', file_id=f['file_id'])

    def jquants(self, spec):
        from jquants_local import csv_rows, code
        rid = spec['id']
        for f in [x for x in self.files if x['root_id'] == rid and x['relative_path'].endswith('.csv.gz')]:
            table = f['relative_path'].split('/')[0]
            fields, count = [], 0
            duplicate = ('jquants', table, f['byte_sha256']) in self.logical_seen
            self.logical_seen.add(('jquants', table, f['byte_sha256']))
            try:
                for fields, _, r in csv_rows((self.roots[rid]/f['relative_path']).read_bytes()):
                    count += 1
                    date_field = 'DiscDate' if table == 'fins_summary' else 'Date'
                    if not day(r.get(date_field)): raise ContractError('invalid_jquants_date')
                    if 'Code' in r: code(r['Code'])
                    if not duplicate:
                        self.row('jquants', table, f, when=r.get(date_field), axis=date_field,
                                 security=r.get('Code'))
                f.update(rows=count, row_count_basis='decoded_csv_records', schema=fields)
            except ContractError as exc:
                f.update(rows=count, row_count_basis='partial_before_parse_failure')
                self.gap(str(exc), file_id=f['file_id'], source='jquants', table=table)
        print('profiled J-Quants CSV files', flush=True)

    def derived(self, spec):
        """Read full saved files or accessible row groups. Never use footer totals as acquired rows."""
        from p5_audit import RecordedRanges
        import io
        rid = spec['id']; root = self.roots[rid]
        bundle = json.loads((root/'bundle.json').read_bytes())
        store = PrivateStore(root)
        for a in bundle['assets']:
            source, table, evidence = a['source_id'], a['table'], a['evidence']
            art = evidence['artifacts'][0]
            f = self.artifact(rid, 'raw/'+art['byte_sha256'])
            for ar in evidence['artifacts']:
                physical = self.artifact(rid, 'raw/'+ar['byte_sha256'])
                physical['attributed_sources'] = sorted(set(physical.get('attributed_sources', [])) | {source})
            full = evidence['scope'] == 'complete parquet file'
            count = 0
            inaccessible = []
            streams = []
            if source == 'numad':
                raw = store.read_raw(art)
                # Last partial JSONL line is not a row.
                streams = [(0, (json.loads(line) for line in raw.splitlines()[:-1] if line))]
                if raw.endswith(b'\n'): streams = [(0, (json.loads(line) for line in raw.splitlines() if line))]
            else:
                import pyarrow.parquet as pq
                stream = io.BytesIO(store.read_raw(art)) if full else RecordedRanges(store, evidence)
                parquet = pq.ParquetFile(stream)
                for n in range(parquet.num_row_groups):
                    try:
                        group = parquet.read_row_group(n)
                        streams.append((n, group.to_pylist()))
                    except (ContractError, OSError):
                        inaccessible.append(n)
            for _, rows in streams:
                for r in rows:
                    count += 1
                    doc_id = r.get('doc_id')
                    date_field = next((k for k in ('submit_date_time', 'submit_datetime', 'submit_date', 'period_end', 'period_instant') if day(str(r.get(k)))), None)
                    value = str(r[date_field]) if date_field else None
                    if doc_id:
                        d = self.document(doc_id); d['sources'].add(source)
                        if not value and len(d['submit_dates']) == 1:
                            date_field, value = 'linked_official_submit_date', next(iter(d['submit_dates']))
                    self.row(source, table, f, when=value, axis=date_field or 'unknown', doc=doc_id,
                             entity=r.get('edinet_code'), security=r.get('sec_code'))
            self.gap('partial_source_acquisition' if not full else 'upstream_full_coverage_unverified',
                     source=source, table=table, asset_id=a['asset_id'], decoded_rows=count,
                     unavailable_row_groups=inaccessible, remote_row_count_claim=a.get('file_row_count'))
            # A range may support more than one asset. Asset measurement is separate from physical files.
            self.row('source_assets', source+':'+table, f, axis='asset_observation')
            f.setdefault('decoded_assets', []).append({'asset_id': a['asset_id'], 'source': source,
                'table': table, 'decoded_rows': count, 'whole_file_acquired': full,
                'range_artifact_ids': [self.artifact(rid, 'raw/'+x['byte_sha256'])['file_id'] for x in evidence['artifacts']]})
        print('profiled saved derived source assets', flush=True)

    def snapshots(self, spec):
        rid = spec['id']; root = self.roots[rid]
        targets = {'documents.jsonl', 'canonical_facts.jsonl', 'pit_join_rows.jsonl',
                   'derived_observations.jsonl', 'comparison_ledger.jsonl'}
        accepted = spec.get('accepted_snapshot')
        eligible_ids = set()
        if accepted and (root/accepted/'view_audit.json').is_file():
            eligible_ids = set(json.loads((root/accepted/'view_audit.json').read_bytes())['latest_restated_fact_ids'])
        accepted_originals = {}
        if accepted and (root/accepted/'original_artifacts.jsonl').is_file():
            with (root/accepted/'original_artifacts.jsonl').open(encoding='utf-8') as stream:
                for r in map(json.loads,stream):
                    digest=r['artifact']['byte_sha256']
                    if digest in {a['byte_sha256'] for a in self.docs.get(r['doc_id'],{}).get('originals',[])}:
                        accepted_originals[r['doc_id']]=digest
        for f in [x for x in self.files if x['root_id'] == rid]:
            path = root/f['relative_path']
            if path.suffix == '.jsonl':
                count = 0
                try:
                    with path.open(encoding='utf-8') as stream:
                        for line in stream:
                            r = json.loads(line); count += 1
                            source = spec['source']+':'+path.relative_to(root).parts[0]
                            if path.name not in targets:
                                self.row(source, path.stem, f, axis='unknown')
                                continue
                            doc = r.get('doc_id'); when = r.get('public_available_at') or r.get('submit_datetime') or r.get('decision_at')
                            if (path.relative_to(root).parts[0]==accepted and path.name=='comparison_ledger.jsonl'
                                    and r.get('status')=='PASS' and r.get('origin_ids') and doc in accepted_originals):
                                self.prior_acceptance[r['source_id']]['source_tied_comparison_rows'] += 1
                            tied = (r.get('verification_state') == 'source_tied' and
                                    r.get('source_artifact_sha256') in {a['byte_sha256'] for a in self.docs.get(doc,{}).get('originals',[])})
                            canonical = path.name == 'canonical_facts.jsonl' and tied and r.get('fact_id') in eligible_ids
                            pit = path.name == 'pit_join_rows.jsonl' and r.get('status') == 'PASS'
                            self.row(source, path.stem, f, when=when, axis='public_available_at_or_decision_at',
                                doc=doc, entity=r.get('edinet_code') or r.get('entity_id'), security=r.get('secCode') or r.get('jquants_code'),
                                source_tied=tied, canonical=canonical, pit=pit)
                            if doc:
                                d = self.document(doc); d['sources'].add(source)
                                if path.relative_to(root).parts[0] == accepted:
                                    d['source_tied'] |= tied; d['canonical_eligible'] |= canonical; d['pit_eligible'] |= pit
                    f.update(rows=count, row_count_basis='decoded_snapshot_jsonl_records')
                except (ValueError, UnicodeError):
                    self.gap('snapshot_jsonl_invalid', file_id=f['file_id'])
            elif path.suffix == '.parquet':
                import pyarrow.parquet as pq
                parquet = pq.ParquetFile(path)
                count = 0
                for batch in parquet.iter_batches():
                    for packed in batch.to_pylist():
                        count += 1
                        r = json.loads(packed['payload_json']) if 'payload_json' in packed else packed
                        self.row(spec['source'], path.stem, f, when=r.get('public_available_at') or r.get('decision_at'),
                            axis='public_available_at_or_decision_at', doc=r.get('doc_id'),
                            entity=r.get('edinet_code') or r.get('entity_id'), security=r.get('secCode') or r.get('jquants_code'))
                f.update(rows=count, row_count_basis='decoded_snapshot_parquet_records', schema=str(parquet.schema_arrow))
            elif path.name in ('CURRENT', 'CURRENT.json'):
                f['role'] = 'protected_current_pointer'

    def finalize_documents(self):
        result = []
        for doc_id, d in sorted(self.docs.items()):
            reasons = []
            if not d['originals']: reasons.append('official_original_not_available')
            if not d['metadata']: reasons.append('official_metadata_not_available')
            if len(d['submit_dates']) != 1: reasons.append('submit_date_missing_or_ambiguous')
            if len(d['entities']) != 1: reasons.append('entity_missing_or_ambiguous')
            hashes = {a['byte_sha256'] for a in d['originals']}
            if len(hashes) > 1: reasons.append('original_bytes_ambiguous')
            submit = next(iter(d['submit_dates'])) if len(d['submit_dates']) == 1 else ''
            for a in d['originals']:
                key = ('edinet_original', doc_id, a['byte_sha256'])
                if key in self.logical_seen: continue
                self.logical_seen.add(key)
                self.row('edinet_original', 'ZIP:'+('|'.join(sorted(d['document_types'])) or 'unknown'), a,
                         when=submit, axis='official_metadata_submit_date', doc=doc_id,
                         entity=next(iter(d['entities'])) if len(d['entities']) == 1 else None,
                         security=next(iter(d['securities'])) if len(d['securities']) == 1 else None,
                         source_tied=d['source_tied'], canonical=d['canonical_eligible'], pit=d['pit_eligible'])
            row = {k: sorted(v) if isinstance(v, set) else v for k, v in d.items()}
            row.update(submit_date=submit, missing_reasons=reasons,
                data_exists='PASS', official_original_available=bool(d['originals']),
                source_tied='PASS' if d['source_tied'] else 'BLOCKED',
                canonical_eligible='PASS' if d['canonical_eligible'] else 'BLOCKED',
                pit_eligible='PASS' if d['pit_eligible'] else 'BLOCKED', research_ready='BLOCKED',
                eligibility_basis='observed prior snapshot rows only; existence never promotes acceptance')
            result.append(row)
            for reason in reasons: self.gap(reason, doc_id=doc_id)
        return result

    def preserve(self):
        expected = {(f['root_id'], f['relative_path']) for f in self.files}
        actual = {(rid, p.relative_to(root).as_posix()) for rid, root in self.roots.items()
                  for p in root.rglob('*') if p.is_file()}
        if expected != actual: raise ContractError('input_file_set_changed')
        def verify(f):
            path = self.roots[f['root_id']]/f['relative_path']
            st = path.stat()
            if (st.st_size, st.st_mtime_ns, file_hash(path)) != (f['byte_count'], f['mtime_ns'], f['byte_sha256']):
                raise ContractError('input_bytes_changed')
        for _ in bounded_map(verify, self.files): pass
        return {'status': 'PASS', 'files_rehashed': len(self.files), 'bytes_rehashed': sum(f['byte_count'] for f in self.files),
                'comparison': 'file set + SHA256 + bytes + mtime; all explicit roots including CURRENT',
                'source_files_sha256': file_hash(self.output/'source_files.jsonl')}

    def finish(self):
        docs = self.finalize_documents()
        self.lines('document_coverage.jsonl', docs)
        self.save('cross_year_selection.json', {'selection': freeze_selection(docs), 'seed': SEED,
            'frozen_before_execution': True, 'outcome_replacement_allowed': False})
        by_id = {f['file_id']: f for f in self.files}
        coverage = []
        for (source, table, axis, month), g in sorted(self.groups.items()):
            coverage.append(dict(source=source, table=table, date_axis=axis, month=month, rows=g['rows'],
                doc_id_count=len(g['docs']), entity_count=len(g['entities']), security_count=len(g['securities']),
                observed_dates=sorted(g['days']), observed_earliest_date=min(g['days'], default=None),
                observed_latest_date=max(g['days'], default=None), input_artifacts=sorted(g['artifacts']),
                bytes=sum(by_id[k]['byte_count'] for k in g['artifacts']),
                source_tied_rows=g['source_tied_rows'], canonical_eligible_rows=g['canonical_eligible_rows'],
                pit_eligible_rows=g['pit_eligible_rows'], research_ready_rows=0))
        self.lines('date_coverage.jsonl', coverage)
        queue = partitions(coverage, self.files, day(self.common['observed_at']))
        self.lines('expansion_queue.jsonl', queue)
        for p in queue:
            if p['status'] in ('BLOCKED', 'UNKNOWN'):
                self.gap(p['reason'], partition_id=p['partition_id'], source=p['source'], month=p['month'], table=p['table'])
        for source in ('edinet_original','jquants','queria','youseiushida','numad'):
            self.gap('rights_unresolved',source=source)
        self.lines('gap_ledger.jsonl', self.gaps)
        sources = sorted({s for d in docs for s in d['sources']})
        doc_sets = {s: {d['doc_id'] for d in docs if s in d['sources']} for s in sources}
        self.lines('overlap_matrix.jsonl', ({'source_a': a, 'source_b': b, 'shared_doc_ids': len(doc_sets[a]&doc_sets[b]),
            'independent_evidence_added': 0, 'basis': 'exact doc_id only; no name/period inference; not a fact tie'}
            for i, a in enumerate(sources) for b in sources[i:]))
        self.lines('source_files.jsonl', self.files)
        summary = {}
        all_sources = sorted({x['source'] for x in coverage}|{x['source'] for x in self.files})
        for s in all_sources:
            gs = [g for (source, _, _, _), g in self.groups.items() if source == s]
            fs = [f for f in self.files if f['source'] == s or s in f.get('attributed_sources', [])]
            dates = set().union(*(g['days'] for g in gs))
            summary[s] = {'files': len(fs), 'physical_bytes': sum(f['byte_count'] for f in fs),
                'distinct_byte_sha256': len({f['byte_sha256'] for f in fs}),
                'decoded_rows': sum(g['rows'] for g in gs), 'row_scope': 'table-specific physical records; no cross-table sample-size interpretation',
                'observed_earliest_date': min(dates, default=None), 'observed_latest_date': max(dates, default=None),
                'doc_id_count': len(set().union(*(g['docs'] for g in gs))),
                'entity_count': len(set().union(*(g['entities'] for g in gs))),
                'security_code_count': len(set().union(*(g['securities'] for g in gs))),
                'year_rows': dict(Counter({str(y): sum(g['rows'] for (src, _, _, m), g in self.groups.items() if src == s and m.startswith(str(y))) for y in YEARS})),
                'data_exists': 'PASS' if fs or gs else 'BLOCKED',
                'source_tied': 'PASS' if any(g['source_tied_rows'] for g in gs) else 'BLOCKED',
                'canonical_eligible': 'PASS' if any(g['canonical_eligible_rows'] for g in gs) else 'BLOCKED',
                'pit_eligible': 'PASS' if any(g['pit_eligible_rows'] for g in gs) else 'BLOCKED',
                'acceptance_scope': 'only counted accepted rows, never the entire source',
                'source_tied_rows': sum(g['source_tied_rows'] for g in gs),
                'canonical_eligible_rows': sum(g['canonical_eligible_rows'] for g in gs),
                'pit_eligible_rows': sum(g['pit_eligible_rows'] for g in gs),
                'research_ready': 'BLOCKED', 'rights_review': 'BLOCKED'}
            summary[s]['source_class'] = ('derived_from_edinet' if s in ('queria','youseiushida','numad') else
                'official_original' if s=='edinet_original' else 'independent_external' if s=='jquants' else 'inventory_or_existing_snapshot')
            prior=dict(self.prior_acceptance.get(s,{}))
            summary[s]['prior_snapshot_acceptance']=prior
            if prior.get('source_tied_comparison_rows'):
                summary[s]['source_tied']='PASS'
                summary[s]['acceptance_scope']='only fixed prior P5 comparison rows with still-present original SHA; new decoded rows unaccepted'
        self.save('coverage_summary.json', {'sources': summary, 'partition_states': dict(Counter(p['status'] for p in queue)),
            'gap_reasons': dict(Counter(g['reason'] for g in self.gaps)), 'document_ids': len(docs),
            'full_10_year_expansion': 'NOT RUN', 'full_market_representativeness': 'NOT ESTABLISHED',
            'system_replay': 'NOT ESTABLISHED', 'research_ready': 'BLOCKED'})
        self.save('preservation_proof.json', self.preserve())
        return summary


def partitions(coverage, files, today):
    """READY means decoded local input can be enumerated, not research or source acceptance."""
    by_id = {f['file_id']: f for f in files}
    grouped = defaultdict(list)
    for c in coverage: grouped[(c['source'], c['table'])].append(c)
    for source, table in [('edinet_original', 'ZIP:120'), ('edinet_metadata', 'daily_files'),
                          ('jquants', 'equities_master'), ('jquants', 'equities_bars_daily'),
                          ('jquants', 'fins_summary'), ('jquants', 'markets_calendar'),
                          ('queria', 'mart_documents'), ('youseiushida', 'filings'), ('numad', 'text_blocks')]:
        grouped.setdefault((source, table), [])
    result = []
    for (source, table), rows in sorted(grouped.items()):
        for year in YEARS:
            for month in range(1, 13):
                ym = f'{year}-{month:02}'
                current = [r for r in rows if r['month'] == ym]
                ids = sorted({i for r in current for i in r['input_artifacts']})
                future = ym > today[:7]
                status = 'UNKNOWN' if future else 'READY' if ids else 'BLOCKED'
                reason = 'future_partition_not_observed' if future else None if ids else 'no_dated_local_rows'
                if ids and any(by_id[i].get('row_count_basis')=='partial_before_parse_failure' for i in ids):
                    status, reason = 'BLOCKED', 'input_decode_incomplete'
                # Finance/mapping definitions are deliberately not enlarged here.
                if source == 'edinet_original' and table != 'ZIP:120' and ids:
                    status, reason = 'BLOCKED', 'not_primary_annual_partition'
                result.append({'partition_id': sha256(encoded([VERSION, source, table, ym])),
                    'source': source, 'year': year, 'month': ym, 'table': table, 'status': status, 'reason': reason,
                    'input_artifacts': [{'file_id': i, 'byte_sha256': by_id[i]['byte_sha256'],
                                         'root_id': by_id[i]['root_id'], 'relative_path': by_id[i]['relative_path']} for i in ids],
                    'estimated_rows': sum(r['rows'] for r in current) if ids else None,
                    'estimated_bytes': sum(by_id[i]['byte_count'] for i in ids) if ids else None,
                    'estimate_basis': 'measured local records and shared input bytes; partitions may share files',
                    'dependency': ['hash_pinned_inputs', 'existing_stage_acceptance', 'revision_closure', 'rights_review'],
                    'execution_scope': 'local_input_enumeration_only', 'downstream_pipeline_status': 'UNKNOWN',
                    'upstream_partition_completeness': 'UNKNOWN',
                    'resume': {'module': 'coverage_replay', 'operation': 'verify_partition', 'partition_id': sha256(encoded([VERSION, source, table, ym]))}})
        unknown = [r for r in rows if r['month']=='unknown']
        if unknown:
            result.append({'partition_id':sha256(encoded([VERSION,source,table,'unknown'])),
                'source':source,'year':None,'month':'unknown','table':table,'status':'UNKNOWN',
                'reason':'row_date_not_available','input_artifacts':sorted({i for r in unknown for i in r['input_artifacts']}),
                'estimated_rows':sum(r['rows'] for r in unknown),'estimated_bytes':None,
                'dependency':['explicit_date_evidence'],'execution_scope':'unassigned_rows',
                'downstream_pipeline_status':'UNKNOWN','upstream_partition_completeness':'UNKNOWN'})
    return result


def run(plan, output):
    inventory = Inventory(plan, output)
    inventory.observe_files()
    for spec in plan['roots']:
        if spec['kind'] == 'edinet': inventory.edinet(spec)
    for spec in plan['roots']:
        if spec['kind'] == 'jquants': inventory.jquants(spec)
        elif spec['kind'] == 'derived_bundle': inventory.derived(spec)
        elif spec['kind'] in ('snapshots', 'package'): inventory.snapshots(spec)
    return inventory.finish()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    run(json.loads(Path(args.plan).read_bytes()), args.output)
