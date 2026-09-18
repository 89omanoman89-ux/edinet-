"""Execute only frozen P5.6 samples through unchanged P3/P4/P5/P5.5 engines."""
import argparse
from collections import Counter
from contextlib import redirect_stdout
import json
from pathlib import Path

from coverage_inventory import file_hash, private_path
from evidence_core import ContractError
from source_acquisition import PrivateStore, encoded, sha256, utcnow


def rows(path):
    with Path(path).open(encoding='utf-8') as f:
        for line in f:
            yield json.loads(line)


def verify_partition(inventory, partition_id):
    root = private_path(inventory)
    plan = json.loads((root/'inventory_plan.json').read_bytes())['plan']
    roots = {r['id']: private_path(r['path']) for r in plan['roots']}
    matches = [r for r in rows(root/'expansion_queue.jsonl') if r['partition_id'] == partition_id]
    if len(matches) != 1: raise ContractError('partition_missing_or_ambiguous')
    partition = matches[0]
    if partition['status'] != 'READY': raise ContractError('partition_not_ready')
    for a in partition['input_artifacts']:
        path = (roots[a['root_id']]/a['relative_path']).resolve()
        if roots[a['root_id']] not in path.parents: raise ContractError('input_path_escape')
        if not path.is_file() or file_hash(path) != a['byte_sha256']:
            raise ContractError('partition_input_changed')
    return partition


def run_p3_partition(inventory, partition_id, output, *, limit):
    """Explicit next-PR operation, not called by cross-year inventory.

    A bounded ordered batch is committed before extraction. Completed per-doc
    outputs are checkpoints; failed documents remain in the result list.
    """
    from p3_audit import run as p3_run
    inventory, output = private_path(inventory), private_path(output)
    partition = verify_partition(inventory, partition_id)
    if partition['source'] != 'edinet_original' or partition['table'] != 'ZIP:120':
        raise ContractError('partition_requires_other_stage_dependencies')
    if not isinstance(limit, int) or not 1 <= limit <= 300: raise ContractError('invalid_partition_batch_limit')
    plan = json.loads((inventory/'inventory_plan.json').read_bytes())['plan']
    roots = {r['id']:r['path'] for r in plan['roots']}
    for p in [inventory, *(private_path(v) for v in roots.values())]:
        if output == p or output in p.parents or p in output.parents: raise ContractError('partition_output_overlaps_input')
    docs = sorted((r for r in rows(inventory/'document_coverage.jsonl')
                   if r['submit_date'].startswith(partition['month']) and r['document_types']==['120'] and r['originals']),
                  key=lambda r:r['doc_id'])
    store = PrivateStore(output)
    before = {'inventory_manifest_sha256':file_hash(inventory/'inventory_plan.json'),
        'partition_id':partition_id,'ordered_doc_ids':[d['doc_id'] for d in docs],
        'limit':limit,'definition_policy':'unchanged P3; one primary plus revision closure per batch'}
    # publish refuses replacement when either input identity or batch policy changes.
    store.publish('partition_plan.json', encoded(before))
    completed = []; new_count = 0
    for d in docs:
        target = output/d['doc_id']
        if (target/'result.json').is_file():
            completed.append(json.loads((target/'result.json').read_bytes())); continue
        if new_count >= limit: break
        new_count += 1
        selection = dict(d, year=partition['year'], status='SELECTED')
        result = {'doc_id':d['doc_id'],'status':'BLOCKED'}
        if target.exists():
            result['reason']='interrupted_snapshot_requires_review'
            PrivateStore(target).publish('result.json',encoded(result));completed.append(result);continue
        target.mkdir(exist_ok=False)
        try:
            root = frame_for(selection, roots, target/'frame', frozen_files=rows(inventory/'source_files.jsonl'))
            with (target/'execution.log').open('x',encoding='utf-8') as log, redirect_stdout(log):
                summary = p3_run(root,target/'frame',target,'p3')
            result.update(status='COMPLETE', document_failures=summary['document_failures'],
                          reason='execution_completed; consult canonical nulls and failure ledger')
        except (ContractError,OSError,ValueError,KeyError) as exc:
            result['reason']=str(exc) if isinstance(exc,ContractError) else type(exc).__name__+':stage_failed'
        PrivateStore(target).publish('result.json',encoded(result));completed.append(result)
    return {'partition_id':partition_id,'completed_or_blocked':len(completed),'total':len(docs),
            'remaining':len(docs)-len(completed),'results':completed}


def frame_for(selection, roots, output, *, frozen_files=None):
    """Choose archive by frozen daily-file count, never extraction results."""
    doc = selection['doc_id']
    frozen_files = list(frozen_files) if frozen_files is not None else None
    counts = Counter(f['root_id'] for f in (frozen_files or []) if f['relative_path'].startswith('listings/') and
                     f['relative_path'].endswith('/documents.json'))
    candidates = sorted(selection['originals'], key=lambda a: (-counts[a['root_id']], a['root_id'], a['relative_path']))
    if not candidates: raise ContractError('original_not_available')
    artifact = candidates[0]
    root = private_path(roots[artifact['root_id']])
    path = root/artifact['relative_path']
    if file_hash(path) != artifact['byte_sha256']: raise ContractError('frozen_original_changed')
    store = PrivateStore(output)
    if any(store.root.iterdir()): raise ContractError('frame_already_exists')
    # P3 independently rebuilds all local revision metadata and verifies bytes.
    record = {'doc_id': doc, 'zip_files': [{'relative_path': artifact['relative_path'],
        'byte_count': artifact['byte_count'], 'mtime_ns': artifact['mtime_ns']}], 'metadata_events': []}
    records = {doc:record}; audits = {doc:artifact['byte_sha256']}; listings=[]
    if frozen_files is not None:
        original_paths=set();listing_paths=set()
        for f in frozen_files:
            if f['root_id'] != artifact['root_id']: continue
            relative=f['relative_path']
            if relative.startswith('documents/') and relative.endswith('.zip'):
                original_paths.add(relative)
                identifier=Path(relative).stem
                if identifier==doc and relative==artifact['relative_path']: continue
                records.setdefault(identifier,{'doc_id':identifier,'zip_files':[],'metadata_events':[]})['zip_files'].append(
                    {k:f[k] for k in ('relative_path','byte_count','mtime_ns')})
                if identifier in audits and audits[identifier]!=f['byte_sha256']:
                    raise ContractError('frozen_original_bytes_ambiguous')
                audits[identifier]=f['byte_sha256']
            elif relative.startswith('listings/') and relative.endswith('/documents.json'):
                listing_paths.add(relative)
                listings.append({k:f[k] for k in ('relative_path','byte_sha256')})
        current_zips={p.relative_to(root).as_posix() for p in (root/'documents').rglob('*.zip')}
        current_lists={p.relative_to(root).as_posix() for p in (root/'listings').rglob('documents.json')}
        if original_paths!=current_zips or listing_paths!=current_lists:
            raise ContractError('frozen_archive_file_set_changed')
    store.publish('selected_documents.json', encoded({'challenge': [doc], 'probability': []}))
    store.publish('universe_manifest.json', encoded({'snapshot_id': 'p56-frozen-'+str(selection['year']),
        'archive_root_id': sha256(str(root).encode()), 'listings':listings}))
    store.publish('universe_documents.jsonl', b''.join(encoded(r)+b'\n' for r in records.values()))
    store.publish('document_audit.jsonl', b''.join(encoded({'doc_id':d,'zip_sha256':h})+b'\n' for d,h in audits.items()))
    return root


def subset_bundle(source, p3, selected, output):
    """No collection: preserve original provider records, locators, asset IDs and docs reviews."""
    source, p3 = private_path(source), private_path(p3)
    store = PrivateStore(output)
    if any(store.root.iterdir()): raise ContractError('bundle_already_exists')
    original = json.loads((source/'bundle.json').read_bytes())
    docs = [r for r in rows(p3/'documents.jsonl') if r['doc_id'] in selected]
    codes = {d.get('edinet_code') for d in docs} - {None}
    # Reuse all locally accessible bytes, not just the three P5 primary documents.
    # This changes selection only; the original extraction/comparison definitions remain unchanged.
    import io
    from p5_audit import RecordedRanges
    from p5_acquisition import json_value
    import pyarrow.parquet as pq
    inputs = PrivateStore(source)
    selected_rows, assets, unavailable = [], [], []
    for old in original['assets']:
        evidence = old['evidence']
        a = dict(old, doc_scope=selected)
        a.pop('asset_id', None); a['asset_id'] = sha256(encoded(a))
        matched = []
        def keep(r, locator):
            if r.get('doc_id') not in selected and not (a['table']=='mart_companies' and r.get('edinet_code') in codes):
                return
            loc = dict(locator, row_sha256=sha256(encoded(r)))
            row = {'provider_fields': r, 'locator': loc, 'source_id': a['source_id'], 'table': a['table'],
                   'asset_id': a['asset_id'], 'extraction_method': 'provider_jsonl' if a['source_id']=='numad' else 'provider_parquet'}
            row['source_row_id'] = sha256(encoded(row)); matched.append(row)
        if a['source_id']=='numad':
            raw = inputs.read_raw(evidence['artifacts'][0])
            lines = raw.splitlines() if raw.endswith(b'\n') else raw.splitlines()[:-1]
            for n, line in enumerate(lines, 1): keep(json.loads(line), {'line_number': n})
        else:
            stream = io.BytesIO(inputs.read_raw(evidence['artifacts'][0])) if evidence['scope']=='complete parquet file' else RecordedRanges(inputs,evidence)
            parquet = pq.ParquetFile(stream)
            for group in range(parquet.num_row_groups):
                try:
                    records = parquet.read_row_group(group).to_pylist()
                except (ContractError, OSError):
                    unavailable.append({'source_id':a['source_id'],'table':a['table'],'row_group':group,
                                        'reason':'recorded_range_missing','asset_id':a['asset_id']})
                    continue
                for n, r in enumerate(records): keep(json_value(r), {'row_group':group,'row_index':n})
        if matched:
            assets.append(a); selected_rows.extend(matched)
    bundle = dict(original, rows=selected_rows, assets=assets, selection={
        'doc_ids': selected, 'p3_document_sha256': file_hash(p3/'documents.jsonl'),
        'selection_rule': 'frozen cross-year primary; reuse existing provider rows only; missing stays missing',
        'original_bundle_sha256': file_hash(source/'bundle.json')}, failures=unavailable)
    artifacts = [a for asset in assets for a in asset['evidence']['artifacts']]
    artifacts += [a for s in original['sources'].values() for a in s.get('documentation', [])]
    for a in artifacts:
        raw = PrivateStore(source).read_raw(a)
        store.publish('raw/'+a['byte_sha256'], raw)
    store.publish('bundle.json', encoded(bundle))
    return len(selected_rows)


def execute_sample(selection, roots, jquants_root, bundle_root, output, *, synthetic=False, frozen_files=None):
    from p3_audit import run as p3_run
    from p4_audit import run as p4_run
    from p5_audit import run as p5_run
    from dataset_export import export_dataset
    output = private_path(output)
    store = PrivateStore(output)
    if any(output.iterdir()): raise ContractError('sample_output_exists')
    result = dict(selection, started_at=utcnow(), p3='NOT RUN', p4='NOT RUN', p5='NOT RUN', p55='NOT RUN',
                  overall='BLOCKED', rights_review='BLOCKED', research_ready='BLOCKED')
    if selection['status'] == 'BLOCKED':
        store.publish('result.json', encoded(result)); return result
    stage = 'p3'
    try:
        root = frame_for(selection, roots, output/'frame', frozen_files=frozen_files)
        with (output/'execution.log').open('x', encoding='utf-8') as log, redirect_stdout(log):
            a = p3_run(root, output/'frame', output, 'p3', synthetic=synthetic)
            result.update(p3='PASS', p3_non_null=a['non_null_canonical_facts'], p3_document_failures=a['document_failures'])
            stage = 'p4'
            p4_run(jquants_root, root, output/'p3', output, 'p4', synthetic=synthetic, direct_dated=True)
            joins = list(rows(output/'p4/pit_join_rows.jsonl'))
            result.update(p4='PASS', pit_pass=sum(r['status']=='PASS' for r in joins), pit_blocked=sum(r['status']!='PASS' for r in joins))
            stage = 'p5'
            count = subset_bundle(bundle_root, output/'p3', [selection['doc_id']], output/'p5-input')
            p5_run(root, output/'p3', output/'p5-input', output, 'p5', synthetic=synthetic)
            acceptance = json.loads((output/'p5/source_acceptance.json').read_bytes())
            result.update(p5='PASS', derived_rows=count, original_ties={s['source_id']:s['original_tied'] for s in acceptance['sources']})
            stage = 'p55'
            packaged = export_dataset(output/'p3', output/'p4', output/'p5', output/'new-package',
                                      'cross-year-'+str(selection['year']), synthetic=synthetic)
            result.update(p55='PASS', package_validation=packaged)
            # Execution success is separate from availability of accepted observations.
            result['reason'] = 'research_rights_unresolved; see per-stage coverage and missing-source records'
    except (ContractError, OSError, ValueError, KeyError, ImportError) as exc:
        result[stage] = 'BLOCKED'
        result['reason'] = str(exc) if isinstance(exc, ContractError) else type(exc).__name__+':stage_failed'
    store.publish('result.json', encoded(result))
    return result


def run(inventory, output):
    inventory = private_path(inventory); output = private_path(output)
    plan = json.loads((inventory/'inventory_plan.json').read_bytes())
    selection = json.loads((inventory/'cross_year_selection.json').read_bytes())
    roots = {r['id']: r['path'] for r in plan['plan']['roots']}
    for p in [inventory, *(private_path(v) for v in roots.values())]:
        if output == p or output in p.parents or p in output.parents: raise ContractError('replay_output_overlaps_input')
    jq = [r['path'] for r in plan['plan']['roots'] if r['kind']=='jquants']
    bundles = [r['path'] for r in plan['plan']['roots'] if r['kind']=='derived_bundle']
    if len(jq)!=1 or len(bundles)!=1: raise ContractError('replay_dependencies_missing_or_ambiguous')
    store = PrivateStore(output)
    if any(output.iterdir()): raise ContractError('replay_snapshot_exists')
    frozen = (inventory/'cross_year_selection.json').read_bytes()
    store.publish('frozen_selection.json', frozen)
    replay_code = {p.name:file_hash(p) for p in Path(__file__).parent.glob('*.py')}
    replay_sha = sha256(encoded(replay_code))
    store.publish('replay_plan.json', encoded({'snapshot_id': output.name, 'code_sha': replay_sha, 'code_files':replay_code,
        'inventory_code_sha':plan['code_sha'],
        'selection_sha256': sha256(frozen), 'selection_policy': 'never replace failed documents',
        'archive_selection_rule':'most frozen daily files among roots with selected ZIP, then root_id/path; before extraction',
        'existing_CURRENT_write': False, 'entrypoints': ['p3_audit.run','p4_audit.run','p5_audit.run','dataset_export.export_dataset']}))
    results = []
    for s in selection['selection']:
        r = execute_sample(s, roots, jq[0], bundles[0], output/str(s['year']), frozen_files=rows(inventory/'source_files.jsonl'))
        results.append(r)
        print(s['year'], {k:r.get(k) for k in ('p3','p4','p5','p55','pit_pass','derived_rows','reason')}, flush=True)
    if frozen != (inventory/'cross_year_selection.json').read_bytes(): raise ContractError('selection_changed')
    store.publish('cross_year_results.json', encoded({'snapshot_id': output.name, 'code_sha': replay_sha,
        'results': results, 'selection_unchanged': True, 'rights_review': 'BLOCKED', 'export_allowed': False}))
    return results


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inventory', required=True)
    p.add_argument('--output')
    p.add_argument('--verify-partition')
    p.add_argument('--p3-partition')
    p.add_argument('--limit', type=int, default=1)
    args = p.parse_args()
    if args.p3_partition and args.output: print(json.dumps(run_p3_partition(args.inventory,args.p3_partition,args.output,limit=args.limit)))
    elif args.verify_partition: print(json.dumps(verify_partition(args.inventory, args.verify_partition)))
    elif args.output: run(args.inventory, args.output)
    else: p.error('--output or --verify-partition required')
