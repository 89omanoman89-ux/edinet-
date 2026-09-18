"""Frozen bounded partitions through P3/P4/P5/P5.5. Local inputs only; no networking."""
import argparse
from collections import Counter,defaultdict
from contextlib import redirect_stdout
import json
from pathlib import Path
import shutil
import tempfile
import zipfile

from coverage_inventory import private_path,file_hash
from evidence_core import ContractError
from expansion_archive import CrossArchive,SqlLinks,lines,make_frame
from revision_series import revision_closure
from source_acquisition import PrivateStore,encoded,sha256,utcnow


def code_identity():
    root=Path(__file__).parent
    # The federation reader can evolve independently; each stage pins its own code.
    names=sorted([p for p in root.glob('*.py') if p.name!='partitioned_dataset.py']+list((root/'registry').glob('*.json')))
    return {p.relative_to(root).as_posix():file_hash(p) for p in names}


def partition_components(components,months,*,limit=30):
    """Whole revision components are indivisible; ordering precedes any extraction."""
    if not 1<=limit<=100:raise ContractError('invalid_batch_limit')
    pending=[];size=0;month=None
    for component in sorted(components,key=lambda c:(min(months.get(d,'unknown') for d in c),min(c))):
        chosen=min(months.get(d,'unknown') for d in component)
        if len(component)>100:
            yield {'doc_ids':sorted(component),'month':chosen,'status':'BLOCKED','reason':'revision_component_exceeds_document_budget'}
            continue
        if pending and (month!=chosen or size+len(component)>limit):
            yield {'doc_ids':sorted(pending),'month':month,'status':'READY','reason':None};pending=[];size=0
        month=chosen;pending.extend(component);size+=len(component)
    if pending:yield {'doc_ids':sorted(pending),'month':month,'status':'READY','reason':None}


def plan_expansion(inventory,archive_index,derived_index,jquants_root,output,*,limit=30,row_cache=None):
    inventory,output=private_path(inventory),private_path(output)
    dependencies=[inventory,private_path(archive_index),private_path(derived_index),private_path(jquants_root)]
    if any(output==p or output in p.parents or p in output.parents for p in dependencies):raise ContractError('plan_input_overlap')
    store=PrivateStore(output)
    if any(output.iterdir()):raise ContractError('snapshot_already_exists')
    archive=CrossArchive(archive_index,store)
    try:
        available={r['doc_id']:r for r in lines(inventory/'document_coverage.jsonl') if r.get('originals')}
        months={d:r.get('submit_date','')[:7] or 'unknown' for d,r in available.items()}
        seen=set();components=[];blocked=[]
        for doc in sorted(available):
            if doc in seen:continue
            r=available[doc]
            if not r.get('metadata') or not set(r['document_types'])<= {'120','130'}:
                blocked.append({'doc_id':doc,'status':'BLOCKED','reason':'metadata_missing' if not r.get('metadata') else 'document_type_out_of_scope'})
                seen.add(doc);continue
            try:
                closure,_=revision_closure([doc],SqlLinks(archive.db),SqlLinks(archive.db,True),300)
                # Primary includes every available raw in the component. Missing revisions
                # are rediscovered by P3 as revision_support, never filled from a mirror.
                primary=set(closure)&available.keys();seen.update(primary);components.append(primary)
            except ContractError as exc:
                blocked.append({'doc_id':doc,'status':'BLOCKED','reason':str(exc)});seen.add(doc)
        jobs=[]
        for n,p in enumerate(partition_components(components,months,limit=limit),1):
            # Full closure must fit downstream budget even if some revision raw is absent.
            closure=set()
            for d in p['doc_ids']:
                found,_=revision_closure([d],SqlLinks(archive.db),SqlLinks(archive.db,True),300);closure.update(found)
            if len(closure)>100:p.update(status='BLOCKED',reason='revision_component_exceeds_document_budget')
            p.update(job_id=f'part-{n:05d}',revision_closure_doc_ids=sorted(closure),
                estimated_input_bytes=sum(sum(a['byte_count'] for a in available[d]['originals']) for d in p['doc_ids']))
            jobs.append(p)
        plan={'snapshot_id':output.name,'created_at':utcnow(),'code_files':code_identity(),
            'inventory':str(inventory),'archive_index':str(Path(archive_index).resolve()),'derived_index':str(Path(derived_index).resolve()),
            'jquants_root':str(Path(jquants_root).resolve()),'batch_limit':limit,'jobs':jobs,'blocked_documents':blocked,
            'row_cache':str(private_path(row_cache or output/'row-cache')),
            'archive_manifest_sha256':file_hash(Path(archive_index)/'cross_archive_index.json'),
            'derived_manifest_sha256':file_hash(Path(derived_index)/'manifest.json'),
            'input_hashes':{n:file_hash(inventory/n) for n in ('source_files.jsonl','document_coverage.jsonl','expansion_queue.jsonl')},
            'raw_doc_id_count':len(available),'selection_rule':'all available official originals, sorted month/doc, indivisible revision components; never outcome substitution',
            'rights_review':'BLOCKED','export_allowed':False,'system_replay':'NOT ESTABLISHED'}
        store.publish('expansion_plan.json',encoded(plan))
        store.publish('document_plan.jsonl',b''.join(encoded(dict(doc_id=d,job_id=j['job_id'],status=j['status'],reason=j['reason']))+b'\n' for j in jobs for d in j['doc_ids'])+
                      b''.join(encoded(b)+b'\n' for b in blocked))
        return {'jobs':len(jobs),'raw_documents':len(available),'blocked_before_execution':len(blocked)}
    finally:archive.close()


def reconstructable_files(work,package,*,codec=None,synthetic=False):
    """Only omit stage bytes when their EXACT serialized content can be replayed."""
    from query_dataset import Dataset
    from dataset_contract import payload
    grouped=defaultdict(dict)
    d=Dataset(package,codec=codec,allow_synthetic=synthetic)
    for table,rows in d.tables.items():
        for r in rows:
            if not r.get('input_stage') or not r.get('input_line'):continue
            value=encoded(payload(r))
            if sha256(value)!=r['input_row_sha256']:continue  # redacted text/anchors stay in the archive
            key=(r['input_snapshot_id'],r['input_file'])
            grouped[key][int(r['input_line'])]=(value,table)
    reusable={}
    for (snapshot,name),rows in grouped.items():
        path=Path(work)/snapshot/name
        if not path.is_file() or sorted(rows)!=list(range(1,len(rows)+1)):continue
        raw=b''.join(rows[n][0]+b'\n' for n in sorted(rows))
        if sha256(raw)!=file_hash(path):continue
        reusable[path.relative_to(work).as_posix()]={'sha256':sha256(raw),'byte_count':len(raw),
            'reconstruction':'package_payload_ordered_by_input_line_with_LF','input_snapshot_id':snapshot,'input_file':name,
            'tables':sorted({v[1] for v in rows.values()}),'row_count':len(rows)}
    return reusable


def replay_stage_file(package,description,*,codec=None,synthetic=False):
    from query_dataset import Dataset
    from dataset_contract import payload
    d=Dataset(package,codec=codec,allow_synthetic=synthetic);values={}
    for table in description['tables']:
        for r in d.tables[table]:
            if (r['input_snapshot_id'],r['input_file'])!=(description['input_snapshot_id'],description['input_file']):continue
            raw=encoded(payload(r))
            if sha256(raw)!=r['input_row_sha256']:continue
            n=int(r['input_line'])
            if n in values and values[n]!=raw:raise ContractError('reconstruction_conflict')
            values[n]=raw
    if sorted(values)!=list(range(1,description['row_count']+1)):raise ContractError('reconstruction_rows_missing')
    raw=b''.join(values[n]+b'\n' for n in sorted(values))
    if (sha256(raw),len(raw))!=(description['sha256'],description['byte_count']):raise ContractError('reconstruction_hash_failed')
    return raw


def seal_evidence(work,target,*,reusable=None):
    """Compress newly generated temporary stages, preserving every byte/locator.

    No source archive or preexisting snapshot is deleted. TemporaryDirectory owns
    only this invocation's work area; its exact paths are never accepted from input.
    """
    entries=[];reusable=reusable or {}
    with zipfile.ZipFile(target,'x',compression=zipfile.ZIP_LZMA,allowZip64=True) as z:
        for p in sorted(Path(work).rglob('*')):
            if not p.is_file():continue
            name=p.relative_to(work).as_posix();digest=file_hash(p)
            if name in reusable:
                if digest!=reusable[name]['sha256']:raise ContractError('reconstructed_input_changed')
                continue
            z.write(p,name);entries.append({'member':name,'sha256':digest,'byte_count':p.stat().st_size})
    import hashlib
    with zipfile.ZipFile(target) as z:
        for e in entries:
            h=hashlib.sha256();count=0
            with z.open(e['member']) as f:
                for b in iter(lambda:f.read(1024*1024),b''):h.update(b);count+=len(b)
            if (h.hexdigest(),count)!=(e['sha256'],e['byte_count']):raise ContractError('stage_archive_roundtrip_failed')
    return {'archive_sha256':file_hash(target),'byte_count':Path(target).stat().st_size,'members':entries,
            'reconstructed_members':reusable,'roundtrip':'PASS'}


def validate_checkpoint(folder,expected):
    folder=Path(folder);r=json.loads((folder/'result.json').read_bytes())
    if r['plan_sha256']!=expected:raise ContractError('checkpoint_plan_changed')
    for rel,h in r['artifacts'].items():
        if file_hash(folder/rel)!=h:raise ContractError('checkpoint_artifact_changed')
    return r


def execute_job(plan,job,root,plan_sha,*,synthetic=False,codec=None):
    from p3_audit import run as p3
    from p4_audit import run as p4
    from p5_audit import run as p5
    from expansion_sources import indexed_bundle
    from dataset_export import export_dataset
    from dataset_contract import ParquetCodec
    if plan['code_files']!=code_identity():raise ContractError('execution_code_changed_since_plan')
    codec=codec or ParquetCodec(compression_level=9,compact=True)
    folder=Path(root)/'jobs'/job['job_id']
    if (folder/'result.json').exists():return validate_checkpoint(folder,plan_sha)
    if folder.exists():raise ContractError('interrupted_job_requires_new_attempt_directory')
    out=PrivateStore(folder)
    result={'job_id':job['job_id'],'month':job['month'],'doc_ids':job['doc_ids'],'plan_sha256':plan_sha,
        'status':'BLOCKED','reason':job['reason'],'stages':{},'artifacts':{},'rights_review':'BLOCKED','export_allowed':False}
    if job['status']=='READY':
        if shutil.disk_usage(root).free<2*1024**3:raise ContractError('insufficient_working_disk_space')
        # Temp stages are owned by this invocation; sealed bytes remain queryable in evidence.zip.
        with tempfile.TemporaryDirectory(prefix='expansion-',dir=root) as tmp:
            work=Path(tmp)
            stage='p3'
            try:
                archive=CrossArchive(plan['archive_index'],PrivateStore(work/'index-check'))
                try:make_frame(archive,job['doc_ids'],work/'frame')
                finally:archive.close()
                with (work/'execution.log').open('x',encoding='utf-8') as log,redirect_stdout(log):
                    result['stages']['p3']=p3(plan['archive_index'],work/'frame',work,job['job_id']+'-p3',synthetic=synthetic,compact_candidates=True)
                    p3path=work/(job['job_id']+'-p3');stage='p4'
                    result['stages']['p4']=p4(plan['jquants_root'],plan['archive_index'],p3path,work,job['job_id']+'-p4',synthetic=synthetic,
                        direct_dated=True,row_cache=plan['row_cache'],bounded_calendar=True)
                    docs=json.loads((p3path/'audit_plan.json').read_bytes())['all'];stage='p5'
                    source=indexed_bundle(plan['derived_index'],p3path,docs,work/'p5-input')
                    result['stages']['p5']=p5(plan['archive_index'],p3path,work/'p5-input',work,job['job_id']+'-p5',synthetic=synthetic,
                        compact_originals=True,document_limit=100,raw_store=source)
                    stage='p55'
                    result['stages']['p55']=export_dataset(p3path,work/(job['job_id']+'-p4'),work/(job['job_id']+'-p5'),
                        folder/'package',job['job_id'],codec=codec,synthetic=synthetic)
                result.update(status='COMPLETE',reason='execution_complete; row-level BLOCKED and rights remain independent')
            except (ContractError,ValueError,KeyError,OSError,TypeError,ImportError) as exc:
                result.update(failed_stage=stage,reason=str(exc) if isinstance(exc,ContractError) else type(exc).__name__+':stage_failed')
                # Exact exception is private diagnostics, never public CI output.
                import traceback
                (work/'failure_trace.txt').write_text(traceback.format_exc(),encoding='utf-8')
            reusable=reconstructable_files(work,folder/'package',codec=codec,synthetic=synthetic) if result['status']=='COMPLETE' else {}
            proof=seal_evidence(work,folder/'evidence.zip',reusable=reusable)
            out.publish('evidence_manifest.json',encoded(proof))
    result['artifacts']={p.relative_to(folder).as_posix():file_hash(p) for p in sorted(folder.rglob('*')) if p.is_file()}
    out.publish('result.json',encoded(result));return result


def prewarm_market_cache(plan,root):
    """Single writer before parallel jobs; no cache creation races or new acquisition."""
    from expansion_sources import CachedJQuants
    from jquants_local import DATASETS
    jq=CachedJQuants(plan['jquants_root'],PrivateStore(Path(root)/'cache-check'),cache_root=plan['row_cache'])
    windows={d:[('2015-01-01','2027-01-01')] for d in DATASETS if d!='markets_calendar'}
    failures=[]
    for n,f in enumerate(jq.plan(windows)['files'],1):
        try:jq._cache(f)
        except (ContractError,ValueError) as exc:
            failures.append({'relative_path':f['relative_path'],'reason':str(exc) if isinstance(exc,ContractError) else 'invalid_date'})
        if n%25==0:print(json.dumps({'cache_files_checked':n,'failed':len(failures)}),flush=True)
    proof={'preservation':jq.prove_unchanged(),'failures':failures}
    PrivateStore(Path(root)/'cache-check').publish('result.json',encoded(proof))


def run(output,*,limit=None,workers=1):
    root=private_path(output);raw=(root/'expansion_plan.json').read_bytes();plan=json.loads(raw);digest=sha256(raw)
    if plan['code_files']!=code_identity():raise ContractError('execution_code_changed_since_plan')
    for key,name in [('archive_index','cross_archive_index.json'),('derived_index','manifest.json')]:
        expected=plan['archive_manifest_sha256' if key=='archive_index' else 'derived_manifest_sha256']
        if file_hash(Path(plan[key])/name)!=expected:raise ContractError('dependency_manifest_changed')
    for name,h in plan['input_hashes'].items():
        if file_hash(Path(plan['inventory'])/name)!=h:raise ContractError('frozen_inventory_changed')
    if not 1<=workers<=3:raise ContractError('invalid_worker_count')
    new=0;counts=Counter();pending=[]
    for job in plan['jobs']:
        if not (root/'jobs'/job['job_id']/'result.json').exists():
            if limit is not None and new>=limit:break
            new+=1
        pending.append(job)
    if workers>1:
        # Existing accepted caches are immutable. Prewarm before child processes read them.
        if not (root/'cache-check/result.json').exists():prewarm_market_cache(plan,root)
        from concurrent.futures import ProcessPoolExecutor,wait,FIRST_COMPLETED
        with ProcessPoolExecutor(max_workers=workers) as pool:
            it=iter(pending);running={}
            def submit():
                job=next(it,None)
                if job is not None:running[pool.submit(execute_job,plan,job,root,digest)]=job['job_id']
            for _ in range(workers):submit()
            while running:
                done,_=wait(running,return_when=FIRST_COMPLETED)
                for future in done:
                    running.pop(future);result=future.result();counts[result['status']]+=1
                    print(json.dumps({'job':result['job_id'],'status':result['status'],'reason':result['reason'],'counts':dict(counts)}),flush=True)
                    submit()
        return dict(counts)
    for job in pending:
        result=execute_job(plan,job,root,digest)
        counts[result['status']]+=1
        print(json.dumps({'job':job['job_id'],'status':result['status'],'reason':result['reason'],'counts':dict(counts)}),flush=True)
    return dict(counts)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True);p.add_argument('--limit',type=int);p.add_argument('--workers',type=int,default=1)
    a=p.parse_args();run(a.output,limit=a.limit,workers=a.workers)
