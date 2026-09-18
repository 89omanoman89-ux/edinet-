"""Bounded public evidence acquisition. No credentials and no provider code execution."""
import io
import json
import re
import tarfile
from urllib.request import Request, urlopen

from evidence_core import ContractError
from source_acquisition import encoded, sha256, safe_uri, utcnow


def fetch(store, url, version, *, start=None, size=None, limit=64 * 1024 * 1024, opener=urlopen):
    safe = safe_uri(url)
    if safe != url: raise ContractError('public_url_query_not_allowed')
    if start is not None and (start < 0 or size is None or not 0 < size <= limit):
        raise ContractError('invalid_public_range')
    key = sha256(encoded([url, version, start, size]))
    checkpoint = store.root / 'completed' / (key + '.json')
    if checkpoint.exists():
        record = json.loads(checkpoint.read_bytes())
        return store.read_raw(record), record
    headers = {'User-Agent': 'edinet-derived-source-audit/1.0'}
    if start is not None: headers['Range'] = f'bytes={start}-{start + size - 1}'
    with opener(Request(url, headers=headers), timeout=60) as response:
        raw = response.read((size if start is not None else limit) + 1)
        content_range = response.headers.get('Content-Range')
        if start is not None:
            match = re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)', content_range or '')
            if (response.status != 206 or not match or tuple(map(int, match.groups()[:2])) != (start, start+size-1)
                    or len(raw) != size): raise ContractError('public_range_not_honored')
        elif response.status != 200 or len(raw) > limit: raise ContractError('public_response_limit_or_status')
        record = {'safe_url': safe, 'provider_version': version, 'retrieved_at': utcnow(),
            'http_status': response.status, 'byte_sha256': sha256(raw), 'byte_count': len(raw),
            'content_range': content_range, 'range_start': start, 'range_size': size,
            'artifact_scope': 'range_bytes' if start is not None else 'complete_response',
            'etag': response.headers.get('ETag'), 'last_modified': response.headers.get('Last-Modified'),
            'rights_review': 'BLOCKED', 'export_allowed': False}
    store.publish('raw/'+record['byte_sha256'],raw)
    store.publish('completed/'+key+'.json',encoded(record))
    return raw, record


def tar_index(store, url, version, total_bytes, *, max_members=100, opener=urlopen):
    """Read checked tar headers only; never extract paths or fetch all filing types."""
    offset, entries, headers = 0, [], []
    for _ in range(max_members):
        if offset + 512 > total_bytes: raise ContractError('tar_header_outside_asset')
        raw, artifact = fetch(store,url,version,start=offset,size=512,opener=opener)
        headers.append(artifact)
        if raw == b'\0'*512: return entries, headers
        try: info = tarfile.TarInfo.frombuf(raw,'utf-8','strict')
        except (tarfile.TarError,ValueError): raise ContractError('invalid_tar_header') from None
        if not info.isfile() or '/' in info.name or '\\' in info.name or info.size < 0:
            raise ContractError('unsupported_tar_member')
        if offset+512+info.size > total_bytes: raise ContractError('tar_member_outside_asset')
        entries.append({'name':info.name,'offset':offset+512,'size':info.size,'header':artifact})
        offset += 512 + ((info.size+511)//512)*512
    raise ContractError('tar_member_budget_exceeded')


class RangeFile(io.RawIOBase):
    """Seekable bounded member view. Each fetched range has its own byte hash.

    A set of ranges is explicitly NOT a whole-file digest. Stable ETag is required
    across reads; a mutable remote replacement cannot silently mix generations.
    """
    def __init__(self, store, url, version, offset, size, *, budget=128*1024*1024, opener=urlopen, expected_etag=None):
        self.store,self.url,self.version,self.offset,self.size=store,url,version,offset,size
        self.position,self.budget,self.opener=0,budget,opener
        self.artifacts,self.cache,self.etag=[],{},expected_etag

    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.position
    def seek(self, offset, whence=0):
        position=offset if whence==0 else self.position+offset if whence==1 else self.size+offset if whence==2 else -1
        if not 0 <= position <= self.size: raise ContractError('range_seek_outside_member')
        self.position=position;return position

    def read(self, size=-1):
        size=self.size-self.position if size<0 else min(size,self.size-self.position)
        if not size:return b''
        key=(self.position,size)
        if key not in self.cache:
            if sum(len(x) for x in self.cache.values())+size>self.budget:raise ContractError('range_budget_exceeded')
            raw,a=fetch(self.store,self.url,self.version,start=self.offset+self.position,size=size,opener=self.opener)
            if not a['etag']:raise ContractError('range_version_validator_missing')
            if self.etag is not None and a['etag']!=self.etag:raise ContractError('range_version_changed')
            self.etag=a['etag'];self.cache[key]=raw;self.artifacts.append(a)
        self.position+=size
        return self.cache[key]

    def readinto(self, buffer):
        raw=self.read(len(buffer));buffer[:len(raw)]=raw;return len(raw)


def json_value(value):
    from decimal import Decimal
    if isinstance(value, dict): return {k:json_value(v) for k,v in value.items()}
    if isinstance(value, (list,tuple)): return [json_value(v) for v in value]
    if isinstance(value, Decimal): return str(value)
    if hasattr(value,'isoformat'): return value.isoformat()
    return value


def parquet_rows(file, targets, key='doc_id'):
    """Select fixed identifiers, preserving physical row group and row index.

    Optional PyArrow is for private acquisition only; public CI uses JSON fixtures.
    Min/max pruning is followed by exact column selection; no name matching.
    """
    import pyarrow.parquet as pq
    p=pq.ParquetFile(file)
    if key not in p.schema.names: raise ContractError('parquet_identifier_column_missing')
    column=p.schema.names.index(key);rows=[];scanned=0
    for group in range(p.num_row_groups):
        stats=p.metadata.row_group(group).column(column).statistics
        if stats and stats.has_min_max and not any(stats.min<=x<=stats.max for x in targets):continue
        ids=p.read_row_group(group,columns=[key]).column(key).to_pylist();scanned+=1
        indices=[i for i,x in enumerate(ids) if x in targets]
        if not indices:continue
        table=p.read_row_group(group)
        for index in indices:
            row=json_value(table.slice(index,1).to_pylist()[0])
            rows.append({'provider_fields':row,'locator':{'row_group':group,'row_index':index,
                                                        'row_sha256':sha256(encoded(row))}})
    return {'schema':str(p.schema_arrow),'schema_sha256':sha256(str(p.schema_arrow).encode()),
            'file_row_count':p.metadata.num_rows,'row_group_count':p.num_row_groups,
            'groups_inspected':scanned,'key':key,'selected_count':len(rows),'rows':rows}
