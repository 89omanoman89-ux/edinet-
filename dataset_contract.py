"""Public P5.5 table contract. No provider rows or private locations belong here."""
from pathlib import Path, PurePosixPath
import json

from evidence_core import ContractError
from source_acquisition import encoded, sha256

VERSION = 'private-query-v1'
# Primary IDs remain the IDs of the upstream audit. Composite keys are explicit.
TABLES = {
    'entities': ('entity_id', 'Submitter entity search index; names are search hints only', ['documents.edinet_code', 'securities.entity_id']),
    'securities': ('mapping_id', 'P4 dated security mapping; security_id is not a lifetime security master', ['entities.entity_id', 'pit_join_rows.mapping_id']),
    'documents': ('doc_id', 'P3 document metadata, revision parents and status events', ['canonical_facts.doc_id', 'derived_source_links.doc_id']),
    'canonical_facts': ('fact_id', 'All P3 candidates including reasoned nulls; use facts --as-of for PIT selection', ['documents.doc_id', 'pit_join_rows.edinet_fact_id']),
    'market_observations': ('observation_id', 'P4 raw-basis market views with source availability rules', ['pit_join_rows.market_observation_id', 'jquants_source_rows.observation_id']),
    'pit_join_rows': ('research_row_id', 'All audited P4 decisions, including BLOCKED; not new joins at arbitrary dates', ['canonical_facts.fact_id', 'securities.mapping_id', 'market_observations.observation_id']),
    'derived_source_links': ('comparison_id', 'P5 comparisons; mirrors remain dependent on the same EDINET original', ['derived_source_rows.source_row_id', 'original_facts.origin_id', 'canonical_facts.fact_id']),
    'text_index': ('source_row_id', 'Text hashes and private references; no block bodies', ['documents.doc_id', 'derived_source_rows.source_row_id']),
    'lineage': ('from_table,from_id,to_table,to_id,relation', 'Directed evidence edges; traversal reaches original locator and source rows', ['typed table primary keys']),
    'failures': ('input_stage,input_file,input_line', 'All supplied ledgers, null coverage and acceptance gates; never imputed', ['doc_id', 'fact_id', 'research_row_id', 'comparison_id']),
    'jquants_source_rows': ('observation_id', 'Original P4 J-Quants records including master/calendar/financial evidence', ['market_observations.observation_id', 'securities.date_observations']),
    'derived_source_rows': ('source_row_id', 'P5 provider records; block text replaced by hash and private content reference', ['derived_source_links.source_row_id']),
    'original_facts': ('origin_id', 'P5 original element/context/relation locators; long text omitted', ['derived_source_links.origin_ids']),
    'original_locators': ('candidate_id', 'P3 ZIP/member/element/context/unit anchors; IDs retained', ['canonical_facts.candidate_id']),
    'edinet_identity_evidence': ('identity_evidence_id', 'P4 official metadata evidence for filer secCode', ['pit_join_rows.identity_evidence_id']),
    'trading_calendar': ('observation_id', 'P4 calendar; historical calendar delivery remains unknown', ['pit_join_rows.trading_session']),
}

# Queryable string columns avoid float conversion and preserve exact lexical codes,
# decimals and timezone-bearing timestamps. Nested evidence remains lossless JSON.
COLUMNS = ('entity_id', 'security_id', 'edinet_code', 'jquants_code', 'doc_id', 'fact_id',
    'research_row_id', 'source_row_id', 'origin_id', 'comparison_id', 'mapping_id',
    'observation_id', 'identity_evidence_id', 'candidate_id', 'source_id', 'metric',
    'normalized_value', 'public_available_at', 'decision_at', 'status', 'missing_reason',
    'from_table', 'from_id', 'to_table', 'to_id', 'relation',
    'input_stage', 'input_file', 'input_line', 'input_snapshot_id', 'input_file_sha256',
    'input_row_sha256', 'payload_json')
SCHEMA = [[name, 'string', True] for name in COLUMNS]
CHAT_COLUMNS = {
    'company_index': ('snapshot_id', 'entity_id', 'edinet_code', 'names_json', 'codes_json', 'search_only'),
    'filing_index': ('snapshot_id', 'doc_id', 'entity_id', 'sec_code', 'parent_doc_id', 'public_available_at', 'sample_kind', 'status', 'missing_reason'),
    'latest_financials': ('snapshot_id', 'snapshot_cutoff', 'view', 'entity_id', 'doc_id', 'fact_id', 'metric', 'value', 'unit', 'scope', 'accounting_standard', 'period_start', 'period_end', 'instant_date', 'public_available_at', 'status', 'missing_reason'),
    'source_comparison': ('snapshot_id', 'doc_id', 'source_id', 'comparison_id', 'source_row_id', 'comparison', 'status', 'missing_reason', 'independent_evidence_increment'),
}


def catalog():
    return {name: {'path': name + '.parquet', 'meaning': meaning, 'primary_key': pk.split(','),
        'join_keys': joins, 'columns': SCHEMA,
        'date_time_semantics': 'Payload retains period, public/provider/recorded times separately; no inferred intervals',
        'pit_availability': 'P3 fact_view required; raw candidates and provider views are not PIT approval',
        'lineage_availability': 'Typed lineage edges plus exact input snapshot/file/line/hash',
        'rights_status': 'BLOCKED', 'export_allowed': False}
        for name, (pk, meaning, joins) in TABLES.items()}


def discovery_index():
    # This file never changes when CURRENT advances. Dynamic fields are references,
    # not a second mutable or potentially stale current-snapshot pointer.
    ref = lambda field: {'resolve': 'CURRENT.json -> manifest.json -> dataset_index.json', 'field': field}
    return {'dataset_name': 'edinet-research', 'contract_version': VERSION,
        **{k: ref(k) for k in ('snapshot_id', 'created_at', 'definition_versions', 'coverage', 'snapshot_cutoff')},
        'CURRENT_snapshot': {'pointer': 'CURRENT.json'}, 'tables': catalog(),
        'read_order': ['dataset_index.json', 'CURRENT.json', 'snapshot manifest and index', 'chat views', 'required Parquet', 'lineage'],
        'rights_status': 'BLOCKED', 'export_allowed': False, 'distribution': 'private_local_package_only',
        'known_limitations': ['No system replay established', 'No full-market representativeness',
            'Raw archives and text bodies are external hash-addressed references, not embedded',
            'P0-P2 failures only where inherited by supplied P3-P5 snapshots',
            'Drive upload and access to private content are separate, not performed by this code']}


def safe_path(root, relative):
    if not isinstance(relative, str) or '\\' in relative or ':' in relative:
        raise ContractError('unsafe_package_path')
    part = PurePosixPath(relative)
    if part.is_absolute() or any(p in ('..', '.') for p in relative.split('/')):
        raise ContractError('unsafe_package_path')
    path = (Path(root) / relative).resolve()
    if Path(root).resolve() not in path.parents: raise ContractError('package_path_escape')
    return path


def pack(payload, reference=None):
    row = {k: None for k in COLUMNS}
    for k in COLUMNS:
        value = payload.get(k)
        if isinstance(value, (str, int)) and not isinstance(value, bool): row[k] = str(value)
    row.update(reference or {})
    row['payload_json'] = encoded(payload).decode('utf-8')
    return row


def payload(row): return json.loads(row['payload_json'])


class ParquetCodec:
    format = 'parquet'
    extension = '.parquet'

    def encode(self, rows):
        import pyarrow as pa
        import pyarrow.parquet as pq
        schema = pa.schema([pa.field(k, pa.string()) for k in COLUMNS])
        sink = pa.BufferOutputStream()
        pq.write_table(pa.Table.from_pylist(rows, schema=schema), sink, compression='zstd')
        return sink.getvalue().to_pybytes()

    def decode(self, raw):
        import pyarrow as pa
        import pyarrow.parquet as pq
        table = pq.read_table(pa.BufferReader(raw))
        observed = [[f.name, str(f.type), f.nullable] for f in table.schema]
        if observed != SCHEMA: raise ContractError('parquet_schema_mismatch')
        return table.to_pylist()
