"""P5 comparison views. Never mutate canonical facts or infer identity from names."""
from collections import Counter, defaultdict
from decimal import Decimal, InvalidOperation
import io
import json
import re
import zipfile
from xml.etree import ElementTree as ET

from evidence_core import ContractError
from financial_facts import parsed_members, period, unit_definition, qname, XI, DI, DEI, NIL
from original_tie import normalized
from source_acquisition import encoded, sha256

DEFINITION='p5-derived-views-v1'
SOURCE_CLASSES={'official_original','derived_from_edinet','independent_external'}
COMPARISONS={'exact_match','extraction_difference','context_difference','unit_difference','scope_difference',
             'revision_difference','text_difference','missing_in_source','unresolved'}
DEI_FIELDS={'edinet_code':'EDINETCodeDEI','security_code':'SecurityCodeDEI','accounting_standards':'AccountingStandardsDEI',
    'has_consolidated':'WhetherConsolidatedFinancialStatementsArePreparedDEI',
    'current_fiscal_year_start_date':'CurrentFiscalYearStartDateDEI','current_fiscal_year_end_date':'CurrentFiscalYearEndDateDEI',
    'amendment_flag':'AmendmentFlagDEI','number_of_submission':'NumberOfSubmissionDEI'}
# Provider's explicit SQL coalesce order, not new canonical mappings. Other fields stay out of scope.
MART_FIELDS={
    'net_sales':['RevenueIFRS','NetSales'],'net_income':['NetIncomeLoss'],
    'profit_attributable_to_owners':['ProfitLossAttributableToOwnersOfParentIFRS','ProfitLossAttributableToOwnersOfParent'],
    'total_assets':['TotalAssetsIFRS','TotalAssets'],'net_assets':['EquityAttributableToOwnersOfParentIFRS','NetAssets'],
    'total_issued_shares':['TotalNumberOfIssuedShares'],
    'basic_eps':['BasicEarningsLossPerShareIFRS','BasicEarningsLossPerShare'],
    'net_assets_per_share':['NetAssetsPerShare','EquityToAssetRatioIFRS'],
    'operating_cash_flow':['CashFlowsFromUsedInOperatingActivitiesIFRS','NetCashProvidedByUsedInOperatingActivities'],
    'investing_cash_flow':['CashFlowsFromUsedInInvestingActivitiesIFRS','NetCashProvidedByUsedInInvestingActivities']}


def scalar_equal(a,b):
    if a is None or b is None:return a is b
    try:
        x,y=Decimal(str(a)),Decimal(str(b))
        return x.is_finite() and y.is_finite() and x==y
    except InvalidOperation:return str(a)==str(b)


def document_link(row, document):
    """Every provided identifier/period/time must agree; document ID is mandatory."""
    if row.get('doc_id')!=document['doc_id']:return 'document_id_mismatch'
    metadata=document['metadata_locators'][0]['provider_fields']
    for field,expected in [('edinet_code',document['edinet_code']),('sec_code',document.get('secCode')),
        ('period_start',metadata.get('periodStart')),('period_end',metadata.get('periodEnd')),
        ('doc_type_code',document.get('doc_type')),('parent_doc_id',document.get('parentDocID'))]:
        if field in row and (row[field] or None)!=(expected or None):
            return 'revision_difference' if field=='parent_doc_id' else 'identifier_or_period_mismatch'
    for key,original in [('withdrawal_status','withdrawalStatus'),('doc_info_edit_status','docInfoEditStatus'),('disclosure_status','disclosureStatus')]:
        if key in row and row[key]!=metadata.get(original):return 'revision_difference'
    submitted=document.get('submit_datetime','')
    for key in ('submit_datetime','submit_date_time','submit_date'):
        if row.get(key):
            actual=row[key].replace('T',' ')
            # Original metadata has minute precision. Compare only the shared precision.
            length=10 if key=='submit_date' else len(submitted)
            if not submitted or actual[:length]!=submitted[:length]:return 'submit_time_mismatch'
    return None


def context_record(element, scopes):
    try:p=period(element)
    except (ContractError,ValueError):p={'period_kind':None,'period_start':None,'period_end':None,'instant_date':None}
    identifiers=element.findall(f'{{{XI}}}entity/{{{XI}}}identifier')
    dims=[]
    for e in element.iter():
        if e.tag==f'{{{DI}}}explicitMember':
            dims.append({'axis':qname(e.get('dimension'),scopes[id(e)]),'member':qname(e.text,scopes[id(e)])})
        elif e.tag==f'{{{DI}}}typedMember':
            dims.append({'axis':qname(e.get('dimension'),scopes[id(e)]),'typed_xml':ET.tostring(e,encoding='unicode')})
    return dict(p,context_id=element.get('id'),entity_id=identifiers[0].text if len(identifiers)==1 else None,
        entity_scheme=identifiers[0].get('scheme') if len(identifiers)==1 else None,dimensions=dims,
        xml_sha256=sha256(ET.tostring(element)))


def original_index(raw, artifact, document):
    if sha256(raw)!=artifact['byte_sha256'] or len(raw)!=artifact['byte_count']:raise ContractError('original_byte_integrity_failed')
    if artifact['doc_id']!=document['doc_id']:raise ContractError('original_document_mismatch')
    facts,contexts,relations=[],[],[]
    group=sha256(encoded([document['doc_id'],artifact['byte_sha256']]))
    for member,xml,tree,scopes in parsed_members(raw):
        base={'doc_id':document['doc_id'],'source_class':'official_original','upstream_evidence_group':group,
              'artifact_sha256':artifact['byte_sha256'],'member':member,'member_sha256':sha256(xml)}
        cs=defaultdict(list);us=defaultdict(list)
        for e in tree.findall(f'{{{XI}}}context'):
            c=dict(base,**context_record(e,scopes));c['origin_id']=sha256(encoded(c));cs[c['context_id']].append(c);contexts.append(c)
        for e in tree.findall(f'{{{XI}}}unit'):
            try:us[e.get('id')].append(unit_definition(e,scopes))
            except ContractError:us[e.get('id')].append(None)
        for i,e in enumerate(tree.iter()):
            if e.get('contextRef') is None:continue
            candidates=cs[e.get('contextRef')];units=us[e.get('unitRef')]
            c=dict(base,element_index=i,qname=e.tag,context_ref=e.get('contextRef'),unit_ref=e.get('unitRef'),
                value=''.join(e.itertext()),is_nil=e.get(NIL) in ('true','1'),
                context=candidates[0] if len(candidates)==1 else None,unit=units[0] if len(units)==1 else None,
                lexical_qnames=sorted(prefix+':'+e.tag.split('}')[-1] for prefix,ns in scopes[id(e)].items()
                    if prefix and e.tag.startswith('{'+ns+'}')))
            c['origin_id']=sha256(encoded([base,i]));facts.append(c)
    # Resolve loc labels within actual ZIP linkbases. No external taxonomy fetch or guessed arcs.
    link='http://www.xbrl.org/2003/linkbase';xl='{http://www.w3.org/1999/xlink}'
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        for info in z.infolist():
            if not info.filename.endswith(('_cal.xml','_def.xml')):continue
            xml=z.read(info);guard=xml.replace(b'\0',b'').upper()
            if b'<!DOCTYPE' in guard or b'<!ENTITY' in guard:raise ContractError('xml_rejected')
            try:tree=ET.fromstring(xml)
            except ET.ParseError:raise ContractError('xml_parse_failed') from None
            for parent in tree:
                locs=defaultdict(list)
                for loc in parent.findall(f'{{{link}}}loc'):locs[loc.get(xl+'label')].append(loc.get(xl+'href'))
                for i,e in enumerate(parent):
                    if e.tag not in {f'{{{link}}}calculationArc',f'{{{link}}}definitionArc'}:continue
                    left,right=locs[e.get(xl+'from')],locs[e.get(xl+'to')]
                    if len(left)!=1 or len(right)!=1:continue
                    rel={'doc_id':document['doc_id'],'source_class':'official_original','upstream_evidence_group':group,
                        'artifact_sha256':artifact['byte_sha256'],'member':info.filename,'member_sha256':sha256(xml),
                        'element_index':i,'role_uri':parent.get(xl+'role'),'arcrole':e.get(xl+'arcrole'),
                        'parent_href':left[0],'child_href':right[0],'weight':e.get('weight'),'order':e.get('order')}
                    rel['origin_id']=sha256(encoded(rel));relations.append(rel)
    return {'facts':facts,'contexts':contexts,'relations':relations,'upstream_evidence_group':group}


def context_difference(row, original):
    if original is None:return 'context_difference'
    for field,expected in [('period_type',original['period_kind']),('period_instant',original['instant_date']),
        ('period_start',original['period_start']),('period_end',original['period_end']),
        ('entity_id',original['entity_id']),('entity_scheme',original['entity_scheme'])]:
        if field in row and row[field]!=expected:return 'context_difference'
    if 'dimensions_json' in row:
        try:dims=json.loads(row['dimensions_json']) if row['dimensions_json'] else []
        except (TypeError,ValueError):return 'context_difference'
        if sorted(map(encoded,dims))!=sorted(map(encoded,original['dimensions'])):
            content=str(dims)+str(original['dimensions'])
            return 'scope_difference' if 'ConsolidatedOrNonConsolidatedAxis' in content else 'context_difference'
    return None


def compare_fact(source, table, row, index):
    candidates=index['facts']
    if source=='numad':candidates=[f for f in candidates if f['qname'].rsplit('}',1)[-1]==row.get('tag')]
    elif source=='queria':candidates=[f for f in candidates if row.get('element_id') in f['lexical_qnames']]
    else:candidates=[f for f in candidates if f['qname']==row.get('concept')]
    if not candidates:return 'extraction_difference','original_element_not_found',[]
    if source!='numad':
        candidates=[f for f in candidates if f['context_ref']==row.get('context_id')]
        if not candidates:return 'context_difference','original_context_not_matched',[]
    if len(candidates)!=1:return 'unresolved','original_element_ambiguous',[f['origin_id'] for f in candidates]
    f=candidates[0];loc=[f['origin_id']]
    if f['context'] is None:return 'unresolved','original_context_ambiguous',loc
    if source=='youseiushida':
        difference=context_difference(row,f['context'])
        if difference:return difference,'provider_context_differs',loc
        if row.get('is_nil')!=f['is_nil']:return 'extraction_difference','nil_state_differs',loc
    if source!='numad' and row.get('unit_id' if source=='queria' else 'unit_ref')!=f['unit_ref']:
        return 'unit_difference','unit_ref_differs',loc
    if f['unit_ref'] and f['unit'] is None:return 'unresolved','original_unit_ambiguous',loc
    value=row.get('text') if source=='numad' else row.get('value') if source=='queria' else (
        row.get('value_numeric') if row.get('value_type')=='decimal' else row.get('value_text'))
    if f['is_nil']:
        return ('exact_match',None,loc) if value in (None,'') else ('extraction_difference','nil_value_differs',loc)
    text=source=='numad' or table=='text_blocks' or f['qname'].endswith('TextBlock')
    equal=bool(normalized(str(value or ''))) and normalized(str(value or ''))==normalized(f['value']) if text else scalar_equal(value,f['value'])
    if equal:return 'exact_match',None,loc
    return ('text_difference' if text else 'extraction_difference'),'provider_value_differs',loc


def compare_relation(table,row,index):
    if table=='calc_edges':
        matches=[r for r in index['relations'] if r['arcrole']=='http://www.xbrl.org/2003/arcrole/summation-item' and
            all(r[k]==row.get(k) for k in ('role_uri','parent_href','child_href'))]
        if len(matches)!=1:return 'unresolved','original_relation_missing_or_ambiguous',[r['origin_id'] for r in matches]
        r=matches[0]
        if not all(scalar_equal(r[k],row.get(k)) for k in ('weight','order')):return 'extraction_difference','calculation_arc_attributes_differ',[r['origin_id']]
        return 'exact_match',None,[r['origin_id']]
    # This flattened provider view drops namespace, role and full ancestry.
    # Preserve candidate original arcs; never promote a local-name pair to verified mapping.
    candidates=[r['origin_id'] for r in index['relations'] if row.get('child_concept') in r['child_href'] and
                row.get('parent_standard_concept') in r['parent_href']]
    return 'unresolved','flattened_definition_relation_lacks_qname_role_path',candidates


def compare_context(row,index):
    matches=[c for c in index['contexts'] if c['context_id']==row.get('context_id')]
    if len(matches)!=1:return 'unresolved','original_context_ambiguous',[c['origin_id'] for c in matches]
    diff=context_difference(row,matches[0]);return diff or 'exact_match','provider_context_differs' if diff else None,[matches[0]['origin_id']]


def mart_components(row,field,source_rows):
    summary=[r for r in source_rows if r['provider_fields'].get('doc_id')==row['doc_id'] and
             re.fullmatch(r'jpcrp_cor:[A-Za-z0-9]+SummaryOfBusinessResults',r['provider_fields'].get('element_id','')) and
             re.fullmatch(r'(CurrentYear|Prior[1-4]Year)(Duration|Instant)(_NonConsolidatedMember)?',r['provider_fields'].get('context_id',''))]
    consolidated=any('NonConsolidatedMember' not in r['provider_fields']['context_id'] for r in summary)
    prefix='CurrentYear' if row['year_offset']==0 else f"Prior{abs(row['year_offset'])}Year"
    picked=[r for r in summary if r['provider_fields']['context_id'].startswith(prefix) and
            ('NonConsolidatedMember' not in r['provider_fields']['context_id'])==consolidated]
    for name in MART_FIELDS[field]:
        matches=[r for r in picked if r['provider_fields']['element_id']=='jpcrp_cor:'+name+'SummaryOfBusinessResults' and
            (name!='EquityToAssetRatioIFRS' or r['provider_fields'].get('unit_id')=='JPYPerShares') and r['provider_fields'].get('value') is not None]
        if matches:return matches
    return []
