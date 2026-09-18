"""Direct dated identity and public reconstruction; outcomes never enter features."""
from datetime import date, datetime, time, timedelta
import json
from pathlib import Path

from evidence_core import ContractError, JST
from filing_catalog import edinet_metadata
from jquants_local import code
from pit_market import instant, number, entry_candidate, choose_price, price_observation, validate_locator
from source_acquisition import encoded, sha256

RULE_FILE = 'registry/p4_dated_rules_v1.json'


def rules():
    return json.loads((Path(__file__).parent / RULE_FILE).read_bytes())


def edinet_identity_evidence(archive, documents):
    """Re-read the actual daily JSON; P3's copied metadata alone is insufficient."""
    cache, output = {}, []
    for doc in documents:
        a = {k: doc.get(k) for k in ('doc_id', 'edinet_code', 'secCode', 'doc_type', 'public_available_at', 'synthetic')}
        a.update(status='BLOCKED', missing_reason=None, sources=[], evidence_level='direct_dated_observation',
                 edinet_role='filer', identity_spec=rules()['specs']['edinet'])
        try:
            code(doc.get('secCode'))
            if not doc.get('edinet_code'): raise ContractError('edinet_filer_identifier_missing')
            if doc.get('doc_type') not in rules()['accepted_document_types']: raise ContractError('filer_security_role_unsupported')
            if not doc.get('metadata_locators'): raise ContractError('edinet_identity_source_missing')
            for loc in doc['metadata_locators']:
                relative = loc['relative_path']
                if relative not in cache:
                    raw, _ = archive._bytes(relative)
                    parsed, _ = edinet_metadata(raw)
                    cache[relative] = (raw, parsed, json.loads(raw)['metadata']['parameter']['date'])
                raw, rows, day = cache[relative]
                if sha256(raw) != loc['source_artifact_sha256']: raise ContractError('edinet_metadata_integrity_failed')
                matches = [r for r in rows if r['seqNumber'] == loc['seqNumber']]
                if len(matches) != 1 or day != loc['day']: raise ContractError('edinet_identity_locator_mismatch')
                r = matches[0]
                if (r['docID'], r['edinetCode'], r['secCode'], r['docTypeCode']) != (
                        doc['doc_id'], doc['edinet_code'], doc['secCode'], doc['doc_type']):
                    raise ContractError('edinet_identity_mismatch')
                if loc.get('provider_fields') != r: raise ContractError('edinet_identity_source_row_mismatch')
                if r.get('fundCode') or r.get('subjectEdinetCode') or r.get('issuerEdinetCode') not in (None, doc['edinet_code']):
                    raise ContractError('filer_security_role_unsupported')
                a['sources'].append({'relative_path': relative, 'byte_sha256': sha256(raw), 'byte_count': len(raw),
                    'day': day, 'seqNumber': r['seqNumber'], 'row_sha256': sha256(encoded(r)), 'provider_fields': r})
            a['status'] = 'PASS'
        except (ContractError, KeyError, ValueError, TypeError) as exc:
            a['missing_reason'] = str(exc) if isinstance(exc, ContractError) else 'edinet_identity_schema_invalid'
        a['identity_evidence_id'] = sha256(encoded(a)); output.append(a)
    return output


def reconstruct_price(observation, channels):
    p = price_observation(observation)
    channel = channels.get(p['source']['artifact']['relative_path'], {})
    if (channel.get('status') != 'PASS' or channel.get('channel') != 'bulk_csv' or
            channel.get('endpoint') != '/equities/bars/daily' or
            channel.get('file_sha256') != p['source']['artifact']['byte_sha256']):
        return dict(p, time_evidence={'level': 'unknown'}, missing_reason='acquisition_channel_unknown')
    config = rules()
    # The provider says daily data ~16:30 and same-day CSV. Round to the next day;
    # this is a schedule reconstruction, not a promise or an old object timestamp.
    at = datetime.combine(date.fromisoformat(p['date']) + timedelta(days=1), time(), JST)
    return dict(p, public_available_at=at.isoformat(), missing_reason=None,
        time_evidence={'level': 'official_provider_schedule_reconstruction', 'rule': config['price_rule'],
            'spec_version': config['spec_version'], 'specs': {k: config['specs'][k] for k in ('update','bulk','bars')},
            'channel_evidence': channel, 'historical_delivery_observed': False, 'system_replay': 'NOT ESTABLISHED'})


def dated_mapping(anchor, masters, required_dates, verified_observation_ids, *, other_anchors=(), decision_at):
    config = rules()
    m = {'definition_version': config['definition_version'], 'doc_id': anchor['doc_id'],
        'entity_id': 'edinet:' + str(anchor.get('edinet_code')), 'security_id': None,
        'jquants_code': anchor.get('secCode'), 'edinet_role': 'filer', 'issuer_role_basis': 'filer_own_security_code_annual_report',
        'identity_evidence_id': anchor['identity_evidence_id'], 'required_dates': sorted(set(required_dates)),
        'date_observations': [], 'matching_method': 'exact_code_direct_dated_observation',
        'listing_basis': 'direct_dated_listing_observation', 'identifier_validity': None, 'listing_period': None,
        'continuity_between_dates': 'NOT ESTABLISHED', 'status': 'BLOCKED', 'missing_reason': None,
        'synthetic': anchor.get('synthetic', False)}
    try:
        if anchor['status'] != 'PASS': raise ContractError(anchor['missing_reason'])
        if instant(anchor['public_available_at']) >= instant(decision_at): raise ContractError('edinet_identity_not_yet_available')
        jq_code = code(anchor['secCode'])
        # Do not silently choose between known different EDINET owners of a code.
        # Future filings cannot invalidate a past decision. This is bounded to the
        # inventoried anchors; no claim to a complete lifetime identity history.
        conflicts = [x['identity_evidence_id'] for x in other_anchors if x['status'] == 'PASS' and
            x.get('secCode') == jq_code and x.get('edinet_code') != anchor['edinet_code'] and
            x.get('public_available_at') and instant(x['public_available_at']) < instant(decision_at)]
        if conflicts:
            m['conflict_evidence_ids'] = conflicts
            raise ContractError('code_reuse_or_entity_conflict')
        for day in m['required_dates']:
            date.fromisoformat(day)
            matches = [r for r in masters if r['provider_fields']['Date'] == day and r['provider_fields']['Code'] == jq_code]
            if len(matches) != 1: raise ContractError('dated_master_ambiguous' if matches else 'dated_master_missing_or_code_mismatch')
            r = matches[0]; fields = r['provider_fields']
            if r['observation_id'] not in verified_observation_ids: raise ContractError('master_source_unverified')
            validate_locator(r['source'])
            if fields.get('ProdCat') not in config['accepted_product_categories']: raise ContractError('product_category_incompatible')
            if fields.get('Mkt') not in config['accepted_markets']: raise ContractError('market_unknown_or_incompatible')
            m['date_observations'].append({'date': day, 'edinet_secCode': jq_code, 'Code': fields['Code'],
                'ProdCat': fields['ProdCat'], 'Mkt': fields['Mkt'], 'MktNm': fields.get('MktNm'),
                'observation_id': r['observation_id'], 'source': r['source'], 'synthetic': r.get('synthetic',False),
                'evidence_level': 'direct_dated_observation', 'listing_basis': m['listing_basis'],
                'use': 'decision_identity' if day <= instant(decision_at).astimezone(JST).date().isoformat() else 'entry_validation_only'})
        # IDs have a dated scope; they do not connect an unobserved interval.
        m.update(status='PASS', security_id='dated-security:' + sha256(encoded([
            anchor['edinet_code'], jq_code, m['required_dates'], config['accepted_product_categories']])))
    except (ContractError, KeyError, ValueError, TypeError) as exc:
        m['missing_reason'] = str(exc) if isinstance(exc,ContractError) else 'dated_identity_schema_invalid'
    m['mapping_id'] = sha256(encoded(m)); return m


def previous_session_day(decision_at, calendar):
    day = instant(decision_at).astimezone(JST).date()
    for offset in range(1,16):
        target = (day-timedelta(days=offset)).isoformat()
        rows = [r for r in calendar if r['provider_fields']['Date'] == target]
        if len(rows) != 1: raise ContractError('trading_calendar_missing_or_ambiguous')
        if rows[0]['provider_fields']['HolDiv'] == '1': return target
        if rows[0]['provider_fields']['HolDiv'] not in {'0','3'}: raise ContractError('session_time_unverified')
    raise ContractError('prior_session_not_available')


def prepare_join(anchor, masters, prices, calendar, verified_ids, *, decision_at, other_anchors=()):
    plan = {'doc_id': anchor['doc_id'], 'decision_at': decision_at, 'status':'BLOCKED', 'missing_reason':None,
            'mapping':None, 'price':None, 'session':None, 'identity_evidence':anchor}
    try:
        prior = previous_session_day(decision_at,calendar)
        session = entry_candidate(anchor['public_available_at'],decision_at,calendar)
        used = [r for r in calendar if r['observation_id'] in session['calendar_observation_ids'] or r['provider_fields']['Date'] == prior]
        if any(r['observation_id'] not in verified_ids for r in used): raise ContractError('calendar_source_unverified')
        session.update(evidence_level='current_reconstruction', public_available_at=None,
            historical_schedule_vintage='NOT ESTABLISHED', decision_feature=False,
            synthetic=any(r.get('synthetic',False) for r in used))
        plan['session'] = session
        m = dated_mapping(anchor,masters,[prior,instant(decision_at).astimezone(JST).date().isoformat(),session['date']],
                          verified_ids,other_anchors=other_anchors,decision_at=decision_at)
        plan['mapping'] = m
        if m['status'] != 'PASS': raise ContractError(m['missing_reason'])
        prior_prices = [p for p in prices if p['date'] == prior and p['jquants_code'] == anchor['secCode']]
        if any(p.get('missing_reason') for p in prior_prices): raise ContractError(prior_prices[0]['missing_reason'])
        p = choose_price(prior_prices, anchor['secCode'], decision_at)
        if p['observation_id'] not in verified_ids: raise ContractError('market_source_unverified')
        validate_locator(p['source'])
        if p.get('time_evidence',{}).get('level') != 'official_provider_schedule_reconstruction':
            raise ContractError('price_availability_evidence_unknown')
        plan.update(status='PASS',price=p)
    except (ContractError, KeyError, ValueError, TypeError) as exc:
        plan['missing_reason'] = str(exc) if isinstance(exc,ContractError) else 'dated_join_schema_invalid'
    plan['prepared_join_id'] = sha256(encoded(plan)); return plan


def join_dated_fact(fact, p3_view, plan, *, decision_at, verified_fact_ids, allow_synthetic_for_tests=False):
    out = {'definition_version':rules()['definition_version'], 'entity_id':'edinet:'+str(fact.get('edinet_code')),
        'edinet_fact_id':fact['fact_id'], 'doc_id':fact['doc_id'], 'public_available_at':fact.get('public_available_at'),
        'decision_at':decision_at, 'entry_at':None, 'trading_session':None, 'mapping_id':None, 'security_id':None,
        'market_observation_id':None, 'identity_evidence_id':plan['identity_evidence']['identity_evidence_id'],
        'normalized_value':None, 'price':None, 'status':'BLOCKED', 'missing_reason':None,
        'replay':'public_reconstruction', 'system_replay':'NOT ESTABLISHED', 'execution_claim':False,
        'synthetic':fact.get('synthetic',False), 'rights_review':'BLOCKED', 'export_allowed':False,
        'edinet_source':{k:fact.get(k) for k in ('source_artifact_sha256','xbrl_member_sha256','xbrl_member',
            'element_index','original_qname','contextRef','unitRef','definition_version')}}
    try:
        if fact['normalized_value'] is None: raise ContractError(fact.get('missing_reason') or 'edinet_null')
        if fact['fact_id'] not in verified_fact_ids: raise ContractError('edinet_source_lineage_unverified')
        if p3_view.get('mode') != 'as_of' or p3_view.get('decision_at') != decision_at: raise ContractError('p3_view_decision_mismatch')
        if fact not in p3_view['facts']:
            reasons = [b['reason'] for b in p3_view['blocked'] if b.get('doc_id') == fact['doc_id'] or
                fact['doc_id'] in b.get('doc_ids',[]) or fact['fact_id'] in b.get('fact_ids',[])]
            raise ContractError(sorted(set(reasons))[0] if reasons else 'unavailable_edinet_vintage')
        if not instant(fact['public_available_at']) < instant(decision_at): raise ContractError('future_information_leakage')
        if plan['doc_id'] != fact['doc_id'] or plan['decision_at'] != decision_at: raise ContractError('dated_plan_mismatch')
        if plan['status'] != 'PASS': raise ContractError(plan['missing_reason'])
        m,p,s = plan['mapping'],plan['price'],plan['session']
        if m['entity_id'] != out['entity_id']: raise ContractError('dated_entity_mismatch')
        synthetic = any(x.get('synthetic',False) for x in [fact,m,p,s,*m['date_observations']])
        if synthetic and not allow_synthetic_for_tests: raise ContractError('synthetic_not_empirical')
        out.update(status='PASS',synthetic=synthetic,normalized_value=fact['normalized_value'], price=p['close'],
            mapping_id=m['mapping_id'],security_id=m['security_id'],jquants_code=m['jquants_code'],
            dated_listing_evidence=m['date_observations'],identifier_validity=None,listing_period=None,
            market_observation_id=p['observation_id'],jquants_source=p['source'],price_date=p['date'],
            price_basis=p['price_basis'],adjustment_basis=p['adjustment_basis'],adjustment_factor=p['adjustment_factor'],
            price_public_available_at=p['public_available_at'],price_time_evidence=p['time_evidence'],
            entry_at=s['start'],trading_session=s,decision_information={
                'edinet_fact_id':fact['fact_id'],'prior_market_observation_id':p['observation_id'],
                'master_observation_ids':[r['observation_id'] for r in m['date_observations'] if r['use']=='decision_identity'],
                'identity_evidence_id':out['identity_evidence_id']},
            entry_validation_master_ids=[r['observation_id'] for r in m['date_observations'] if r['use']=='entry_validation_only'])
    except ContractError as exc: out['missing_reason']=str(exc)
    out['research_row_id']=sha256(encoded(out)); return out


def execution_outcome(jq_code, session, observations, verified_ids):
    """Never used by prepare_join/join_dated_fact, including for selecting a date."""
    out={'jquants_code':jq_code,'entry_at':session['start'],'session_date':session['date'],
        'evidence_level':'current_reconstruction','phase':'post_entry_outcome','decision_feature':False,
        'execution_claim':False,'status':'price_unavailable','missing_reason':'entry_daily_row_missing','sources':[]}
    matches=[r for r in observations if r['dataset']=='equities_bars_daily' and
             r['provider_fields']['Code']==jq_code and r['provider_fields']['Date']==session['date']]
    if len(matches)>1: out.update(status='ambiguous',missing_reason='duplicate_entry_daily_rows')
    elif matches:
        r=matches[0];out['sources']=[{'observation_id':r['observation_id'],'source':r['source']}]
        try:
            if r['observation_id'] not in verified_ids: raise ContractError('entry_source_unverified')
            f=r['provider_fields']; keys=('O','H','L','C','Vo','Va')
            if any(k not in f for k in keys): raise ContractError('entry_schema_incomplete')
            values=[number(f[k]) for k in keys]
            if all(x is None for x in values): out.update(status='no_observed_trade',missing_reason=None)
            elif all(x is not None and x>0 for x in values):
                o,h,l,c,_,_=values
                if not l<=min(o,c)<=max(o,c)<=h: raise ContractError('entry_price_inconsistent')
                out.update(status='traded',missing_reason=None)
            else: raise ContractError('entry_partial_or_inconsistent_values')
        except ContractError as exc: out.update(status='ambiguous',missing_reason=str(exc))
    out['outcome_id']=sha256(encoded(out));return out


def verify_dated_lineage(research, facts, anchors, mappings, observations, verified_fact_ids, views):
    """Validate all admitted rows against re-read source records, not just non-null IDs."""
    fs={f['fact_id']:f for f in facts}; aa={a['identity_evidence_id']:a for a in anchors}
    mm={m['mapping_id']:m for m in mappings}; oo={r['observation_id']:r for r in observations}
    eligible={(v['trigger_doc_id'],v['decision_at']):set(v['selected_fact_ids']) for v in views}
    checked=0
    for r in research:
        if r['status']!='PASS':
            if r['normalized_value'] is not None or not r['missing_reason']: raise ContractError('blocked_row_not_reasoned_null')
            continue
        try:
            f,a,m,p=fs[r['edinet_fact_id']],aa[r['identity_evidence_id']],mm[r['mapping_id']],oo[r['market_observation_id']]
            if f['fact_id'] not in verified_fact_ids or f['fact_id'] not in eligible[r['doc_id'],r['decision_at']]:
                raise ContractError('dated_fact_vintage_unverified')
            if r['doc_id']!=f['doc_id'] or r['doc_id']!=a['doc_id'] or r['normalized_value']!=f['normalized_value']:
                raise ContractError('dated_fact_lineage_mismatch')
            if any(v!=f.get(k) for k,v in r['edinet_source'].items()): raise ContractError('dated_xbrl_lineage_mismatch')
            if not instant(f['public_available_at'])<instant(r['decision_at'])<instant(r['entry_at']):
                raise ContractError('dated_time_leakage')
            if a['status']!='PASS' or m['status']!='PASS' or m['entity_id']!='edinet:'+a['edinet_code'] or a['edinet_code']!=f['edinet_code']:
                raise ContractError('dated_identity_lineage_mismatch')
            if r['dated_listing_evidence']!=m['date_observations'] or r['security_id']!=m['security_id']:
                raise ContractError('dated_master_lineage_mismatch')
            expected_dates={r['price_date'],instant(r['decision_at']).astimezone(JST).date().isoformat(),r['trading_session']['date']}
            if set(m['required_dates'])!=expected_dates or {d['date'] for d in m['date_observations']}!=expected_dates:
                raise ContractError('dated_observation_missing')
            for s in a['sources']:
                if sha256(encoded(s['provider_fields']))!=s['row_sha256'] or s['provider_fields']['secCode']!=r['jquants_code']:
                    raise ContractError('edinet_identity_row_mismatch')
            for d in m['date_observations']:
                original=oo[d['observation_id']]
                if d['source']!=original['source'] or any(d[k]!=original['provider_fields'].get(k) for k in ('Code','ProdCat','Mkt','MktNm')):
                    raise ContractError('master_row_lineage_mismatch')
                if d['date']!=original['provider_fields']['Date'] or d['Code']!=a['secCode']:
                    raise ContractError('dated_code_mismatch')
            projected=price_observation(p)
            if (r['price']!=projected['close'] or r['jquants_source']!=p['source'] or r['price_date']!=projected['date'] or
                    r['jquants_code']!=projected['jquants_code'] or r['jquants_code']!=a['secCode']):
                raise ContractError('market_row_lineage_mismatch')
            expected_at=datetime.combine(date.fromisoformat(projected['date'])+timedelta(days=1),time(),JST).isoformat()
            if r['price_public_available_at']!=expected_at or not instant(expected_at)<instant(r['decision_at']):
                raise ContractError('price_schedule_lineage_mismatch')
            decision=r['decision_information']
            if decision['prior_market_observation_id']!=p['observation_id'] or decision['edinet_fact_id']!=f['fact_id']:
                raise ContractError('decision_feature_lineage_mismatch')
            if set(decision['master_observation_ids']) & set(r['entry_validation_master_ids']):
                raise ContractError('entry_evidence_in_decision_features')
            for original in [p,*[oo[d['observation_id']] for d in m['date_observations']]]:
                if sha256(encoded(original['provider_fields']))!=original['source']['row_sha256']:
                    raise ContractError('source_row_hash_mismatch')
            if r['execution_claim'] or r['system_replay']!='NOT ESTABLISHED': raise ContractError('unsupported_execution_claim')
            checked+=1
        except (KeyError,TypeError,ValueError) as exc:
            if isinstance(exc,ContractError): raise
            raise ContractError('dated_lineage_missing') from None
    return {'status':'PASS' if checked else 'BLOCKED','checked_positive_rows':checked,
            'basis':'P3 XBRL reverse verification + re-read EDINET JSON and J-Quants CSV rows',
            'system_replay':'NOT ESTABLISHED','execution_claim':False}
