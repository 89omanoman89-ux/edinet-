"""Bounded, exact-QName financial mapping. No network, fuzzy tags or imputation."""
from collections import Counter
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation
import io
import json
from pathlib import Path
import re
import zipfile
from xml.etree import ElementTree as ET

from evidence_core import ContractError, JST
from source_acquisition import encoded, sha256

XI = "http://www.xbrl.org/2003/instance"
DI = "http://xbrl.org/2006/xbrldi"
NIL = "{http://www.w3.org/2001/XMLSchema-instance}nil"
DEI = "http://disclosure.edinet-fsa.go.jp/taxonomy/jpdei/2013-08-31/jpdei_cor"
MAX_EXPANDED = 32 * 1024 * 1024


def definitions():
    base=Path(__file__).parent / 'registry'
    config=json.loads((base/'financial_definitions_v1.json').read_bytes())
    extension=json.loads((base/'financial_extensions_v2.json').read_bytes())
    if sha256(encoded(config))!=extension['parent_definition_sha256']:
        raise ContractError('mapping_extension_parent_mismatch')
    rules={r['rule_id']:r for r in config['rules']}
    for addition in extension['extensions']:
        rule=rules[addition['rule_id']]
        q=addition['accepted_qname']
        if q in rule['accepted_qnames']:raise ContractError('duplicate_mapping_extension')
        rule['accepted_qnames'].append(q)
    config['taxonomy_sources'].extend(extension['taxonomy_sources'])
    config['definition_version']=extension['definition_version']
    config['fact_id_definition_version']=extension['fact_id_definition_version']
    config['extension_sha256']=sha256(encoded(extension))
    return config


def timestamp(value):
    """API minute precision: use the END of that minute, explicitly conservative."""
    if not value: return None
    try:
        if re.fullmatch(r"\d{4}-\d\d-\d\d", value):
            return (datetime.fromisoformat(value).replace(tzinfo=JST) + timedelta(days=1)).isoformat()
        if not re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d(?::\d\d)?", value): return None
        t = datetime.fromisoformat(value).replace(tzinfo=JST)
        return (t + (timedelta(minutes=1) if len(value) == 16 else timedelta())).isoformat()
    except ValueError: return None


def parsed_members(data):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = z.infolist()
            if sum(i.file_size for i in infos) > MAX_EXPANDED: raise ContractError("zip_expansion_limit")
            if len({i.filename for i in infos}) != len(infos): raise ContractError("duplicate_zip_member")
            targets = [i for i in infos if i.filename.lower().endswith(".xbrl")]
            if not targets: raise ContractError("xbrl_member_missing")
            result = []
            for info in targets:
                raw = z.read(info)
                guard = raw.replace(b"\x00", b"").upper()
                if b"<!DOCTYPE" in guard or b"<!ENTITY" in guard: raise ContractError("xml_rejected")
                scopes, stack, pending = {}, [], {}
                parser = ET.iterparse(io.BytesIO(raw), events=("start-ns", "start", "end"))
                for event, e in parser:
                    if event == "start-ns": pending[e[0]] = e[1]
                    elif event == "start":
                        ns = dict(stack[-1] if stack else {}, **pending)
                        pending.clear(); stack.append(ns); scopes[id(e)] = ns
                    else: stack.pop()
                if parser.root.tag != f"{{{XI}}}xbrl": raise ContractError("xbrl_root_unknown")
                result.append((info.filename, raw, parser.root, scopes))
            return result
    except zipfile.BadZipFile: raise ContractError("invalid_zip") from None
    except (LookupError, UnicodeError): raise ContractError("unsupported_encoding") from None
    except ET.ParseError: raise ContractError("xml_parse_failed") from None
    except (RuntimeError, NotImplementedError, OSError, EOFError): raise ContractError("zip_read_failed") from None


def qname(text, namespaces):
    text = (text or "").strip()
    prefix, name = text.split(":", 1) if ":" in text else ("", text)
    return f"{{{namespaces[prefix]}}}{name}" if prefix in namespaces and name else None


def period(context):
    p = context.find(f"{{{XI}}}period")
    if p is None: raise ContractError("context_period_unknown")
    tags = [x.tag for x in p]
    if tags == [f"{{{XI}}}instant"]:
        instant = date.fromisoformat(p[0].text).isoformat()
        return {"period_kind": "instant", "period_start": None, "period_end": None, "instant_date": instant}
    if tags == [f"{{{XI}}}startDate", f"{{{XI}}}endDate"]:
        start, end = (date.fromisoformat(x.text).isoformat() for x in p)
        if end < start: raise ContractError("context_period_reversed")
        return {"period_kind": "duration", "period_start": start, "period_end": end, "instant_date": None}
    raise ContractError("context_period_unknown")


def unit_definition(unit, scopes):
    def measures(node):
        return [qname(e.text, scopes[id(e)]) for e in node if e.tag == f"{{{XI}}}measure"]
    children = list(unit)
    if children and all(e.tag == f"{{{XI}}}measure" for e in children):
        numerator, denominator = measures(unit), []
    elif len(children) == 1 and children[0].tag == f"{{{XI}}}divide":
        if [e.tag for e in children[0]] != [f"{{{XI}}}unitNumerator", f"{{{XI}}}unitDenominator"]:
            raise ContractError("unit_unknown")
        n, d = children[0].find(f"{{{XI}}}unitNumerator"), children[0].find(f"{{{XI}}}unitDenominator")
        if n is None or d is None: raise ContractError("unit_unknown")
        if any(e.tag != f"{{{XI}}}measure" for node in (n, d) for e in node): raise ContractError("unit_unknown")
        numerator, denominator = measures(n), measures(d)
    else: raise ContractError("unit_unknown")
    return {"numerator": numerator, "denominator": denominator,
            "xml_sha256": sha256(ET.tostring(unit)), "xml": ET.tostring(unit, encoding="unicode")}


def source_context(context, scopes, edinet_code, dei, config):
    result = dict(period(context), dimensions=[], consolidation=None, scope_basis=None,
                  period_class=None, fiscal_year_start=None, context_xml=ET.tostring(context, encoding="unicode"),
                  context_sha256=sha256(ET.tostring(context)))
    ident = context.findall(f"{{{XI}}}entity/{{{XI}}}identifier")
    if len(ident) != 1 or not re.fullmatch(re.escape(edinet_code or "INVALID") + r"(?:-\d{3})?", ident[0].text or ""):
        raise ContractError("context_entity_mismatch")
    result["entity_identifier"] = {"scheme": ident[0].get("scheme"), "value": ident[0].text}
    if ident[0].get("scheme") != "http://disclosure.edinet-fsa.go.jp": raise ContractError("entity_scheme_unknown")
    namespaces = {s["namespace"] for s in config["taxonomy_sources"] if "/jppfs/" in s["namespace"]}
    axes = {f"{{{n}}}ConsolidatedOrNonConsolidatedAxis": n for n in namespaces}
    scope_dims, unsupported = [], False
    for container in context.iter():
        if container.tag not in {f"{{{XI}}}scenario", f"{{{XI}}}segment"}: continue
        for e in container:
            axis = qname(e.get("dimension"), scopes[id(e)])
            member = qname(e.text, scopes[id(e)]) if e.tag == f"{{{DI}}}explicitMember" else None
            result["dimensions"].append({"axis": axis, "member": member, "container": container.tag,
                "kind": e.tag, "xml": ET.tostring(e, encoding="unicode")})
            n = axes.get(axis)
            if n and member in {f"{{{n}}}NonConsolidatedMember", f"{{{n}}}ConsolidatedMember"}:
                scope_dims.append("standalone" if member.endswith("}NonConsolidatedMember") else "consolidated")
            else: unsupported = True
    if len(scope_dims) > 1: raise ContractError("scope_ambiguous")
    if scope_dims:
        result.update(consolidation=scope_dims[0], scope_basis="explicit_standard_dimension")
    elif dei.get("WhetherConsolidatedFinancialStatementsArePreparedDEI") == "true":
        result.update(consolidation="consolidated", scope_basis="financial_context_default_and_DEI_true")
    else: raise ContractError("scope_unverified")
    if unsupported:
        # A valid detailed context is not a malformed total. Preserve its scope,
        # dates and dimensions, but do not normalize it under a total-only rule.
        result["context_warning"] = "unsupported_dimensions"
        return result
    context_id = context.get("id", "")
    base = context_id.removesuffix("_NonConsolidatedMember")
    if bool(scope_dims and scope_dims[0] == "standalone") != context_id.endswith("_NonConsolidatedMember"):
        raise ContractError("context_scope_name_mismatch")
    if result["period_kind"] == "instant":
        if not re.fullmatch(r"(?:CurrentYear|Prior[1-9][0-9]*Year)Instant", base):
            result["context_warning"] = "context_period_class_unverified"
        result["period_class"] = "instant"
    else:
        if re.fullmatch(r"(?:CurrentYear|Prior[1-9][0-9]*Year)Duration", base): result["period_class"] = "annual"
        elif base == "CurrentYTDDuration": result["period_class"] = "cumulative"
        elif base == "CurrentQuarterDuration": result["period_class"] = "quarter"
        else: result["context_warning"] = "context_period_class_unverified"
        result["fiscal_year_start"] = result["period_start"] if result["period_class"] in {"annual", "cumulative"} else None
    # Current contexts must agree with the original DEI, not just with an ID name.
    if base in {"CurrentYearDuration", "CurrentYTDDuration"} and dei.get("CurrentFiscalYearStartDateDEI") != result["period_start"]:
        result["context_warning"] = "context_dei_period_mismatch"
    if base in {"CurrentYearDuration", "CurrentYearInstant"} and dei.get("CurrentFiscalYearEndDateDEI") != (result["period_end"] or result["instant_date"]):
        result["context_warning"] = "context_dei_period_mismatch"
    return result


def extract_candidates(data, artifact, document, config):
    if sha256(data) != artifact["byte_sha256"] or len(data) != artifact["byte_count"]:
        raise ContractError("source_byte_integrity_failed")
    if artifact["doc_id"] != document["doc_id"]: raise ContractError("source_document_mismatch")
    rules = {q: r for r in config["rules"] for q in r["accepted_qnames"]}
    definition_sha = sha256(encoded(config))
    metadata_sha = sha256(encoded(document.get("metadata_locators", [])))
    document_fields = {k: document.get(k) for k in ("doc_id", "edinet_code", "secCode", "parentDocID", "doc_type",
        "sample_kind", "submit_datetime", "public_available_at", "availability_basis", "recorded_at",
        "original_provider_retrieved_at", "provenance_class", "synthetic", "rights_review", "export_allowed")}
    result = []
    for member, raw, tree, scopes in parsed_members(data):
        member_sha = sha256(raw)
        dei_sets = {}
        for e in tree:
            if e.tag.startswith("{" + DEI + "}"):
                dei_sets.setdefault(e.tag.split("}")[1], set()).add(e.text)
        dei = {k: next(iter(v)) for k, v in dei_sets.items() if len(v) == 1}
        contexts = tree.findall(f"{{{XI}}}context"); units = tree.findall(f"{{{XI}}}unit")
        cc, uc = Counter(c.get("id") for c in contexts), Counter(u.get("id") for u in units)
        contexts = {c.get("id"): c for c in contexts}; units = {u.get("id"): u for u in units}
        context_cache, unit_cache = {}, {}
        for index, e in enumerate(tree.iter()):
            if e.get("contextRef") is None or (e.get("unitRef") is None and e.tag not in rules): continue
            rule = rules.get(e.tag)
            c = dict(document_fields, metadata_lineage_sha256=metadata_sha,
                source_artifact_sha256=artifact["byte_sha256"], xbrl_member=member,
                xbrl_member_sha256=member_sha, element_index=index, original_qname=e.tag,
                contextRef=e.get("contextRef"), unitRef=e.get("unitRef"), original_unit=None,
                original_value=e.text, original_attributes=dict(e.attrib), representation="reported",
                extraction_method="xbrl_instance_decimal_v1", definition_version=config["definition_version"],
                definition_sha256=definition_sha,
                period_start=None, period_end=None, instant_date=None, period_kind=None, period_class=None,
                consolidation=None, accounting_standard=None, document_accounting_standard=dei.get("AccountingStandardsDEI"),
                dimensions=[], normalized_value=None, normalized_unit=None, missing_reason=None,
                verification_state="unverified", input_ids=[], element_class="standard" if any(
                    e.tag.startswith("{" + s["namespace"] + "}") for s in config["taxonomy_sources"]) else "company_specific_or_unknown",
                share_basis="as_reported_not_split_adjusted", decimals=e.get("decimals"), precision=e.get("precision"))
            c["candidate_id"] = sha256(encoded([c["doc_id"], c["source_artifact_sha256"], member, index]))
            c["rule_id"] = rule["rule_id"] if rule else None
            c["metric"] = rule["metric"] if rule else None
            c["family"] = rule["family"] if rule else None
            try:
                if not rule: raise ContractError("unknown_mapping")
                if dei.get("EDINETCodeDEI") != document["edinet_code"]: raise ContractError("dei_identifier_unverified")
                if cc[c["contextRef"]] != 1: raise ContractError("context_ambiguous")
                context_id = c["contextRef"]
                if context_id not in context_cache:
                    try: context_cache[context_id] = source_context(contexts[context_id], scopes, document["edinet_code"], dei, config)
                    except ContractError as exc: context_cache[context_id] = str(exc)
                if isinstance(context_cache[context_id], str): raise ContractError(context_cache[context_id])
                c.update(context_cache[context_id])
                if uc[c["unitRef"]] != 1: raise ContractError("unit_unknown")
                if c["unitRef"] not in unit_cache: unit_cache[c["unitRef"]] = unit_definition(units[c["unitRef"]], scopes)
                c["original_unit"] = unit_cache[c["unitRef"]]
                c["accounting_standard"] = rule["accounting_standard"]
                # JP GAAP standalone statements can accompany consolidated IFRS/US GAAP.
                expected = {"Japan GAAP": "JP GAAP", "IFRS": "IFRS"}.get(dei.get("AccountingStandardsDEI"))
                if c["accounting_standard"] != expected and not (
                    c["consolidation"] == "standalone" and c["accounting_standard"] == "JP GAAP"
                    and dei.get("AccountingStandardsDEI") in {"IFRS", "US GAAP"}):
                    raise ContractError("accounting_standard_unverified")
                if c.get("context_warning"): raise ContractError(c["context_warning"])
                if c["period_kind"] != rule["period_kind"]: raise ContractError("period_rule_mismatch")
                if c["consolidation"] not in rule["scopes"]: raise ContractError("scope_rule_mismatch")
                if c["public_available_at"] is None: raise ContractError("public_time_unknown")
                if (c["instant_date"] or c["period_end"]) > c["public_available_at"][:10]:
                    raise ContractError("future_period_not_reported_actual")
                # The XBRL instance already contains base-unit values. decimals is NOT scale.
                unit = c["original_unit"]
                money, shares = config["units"]["JPY"], config["units"]["shares"]
                kind = {((money,), ()): "JPY", ((shares,), ()): "shares", ((money,), (shares,)): "JPY/share"}.get(
                    (tuple(unit["numerator"]), tuple(unit["denominator"])))
                if kind != rule["normalized_unit"]: raise ContractError("unit_unknown_or_incompatible")
                c["normalized_unit"] = kind
                if e.get(NIL) in {"true", "1"}: raise ContractError("reported_nil")
                if e.get(NIL) not in {None, "false", "0"}: raise ContractError("invalid_nil_attribute")
                if any(k in e.attrib for k in ("scale", "sign", "format")): raise ContractError("inline_transform_in_instance")
                if e.get("decimals") is not None and not re.fullmatch(r"(?:INF|[+-]?\d+)", e.get("decimals")):
                    raise ContractError("invalid_numeric_accuracy")
                if e.get("precision") is not None and (e.get("decimals") is not None or not re.fullmatch(r"(?:INF|[1-9]\d*)", e.get("precision"))):
                    raise ContractError("invalid_numeric_accuracy")
                if list(e) or not re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)", (e.text or "").strip()):
                    raise ContractError("invalid_numeric_lexical")
                value = Decimal(e.text.strip())
                if not value.is_finite(): raise ContractError("nonfinite_numeric")
                c["normalized_value"] = str(value)
                c["verification_state"] = "source_tied"
            except ContractError as exc: c["missing_reason"] = str(exc)
            except (ValueError, TypeError, InvalidOperation): c["missing_reason"] = "context_or_numeric_invalid"
            result.append(c)
    return result


def canonicalize(candidates, config):
    rows = []
    for c in candidates:
        if c["rule_id"] is None: continue
        f = dict(c, fact_id=sha256(encoded([c["candidate_id"], config.get('fact_id_definition_version',config["definition_version"]), c["rule_id"]])))
        rows.append(f)
    return rows


def reverse_verify(data, artifact, document, config, facts):
    """Re-open ZIP bytes and re-resolve every locator, context, unit and rule."""
    replay = {r["fact_id"]: r for r in canonicalize(extract_candidates(data, artifact, document, config), config)}
    if len({f["fact_id"] for f in facts}) != len(facts): raise ContractError("duplicate_fact_id")
    for fact in facts:
        # Snapshot envelopes are not source fields; support verification after
        # reloading canonical_facts.jsonl, not just the in-memory pre-save rows.
        source_fields = {k: v for k, v in fact.items() if k not in {"snapshot_id", "code_sha", "p2_snapshot_id"}}
        if replay.get(fact["fact_id"]) != source_fields: raise ContractError("source_reverse_lookup_mismatch")
    return {"status": "PASS", "checked_facts": len(facts), "non_null_facts": sum(f["normalized_value"] is not None for f in facts)}
