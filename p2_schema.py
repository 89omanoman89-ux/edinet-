"""Bounded XBRL structure measurements; no financial normalization or valuation."""
from collections import Counter, defaultdict
from decimal import Decimal, InvalidOperation
import io
import zipfile
from xml.etree import ElementTree as ET

from source_acquisition import encoded, sha256

XBRLI = "http://www.xbrl.org/2003/instance"
XBRLDI = "http://xbrl.org/2006/xbrldi"
MAX_EXPANDED = 32 * 1024 * 1024


def local(tag):
    return tag.rsplit("}", 1)[-1]


def profile_zip(data):
    """Locators remain member-scoped; different contexts are not duplicate facts."""
    result = {"parse_status": "BLOCKED", "failures": [], "members": [], "dei": {},
              "xbrl_member_count": 0, "namespace_uris": [], "qname_count": 0,
              "context_count": 0, "unit_count": 0, "text_block_count": 0,
              "numeric_fact_count": 0, "duplicate_fact_candidate_count": 0,
              "context_ref_count": 0, "instant_context_count": 0, "duration_context_count": 0,
              "dimensions": [], "segment_count": 0, "scenario_count": 0,
              "same_tag_multiple_contexts": False, "challenge_evidence": {}}
    qnames, namespaces, dimensions, dei = set(), set(), set(), defaultdict(set)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            targets = [i for i in infos if i.filename.lower().endswith(".xbrl")]
            result["xbrl_member_count"] = len(targets)
            if sum(i.file_size for i in infos) > MAX_EXPANDED:
                result["failures"].append("zip_expansion_limit")
                return result
            if len({i.filename for i in infos}) != len(infos):
                result["failures"].append("duplicate_zip_member")
                return result
            if not targets:
                result["failures"].append("xbrl_member_missing")
                return result
            for info in targets:
                xml = archive.read(info)
                member = {"member": info.filename, "sha256": sha256(xml), "byte_count": len(xml)}
                result["members"].append(member)
                declarations = xml.replace(b"\x00", b"").upper()
                if b"<!DOCTYPE" in declarations or b"<!ENTITY" in declarations:
                    result["failures"].append("xml_rejected")
                    member["parse_status"] = "BLOCKED"
                    continue
                try:
                    # start-ns includes namespaces used only in QName-valued text/attributes.
                    parser = ET.iterparse(io.BytesIO(xml), events=("start-ns", "end"))
                    for event, value in parser:
                        if event == "start-ns":
                            namespaces.add(value[1])
                    tree = parser.root
                except (LookupError, UnicodeError):
                    result["failures"].append("unsupported_encoding")
                    continue
                except (ET.ParseError, ValueError):
                    result["failures"].append("xml_parse_failed")
                    continue
                if tree.tag != f"{{{XBRLI}}}xbrl":
                    result["failures"].append("xbrl_root_unknown")
                member["parse_status"] = "PASS"
                contexts = tree.findall(f"{{{XBRLI}}}context")
                units = tree.findall(f"{{{XBRLI}}}unit")
                context_ids = [c.get("id") for c in contexts]
                unit_ids = [u.get("id") for u in units]
                if None in context_ids or len(set(context_ids)) != len(context_ids):
                    result["failures"].append("context_ambiguous")
                if None in unit_ids or len(set(unit_ids)) != len(unit_ids):
                    result["failures"].append("unit_unknown")
                result["context_count"] += len(contexts)
                result["unit_count"] += len(units)
                member["period_patterns"], member["units"] = [], []
                member["entity_identifiers"] = sorted({(x.get("scheme", ""), x.text or "")
                    for c in contexts for x in c.iter(f"{{{XBRLI}}}identifier")})
                for c in contexts:
                    instants = c.findall(f"{{{XBRLI}}}period/{{{XBRLI}}}instant")
                    starts = c.findall(f"{{{XBRLI}}}period/{{{XBRLI}}}startDate")
                    ends = c.findall(f"{{{XBRLI}}}period/{{{XBRLI}}}endDate")
                    kind = "instant" if len(instants) == 1 and not starts and not ends else (
                        "duration" if len(starts) == len(ends) == 1 and not instants else "unknown")
                    if kind == "unknown":
                        result["failures"].append("context_ambiguous")
                    else:
                        result[f"{kind}_context_count"] += 1
                    member["period_patterns"].append({"context_id": c.get("id"), "kind": kind,
                        "dates": [x.text for x in instants + starts + ends]})
                for u in units:
                    measures = [x.text for x in u.iter(f"{{{XBRLI}}}measure")]
                    member["units"].append({"id": u.get("id"), "measures": measures,
                        "definition_sha256": sha256(ET.tostring(u))})
                    if not measures or any(not m for m in measures):
                        result["failures"].append("unit_unknown")
                facts, tag_contexts, context_refs = Counter(), defaultdict(set), set()
                for index, e in enumerate(tree.iter()):
                    qnames.add(e.tag)
                    if e.tag in {f"{{{XBRLDI}}}explicitMember", f"{{{XBRLDI}}}typedMember"}:
                        dimension = e.get("dimension")
                        dimensions.add((dimension or "", e.text or "", local(e.tag)))
                    if e.tag == f"{{{XBRLI}}}segment": result["segment_count"] += 1
                    if e.tag == f"{{{XBRLI}}}scenario": result["scenario_count"] += 1
                    context = e.get("contextRef")
                    if context is None:
                        continue
                    context_refs.add(context)
                    tag_contexts[e.tag].add(context)
                    if context not in context_ids: result["failures"].append("context_ambiguous")
                    unit = e.get("unitRef")
                    if unit is not None:
                        result["numeric_fact_count"] += 1
                        if unit not in unit_ids: result["failures"].append("unit_unknown")
                    facts[(e.tag, context, unit, e.get("{http://www.w3.org/XML/1998/namespace}lang"))] += 1
                    name = local(e.tag)
                    if name.endswith("TextBlock"): result["text_block_count"] += 1
                    if "jpdei" in e.tag and name.endswith("DEI"):
                        dei[name].add(e.text)
                    # A sign-bearing reported fact is a challenge cue, not standardized earnings.
                    if name in {"ProfitLoss", "ProfitLossAttributableToOwnersOfParent", "ProfitLossSummaryOfBusinessResults"}:
                        try:
                            value = Decimal(e.text or "")
                            if value.is_finite() and value < 0:
                                result["challenge_evidence"].setdefault("loss_fact", []).append(
                                    {"member": info.filename, "element_index": index, "qname": e.tag,
                                     "context_ref": context, "rule": "reported_profit_loss_fact_negative"})
                        except InvalidOperation:
                            pass
                result["context_ref_count"] += len(context_refs)
                result["same_tag_multiple_contexts"] |= any(len(c) > 1 for c in tag_contexts.values())
                result["duplicate_fact_candidate_count"] += sum(n - 1 for n in facts.values() if n > 1)
    except zipfile.BadZipFile:
        result["failures"].append("invalid_zip")
    except (RuntimeError, NotImplementedError, OSError, EOFError):
        result["failures"].append("zip_read_failed")
    result["dei"] = {k: sorted(v, key=lambda x: x or "") for k, v in sorted(dei.items())}
    result["namespace_uris"] = sorted(namespaces)
    result["qname_count"] = len(qnames)
    result["qnames_sha256"] = sha256(encoded(sorted(qnames)))
    result["dimensions"] = sorted(dimensions)
    result["consolidation_identifiable"] = bool(dei.get("WhetherConsolidatedFinancialStatementsArePreparedDEI"))
    result["failures"] = sorted(set(result["failures"]))
    result["parse_status"] = "BLOCKED" if any(f in result["failures"] for f in (
        "invalid_zip", "zip_read_failed", "xml_rejected", "xml_parse_failed", "unsupported_encoding",
        "xbrl_root_unknown")) else "PASS"
    result["schema_sha256"] = sha256(encoded({k: result[k] for k in (
        "namespace_uris", "qnames_sha256", "dimensions", "dei")}))
    return result
