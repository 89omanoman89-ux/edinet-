"""Conservative P4 identity, daily-session joins and independent source comparison."""
from datetime import date, datetime, time, timedelta
from decimal import Decimal, InvalidOperation
import re

from evidence_core import ContractError, JST, aware
from jquants_local import code
from source_acquisition import encoded, sha256

DEFINITION = "p4-pit-market-v1"
SESSION_RULE = "TSE_daily_bar_0900_JST_2016_onwards_v1"


def instant(value):
    if not isinstance(value, str): raise ContractError("time_precision_unknown")
    try: return aware(datetime.fromisoformat(value))
    except (ValueError, TypeError): raise ContractError("time_precision_unknown") from None


def number(value):
    if value in (None, ""): return None
    if not isinstance(value, (str, Decimal)): raise ContractError("invalid_market_number")
    try:
        out = Decimal(value)
        if not out.is_finite(): raise InvalidOperation
        return out
    except (InvalidOperation, ValueError, TypeError): raise ContractError("invalid_market_number") from None


def validate_locator(source):
    """Structural gate; byte/row verification must separately precede admission."""
    if not isinstance(source, dict): raise ContractError("source_locator_missing")
    artifact = source.get("artifact", {})
    relative = artifact.get("relative_path", "")
    if (not relative or relative.startswith(("/", "\\")) or ":" in relative or ".." in relative.replace("\\", "/").split("/") or
            not isinstance(artifact.get("byte_count"), int) or artifact["byte_count"] <= 0 or
            not re.fullmatch(r"[0-9a-f]{64}", artifact.get("byte_sha256", "")) or
            not re.fullmatch(r"[0-9a-f]{64}", source.get("row_sha256", "")) or
            not isinstance(source.get("record_index"), int) or source["record_index"] < 1):
        raise ContractError("source_locator_invalid")


def entry_candidate(public_available_at, decision_at, calendar):
    """Earliest available DAILY session strictly after disclosure and decision; not a fill."""
    public, decision = instant(public_available_at), instant(decision_at)
    if not public < decision: raise ContractError("future_information_leakage")
    threshold = max(public, decision); day = threshold.astimezone(JST).date()
    if day < date(2016, 1, 1): raise ContractError("session_rule_period_unsupported")
    by_day = {}
    for row in calendar: by_day.setdefault(row["provider_fields"]["Date"], []).append(row)
    evidence = []
    for offset in range(15):
        current = day + timedelta(days=offset); rows = by_day.get(current.isoformat(), [])
        if len(rows) != 1: raise ContractError("trading_calendar_missing_or_ambiguous")
        row = rows[0]; evidence.append(row["observation_id"])
        holiday = row["provider_fields"]["HolDiv"]
        if holiday in {"0", "3"}: continue  # OSE holiday trading is not TSE cash trading.
        if holiday != "1": raise ContractError("session_time_unverified")
        start = datetime.combine(current, time(9), JST)
        if start <= threshold: continue
        end = datetime.combine(current, time(15, 30) if current >= date(2024, 11, 5) else time(15), JST)
        return {"date": current.isoformat(), "start": start.isoformat(), "end": end.isoformat(),
            "market": "TSE_cash", "granularity": "daily_bar", "session_rule": SESSION_RULE,
            "calendar_observation_ids": evidence, "execution_claim": False}
    raise ContractError("entry_session_not_available_in_window")


def active(mapping, when, prefix):
    lo, hi = mapping.get(prefix + "_from"), mapping.get(prefix + "_to")
    if not lo or not mapping.get(prefix + "_verified"): raise ContractError(prefix + "_not_established")
    try:
        start, end = date.fromisoformat(lo), date.fromisoformat(hi) if hi else None
    except ValueError: raise ContractError("invalid_identifier_interval") from None
    if end is not None and end <= start: raise ContractError("invalid_identifier_interval")
    return start <= when and (end is None or when < end)


def resolve_security(mappings, entity_id, decision_at, entry_at, requested_code=None):
    decision, entry = instant(decision_at), instant(entry_at)
    if requested_code is not None: code(requested_code)
    candidates, errors, inactive = [], [], []
    for m in mappings:
        if m.get("entity_id") != entity_id: continue
        if requested_code is not None and m.get("jquants_code") != requested_code: continue
        try:
            code(m["jquants_code"])
            if m.get("status") != "PASS": raise ContractError(m.get("missing_reason") or "mapping_unverified")
            if not m.get("mapping_evidence") or m.get("matching_method") != "explicit_dated_identifier_evidence":
                raise ContractError("mapping_evidence_missing")
            for evidence in m["mapping_evidence"]: validate_locator(evidence)
            if m.get("issuer_entity_id") != entity_id or not m.get("security_id"): raise ContractError("issuer_role_unverified")
            if instant(m.get("public_available_at")) >= decision: raise ContractError("mapping_not_yet_available")
            if not all(active(m, t.astimezone(JST).date(), "identifier_validity") for t in (decision, entry)):
                inactive.append("code_not_valid_at_decision_or_entry"); continue
            if not all(active(m, t.astimezone(JST).date(), "listing") for t in (decision, entry)):
                inactive.append("not_listed_at_decision_or_entry"); continue
            candidates.append(m)
        except ContractError as exc: errors.append(str(exc))
    # An unresolved candidate cannot be ignored in favour of a convenient verified candidate.
    if errors: raise ContractError(sorted(set(errors))[0])
    if len(candidates) > 1: raise ContractError("ambiguous_security_mapping")
    if not candidates: raise ContractError(sorted(set(inactive))[0] if inactive else "security_mapping_not_available")
    return candidates[0]


def price_observation(observation):
    row = observation["provider_fields"]
    return dict(observation, jquants_code=code(row["Code"]), date=row["Date"],
        price_basis="reported_unadjusted", adjustment_basis="provider_ex_date_factor_no_adjustment_applied",
        original_close=row.get("C"), close=str(number(row.get("C"))) if number(row.get("C")) is not None else None,
        adjustment_factor=str(number(row.get("AdjFactor"))) if number(row.get("AdjFactor")) is not None else None,
        corporate_action_type=row.get("ExRT"), public_available_at=None,
        missing_reason="daily_row_publication_time_not_recorded",
        trading_status="no_trade_reason_unknown" if all(row.get(k) in (None, "") for k in ("O", "H", "L", "C", "Vo", "Va")) else "intraday_status_not_provided")


def choose_price(prices, jq_code, decision_at):
    decision = instant(decision_at)
    rows = [p for p in prices if p["jquants_code"] == jq_code and date.fromisoformat(p["date"]) < decision.astimezone(JST).date()]
    if not rows: raise ContractError("price_missing")
    last_day = max(p["date"] for p in rows)
    rows = [p for p in rows if p["date"] == last_day]
    if len(rows) != 1: raise ContractError("price_observation_ambiguous")
    p = rows[0]
    if p.get("close") is None: raise ContractError("price_missing")
    if instant(p.get("public_available_at")) >= decision: raise ContractError("price_not_yet_available")
    if p.get("price_basis") != "reported_unadjusted":
        if not p.get("adjustment_basis_at"): raise ContractError("adjusted_price_vintage_unknown")
        if instant(p["adjustment_basis_at"]) >= decision: raise ContractError("future_corporate_action_adjustment")
        raise ContractError("adjusted_price_out_of_scope")
    if number(p.get("adjustment_factor")) is None or number(p["adjustment_factor"]) <= 0:
        raise ContractError("corporate_action_basis_unknown")
    reported = price_observation(p)
    if any(p.get(k) != reported[k] for k in ("close", "date", "jquants_code", "adjustment_factor", "adjustment_basis")):
        raise ContractError("price_projection_source_mismatch")
    return p


def join_fact(fact, p3_view, mappings, calendar, prices, trading_status, *, decision_at,
              verified_fact_ids, verified_observation_ids=frozenset(), requested_code=None, allow_synthetic_for_tests=False):
    """No J-Quants financial value is an input to the EDINET value selection."""
    entity = "edinet:" + str(fact.get("edinet_code"))
    out = {"definition_version": DEFINITION, "entity_id": entity, "security_id": None,
        "jquants_code": requested_code, "edinet_fact_id": fact["fact_id"], "doc_id": fact["doc_id"],
        "public_available_at": fact.get("public_available_at"), "decision_at": decision_at,
        "entry_at": None, "trading_session": None, "identifier_validity": None,
        "price_basis": None, "adjustment_basis": None, "market_observation_id": None,
        "mapping_id": None, "mapping_evidence": [], "normalized_value": None, "price": None,
        "status": "BLOCKED", "missing_reason": None, "synthetic": fact.get("synthetic", False),
        "execution_claim": False, "rights_review": "BLOCKED", "export_allowed": False,
        "edinet_source": {k: fact.get(k) for k in ("source_artifact_sha256", "xbrl_member_sha256", "xbrl_member",
            "element_index", "original_qname", "contextRef", "unitRef", "definition_version")}}
    try:
        if fact.get("synthetic") and not allow_synthetic_for_tests: raise ContractError("synthetic_not_empirical")
        if fact["normalized_value"] is None: raise ContractError(fact.get("missing_reason") or "edinet_null")
        if fact["fact_id"] not in verified_fact_ids: raise ContractError("edinet_source_lineage_unverified")
        if p3_view.get("mode") != "as_of" or p3_view.get("decision_at") != decision_at:
            raise ContractError("p3_view_decision_mismatch")
        if fact not in p3_view["facts"]:
            reasons = [b["reason"] for b in p3_view["blocked"] if b.get("doc_id") == fact["doc_id"] or
                       fact["doc_id"] in b.get("doc_ids", []) or fact["fact_id"] in b.get("fact_ids", [])]
            raise ContractError(sorted(set(reasons))[0] if reasons else "unavailable_edinet_vintage")
        session = entry_candidate(fact["public_available_at"], decision_at, calendar)
        out.update(entry_at=session["start"], trading_session=session)
        used_calendar = [r for r in calendar if r["observation_id"] in session["calendar_observation_ids"]]
        if any(r["observation_id"] not in verified_observation_ids for r in used_calendar):
            raise ContractError("jquants_source_lineage_unverified")
        for r in used_calendar: validate_locator(r.get("source"))
        mapping = resolve_security(mappings, entity, decision_at, session["start"], requested_code)
        out.update(security_id=mapping["security_id"], jquants_code=mapping["jquants_code"], mapping_id=mapping["mapping_id"],
            mapping_evidence=mapping["mapping_evidence"], identifier_validity={k: mapping[k] for k in
                ("identifier_validity_from", "identifier_validity_to", "listing_from", "listing_to")})
        statuses = [s for s in trading_status if s["security_id"] == mapping["security_id"] and
                    instant(s["valid_from"]) <= instant(session["start"]) < instant(s["valid_to"])]
        if len(statuses) != 1: raise ContractError("trading_status_unknown_or_ambiguous")
        status = statuses[0]
        if not status.get("source") or instant(status.get("public_available_at")) >= instant(decision_at):
            raise ContractError("trading_status_not_known_at_decision")
        validate_locator(status["source"])
        if status["status"] != "tradable": raise ContractError("trading_suspended")
        p = choose_price(prices, mapping["jquants_code"], decision_at)
        if p["observation_id"] not in verified_observation_ids: raise ContractError("jquants_source_lineage_unverified")
        validate_locator(p.get("source"))
        # A recycled code cannot attribute an earlier owner's price to today's security.
        if not all(active(mapping, date.fromisoformat(p["date"]), prefix) for prefix in ("identifier_validity", "listing")):
            raise ContractError("price_date_security_identity_unverified")
        synthetic_input = any(x.get("synthetic") for x in [fact, p, mapping, status, *used_calendar])
        if synthetic_input and not allow_synthetic_for_tests:
            raise ContractError("synthetic_not_empirical")
        out.update(status="PASS", normalized_value=fact["normalized_value"], price=p["close"],
            synthetic=synthetic_input,
            market_observation_id=p["observation_id"], jquants_source=p["source"], price_basis=p["price_basis"],
            adjustment_basis=p["adjustment_basis"], adjustment_factor=p["adjustment_factor"],
            price_date=p["date"], price_public_available_at=p["public_available_at"], trading_status_evidence=status)
    except ContractError as exc: out["missing_reason"] = str(exc)
    out["research_row_id"] = sha256(encoded(out))
    return out


def reconcile_sources(edinet, other, decision_at, *, identity_verified, edinet_is_revision=False):
    reasons = []
    if not identity_verified: reasons.append("unresolved")
    for key, reason in (("metric", "definition_difference"), ("period_kind", "definition_difference"),
        ("period_class", "definition_difference"),
        ("period_start", "definition_difference"), ("period_end", "definition_difference"),
        ("instant_date", "definition_difference"), ("normalized_unit", "definition_difference"),
        ("consolidation", "scope_difference"), ("accounting_standard", "accounting_standard_difference")):
        if edinet.get(key) != other.get(key): reasons.append(reason)
    if edinet.get("dimensions"): reasons.append("scope_difference")
    if edinet.get("normalized_unit") in {"shares", "JPY/share"} and edinet.get("share_basis") != other.get("share_basis"):
        reasons.append("definition_difference")
    if edinet_is_revision or other.get("revision_state") != "reported_initial_or_unknown" or other.get("restated"):
        reasons.append("revision_difference")
    try:
        future = max(instant(other.get("public_available_at")), instant(edinet.get("public_available_at"))) >= instant(decision_at)
        if future or other.get("public_available_at") != edinet.get("public_available_at"): reasons.append("timing_difference")
    except ContractError: future = True; reasons.append("unresolved")
    a, b = number(edinet.get("normalized_value")), number(other.get("normalized_value"))
    numeric = None
    if a is None or b is None: reasons.append("unresolved")
    elif identity_verified and not future and not (set(reasons) - {"timing_difference", "revision_difference"}):
        numeric = "equal" if a == b else "different"
        reasons.append("exact_match" if a == b else "value_conflict")
    return {"edinet_fact_id": edinet["fact_id"], "jquants_fact_id": other["jquants_fact_id"],
        "classifications": sorted(set(reasons or ["unresolved"])), "numeric_comparison": numeric,
        "identity_verified": identity_verified, "eligible_at_decision": not future, "decision_at": decision_at,
        "edinet_is_revision": edinet_is_revision, "jquants_revision_state": other.get("revision_state"),
        "resolution": "sources_preserved_no_override_no_imputation"}


def financial_observations(observation):
    """Small explicit annual-report comparison map; forecast/unknown definitions stay out."""
    r = observation["provider_fields"]
    match = re.fullmatch(r"FYFinancialStatements_(Consolidated|NonConsolidated)_(JP|IFRS)", r["DocType"])
    if not match or r.get("CurPerType") != "FY": return []
    scope, standard = ("consolidated" if match[1] == "Consolidated" else "standalone"), ("JP GAAP" if match[2] == "JP" else "IFRS")
    try:
        at = datetime.fromisoformat(r["DiscDate"] + "T" + r["DiscTime"]).replace(tzinfo=JST)
        if not re.fullmatch(r"\d{2}:\d{2}:\d{2}", r["DiscTime"]): return []
    except ValueError: return []
    try:
        if date.fromisoformat(r["CurPerSt"]) > date.fromisoformat(r["CurPerEn"]): return []
    except (ValueError, TypeError): return []
    mapping = {"Sales": ("revenue_sales" if standard == "JP GAAP" else "revenue_ifrs", "duration", "JPY"),
        "OP": ("operating_profit", "duration", "JPY"), "NP": ("net_profit_owners" if scope == "consolidated" else "net_profit_total", "duration", "JPY"),
        "TA": ("assets_total", "instant", "JPY"), "CFO": ("cfo", "duration", "JPY"), "CFI": ("cfi", "duration", "JPY"),
        "EPS": ("eps_basic_reported", "duration", "JPY/share"),
        "BPS": ("bps_net_assets_reported" if standard == "JP GAAP" else "bps_definition_unresolved", "instant", "JPY/share"),
        "Eq": ("net_assets_total" if standard == "JP GAAP" else "equity_definition_unresolved", "instant", "JPY"),
        "ShOutFY": ("shares_issued_gross", "instant", "shares")}
    output = []
    for field, (metric, kind, unit) in mapping.items():
        f = {"jquants_fact_id": sha256(encoded([observation["observation_id"], field, DEFINITION])),
            "observation_id": observation["observation_id"], "source": observation["source"], "field": field,
            "jquants_code": code(r["Code"]), "metric": metric, "period_kind": kind, "period_class": "annual" if kind == "duration" else "instant",
            "period_start": r["CurPerSt"] if kind == "duration" else None, "period_end": r["CurPerEn"] if kind == "duration" else None,
            "instant_date": r["CurPerEn"] if kind == "instant" else None, "normalized_unit": unit,
            "consolidation": scope, "accounting_standard": standard, "original_string": r.get(field),
            "normalized_value": str(number(r.get(field))) if number(r.get(field)) is not None else None,
            "public_available_at": at.isoformat(), "revision_state": "reported_initial_or_unknown", "restated": r.get("RetroRst") not in (None, "", "false", "False", "0"),
            "share_basis": "provider_reported_split_basis_unverified" if unit in {"shares", "JPY/share"} else None,
            "definition_version": DEFINITION, "representation": "reported", "synthetic": observation["synthetic"]}
        output.append(f)
    return output
