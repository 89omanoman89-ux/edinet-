"""Match saved documentation bytes to an explicit, separately maintained review.

No networking, review generation, data approval, or rights approval occurs here.
"""
import re

from evidence_core import ContractError
from source_acquisition import encoded, sha256


def _known_text(value):
    return isinstance(value, str) and value.strip().lower() not in ('', 'unknown', 'unresolved', 'not reviewed')


def _statements(value):
    return isinstance(value, list) and bool(value) and all(_known_text(x) for x in value)


def documentation_acceptance(store, source_id, artifacts, registry):
    """Fetched concerns supplied artifacts; checked requires the entire reviewed set.

    A logical document name is optional in older acquisition manifests. Its exact
    pinned URL must still match; basename or hash-only matching is never used.
    """
    source = registry.get('sources', {}).get(source_id, {})
    required = source.get('required_documents', [])
    reviews = source.get('reviews', [])
    reasons = []
    if not required or not reviews:
        reasons.append('documentation_review_not_registered')
    by_url = {}
    by_document = {}
    for review in reviews:
        document, url = review.get('document'), review.get('safe_url')
        if (review.get('source_id') != source_id or not _known_text(document)
                or not _known_text(url) or url in by_url or document in by_document):
            reasons.append('documentation_review_registry_invalid')
            continue
        by_url[url] = review
        by_document[document] = review
        if not re.fullmatch(r'[a-f0-9]{64}', str(review.get('expected_sha256', ''))):
            reasons.append('documentation_hash_not_registered')
        if not _statements(review.get('review_scope')):
            reasons.append('documentation_review_scope_unknown')
        if not _known_text(review.get('reviewed_source_version')):
            reasons.append('documentation_review_version_unknown')
        if not _statements(review.get('assertions_relied_upon')):
            reasons.append('documentation_review_assertions_unknown')
        if not _statements(review.get('known_limitations')):
            reasons.append('documentation_review_limitations_unknown')
    if len(set(required)) != len(required) or set(required) != set(by_document):
        reasons.append('documentation_required_review_missing')

    evidence, seen = [], set()
    for artifact in artifacts:
        why = []
        review = by_url.get(artifact.get('safe_url'))
        document = review['document'] if review else artifact.get('document')
        observed = None
        byte_count = None
        try:
            raw = store.read_raw(artifact)
            observed, byte_count = sha256(raw), len(raw)
        except (ContractError, OSError, ValueError, TypeError):
            why.append('documentation_artifact_missing_or_integrity_failed')
        if review is None:
            why.append('documentation_hash_not_registered')
        else:
            if document in seen:
                why.append('documentation_artifact_ambiguous')
            seen.add(document)
            if artifact.get('document', document) != document:
                why.append('documentation_locator_mismatch')
            if artifact.get('provider_version') != review.get('reviewed_source_version'):
                why.append('documentation_version_mismatch')
            if observed is None or observed != review.get('expected_sha256'):
                why.append('documentation_review_hash_mismatch')
        reasons.extend(why)
        evidence.append({'document': document, 'safe_url': artifact.get('safe_url'),
            'provider_version': artifact.get('provider_version'),
            'retrieved_at': artifact.get('retrieved_at'),
            'artifact_sha256': artifact.get('byte_sha256'),
            'observed_sha256': observed, 'observed_byte_count': byte_count,
            'expected_sha256': review.get('expected_sha256') if review else None,
            'byte_integrity': 'PASS' if observed is not None else 'BLOCKED',
            'missing_reasons': sorted(set(why))})
    missing = sorted(set(required) - seen)
    if missing:
        reasons.append('documentation_required_document_missing')
    if not artifacts:
        reasons.append('documentation_not_fetched')
    return {
        'documentation_fetched': 'PASS' if evidence and all(x['byte_integrity'] == 'PASS' for x in evidence) else 'BLOCKED',
        'documentation_checked': 'BLOCKED' if reasons else 'PASS',
        'documentation_review': {
            'registry_version': registry.get('registry_version'),
            'registry_sha256': sha256(encoded(registry)),
            'fetched_scope': 'supplied artifacts only; not completeness or specification approval',
            'checked_scope': 'all required documents and registered assertions only',
            'required_documents': required, 'missing_documents': missing,
            'reviews': reviews, 'artifacts': evidence,
            'missing_reasons': sorted(set(reasons)),
        },
    }


def acceptance_states(documentation, *, data_fetched, schema_profiled, original_tied):
    """Independent axes; documentation approval never authorizes redistribution."""
    return dict(documentation, data_fetched=data_fetched, schema_profiled=schema_profiled,
                original_tied=original_tied, rights_reviewed='BLOCKED', export_allowed=False)
