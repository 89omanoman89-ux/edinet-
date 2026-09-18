"""Synthetic byte fixtures only; no public documentation or network is fetched."""
from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from source_acquisition import PrivateStore, sha256
from source_documentation import acceptance_states, documentation_acceptance


class DocumentationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = PrivateStore(Path(tmp.name) / 'private')
        self.artifact = self.saved(b'SYNTHETIC schema specification\n')
        self.review = {
            'source_id': 'synthetic', 'document': 'schema.md',
            'safe_url': self.artifact['safe_url'], 'expected_sha256': self.artifact['byte_sha256'],
            'reviewed_source_version': 'synthetic-v1', 'review_scope': ['Fixture schema only'],
            'known_limitations': ['Synthetic; not empirical'],
            'assertions_relied_upon': ['Fixture documents a synthetic row'],
        }
        self.registry = {'registry_version': 'synthetic-v1', 'sources': {'synthetic': {
            'required_documents': ['schema.md'], 'reviews': [self.review]}}}

    def saved(self, raw):
        digest = sha256(raw)
        self.store.publish('raw/' + digest, raw)
        return {'byte_sha256': digest, 'byte_count': len(raw), 'provider_version': 'synthetic-v1',
                'safe_url': 'https://example.org/synthetic-v1/schema.md', 'retrieved_at': '2026-01-01T00:00:00Z'}

    def check(self, artifacts=None, registry=None):
        return documentation_acceptance(self.store, 'synthetic',
            [self.artifact] if artifacts is None else artifacts, self.registry if registry is None else registry)

    def blocked(self, result, reason, fetched='PASS'):
        self.assertEqual(result['documentation_fetched'], fetched)
        self.assertEqual(result['documentation_checked'], 'BLOCKED')
        self.assertIn(reason, result['documentation_review']['missing_reasons'])

    def test_fetched_is_not_reviewed(self):
        self.blocked(self.check(registry={}), 'documentation_hash_not_registered')

    def test_exact_reviewed_bytes_pass_and_evidence_is_reversible(self):
        result = self.check()
        self.assertEqual(result['documentation_checked'], 'PASS')
        self.assertEqual(result['documentation_fetched'], 'PASS')
        evidence = result['documentation_review']['artifacts'][0]
        self.assertEqual(evidence['observed_sha256'], self.review['expected_sha256'])
        self.assertEqual(evidence['observed_byte_count'], self.artifact['byte_count'])
        self.assertEqual(result['documentation_review']['reviews'], [self.review])

    def test_changed_bytes_with_valid_acquisition_hash_are_not_reviewed(self):
        changed = self.saved(b'SYNTHETIC changed schema\n')
        self.blocked(self.check([changed]), 'documentation_review_hash_mismatch')

    def test_corrupt_saved_bytes_block_instead_of_crashing(self):
        (self.store.root / 'raw' / self.artifact['byte_sha256']).write_bytes(b'corrupt')
        self.blocked(self.check(), 'documentation_artifact_missing_or_integrity_failed', 'BLOCKED')

    def test_missing_required_document_even_with_other_document_fetched(self):
        second = dict(self.review, document='required.md', safe_url='https://example.org/required.md')
        source = self.registry['sources']['synthetic']
        source['required_documents'].append('required.md'); source['reviews'].append(second)
        result = self.check()
        self.blocked(result, 'documentation_required_document_missing')
        self.assertEqual(result['documentation_review']['missing_documents'], ['required.md'])

    def test_missing_raw_is_not_replaced_by_manifest_hash(self):
        (self.store.root / 'raw' / self.artifact['byte_sha256']).unlink()
        self.blocked(self.check(), 'documentation_artifact_missing_or_integrity_failed', 'BLOCKED')

    def test_unregistered_hash_blocks(self):
        self.review['expected_sha256'] = None
        self.blocked(self.check(), 'documentation_hash_not_registered')

    def test_unknown_review_scope_blocks(self):
        for scope in (None, [], [''], ['unknown']):
            with self.subTest(scope=scope):
                self.review['review_scope'] = scope
                self.blocked(self.check(), 'documentation_review_scope_unknown')

    def test_matching_hash_at_other_version_blocks(self):
        self.artifact['provider_version'] = 'synthetic-v2'
        self.blocked(self.check(), 'documentation_version_mismatch')

    def test_wrong_url_or_document_cannot_reuse_reviewed_hash(self):
        self.artifact['safe_url'] = 'https://example.org/other/schema.md'
        self.blocked(self.check(), 'documentation_hash_not_registered')
        self.artifact['safe_url'] = self.review['safe_url']
        self.artifact['document'] = 'other.md'
        self.blocked(self.check(), 'documentation_locator_mismatch')

    def test_ambiguous_artifact_or_review_blocks(self):
        self.blocked(self.check([self.artifact, self.artifact]), 'documentation_artifact_ambiguous')
        self.registry['sources']['synthetic']['reviews'].append(deepcopy(self.review))
        self.blocked(self.check(), 'documentation_review_registry_invalid')

    def test_review_for_other_source_cannot_be_adopted(self):
        self.review['source_id'] = 'other'
        self.blocked(self.check(), 'documentation_review_registry_invalid')

    def test_assertions_and_limitations_are_required(self):
        for key, reason in [('assertions_relied_upon', 'documentation_review_assertions_unknown'),
                            ('known_limitations', 'documentation_review_limitations_unknown')]:
            with self.subTest(key=key):
                registry = deepcopy(self.registry)
                registry['sources']['synthetic']['reviews'][0][key] = []
                self.blocked(self.check(registry=registry), reason)

    def test_documentation_pass_does_not_approve_other_axes(self):
        result = acceptance_states(self.check(), data_fetched='BLOCKED', schema_profiled='BLOCKED', original_tied='BLOCKED')
        self.assertEqual(result['documentation_checked'], 'PASS')
        for key in ('data_fetched', 'schema_profiled', 'original_tied', 'rights_reviewed'):
            self.assertEqual(result[key], 'BLOCKED')
        self.assertFalse(result['export_allowed'])

    def test_saved_p5_acceptance_keeps_states_independent(self):
        # Use the existing tiny P3/P5 fixture, never the real source manifests.
        import test_derived_sources as fixtures
        fixture = fixtures.PrivateP5Tests()
        with redirect_stdout(io.StringIO()):
            fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.store.publish('raw/' + self.artifact['byte_sha256'], self.store.read_raw(self.artifact))
        fixture.bundle['sources']['numad']['documentation'] = [self.artifact]
        fixture.write()
        registry = deepcopy(self.registry)
        source = registry['sources'].pop('synthetic')
        source['reviews'][0]['source_id'] = 'numad'
        registry['sources']['numad'] = source
        import p5_audit
        real_acceptance = documentation_acceptance
        def fixture_review(store, source_id, artifacts, _registry):
            return real_acceptance(store, source_id, artifacts, registry)
        with patch.object(p5_audit, 'documentation_acceptance', side_effect=fixture_review):
            fixture.audit()
        result = json.loads((fixture.base / 'p5/synthetic-p5/source_acceptance.json').read_bytes())
        sources = {s['source_id']: s for s in result['sources']}
        self.assertEqual(sources['numad']['documentation_checked'], 'PASS')
        self.assertEqual(sources['queria']['documentation_checked'], 'BLOCKED')
        for source in sources.values():
            self.assertEqual(source['data_fetched'], 'PASS')
            self.assertEqual(source['schema_profiled'], 'PASS')
            self.assertEqual(source['original_tied'], 'PASS')
            self.assertEqual(source['rights_reviewed'], 'BLOCKED')
            self.assertEqual(source['rights_review'], 'BLOCKED')
            self.assertFalse(source['export_allowed'])
            self.assertEqual(source['docs_checked'], source['documentation_checked'])


if __name__ == '__main__':
    unittest.main()
