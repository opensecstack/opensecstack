"""
Unit tests for the CITADEL audit chain hash computation.
These tests do NOT require a database — they test pure functions.
"""
import hashlib
import pytest
from app.audit import _compute_chain_hash, _compute_object_fingerprint


class TestComputeChainHash:
    def test_returns_64_hex_chars(self):
        h = _compute_chain_hash('id', 'action', 'actor', 'type', None, None, 'ts')
        assert len(h) == 64
        assert all(c in '0123456789abcdef' for c in h)

    def test_deterministic(self):
        args = ('id-1', 'org_created', 'alice', 'organisation', 'res-1', 'prev-hash', '2026-01-01T00:00:00+00:00')
        h1 = _compute_chain_hash(*args)
        h2 = _compute_chain_hash(*args)
        assert h1 == h2

    def test_different_inputs_produce_different_hashes(self):
        h1 = _compute_chain_hash('id-1', 'action', 'alice', 'org', None, None, 'ts')
        h2 = _compute_chain_hash('id-2', 'action', 'alice', 'org', None, None, 'ts')
        assert h1 != h2

    def test_null_resource_id_uses_NULL_string(self):
        h_none = _compute_chain_hash('id', 'a', 'b', 'c', None, None, 'ts')
        h_null = _compute_chain_hash('id', 'a', 'b', 'c', 'NULL', None, 'ts')
        # None and 'NULL' should produce the same hash (both map to 'NULL')
        assert h_none == h_null

    def test_null_prev_hash_uses_NULL_string(self):
        h_none = _compute_chain_hash('id', 'a', 'b', 'c', None, None, 'ts')
        h_null = _compute_chain_hash('id', 'a', 'b', 'c', None, 'NULL', 'ts')
        assert h_none == h_null

    def test_chain_links(self):
        """Verify that chain_hash feeds into next entry's prev_hash."""
        h1 = _compute_chain_hash('id-1', 'create', 'alice', 'org', 'res-1', None, 'ts1')
        h2 = _compute_chain_hash('id-2', 'update', 'alice', 'org', 'res-1', h1, 'ts2')
        # Changing h1 should change h2
        h1_modified = _compute_chain_hash('id-1', 'create', 'TAMPERED', 'org', 'res-1', None, 'ts1')
        h2_recomputed = _compute_chain_hash('id-2', 'update', 'alice', 'org', 'res-1', h1_modified, 'ts2')
        assert h2 != h2_recomputed

    def test_matches_manual_sha256(self):
        entry_id = 'abc'
        action = 'created'
        actor = 'bob'
        resource_type = 'assessment'
        resource_id = 'NULL'
        prev_hash = 'NULL'
        timestamp = '2026-01-01T00:00:00'
        raw = f'{entry_id}||{action}||{actor}||{resource_type}||{resource_id}||{prev_hash}||{timestamp}'
        expected = hashlib.sha256(raw.encode('utf-8')).hexdigest()
        result = _compute_chain_hash(entry_id, action, actor, resource_type, None, None, timestamp)
        assert result == expected


class TestComputeObjectFingerprint:
    def test_none_returns_none(self):
        assert _compute_object_fingerprint(None) is None

    def test_returns_64_hex_chars(self):
        fp = _compute_object_fingerprint({'key': 'value'})
        assert len(fp) == 64

    def test_deterministic_regardless_of_key_order(self):
        fp1 = _compute_object_fingerprint({'a': 1, 'b': 2})
        fp2 = _compute_object_fingerprint({'b': 2, 'a': 1})
        assert fp1 == fp2

    def test_different_objects_produce_different_fingerprints(self):
        fp1 = _compute_object_fingerprint({'status': 'compliant'})
        fp2 = _compute_object_fingerprint({'status': 'non_compliant'})
        assert fp1 != fp2

    def test_matches_manual_sha256(self):
        import json
        obj = {'id': '123', 'status': 'compliant'}
        canonical = json.dumps(obj, sort_keys=True, default=str, ensure_ascii=False)
        expected = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
        assert _compute_object_fingerprint(obj) == expected
