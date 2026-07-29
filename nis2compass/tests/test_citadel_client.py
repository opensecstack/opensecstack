"""
Unit tests for app/citadel_client.py — the CITADEL HTTP client.

Wire-shape assertions here mirror citadel/internal/marshal/types.go and
citadel/internal/api/handlers/worm.go field-for-field (see that module's
docstring for the mapping). These tests do not require a live CITADEL or
database — HTTP calls are monkeypatched.
"""
import pytest
from flask import g

from app import citadel_client


# --------------------------------------------------------------------- #
# build_kerkese() — wire-shape correctness
# --------------------------------------------------------------------- #

class TestBuildKerkese:
    def test_top_level_field_names_match_go_struct_tags(self):
        k = citadel_client.build_kerkese(
            'CONTROL_STATUS_UPDATE',
            actor_user_id='11111111-1111-1111-1111-111111111111',
            actor_role='assessor',
            actor_token='actor-jwt',
        )
        # citadel/internal/marshal/types.go Kerkese json tags
        expected_keys = {
            'kerkese_version', 'ts_utc', 'project_id', 'execution_id',
            'action', 'actor', 'verifier', 'evidence', 'sod', 'dry_run',
            'actor_token', 'verifier_token',
        }
        assert expected_keys.issubset(k.keys())

    def test_action_field_names(self):
        k = citadel_client.build_kerkese(
            'ARTIFACT_SIGN',
            actor_user_id='u1', actor_role='assessor',
            description='sign it', change_id='artifact-1',
        )
        assert k['action'] == {
            'type': 'ARTIFACT_SIGN',
            'description': 'sign it',
            'change_id': 'artifact-1',
        }

    def test_actor_and_verifier_field_names(self):
        k = citadel_client.build_kerkese(
            'ASSESSMENT_LOCK',
            actor_user_id='actor-uuid', actor_role='admin', actor_email='a@example.com',
            verifier_user_id='verifier-uuid', verifier_role='viewer', verifier_email='v@example.com',
        )
        assert k['actor']['user_id'] == 'actor-uuid'
        assert k['actor']['role'] == 'admin'
        assert k['actor']['email'] == 'a@example.com'
        assert k['verifier']['user_id'] == 'verifier-uuid'
        assert k['verifier']['role'] == 'viewer'
        assert k['verifier']['email'] == 'v@example.com'

    def test_email_omitted_when_not_given(self):
        k = citadel_client.build_kerkese('X', actor_user_id='u', actor_role='r')
        assert 'email' not in k['actor']
        assert 'email' not in k['verifier']

    def test_sod_mirrors_actor_and_verifier_user_ids(self):
        k = citadel_client.build_kerkese(
            'ASSESSMENT_UNLOCK',
            actor_user_id='op-1', actor_role='admin',
            verifier_user_id='vf-1', verifier_role='viewer',
        )
        assert k['sod'] == {'operator_user_id': 'op-1', 'verifier_user_id': 'vf-1'}

    def test_defaults_to_system_placeholder_verifier(self):
        k = citadel_client.build_kerkese('X', actor_user_id='u', actor_role='r')
        assert k['verifier']['user_id'] == citadel_client.SYSTEM_VERIFIER_USER_ID
        assert k['verifier']['user_id'] != k['actor']['user_id']

    def test_execution_id_is_a_valid_uuid(self):
        import uuid
        k = citadel_client.build_kerkese('X', actor_user_id='u', actor_role='r')
        uuid.UUID(k['execution_id'])  # raises ValueError if malformed

    def test_ts_utc_is_iso_format(self):
        from datetime import datetime
        k = citadel_client.build_kerkese('X', actor_user_id='u', actor_role='r')
        datetime.fromisoformat(k['ts_utc'])

    def test_tokens_forwarded_verbatim(self):
        k = citadel_client.build_kerkese(
            'X', actor_user_id='u', actor_role='r',
            actor_token='actor-jwt-raw', verifier_token='verifier-jwt-raw',
        )
        assert k['actor_token'] == 'actor-jwt-raw'
        assert k['verifier_token'] == 'verifier-jwt-raw'

    def test_dry_run_false_by_default(self):
        k = citadel_client.build_kerkese('X', actor_user_id='u', actor_role='r')
        assert k['dry_run'] is False


# --------------------------------------------------------------------- #
# emit_worm() — POST /api/v1/worm/emit, fire-and-forget
# --------------------------------------------------------------------- #

class TestEmitWorm:
    def test_no_op_when_citadel_not_configured(self, app, monkeypatch):
        calls = []
        monkeypatch.setattr('requests.post', lambda *a, **kw: calls.append((a, kw)))
        with app.app_context():
            monkeypatch.setitem(app.config, 'CITADEL_API_URL', '')
            citadel_client.emit_worm('nis2compass', 'control_status_updated', 'nis2compass', {})
        assert calls == []

    def test_posts_to_correct_endpoint_with_correct_shape(self, app, monkeypatch):
        captured = {}

        class FakeResp:
            status_code = 200

            def json(self):
                return {'worm_entry_id': 'x'}

        def fake_post(url, json=None, headers=None, timeout=None):
            captured['url'] = url
            captured['json'] = json
            captured['headers'] = headers
            captured['timeout'] = timeout
            return FakeResp()

        monkeypatch.setattr('requests.post', fake_post)
        with app.app_context():
            monkeypatch.setitem(app.config, 'CITADEL_API_URL', 'http://citadel.local:8099')
            monkeypatch.setitem(app.config, 'CITADEL_API_KEY', 'secret-key')
            citadel_client.emit_worm(
                'nis2compass', 'control_status_updated', 'nis2compass',
                {'action': 'control_status_updated', 'actor': 'user-1'},
            )

        assert captured['url'] == 'http://citadel.local:8099/api/v1/worm/emit'
        assert captured['json'] == {
            'source': 'nis2compass',
            'event_type': 'control_status_updated',
            'project_id': 'nis2compass',
            'payload': {'action': 'control_status_updated', 'actor': 'user-1'},
        }
        assert captured['headers']['Authorization'] == 'Bearer secret-key'

    def test_strips_trailing_slash_from_configured_url(self, app, monkeypatch):
        captured = {}

        class FakeResp:
            status_code = 200

            def json(self):
                return {}

        def fake_post(url, **kw):
            captured['url'] = url
            return FakeResp()

        monkeypatch.setattr('requests.post', fake_post)
        with app.app_context():
            monkeypatch.setitem(app.config, 'CITADEL_API_URL', 'http://citadel.local:8099/')
            citadel_client.emit_worm('nis2compass', 'evt', 'nis2compass', {})
        assert captured['url'] == 'http://citadel.local:8099/api/v1/worm/emit'

    def test_never_raises_on_network_failure(self, app, monkeypatch):
        def boom(*a, **kw):
            raise ConnectionError('unreachable')

        monkeypatch.setattr('requests.post', boom)
        with app.app_context():
            monkeypatch.setitem(app.config, 'CITADEL_API_URL', 'http://citadel.local:8099')
            # Must not raise.
            citadel_client.emit_worm('nis2compass', 'evt', 'nis2compass', {})


# --------------------------------------------------------------------- #
# evaluate() — POST /api/v1/marshal/evaluate, synchronous
# --------------------------------------------------------------------- #

class TestEvaluate:
    def test_posts_to_correct_endpoint(self, app, monkeypatch):
        captured = {}

        class FakeResp:
            status_code = 200

            def json(self):
                return {'outcome': 'EXECUTE', 'gates': [], 'reasons': []}

        def fake_post(url, json=None, headers=None, timeout=None):
            captured['url'] = url
            captured['json'] = json
            return FakeResp()

        monkeypatch.setattr('requests.post', fake_post)
        with app.app_context():
            monkeypatch.setitem(app.config, 'CITADEL_API_URL', 'http://citadel.local:8099')
            k = citadel_client.build_kerkese('X', actor_user_id='u', actor_role='r')
            decision = citadel_client.evaluate(k)

        assert captured['url'] == 'http://citadel.local:8099/api/v1/marshal/evaluate'
        assert captured['json'] == k
        assert decision['outcome'] == 'EXECUTE'

    def test_403_refuse_is_a_real_decision_not_an_error(self, app, monkeypatch):
        class FakeResp:
            status_code = 403

            def json(self):
                return {'outcome': 'REFUSE', 'gates': [], 'reasons': ['AUTHZ_FAIL: role not permitted']}

        monkeypatch.setattr('requests.post', lambda *a, **kw: FakeResp())
        with app.app_context():
            monkeypatch.setitem(app.config, 'CITADEL_API_URL', 'http://citadel.local:8099')
            k = citadel_client.build_kerkese('X', actor_user_id='u', actor_role='r')
            decision = citadel_client.evaluate(k)
        assert decision['outcome'] == 'REFUSE'

    def test_raises_unavailable_when_url_not_configured(self, app, monkeypatch):
        with app.app_context():
            monkeypatch.setitem(app.config, 'CITADEL_API_URL', '')
            k = citadel_client.build_kerkese('X', actor_user_id='u', actor_role='r')
            with pytest.raises(citadel_client.CitadelUnavailableError):
                citadel_client.evaluate(k)

    def test_raises_unavailable_on_network_failure(self, app, monkeypatch):
        def boom(*a, **kw):
            raise ConnectionError('unreachable')

        monkeypatch.setattr('requests.post', boom)
        with app.app_context():
            monkeypatch.setitem(app.config, 'CITADEL_API_URL', 'http://citadel.local:8099')
            k = citadel_client.build_kerkese('X', actor_user_id='u', actor_role='r')
            with pytest.raises(citadel_client.CitadelUnavailableError):
                citadel_client.evaluate(k)

    def test_raises_unavailable_on_5xx(self, app, monkeypatch):
        class FakeResp:
            status_code = 500

            def json(self):
                return {'error': 'internal server error'}

        monkeypatch.setattr('requests.post', lambda *a, **kw: FakeResp())
        with app.app_context():
            monkeypatch.setitem(app.config, 'CITADEL_API_URL', 'http://citadel.local:8099')
            k = citadel_client.build_kerkese('X', actor_user_id='u', actor_role='r')
            with pytest.raises(citadel_client.CitadelUnavailableError):
                citadel_client.evaluate(k)

    def test_raises_unavailable_on_non_json_body(self, app, monkeypatch):
        class FakeResp:
            status_code = 200

            def json(self):
                raise ValueError('not json')

        monkeypatch.setattr('requests.post', lambda *a, **kw: FakeResp())
        with app.app_context():
            monkeypatch.setitem(app.config, 'CITADEL_API_URL', 'http://citadel.local:8099')
            k = citadel_client.build_kerkese('X', actor_user_id='u', actor_role='r')
            with pytest.raises(citadel_client.CitadelUnavailableError):
                citadel_client.evaluate(k)


# --------------------------------------------------------------------- #
# evaluate_governance_action() — blocking semantics
# --------------------------------------------------------------------- #

class TestEvaluateGovernanceAction:
    def test_execute_returns_decision(self, app, monkeypatch):
        monkeypatch.setattr(
            citadel_client, 'evaluate',
            lambda k, **kw: {'outcome': 'EXECUTE', 'gates': [], 'reasons': []},
        )
        with app.app_context():
            decision = citadel_client.evaluate_governance_action(
                'CONTROL_STATUS_UPDATE', actor_user_id='u', actor_role='assessor',
            )
        assert decision['outcome'] == 'EXECUTE'

    def test_refuse_raises_governance_error(self, app, monkeypatch):
        monkeypatch.setattr(
            citadel_client, 'evaluate',
            lambda k, **kw: {'outcome': 'REFUSE', 'gates': [], 'reasons': ['nope']},
        )
        with app.app_context():
            with pytest.raises(citadel_client.CitadelGovernanceError) as exc_info:
                citadel_client.evaluate_governance_action(
                    'CONTROL_STATUS_UPDATE', actor_user_id='u', actor_role='assessor',
                )
        assert exc_info.value.outcome == 'REFUSE'
        assert exc_info.value.reasons == ['nope']

    def test_hard_stop_raises_governance_error(self, app, monkeypatch):
        monkeypatch.setattr(
            citadel_client, 'evaluate',
            lambda k, **kw: {'outcome': 'HARD_STOP', 'gates': [], 'reasons': ['NDS_SAME_IDENTITY']},
        )
        with app.app_context():
            with pytest.raises(citadel_client.CitadelGovernanceError) as exc_info:
                citadel_client.evaluate_governance_action(
                    'ARTIFACT_SIGN', actor_user_id='u', actor_role='assessor',
                    verifier_user_id='u',  # same as actor — real NDS violation
                )
        assert exc_info.value.outcome == 'HARD_STOP'

    def test_citadel_unavailable_propagates(self, app, monkeypatch):
        def boom(k, **kw):
            raise citadel_client.CitadelUnavailableError('down')

        monkeypatch.setattr(citadel_client, 'evaluate', boom)
        with app.app_context():
            with pytest.raises(citadel_client.CitadelUnavailableError):
                citadel_client.evaluate_governance_action(
                    'ASSESSMENT_LOCK', actor_user_id='u', actor_role='assessor',
                )

    def test_not_configured_allows_action_through(self, app, monkeypatch):
        """Unlike a live-but-unreachable CITADEL (fail closed), no CITADEL_API_URL
        at all means governance is off for this deployment — the action proceeds."""
        def not_configured(k, **kw):
            raise citadel_client.CitadelNotConfiguredError('no url')

        monkeypatch.setattr(citadel_client, 'evaluate', not_configured)
        with app.app_context():
            decision = citadel_client.evaluate_governance_action(
                'ASSESSMENT_LOCK', actor_user_id='u', actor_role='assessor',
            )
        assert decision['outcome'] == 'EXECUTE'


# --------------------------------------------------------------------- #
# current_actor_identity() — real (non-placeholder) actor sourcing
# --------------------------------------------------------------------- #

class TestCurrentActorIdentity:
    def test_pulls_identity_from_flask_g(self, app):
        with app.test_request_context('/'):
            g.actor = 'sinauth-uuid-1234'
            g.token_role = 'admin'
            g.raw_token = 'raw-bearer-jwt'
            g.actor_email = 'user@example.com'
            identity = citadel_client.current_actor_identity()
        assert identity == {
            'actor_user_id': 'sinauth-uuid-1234',
            'actor_role': 'admin',
            'actor_token': 'raw-bearer-jwt',
            'actor_email': 'user@example.com',
        }

    def test_raises_outside_authenticated_request(self, app):
        with app.test_request_context('/'):
            with pytest.raises(RuntimeError):
                citadel_client.current_actor_identity()
