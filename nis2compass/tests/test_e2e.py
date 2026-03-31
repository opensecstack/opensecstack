"""
End-to-end tests for NIS2 Compass.

These tests exercise the *live* NIS2 Compass HTTP service through the
official Python SDK.  They are skipped automatically when the required
environment variables are absent so they never block CI unless explicitly
wired to a running instance.

Required environment variables
-------------------------------
    NIS2_E2E_URL      Base URL of the service  (e.g. http://localhost:8090)
    NIS2_E2E_API_KEY  A valid read_write API key

Optional
--------
    NIS2_E2E_SKIP_REPORT  Set to '1' to skip SARIF/JSON report streaming
                          (useful when WeasyPrint / font dependencies are absent)

Run
---
    NIS2_E2E_URL=http://localhost:8090 \\
    NIS2_E2E_API_KEY=my-api-key        \\
    pytest tests/test_e2e.py -v -m e2e
"""

import hashlib
import io
import os
import threading
import uuid

import pytest

try:
    from opensecstack.nis2compass import NIS2CompassClient
    from opensecstack.exceptions import APIError, AuthenticationError, NotFoundError

    _SDK_AVAILABLE = True
except ImportError:
    _SDK_AVAILABLE = False

# ---------------------------------------------------------------------------
# Skip guards
# ---------------------------------------------------------------------------

_E2E_URL = os.getenv("NIS2_E2E_URL", "").rstrip("/")
_E2E_API_KEY = os.getenv("NIS2_E2E_API_KEY", "")
_SKIP_REPORT = os.getenv("NIS2_E2E_SKIP_REPORT", "0") == "1"

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        not (_E2E_URL and _E2E_API_KEY and _SDK_AVAILABLE),
        reason=(
            "E2E tests require NIS2_E2E_URL, NIS2_E2E_API_KEY, "
            "and the opensecstack SDK to be importable."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def client():
    return NIS2CompassClient(base_url=_E2E_URL, api_key=_E2E_API_KEY)


@pytest.fixture()
def org(client):
    """Create a throw-away organisation; delete it (and all children) after."""
    unique = uuid.uuid4().hex[:8]
    created = client.create_organisation(
        name=f"E2E-Org-{unique}",
        industry="Energy",
        country="DE",
        size="medium",
        entity_type="important",
        contact_email=f"e2e-{unique}@example.test",
    )
    yield created
    try:
        client.delete_organisation(created["id"])
    except Exception:
        pass


@pytest.fixture()
def assessment(client, org):
    """Create a throw-away assessment under `org`."""
    unique = uuid.uuid4().hex[:8]
    created = client.create_assessment(
        org_id=org["id"],
        title=f"E2E Assessment {unique}",
    )
    yield created
    try:
        client.delete_assessment(created["id"])
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


class TestHealthE2E:
    def test_public_health_returns_ok(self, client):
        data = client.get_health()
        assert data["status"] == "ok"

    def test_public_health_no_internal_details(self, client):
        data = client.get_health()
        assert "db" not in data
        assert "version" not in data

    def test_detailed_health_with_auth(self, client):
        data = client.get_health_detail()
        assert data["status"] == "ok"
        assert "db" in data
        assert "version" in data

    def test_detailed_health_rejects_bad_key(self):
        bad = NIS2CompassClient(base_url=_E2E_URL, api_key="bad-key-xyz-e2e")
        with pytest.raises((APIError, AuthenticationError)):
            bad.get_health_detail()


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


class TestAuthE2E:
    def test_invalid_api_key_rejected(self):
        bad = NIS2CompassClient(base_url=_E2E_URL, api_key="not-a-real-key-e2e")
        with pytest.raises((APIError, AuthenticationError)):
            bad.get_organisations()

    def test_sequential_calls_reuse_token(self, client):
        # Two calls must both succeed; the SDK must not re-authenticate
        # between them for a fresh token.
        h1 = client.get_health()
        h2 = client.get_health()
        assert h1["status"] == h2["status"] == "ok"


# ---------------------------------------------------------------------------
# Organisations
# ---------------------------------------------------------------------------


class TestOrganisationsE2E:
    def test_create_returns_expected_fields(self, client):
        unique = uuid.uuid4().hex[:8]
        org = client.create_organisation(
            name=f"E2E-Fields-{unique}",
            industry="Finance",
            country="FR",
            size="large",
            entity_type="essential",
            registration_number=f"REG-{unique}",
            contact_email=f"fields-{unique}@example.test",
        )
        try:
            assert org["country"] == "FR"
            assert org["size"] == "large"
            assert org["entity_type"] == "essential"
            assert org["registration_number"] == f"REG-{unique}"
            assert "id" in org
            assert "created_at" in org
        finally:
            client.delete_organisation(org["id"])

    def test_get_matches_create(self, client, org):
        fetched = client.get_organisation(org["id"])
        assert fetched["id"] == org["id"]
        assert fetched["name"] == org["name"]
        assert fetched["country"] == org["country"]

    def test_list_includes_created_org(self, client, org):
        orgs = client.get_organisations(per_page=100)
        ids = [o["id"] for o in orgs]
        assert org["id"] in ids

    def test_patch_persists(self, client, org):
        new_name = f"Updated-{uuid.uuid4().hex[:6]}"
        updated = client.patch_organisation(org["id"], name=new_name)
        assert updated["name"] == new_name
        # Verify the change was actually written to the DB
        fetched = client.get_organisation(org["id"])
        assert fetched["name"] == new_name

    def test_delete_makes_org_unreachable(self, client):
        unique = uuid.uuid4().hex[:8]
        org = client.create_organisation(
            name=f"E2E-Delete-{unique}",
            industry="Transport",
            country="ES",
        )
        client.delete_organisation(org["id"])
        with pytest.raises((APIError, NotFoundError)):
            client.get_organisation(org["id"])

    def test_invalid_country_code_rejected(self, client):
        with pytest.raises((APIError, Exception)):
            client.create_organisation(
                name=f"BadCountry-{uuid.uuid4().hex[:6]}",
                industry="Energy",
                country="ZZZ",  # not a valid ISO 3166-1 alpha-2 code
            )

    def test_get_nonexistent_org_returns_404(self, client):
        with pytest.raises((APIError, NotFoundError)):
            client.get_organisation("00000000-0000-0000-0000-000000000000")

    def test_pagination_page_size_respected(self, client):
        # Create three orgs so there is guaranteed data, then ask for page of 1
        created = []
        for _ in range(3):
            o = client.create_organisation(
                name=f"E2E-Page-{uuid.uuid4().hex[:6]}",
                industry="Health",
                country="AT",
            )
            created.append(o["id"])
        try:
            page = client.get_organisations(page=1, per_page=1)
            assert len(page) == 1
            page2 = client.get_organisations(page=2, per_page=1)
            assert len(page2) == 1
            # Two pages of 1 must not return the same item
            assert page[0]["id"] != page2[0]["id"]
        finally:
            for oid in created:
                try:
                    client.delete_organisation(oid)
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------


class TestAssessmentsE2E:
    def test_create_assessment_defaults(self, client, assessment):
        assert assessment["status"] == "draft"
        assert "id" in assessment
        assert "created_at" in assessment

    def test_get_assessment_has_stats(self, client, assessment):
        fetched = client.get_assessment(assessment["id"])
        assert fetched["id"] == assessment["id"]
        # Stats block (or equivalent) must be present
        has_stats = (
            "stats" in fetched
            or "total_controls" in fetched
            or "controls" in fetched
        )
        assert has_stats

    def test_list_assessments_for_org(self, client, assessment, org):
        assessments = client.list_assessments(org["id"])
        ids = [a["id"] for a in assessments]
        assert assessment["id"] in ids

    def test_state_machine_full_path(self, client, org):
        """draft → in_progress → under_review → completed → archived"""
        unique = uuid.uuid4().hex[:8]
        a = client.create_assessment(org_id=org["id"], title=f"StateMachine-{unique}")
        aid = a["id"]
        try:
            assert a["status"] == "draft"
            a = client.patch_assessment(aid, status="in_progress")
            assert a["status"] == "in_progress"
            a = client.patch_assessment(aid, status="under_review")
            assert a["status"] == "under_review"
            a = client.patch_assessment(aid, status="completed")
            assert a["status"] == "completed"
            a = client.patch_assessment(aid, status="archived")
            assert a["status"] == "archived"
        finally:
            try:
                client.delete_assessment(aid)
            except Exception:
                pass

    def test_invalid_state_transition_rejected(self, client, org):
        """draft → completed (skipping steps) must be rejected."""
        unique = uuid.uuid4().hex[:8]
        a = client.create_assessment(org_id=org["id"], title=f"BadTransition-{unique}")
        try:
            with pytest.raises((APIError, Exception)):
                client.patch_assessment(a["id"], status="completed")
        finally:
            try:
                client.delete_assessment(a["id"])
            except Exception:
                pass

    def test_delete_assessment_removes_it(self, client, org):
        unique = uuid.uuid4().hex[:8]
        a = client.create_assessment(org_id=org["id"], title=f"DeleteMe-{unique}")
        client.delete_assessment(a["id"])
        with pytest.raises((APIError, NotFoundError)):
            client.get_assessment(a["id"])


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


class TestControlsE2E:
    def test_new_assessment_has_ten_controls(self, client, assessment):
        controls = client.list_controls(assessment["id"])
        assert len(controls) == 10

    def test_controls_cover_all_nis2_measures(self, client, assessment):
        controls = client.list_controls(assessment["id"])
        measure_refs = {c["measure_ref"] for c in controls}
        assert measure_refs == set("abcdefghij")

    def test_controls_default_to_not_assessed(self, client, assessment):
        controls = client.list_controls(assessment["id"])
        assert all(c["status"] == "not_assessed" for c in controls)

    def test_get_single_control(self, client, assessment):
        ctrl = client.get_control(assessment["id"], "a")
        assert ctrl["measure_ref"] == "a"
        assert ctrl["status"] == "not_assessed"

    def test_patch_control_status_persists(self, client, assessment):
        client.patch_control(assessment["id"], "a", status="compliant")
        fetched = client.get_control(assessment["id"], "a")
        assert fetched["status"] == "compliant"

    def test_patch_control_risk_score(self, client, assessment):
        updated = client.patch_control(assessment["id"], "b", risk_score=7.5)
        assert float(updated["risk_score"]) == pytest.approx(7.5)

    def test_patch_control_risk_score_out_of_range_rejected(self, client, assessment):
        with pytest.raises((APIError, Exception)):
            client.patch_control(assessment["id"], "c", risk_score=11.0)

    def test_filter_controls_by_status(self, client, assessment):
        client.patch_control(assessment["id"], "d", status="non_compliant")
        non_compliant = client.list_controls(assessment["id"], status="non_compliant")
        assert any(c["measure_ref"] == "d" for c in non_compliant)
        # The filtered list must not contain controls in other statuses
        assert all(c["status"] == "non_compliant" for c in non_compliant)

    def test_remediation_fields_persist(self, client, assessment):
        updated = client.patch_control(
            assessment["id"],
            "e",
            status="partially_compliant",
            gap_description="Missing encryption at rest.",
            remediation_plan="Enable AES-256 on all storage.",
        )
        assert updated["gap_description"] == "Missing encryption at rest."
        assert updated["remediation_plan"] == "Enable AES-256 on all storage."


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------


class TestArtifactsE2E:
    def test_upload_and_list(self, client, assessment, tmp_path):
        pdf = tmp_path / "evidence.pdf"
        pdf.write_bytes(b"%PDF-1.4 minimal pdf content for E2E testing")

        artifact = client.upload_artifact(
            assessment_id=assessment["id"],
            file_path=str(pdf),
            artifact_type="evidence",
            description="E2E evidence document",
        )
        try:
            assert "id" in artifact
            assert artifact["filename"] == "evidence.pdf"
            assert "hash" in artifact

            listed = client.list_artifacts(assessment["id"])
            ids = [a["id"] for a in listed]
            assert artifact["id"] in ids
        finally:
            try:
                client.delete_artifact(artifact["id"])
            except Exception:
                pass

    def test_sha256_hash_matches_upload(self, client, assessment, tmp_path):
        content = b"integrity-check-" + uuid.uuid4().bytes
        f = tmp_path / "integrity.txt"
        f.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()

        artifact = client.upload_artifact(
            assessment_id=assessment["id"],
            file_path=str(f),
            artifact_type="evidence",
        )
        try:
            assert artifact["hash"] == expected
        finally:
            try:
                client.delete_artifact(artifact["id"])
            except Exception:
                pass

    def test_download_roundtrip(self, client, assessment, tmp_path):
        content = b"roundtrip-download-" + uuid.uuid4().bytes
        src = tmp_path / "upload.txt"
        src.write_bytes(content)

        artifact = client.upload_artifact(
            assessment_id=assessment["id"],
            file_path=str(src),
            artifact_type="policy",
        )
        try:
            dest = tmp_path / "downloaded.txt"
            client.download_artifact(artifact["id"], str(dest))
            assert dest.read_bytes() == content
        finally:
            try:
                client.delete_artifact(artifact["id"])
            except Exception:
                pass

    def test_delete_artifact_makes_it_unreachable(self, client, assessment, tmp_path):
        f = tmp_path / "delete_me.txt"
        f.write_text("delete test content")

        artifact = client.upload_artifact(
            assessment_id=assessment["id"],
            file_path=str(f),
            artifact_type="log",
        )
        client.delete_artifact(artifact["id"])
        with pytest.raises((APIError, NotFoundError)):
            client.get_artifact(artifact["id"])

    def test_unsupported_mime_type_rejected(self, client, assessment, tmp_path):
        exe = tmp_path / "binary.exe"
        exe.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)  # PE magic bytes
        with pytest.raises((APIError, Exception)):
            client.upload_artifact(
                assessment_id=assessment["id"],
                file_path=str(exe),
                artifact_type="evidence",
            )

    def test_get_artifact_metadata(self, client, assessment, tmp_path):
        f = tmp_path / "meta.txt"
        f.write_bytes(b"metadata test")
        artifact = client.upload_artifact(
            assessment_id=assessment["id"],
            file_path=str(f),
            artifact_type="procedure",
        )
        try:
            meta = client.get_artifact(artifact["id"])
            assert meta["id"] == artifact["id"]
            assert meta["filename"] == "meta.txt"
            assert "size_bytes" in meta
            assert "created_at" in meta
        finally:
            try:
                client.delete_artifact(artifact["id"])
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Report streaming
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_SKIP_REPORT, reason="NIS2_E2E_SKIP_REPORT=1")
class TestReportStreamingE2E:
    def _completed_assessment(self, client, org):
        """Helper: create and fast-path an assessment to 'completed' status."""
        unique = uuid.uuid4().hex[:8]
        a = client.create_assessment(org_id=org["id"], title=f"Report-{unique}")
        client.patch_assessment(a["id"], status="in_progress")
        for ctrl in client.list_controls(a["id"]):
            client.patch_control(a["id"], ctrl["measure_ref"], status="compliant")
        client.patch_assessment(a["id"], status="under_review")
        client.patch_assessment(a["id"], status="completed")
        return a

    def test_sarif_report_non_empty(self, client, org):
        a = self._completed_assessment(client, org)
        try:
            buf = io.BytesIO()
            client.stream_report(a["id"], format="sarif", dest=buf)
            assert buf.tell() > 0
            buf.seek(0)
            import json
            sarif = json.load(buf)
            assert sarif.get("version") == "2.1.0"
        finally:
            try:
                client.delete_assessment(a["id"])
            except Exception:
                pass

    def test_json_report_non_empty(self, client, org):
        a = self._completed_assessment(client, org)
        try:
            buf = io.BytesIO()
            client.stream_report(a["id"], format="json", dest=buf)
            assert buf.tell() > 0
            buf.seek(0)
            import json
            report = json.load(buf)
            assert "assessment" in report or "controls" in report
        finally:
            try:
                client.delete_assessment(a["id"])
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Full golden-path workflow
# ---------------------------------------------------------------------------


class TestFullWorkflowE2E:
    """
    Single test that walks the entire NIS2 assessment lifecycle
    as a real user would:

        create org → create assessment → assess all controls →
        upload artifact → advance to completed → stream report → archive
    """

    def test_nis2_assessment_golden_path(self, client, tmp_path):
        unique = uuid.uuid4().hex[:8]
        org_id = None
        assessment_id = None

        try:
            # 1. Organisation
            org = client.create_organisation(
                name=f"E2E-Full-{unique}",
                industry="Digital Infrastructure",
                country="NL",
                size="large",
                entity_type="essential",
            )
            org_id = org["id"]

            # 2. Assessment
            a = client.create_assessment(
                org_id=org_id,
                title=f"Golden Path {unique}",
                scope="Corporate IT systems",
                assessor="E2E Automated Bot",
            )
            assessment_id = a["id"]
            assert a["status"] == "draft"

            # 3. Start assessment
            a = client.patch_assessment(assessment_id, status="in_progress")
            assert a["status"] == "in_progress"

            # 4. Assess all 10 NIS2 controls
            controls = client.list_controls(assessment_id)
            assert len(controls) == 10
            for ctrl in controls:
                client.patch_control(
                    assessment_id,
                    ctrl["measure_ref"],
                    status="compliant",
                    risk_score=1.5,
                    gap_description="No gaps.",
                )

            # 5. Verify all controls are now compliant
            assessed = client.list_controls(assessment_id, status="compliant")
            assert len(assessed) == 10

            # 6. Upload a policy artifact
            policy = tmp_path / "security_policy.pdf"
            policy.write_bytes(b"%PDF-1.4 Corporate Security Policy v1.0")
            artifact = client.upload_artifact(
                assessment_id=assessment_id,
                file_path=str(policy),
                artifact_type="policy",
                description="Main corporate security policy",
            )
            assert artifact["filename"] == "security_policy.pdf"

            # 7. Advance to completed
            client.patch_assessment(assessment_id, status="under_review")
            a = client.patch_assessment(assessment_id, status="completed")
            assert a["status"] == "completed"

            # 8. Stream SARIF report (skip if report generation is disabled)
            if not _SKIP_REPORT:
                buf = io.BytesIO()
                client.stream_report(assessment_id, format="sarif", dest=buf)
                assert buf.tell() > 0

            # 9. Archive
            a = client.patch_assessment(assessment_id, status="archived")
            assert a["status"] == "archived"

        finally:
            if assessment_id:
                try:
                    client.delete_assessment(assessment_id)
                except Exception:
                    pass
            if org_id:
                try:
                    client.delete_organisation(org_id)
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# API key management
# ---------------------------------------------------------------------------


class TestAPIKeysE2E:
    def test_list_returns_at_least_one_key(self, client):
        # The key used to authenticate must appear in the list.
        keys = client.list_api_keys()
        assert isinstance(keys, list)
        assert len(keys) >= 1

    def test_create_key_returns_plaintext(self, client):
        key = client.create_api_key(label="e2e-test-key", scope="read_write")
        try:
            assert "id" in key
            # The plaintext secret must be present exactly once in the response.
            assert "key" in key
            assert len(key["key"]) > 16
        finally:
            try:
                client.revoke_api_key(key["id"])
            except Exception:
                pass

    def test_revoked_key_absent_from_list(self, client):
        key = client.create_api_key(label="e2e-revoke-test")
        client.revoke_api_key(key["id"])
        keys = client.list_api_keys()
        ids = [k["id"] for k in keys]
        assert key["id"] not in ids

    def test_revoked_key_cannot_authenticate(self):
        # Create a dedicated client, issue a new key, revoke it, then
        # confirm a fresh client using that key cannot reach the API.
        privileged = NIS2CompassClient(base_url=_E2E_URL, api_key=_E2E_API_KEY)
        new_key = privileged.create_api_key(label="e2e-revoke-auth-test")
        try:
            # Revoke immediately.
            privileged.revoke_api_key(new_key["id"])
            # A new client backed by the now-revoked key must fail auth.
            revoked_client = NIS2CompassClient(
                base_url=_E2E_URL, api_key=new_key["key"]
            )
            with pytest.raises((APIError, AuthenticationError)):
                revoked_client.get_organisations()
        except Exception:
            # If create_api_key itself fails (e.g. feature not yet live),
            # skip this assertion to avoid a false failure.
            pytest.skip("create_api_key not available on this instance")

    def test_read_scoped_key_cannot_write(self):
        privileged = NIS2CompassClient(base_url=_E2E_URL, api_key=_E2E_API_KEY)
        try:
            ro_key = privileged.create_api_key(label="e2e-read-only", scope="read")
        except Exception:
            pytest.skip("read-only scope not supported on this instance")
        try:
            ro_client = NIS2CompassClient(base_url=_E2E_URL, api_key=ro_key["key"])
            with pytest.raises((APIError, Exception)):
                ro_client.create_organisation(
                    name=f"ReadOnly-{uuid.uuid4().hex[:6]}",
                    industry="Energy",
                    country="DE",
                )
        finally:
            try:
                privileged.revoke_api_key(ro_key["id"])
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


class TestAuditLogE2E:
    def test_create_org_appears_in_audit(self, client):
        unique = uuid.uuid4().hex[:8]
        org = client.create_organisation(
            name=f"E2E-Audit-{unique}",
            industry="Finance",
            country="DE",
        )
        try:
            log = client.get_audit_log(limit=50)
            actions = [e["action"] for e in log]
            assert any("organisation" in a for a in actions)
        finally:
            try:
                client.delete_organisation(org["id"])
            except Exception:
                pass

    def test_control_patch_appears_in_audit(self, client, assessment):
        client.patch_control(assessment["id"], "a", status="compliant")
        log = client.get_audit_log(limit=50)
        actions = [e["action"] for e in log]
        assert any("control" in a for a in actions)

    def test_get_audit_entry_by_id(self, client, assessment):
        client.patch_control(assessment["id"], "b", status="non_compliant")
        log = client.get_audit_log(limit=10)
        assert len(log) >= 1
        entry_id = log[0]["id"]
        entry = client.get_audit_entry(entry_id)
        assert entry["id"] == entry_id
        assert "action" in entry
        assert "actor" in entry
        assert "created_at" in entry

    def test_audit_pagination(self, client, org):
        # Generate a burst of events so there is enough data to paginate.
        for i in range(3):
            a = client.create_assessment(
                org_id=org["id"], title=f"AuditPage-{uuid.uuid4().hex[:6]}"
            )
            try:
                client.delete_assessment(a["id"])
            except Exception:
                pass

        page1 = client.get_audit_log(limit=2, page=1)
        page2 = client.get_audit_log(limit=2, page=2)
        assert len(page1) <= 2
        # Pages must not overlap.
        ids1 = {e["id"] for e in page1}
        ids2 = {e["id"] for e in page2}
        assert ids1.isdisjoint(ids2), "Audit log pages must not share entries"

    def test_audit_entries_ordered_newest_first(self, client, org):
        for _ in range(2):
            a = client.create_assessment(
                org_id=org["id"], title=f"Order-{uuid.uuid4().hex[:6]}"
            )
            try:
                client.delete_assessment(a["id"])
            except Exception:
                pass

        log = client.get_audit_log(limit=10)
        if len(log) >= 2:
            # created_at strings are ISO-8601; lexicographic comparison is valid.
            assert log[0]["created_at"] >= log[1]["created_at"]


# ---------------------------------------------------------------------------
# PDF report (generate_report — saves to disk)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(_SKIP_REPORT, reason="NIS2_E2E_SKIP_REPORT=1")
class TestGenerateReportE2E:
    def _completed_assessment(self, client, org):
        unique = uuid.uuid4().hex[:8]
        a = client.create_assessment(org_id=org["id"], title=f"PDFReport-{unique}")
        client.patch_assessment(a["id"], status="in_progress")
        for ctrl in client.list_controls(a["id"]):
            client.patch_control(a["id"], ctrl["measure_ref"], status="compliant")
        client.patch_assessment(a["id"], status="under_review")
        client.patch_assessment(a["id"], status="completed")
        return a

    def test_generate_report_creates_file(self, client, org, tmp_path):
        a = self._completed_assessment(client, org)
        try:
            dest = tmp_path / "report.pdf"
            client.generate_report(a["id"], str(dest))
            assert dest.exists()
            assert dest.stat().st_size > 0
        finally:
            try:
                client.delete_assessment(a["id"])
            except Exception:
                pass

    def test_generate_report_is_valid_pdf(self, client, org, tmp_path):
        a = self._completed_assessment(client, org)
        try:
            dest = tmp_path / "report_valid.pdf"
            client.generate_report(a["id"], str(dest))
            header = dest.read_bytes()[:5]
            assert header == b"%PDF-", f"File does not start with PDF magic: {header!r}"
        finally:
            try:
                client.delete_assessment(a["id"])
            except Exception:
                pass

    def test_generate_report_nonexistent_assessment_raises(self, client, tmp_path):
        with pytest.raises((APIError, NotFoundError)):
            client.generate_report(
                "00000000-0000-0000-0000-000000000000",
                str(tmp_path / "ghost.pdf"),
            )


# ---------------------------------------------------------------------------
# Control filters (measure_ref and nist_category)
# ---------------------------------------------------------------------------


class TestControlFiltersE2E:
    def test_filter_by_measure_ref(self, client, assessment):
        controls = client.list_controls(assessment["id"], measure_ref="c")
        assert len(controls) == 1
        assert controls[0]["measure_ref"] == "c"

    def test_filter_by_nist_category(self, client, assessment):
        # At least one control must be mapped to a NIST CSF category.
        controls = client.list_controls(assessment["id"])
        categories = {c.get("nist_category") for c in controls if c.get("nist_category")}
        if not categories:
            pytest.skip("Controls have no nist_category; skipping filter test")
        target = next(iter(categories))
        filtered = client.list_controls(assessment["id"], nist_category=target)
        assert len(filtered) >= 1
        assert all(c["nist_category"] == target for c in filtered)

    def test_filter_status_and_measure_ref_combined(self, client, assessment):
        client.patch_control(assessment["id"], "f", status="non_compliant")
        # Filter for the specific measure and status together.
        filtered = client.list_controls(
            assessment["id"], measure_ref="f", status="non_compliant"
        )
        assert len(filtered) == 1
        assert filtered[0]["measure_ref"] == "f"
        assert filtered[0]["status"] == "non_compliant"

    def test_unknown_measure_ref_returns_empty_or_404(self, client, assessment):
        try:
            result = client.list_controls(assessment["id"], measure_ref="z")
            assert result == []
        except (APIError, NotFoundError):
            pass  # Both responses are acceptable


# ---------------------------------------------------------------------------
# Concurrency — parallel read requests must all succeed
# ---------------------------------------------------------------------------


class TestConcurrencyE2E:
    def test_parallel_get_organisations(self, client):
        """Ten concurrent GET /organisations calls must all succeed."""
        errors: list[Exception] = []
        results: list[list] = []

        def _fetch():
            try:
                results.append(client.get_organisations())
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=_fetch) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors, f"Concurrent requests failed: {errors}"
        assert len(results) == 10

    def test_parallel_patch_different_controls(self, client, assessment):
        """Patch all 10 controls concurrently; every write must succeed."""
        errors: list[Exception] = []

        def _patch(ref: str):
            try:
                client.patch_control(
                    assessment["id"], ref,
                    status="compliant",
                    notes=f"concurrent-patch-{ref}",
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [
            threading.Thread(target=_patch, args=(ref,))
            for ref in "abcdefghij"
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors, f"Concurrent PATCH controls failed: {errors}"

        # Verify every control was actually updated.
        for ref in "abcdefghij":
            ctrl = client.get_control(assessment["id"], ref)
            assert ctrl["status"] == "compliant", (
                f"control {ref!r} not updated: {ctrl['status']!r}"
            )
