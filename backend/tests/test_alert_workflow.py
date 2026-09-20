"""
End-to-end analyst workflow over HTTP: upload, forecast, save an alert, then triage it.

These run without a trained checkpoint, which is deliberate. The dashboard must degrade to
the rule-based fallback rather than fail, so the whole demo path is exercised here with
``is_fallback`` set.
"""

import pytest
from sqlalchemy import select

from app.models.network import AuditLog, ModelVersion
from tests.conftest import SAMPLE_CSV, bearer, login


@pytest.fixture()
def source_id(client, seeded_users) -> str:
    """Upload the bundled sample so the source has feature windows."""
    admin = login(client, "admin@what-the-hack.local", seeded_users["admin@what-the-hack.local"])
    created = client.post(
        "/api/v1/ingestion/upload",
        headers=bearer(admin["access_token"]),
        data={"source_name": "workflow-test"},
        files={"file": ("sample.csv", SAMPLE_CSV.read_bytes(), "text/csv")},
    )
    assert created.status_code == 201, created.text
    return created.json()["traffic_source_id"]


@pytest.fixture()
def analyst_token(client, seeded_users) -> str:
    return login(client, "analyst@what-the-hack.local", seeded_users["analyst@what-the-hack.local"])["access_token"]


def save_alert(client, token: str, source_id: str) -> dict:
    response = client.post("/api/v1/analytics/forecast", params={"traffic_source_id": source_id}, headers=bearer(token))
    assert response.status_code == 200, response.text
    return response.json()


def test_forecast_falls_back_instead_of_failing_without_a_checkpoint(client, analyst_token, source_id) -> None:
    response = client.get("/api/v1/analytics/forecast", params={"traffic_source_id": source_id}, headers=bearer(analyst_token))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["is_fallback"] is True
    assert body["fallback_reason"] == "MODEL_UNAVAILABLE"
    assert body["model_name"] == "rule-fallback"
    assert len(body["risk_timeline"]) == 5
    assert 0.0 <= body["confidence_score"] <= 1.0
    assert body["top_feature_contributors"]
    assert "attack_candidates" in body


def test_forecast_on_an_empty_source_is_422_not_500(client, analyst_token) -> None:
    empty = "00000000-0000-0000-0000-000000000000"
    response = client.get("/api/v1/analytics/forecast", params={"traffic_source_id": empty}, headers=bearer(analyst_token))
    assert response.status_code == 422
    assert "no feature windows" in response.json()["detail"]


def test_saved_alert_records_provenance(client, analyst_token, source_id, session_factory) -> None:
    saved = save_alert(client, analyst_token, source_id)
    detail = client.get(f"/api/v1/alerts/{saved['alert_id']}", headers=bearer(analyst_token))
    assert detail.status_code == 200, detail.text
    body = detail.json()

    assert body["status"] == "open"
    assert body["is_fallback"] is True
    assert body["predicted_stage"] is not None
    assert body["predicted_attack_type"] is not None
    assert body["recommended_actions"]
    assert body["target_host"]["ip_address"]          # populated from the busiest destination
    assert body["forecast_window_end"] > body["forecast_window_start"]

    # The prediction must name the model that produced it.
    with session_factory() as db:
        versions = list(db.scalars(select(ModelVersion.version)))
        assert versions == ["rule-fallback-v1.0.0"]


def test_attack_type_stays_inside_the_contract_enum(client, analyst_token, source_id) -> None:
    from ai.inference.contract import ATTACK_TYPES, MITRE_STAGES

    saved = save_alert(client, analyst_token, source_id)
    body = client.get(f"/api/v1/alerts/{saved['alert_id']}", headers=bearer(analyst_token)).json()
    assert body["predicted_attack_type"] in ATTACK_TYPES
    assert body["predicted_stage"] in MITRE_STAGES


def test_full_triage_workflow_with_timeline_and_audit(client, analyst_token, source_id, session_factory) -> None:
    alert_id = save_alert(client, analyst_token, source_id)["alert_id"]
    headers = bearer(analyst_token)

    for target in ("acknowledged", "investigating", "resolved"):
        response = client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": target, "note": f"moving to {target}"}, headers=headers)
        assert response.status_code == 200, response.text
        assert response.json()["status"] == target

    body = client.get(f"/api/v1/alerts/{alert_id}", headers=headers).json()
    assert body["resolved_at"] is not None
    assert [event["to_status"] for event in body["events"]] == ["acknowledged", "investigating", "resolved"]
    assert body["events"][0]["note"] == "moving to acknowledged"

    with session_factory() as db:
        actions = list(db.scalars(select(AuditLog.action)))
        assert actions.count("alert.status_changed") == 3
        assert "alert.created" in actions


def test_invalid_transition_is_rejected_with_guidance(client, analyst_token, source_id) -> None:
    alert_id = save_alert(client, analyst_token, source_id)["alert_id"]
    headers = bearer(analyst_token)
    client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "resolved"}, headers=headers)

    blocked = client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "open"}, headers=headers)
    assert blocked.status_code == 409
    detail = blocked.json()["detail"]
    assert detail["current_status"] == "resolved"
    assert detail["allowed"] == ["investigating"]

    # Reopening for further investigation is allowed, and clears resolved_at.
    reopened = client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "investigating"}, headers=headers)
    assert reopened.status_code == 200
    assert reopened.json()["resolved_at"] is None


def test_repeating_the_current_status_is_rejected(client, analyst_token, source_id) -> None:
    alert_id = save_alert(client, analyst_token, source_id)["alert_id"]
    response = client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "open"}, headers=bearer(analyst_token))
    assert response.status_code == 409


def test_viewer_can_read_but_not_triage(client, analyst_token, seeded_users, source_id) -> None:
    alert_id = save_alert(client, analyst_token, source_id)["alert_id"]
    viewer = login(client, "viewer@what-the-hack.local", seeded_users["viewer@what-the-hack.local"])["access_token"]

    assert client.get("/api/v1/alerts", headers=bearer(viewer)).status_code == 200
    assert client.get(f"/api/v1/alerts/{alert_id}", headers=bearer(viewer)).status_code == 200
    assert client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "acknowledged"}, headers=bearer(viewer)).status_code == 403
    assert client.post(f"/api/v1/alerts/{alert_id}/notes", json={"note": "hi"}, headers=bearer(viewer)).status_code == 403


def test_notes_append_to_the_timeline_without_changing_status(client, analyst_token, source_id) -> None:
    alert_id = save_alert(client, analyst_token, source_id)["alert_id"]
    headers = bearer(analyst_token)
    created = client.post(f"/api/v1/alerts/{alert_id}/notes", json={"note": "Checked the destination, it is our mirror."}, headers=headers)
    assert created.status_code == 201
    assert created.json()["event_type"] == "comment"

    body = client.get(f"/api/v1/alerts/{alert_id}", headers=headers).json()
    assert body["status"] == "open"
    assert [event["event_type"] for event in body["events"]] == ["comment"]


def test_alert_list_filters_and_paginates(client, analyst_token, source_id) -> None:
    headers = bearer(analyst_token)
    first = save_alert(client, analyst_token, source_id)["alert_id"]
    save_alert(client, analyst_token, source_id)
    save_alert(client, analyst_token, source_id)
    client.patch(f"/api/v1/alerts/{first}/status", json={"status": "acknowledged"}, headers=headers)

    everything = client.get("/api/v1/alerts", headers=headers).json()
    assert len(everything["items"]) == 3
    assert everything["next_cursor"] is None

    open_only = client.get("/api/v1/alerts", params={"status": "open"}, headers=headers).json()
    assert len(open_only["items"]) == 2
    assert all(item["status"] == "open" for item in open_only["items"])

    acknowledged = client.get("/api/v1/alerts", params={"status": "acknowledged"}, headers=headers).json()
    assert [item["id"] for item in acknowledged["items"]] == [first]

    severity = everything["items"][0]["severity"]
    filtered = client.get("/api/v1/alerts", params={"severity": severity}, headers=headers).json()
    assert all(item["severity"] == severity for item in filtered["items"])

    page = client.get("/api/v1/alerts", params={"limit": 2}, headers=headers).json()
    assert len(page["items"]) == 2
    assert page["next_cursor"] is not None


def test_unknown_alert_is_404(client, analyst_token) -> None:
    missing = "11111111-1111-1111-1111-111111111111"
    assert client.get(f"/api/v1/alerts/{missing}", headers=bearer(analyst_token)).status_code == 404
    assert client.patch(f"/api/v1/alerts/{missing}/status", json={"status": "acknowledged"}, headers=bearer(analyst_token)).status_code == 404


def test_system_overview_is_admin_only_and_reports_real_state(client, seeded_users, source_id, analyst_token) -> None:
    save_alert(client, analyst_token, source_id)
    admin = login(client, "admin@what-the-hack.local", seeded_users["admin@what-the-hack.local"])["access_token"]

    assert client.get("/api/v1/system/overview", headers=bearer(analyst_token)).status_code == 403
    assert client.get("/api/v1/system/audit", headers=bearer(analyst_token)).status_code == 403

    body = client.get("/api/v1/system/overview", headers=bearer(admin)).json()
    assert body["counts"]["users"] == 3
    assert body["counts"]["alerts"] == 1
    assert body["counts"]["raw_flows"] == 120
    assert body["alerts_by_status"]["open"] == 1
    assert body["fallback_predictions"] == 1
    assert {account["role"] for account in body["users"]} == {"admin", "analyst", "viewer"}
    assert [model["name"] for model in body["models"]] == ["rule-fallback"]
    assert body["configuration"]["checkpoint_present"] is False


def test_audit_trail_records_the_whole_session(client, seeded_users, source_id, analyst_token) -> None:
    alert_id = save_alert(client, analyst_token, source_id)["alert_id"]
    client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "acknowledged"}, headers=bearer(analyst_token))
    admin = login(client, "admin@what-the-hack.local", seeded_users["admin@what-the-hack.local"])["access_token"]

    items = client.get("/api/v1/system/audit", headers=bearer(admin)).json()["items"]
    actions = [entry["action"] for entry in items]
    for expected in ("auth.login", "ingestion.upload", "alert.created", "alert.status_changed"):
        assert expected in actions, f"{expected} missing from {actions}"
    # Newest first, and the actor is resolved to an email.
    assert items[0]["created_at"] >= items[-1]["created_at"]
    assert any(entry["actor_email"] for entry in items)
