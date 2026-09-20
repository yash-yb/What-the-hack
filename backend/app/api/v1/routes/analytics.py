"""Read-only dashboard data, and the forecast endpoints that drive the demo."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import require_analyst, require_viewer
from app.db.session import get_db
from app.models.network import Alert, AlertSeverity, AlertStatus, AuditLog, Prediction, RiskLevel, User
from app.services import forecasting

router = APIRouter(prefix="/analytics")

RECOMMENDED_ACTIONS = {
    "Reconnaissance": [
        "Confirm which services are exposed on the probed destination ports.",
        "Rate-limit or temporarily block the scanning source range.",
        "Raise logging verbosity on the targeted hosts.",
    ],
    "Initial Access": [
        "Review failed authentication bursts on the targeted service.",
        "Enable account lockout or exponential back-off.",
        "Check for any successful login from the offending source.",
    ],
    "Lateral Movement": [
        "Isolate the affected host and inspect east-west traffic.",
        "Review authentication events for reused credentials.",
        "Hunt for remote-execution and scheduled-task activity.",
    ],
    "Command & Control": [
        "Inspect the destination for low-jitter beaconing behaviour.",
        "Correlate with DNS and TLS SNI records for the same host.",
        "Contain the endpoint before it receives further instructions.",
    ],
    "Impact": [
        "Enable TCP SYN cookies and pre-stage upstream rate limiting.",
        "Check egress volume against the host's normal baseline.",
        "Prepare to fail over or shed load on the targeted service.",
    ],
    "Benign": ["No action required. Continue monitoring."],
}

UNCERTAIN_ACTION = "Treat this as a lead, not a verdict: the model reports low confidence, so corroborate with endpoint and identity evidence first."
OOD_ACTION = "This traffic is unlike the model's training baseline, so a false positive is likely. Validate manually before acting."


def _actions(stage: str | None, outcome: forecasting.ForecastOutcome) -> list[str]:
    actions = list(RECOMMENDED_ACTIONS.get(stage or "Benign", RECOMMENDED_ACTIONS["Benign"]))
    if outcome.is_ood:
        actions.insert(0, OOD_ACTION)
    if outcome.is_uncertain:
        actions.insert(0, UNCERTAIN_ACTION)
    if outcome.is_fallback:
        actions.insert(0, "This forecast came from the rule-based fallback, not the trained model. Check that the model artifact is mounted.")
    return actions


@router.get("/overview")
def overview(
    traffic_source_id: UUID = Query(...), user: User = Depends(require_viewer), db: Session = Depends(get_db)
) -> dict:
    rows = forecasting.feature_rows(db, traffic_source_id)
    latest_window = rows[-1][0] if rows else None
    return {
        "traffic_source_id": str(traffic_source_id),
        "window_count": len(rows),
        "model_ready": forecasting.checkpoint_available(),
        "traffic": [
            {"timestamp": window.window_end.isoformat(), "packets": window.packet_count, "bytes": window.byte_count, "flows": window.flow_count}
            for window, _ in rows
        ],
        "latest_features": rows[-1][1].features_json if rows else None,
        "latest_destinations": forecasting.top_destinations(db, traffic_source_id, latest_window),
    }


@router.get("/forecast")
def forecast(
    traffic_source_id: UUID = Query(...), user: User = Depends(require_viewer), db: Session = Depends(get_db)
) -> dict:
    """
    Forecast the next five minutes.

    Never fails because of the model: a missing artifact or an inference error degrades to
    the rule-based fallback and sets ``is_fallback``. The only 422 is a source with no
    feature windows at all, which means nothing has been ingested yet.
    """
    try:
        return forecasting.run_forecast(db, traffic_source_id).payload
    except forecasting.NotEnoughWindows as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"This source has no feature windows yet. Upload traffic first. ({exc})",
        ) from exc


@router.post("/forecast")
def create_forecast(
    traffic_source_id: UUID = Query(...), user: User = Depends(require_analyst), db: Session = Depends(get_db)
) -> dict:
    """Run a forecast and save it as an analyst-visible investigation alert."""
    try:
        outcome = forecasting.run_forecast(db, traffic_source_id)
    except forecasting.NotEnoughWindows as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"This source has no feature windows yet. Upload traffic first. ({exc})",
        ) from exc

    model_version = forecasting.register_model_version(
        db,
        name=outcome.model_name,
        version=outcome.model_version,
        artifact_uri=str(forecasting.settings.world_model_checkpoint) if not outcome.is_fallback else "builtin:ai.inference.fallback",
    )
    host = forecasting.upsert_host(
        db,
        traffic_source_id,
        forecasting.busiest_destination_ip(db, traffic_source_id, outcome.observation),
        outcome.observation.window_end,
    )

    prediction = Prediction(
        observation_window_id=outcome.observation.id,
        model_version_id=model_version.id,
        forecast_window_start=outcome.observation.window_end,
        forecast_window_end=forecasting.forecast_horizon_end(outcome.observation),
        risk_score=outcome.risk_score,
        risk_level=RiskLevel(outcome.risk_level),
        predicted_attack_type=outcome.attack_type,
        predicted_stage=outcome.stage,
        confidence_score=outcome.confidence,
        is_fallback=outcome.is_fallback,
        is_uncertain=outcome.is_uncertain,
        is_ood=outcome.is_ood,
        explanation_json=outcome.payload.get("top_feature_contributors", []),
    )
    db.add(prediction)
    db.flush()

    # An uncertain forecast never presents as critical, however high the raw score.
    severity = AlertSeverity(outcome.risk_level)
    if outcome.is_uncertain and severity is AlertSeverity.CRITICAL:
        severity = AlertSeverity.HIGH

    qualifier = " (low confidence)" if outcome.is_uncertain else ""
    alert = Alert(
        prediction_id=prediction.id,
        target_host_id=host.id if host else None,
        title=f"Forecasted {outcome.stage or 'network'} risk{qualifier}",
        summary=(
            f"The model forecasts {outcome.risk_level} risk ({outcome.risk_score:.0f}/100) "
            f"in the next {forecasting.FORECAST_STEPS} minutes."
        ),
        severity=severity,
        status=AlertStatus.OPEN,
        recommended_actions_json=_actions(outcome.stage, outcome),
    )
    db.add(alert)
    db.flush()
    db.add(
        AuditLog(
            actor_user_id=user.id,
            action="alert.created",
            resource_type="alert",
            resource_id=alert.id,
            metadata_json={
                "risk_score": outcome.risk_score,
                "model": f"{outcome.model_name}@{outcome.model_version}",
                "is_fallback": outcome.is_fallback,
            },
        )
    )
    db.commit()
    db.refresh(alert)
    return {"alert_id": str(alert.id), "prediction_id": str(prediction.id), "forecast": outcome.payload}
