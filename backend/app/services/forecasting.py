"""
Forecast orchestration: trained world model first, rule-based fallback always.

The dashboard must never be blocked by a missing or broken model artifact. This module
owns that policy so the routes stay thin:

* trained checkpoint present and healthy -> world-model forecast
* checkpoint missing, dependencies absent, or inference raises -> rule-based forecast
  with ``is_fallback`` set and a ``fallback_reason`` from the contract's error codes

Both paths return the same shape, defined by `docs/api/ml-inference-contract.md`.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.network import (
    HostEntity,
    ModelVersion,
    RawFlow,
    TrafficWindow,
    WindowFeature,
    WindowScope,
)

logger = logging.getLogger(__name__)

FORECAST_STEPS = 5
FALLBACK_MODEL_NAME = "rule-fallback"
FALLBACK_MODEL_VERSION = "rule-fallback-v1.0.0"
WORLD_MODEL_NAME = "world-model"


class NotEnoughWindows(Exception):
    """Raised when a source has fewer feature windows than the model's history length."""

    def __init__(self, available: int, required: int):
        super().__init__(f"Need {required} feature windows; only {available} are available")
        self.available = available
        self.required = required


@dataclass
class ForecastOutcome:
    payload: dict[str, Any]
    observation: TrafficWindow
    risk_score: float
    risk_level: str
    stage: str | None
    attack_type: str
    confidence: float
    is_fallback: bool
    fallback_reason: str | None
    is_uncertain: bool
    is_ood: bool
    model_name: str
    model_version: str


def feature_rows(db: Session, source_id: UUID) -> list[tuple[TrafficWindow, WindowFeature]]:
    """Every window of a source that has an extracted feature vector, oldest first."""
    return list(
        db.execute(
            select(TrafficWindow, WindowFeature)
            .join(WindowFeature, WindowFeature.traffic_window_id == TrafficWindow.id)
            .where(
                TrafficWindow.traffic_source_id == source_id,
                TrafficWindow.scope_type == WindowScope.SOURCE,
            )
            .order_by(TrafficWindow.window_start)
        ).all()
    )


def checkpoint_available() -> bool:
    return bool(settings.world_model_checkpoint and Path(settings.world_model_checkpoint).is_file())


def _artifact_version(path: Path) -> str:
    """Short content hash, so a prediction records which exact artifact produced it."""
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return f"sha256:{digest[:16]}"


def register_model_version(
    db: Session, *, name: str, version: str, artifact_uri: str, metrics: dict[str, Any] | None = None
) -> ModelVersion:
    """Find or create the `model_versions` row for an artifact. Idempotent."""
    from ai.inference.contract import FEATURE_SCHEMA_VERSION

    existing = db.scalar(select(ModelVersion).where(ModelVersion.name == name, ModelVersion.version == version))
    if existing is not None:
        return existing
    record = ModelVersion(
        name=name,
        version=version,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        artifact_uri=artifact_uri,
        metrics_json=metrics or {},
        is_active=True,
    )
    db.add(record)
    db.flush()
    return record


def _world_model_forecast(history: list[dict[str, float]]) -> tuple[dict[str, Any], str]:
    """Run the trained checkpoint. Raises on any problem so the caller can fall back."""
    from ai.inference.forecast_engine import forecast as run_forecast, load_model

    path = Path(settings.world_model_checkpoint)
    model, checkpoint = load_model(path)
    required = checkpoint["seq_len"]
    if len(history) < required:
        raise NotEnoughWindows(len(history), required)
    payload = run_forecast(model, checkpoint, history[-required:], FORECAST_STEPS)
    return payload, _artifact_version(path)


def _fallback_forecast(window_id: str, features: dict[str, float], timestamp: str, reason: str) -> dict[str, Any]:
    """Score the newest window with the dependency-free precursor rules."""
    from ai.inference import rule_based_forecast
    from ai.inference.mitre_attack_map import candidates_for_stage
    from ai.inference.contract import DEFAULT_HORIZON_SEC

    response = rule_based_forecast(
        {
            "window_id": window_id,
            "timestamp": timestamp,
            "features": features,
            "requested_horizon_sec": DEFAULT_HORIZON_SEC,
        },
        fallback_reason=reason,
    )
    # Present the single rule-based score on the same five-step timeline the UI draws, so
    # the dashboard needs no special case. The rules have no per-minute dynamics, so the
    # score is flat and the UI labels it as a fallback.
    risk = response["risk_score"] / 100.0
    stage_by_type = {
        "BENIGN": "Benign",
        "Reconnaissance": "Reconnaissance",
        "BruteForce": "Initial Access",
        "DDoS": "Impact",
        "DoS": "Impact",
    }
    stage = stage_by_type.get(response["predicted_attack_type"], "Benign")
    return {
        "risk_timeline": [
            {"step": step + 1, "risk_score": risk, "stage": stage, "stage_confidence": response["confidence_score"]}
            for step in range(FORECAST_STEPS)
        ],
        "peak_risk_level": response["risk_level"],
        "peak_risk_window": 1,
        "peak_risk_stage": stage,
        "predicted_attack_type": response["predicted_attack_type"],
        "attack_candidates": candidates_for_stage(stage),
        "confidence_score": response["confidence_score"],
        "is_uncertain": response["is_uncertain"],
        "is_ood": False,  # The rules have no training distribution to compare against.
        "ood_features": [],
        "top_feature_contributors": [
            {"feature": item["feature"], "contribution": item["contribution"], "description": item["description"]}
            for item in response["explanation_json"]["top_features"]
        ],
        "explanation_summary": response["explanation_json"]["summary"],
        "mitigation_recommendation": response["explanation_json"].get("mitigation_recommendation"),
    }


def run_forecast(db: Session, source_id: UUID) -> ForecastOutcome:
    """
    Forecast the next five minutes for one traffic source.

    Raises NotEnoughWindows only when even the fallback cannot run, which means the source
    has no feature windows at all.
    """
    rows = feature_rows(db, source_id)
    if not rows:
        raise NotEnoughWindows(0, 1)

    observation, newest = rows[-1][0], rows[-1][1]
    history = [features.features_json for _, features in rows]
    timestamp = observation.window_end.isoformat()

    payload: dict[str, Any] | None = None
    fallback_reason: str | None = None
    model_name, model_version = WORLD_MODEL_NAME, ""

    if not checkpoint_available():
        fallback_reason = "MODEL_UNAVAILABLE"
    else:
        try:
            payload, model_version = _world_model_forecast(history)
        except NotEnoughWindows:
            # A short source is a real condition, not a model failure: the rules can still
            # score the newest window, so degrade rather than refuse.
            fallback_reason = "MODEL_UNAVAILABLE"
        except ImportError:
            fallback_reason = "MODEL_UNAVAILABLE"
        except Exception:  # noqa: BLE001 - any inference failure degrades, never 500s
            logger.exception("World-model inference failed for source %s", source_id)
            fallback_reason = "INTERNAL_ERROR"

    if payload is None:
        payload = _fallback_forecast(str(observation.id), newest.features_json, timestamp, fallback_reason or "MODEL_UNAVAILABLE")
        model_name, model_version = FALLBACK_MODEL_NAME, FALLBACK_MODEL_VERSION

    payload["observed_until"] = timestamp
    payload["is_fallback"] = fallback_reason is not None
    payload["fallback_reason"] = fallback_reason
    payload["model_name"] = model_name
    payload["model_version"] = model_version
    payload["window_count"] = len(rows)

    risks = [float(point["risk_score"]) for point in payload["risk_timeline"]]
    return ForecastOutcome(
        payload=payload,
        observation=observation,
        risk_score=round(max(risks) * 100, 2),
        risk_level=payload["peak_risk_level"],
        stage=payload.get("peak_risk_stage"),
        attack_type=payload.get("predicted_attack_type", "UNKNOWN"),
        confidence=float(payload["confidence_score"]),
        is_fallback=fallback_reason is not None,
        fallback_reason=fallback_reason,
        is_uncertain=bool(payload["is_uncertain"]),
        is_ood=bool(payload["is_ood"]),
        model_name=model_name,
        model_version=model_version,
    )


def top_destinations(db: Session, source_id: UUID, window: TrafficWindow | None, limit: int = 5) -> list[dict]:
    """Observable destination evidence. Not a claim that any destination is malicious."""
    if window is None:
        return []
    rows = db.execute(
        select(
            RawFlow.dst_ip,
            RawFlow.dst_port,
            RawFlow.protocol,
            func.count(RawFlow.id).label("flows"),
            func.sum(RawFlow.packet_count).label("packets"),
            func.sum(RawFlow.byte_count).label("bytes"),
        )
        .where(
            RawFlow.traffic_source_id == source_id,
            RawFlow.observed_at >= window.window_start,
            RawFlow.observed_at < window.window_end,
        )
        .group_by(RawFlow.dst_ip, RawFlow.dst_port, RawFlow.protocol)
        .order_by(func.sum(RawFlow.byte_count).desc())
        .limit(limit)
    ).all()
    return [
        {
            "destination_ip": ip,
            "destination_port": port,
            "protocol": protocol,
            "flows": int(flows),
            "packets": int(packets or 0),
            "bytes": int(byte_total or 0),
        }
        for ip, port, protocol, flows, packets, byte_total in rows
    ]


def upsert_host(db: Session, source_id: UUID, ip_address: str | None, seen_at: datetime) -> HostEntity | None:
    """
    Find or create the `host_entities` row for an address seen in a source's traffic,
    refreshing ``last_seen_at``. Hosts are scoped per source by a unique constraint.
    """
    if not ip_address:
        return None
    existing = db.scalar(
        select(HostEntity).where(HostEntity.traffic_source_id == source_id, HostEntity.ip_address == ip_address)
    )
    if existing is not None:
        if seen_at > existing.last_seen_at:
            existing.last_seen_at = seen_at
        return existing
    try:
        entity_type = "internal" if ipaddress.ip_address(ip_address).is_private else "external"
    except ValueError:
        entity_type = "unknown"
    host = HostEntity(
        traffic_source_id=source_id,
        ip_address=ip_address,
        entity_type=entity_type,
        first_seen_at=seen_at,
        last_seen_at=seen_at,
    )
    db.add(host)
    db.flush()
    return host


def busiest_destination_ip(db: Session, source_id: UUID, window: TrafficWindow | None) -> str | None:
    destinations = top_destinations(db, source_id, window, limit=1)
    return destinations[0]["destination_ip"] if destinations else None


def forecast_horizon_end(observation: TrafficWindow, steps: int = FORECAST_STEPS):
    return observation.window_end + timedelta(minutes=steps)
