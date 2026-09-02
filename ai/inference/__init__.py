"""
Inference entry point for the backend.

    from ai.inference import forecast
    response = forecast(request_dict)            # dict -> dict, both validated against
                                                 # docs/api/feature_schema_contract.json

`forecast` routes to the trained model when one is registered and otherwise to the
rule-based fallback. Both return the same InferenceResponse shape. See
docs/api/ml-inference-contract.md for the full contract and failure behaviour.
"""

from ai.inference.contract import (
    ALLOWED_HORIZONS_SEC,
    ATTACK_TYPES,
    DEFAULT_ALERT_THRESHOLD,
    DEFAULT_HORIZON_SEC,
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    LOW_CONFIDENCE_THRESHOLD,
    RISK_LEVELS,
    InferenceError,
    risk_level_for,
    stage_for,
    validate_features,
)
from ai.inference.fallback import FALLBACK_MODEL_VERSION, rule_based_forecast

__all__ = [
    "ALLOWED_HORIZONS_SEC",
    "ATTACK_TYPES",
    "DEFAULT_ALERT_THRESHOLD",
    "DEFAULT_HORIZON_SEC",
    "FALLBACK_MODEL_VERSION",
    "FEATURE_NAMES",
    "FEATURE_SCHEMA_VERSION",
    "InferenceError",
    "LOW_CONFIDENCE_THRESHOLD",
    "RISK_LEVELS",
    "forecast",
    "risk_level_for",
    "rule_based_forecast",
    "stage_for",
    "validate_features",
]

_MODEL = None  # populated by ai.inference.model.load_active_model() once a trained artifact exists


def forecast(request: dict) -> dict:
    """
    Produce an InferenceResponse for one InferenceRequest.

    Raises InferenceError (with .code) for FEATURE_SCHEMA_MISMATCH and INVALID_FEATURES.
    Never raises for model problems: those fall back to the rule-based scorer and the
    response carries ``is_fallback: true``.
    """
    if _MODEL is None:
        return rule_based_forecast(request)
    try:
        return _MODEL.predict(request)
    except InferenceError:
        raise
    except Exception:  # noqa: BLE001 - any model failure degrades to the fallback
        return rule_based_forecast(request, fallback_reason="MODEL_ERROR")
