import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas.inference import InferenceRequest, InferenceResponse, WindowFeaturesV1, risk_level_for

CONTRACT_PATH = Path(__file__).resolve().parents[2] / "docs" / "api" / "feature_schema_contract.json"
CONTRACT = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def sample_features() -> dict:
    values = {name: 0.5 for name in CONTRACT["definitions"]["WindowFeatures"]["required"]}
    for name, prop in CONTRACT["definitions"]["WindowFeatures"]["properties"].items():
        if prop["type"] == "integer":
            values[name] = 3
    values["flow_count"] = 12
    return values


def test_pydantic_fields_match_contract_feature_list() -> None:
    assert list(WindowFeaturesV1.model_fields) == CONTRACT["definitions"]["WindowFeatures"]["required"]


def test_pydantic_bounds_match_contract() -> None:
    props = CONTRACT["definitions"]["WindowFeatures"]["properties"]
    for name, field in WindowFeaturesV1.model_fields.items():
        bounds = {type(m).__name__: getattr(m, "ge", getattr(m, "le", None)) for m in field.metadata}
        assert bounds.get("Ge") == props[name].get("minimum"), name
        assert bounds.get("Le") == props[name].get("maximum"), name


def test_request_rejects_out_of_range_and_extra_features() -> None:
    good = InferenceRequest(window_id="win-1", timestamp="2026-08-28T18:00:00Z", features=sample_features())
    assert good.requested_horizon_sec == 300
    with pytest.raises(ValidationError):
        InferenceRequest(window_id="win-1", timestamp="t", features=dict(sample_features(), syn_ratio=1.5))
    with pytest.raises(ValidationError):
        InferenceRequest(window_id="win-1", timestamp="t", features=dict(sample_features(), extra=1))
    with pytest.raises(ValidationError):
        InferenceRequest(window_id="win-1", timestamp="t", features=sample_features(), requested_horizon_sec=90)


def test_fallback_response_passes_backend_validation() -> None:
    ai_inference = pytest.importorskip("ai.inference")
    response = ai_inference.forecast(
        {"window_id": "win-1", "timestamp": "2026-08-28T18:00:00Z", "features": sample_features(), "requested_horizon_sec": 120}
    )
    parsed = InferenceResponse.model_validate(response)
    assert parsed.is_fallback is True
    assert parsed.risk_level == risk_level_for(parsed.risk_score)


def test_risk_bands() -> None:
    assert [risk_level_for(v) for v in (0, 19.9, 20, 49.9, 50, 74.9, 75, 100)] == [
        "low", "low", "medium", "medium", "high", "high", "critical", "critical",
    ]
