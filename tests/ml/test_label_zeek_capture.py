import csv
import json

import pytest

from ai.datasets.label_zeek_capture import convert, read_timeline


def zeek_record(timestamp: float) -> dict:
    return {"ts": timestamp, "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2", "id.orig_p": 50000,
            "id.resp_p": 22, "proto": "tcp", "orig_pkts": 2, "resp_pkts": 1, "orig_bytes": 100,
            "resp_bytes": 80, "duration": 0.1, "history": "ShAD", "conn_state": "SF"}


def test_converter_requires_reviewed_coverage_unless_explicitly_benign(tmp_path):
    log = tmp_path / "conn.log"
    log.write_text(json.dumps(zeek_record(1_700_000_000)) + "\n" + json.dumps(zeek_record(1_700_000_120)) + "\n")
    timeline = tmp_path / "labels.csv"
    timeline.write_text("start,end,label\n2023-11-14T22:13:00Z,2023-11-14T22:14:00Z,SSH-Patator\n")
    output = tmp_path / "training.csv"

    accepted, uncovered = convert(log, timeline, output, assume_uncovered_benign=False)
    assert (accepted, uncovered) == (1, 1)
    assert list(csv.DictReader(output.open()))[0]["label"] == "SSH_Patator"

    accepted, uncovered = convert(log, timeline, output, assume_uncovered_benign=True)
    assert (accepted, uncovered) == (2, 0)
    assert {row["label"] for row in csv.DictReader(output.open())} == {"SSH_Patator", "BENIGN"}


def test_converter_rejects_unknown_labels(tmp_path):
    timeline = tmp_path / "labels.csv"
    timeline.write_text("start,end,label\n2023-11-14T22:13:00Z,2023-11-14T22:14:00Z,definitely-an-attack\n")
    with pytest.raises(ValueError, match="Unsupported label"):
        read_timeline(timeline)
