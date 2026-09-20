"""Create a training CSV from authorised Zeek JSON logs and a reviewed label timeline.

Zeek records do not contain ground-truth attack labels. This tool deliberately requires a
separate CSV of reviewed exercise/incident intervals instead of inferring labels from the
traffic it is about to train on.

Timeline CSV columns: ``start,end,label``. Times must be ISO-8601 with a timezone. Intervals
are [start, end); earlier rows win when intervals overlap. Uncovered connections become
``BENIGN`` only when ``--assume-uncovered-benign`` is explicitly supplied.
"""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ai.datasets.download_cicids2017 import LABEL_MAPPING
from ai.ingestion.zeek_live_adapter import zeek_record_to_flow


@dataclass(frozen=True)
class LabelInterval:
    start: datetime
    end: datetime
    label: str


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def canonical_label(value: str) -> str:
    cleaned = value.strip()
    # Case-insensitive fallback keeps human-authored label timelines convenient while
    # retaining the project's finite, documented training taxonomy.
    matches = {key.lower(): mapped for key, mapped in LABEL_MAPPING.items()}
    label = LABEL_MAPPING.get(cleaned, matches.get(cleaned.lower()))
    if label is None:
        raise ValueError(f"Unsupported label {value!r}; use a documented canonical CICIDS label.")
    return label


def read_timeline(path: str | Path) -> list[LabelInterval]:
    with Path(path).open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if set(reader.fieldnames or []) != {"start", "end", "label"}:
            raise ValueError("Timeline must contain exactly start,end,label columns.")
        result = [LabelInterval(parse_time(row["start"]), parse_time(row["end"]), canonical_label(row["label"])) for row in reader]
    if not result:
        raise ValueError("Timeline is empty.")
    if any(item.end <= item.start for item in result):
        raise ValueError("Every timeline interval must end after it starts.")
    return sorted(result, key=lambda item: item.start)


def label_for(observed_at: datetime, timeline: list[LabelInterval], assume_uncovered_benign: bool) -> str | None:
    for item in timeline:
        if item.start <= observed_at < item.end:
            return item.label
    return "BENIGN" if assume_uncovered_benign else None


def convert(log_path: str | Path, timeline_path: str | Path, output_path: str | Path, assume_uncovered_benign: bool) -> tuple[int, int]:
    timeline = read_timeline(timeline_path)
    accepted, uncovered = [], 0
    with Path(log_path).open(encoding="utf-8") as handle:
        for line in handle:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict) or (flow := zeek_record_to_flow(record)) is None:
                continue
            observed = parse_time(flow["timestamp"])
            label = label_for(observed, timeline, assume_uncovered_benign)
            if label is None:
                uncovered += 1
                continue
            flow["label"] = label
            accepted.append(flow)
    if not accepted:
        raise ValueError("No labeled Zeek connections were written. Check timestamps, intervals, and consented log path.")
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    columns = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packets", "bytes", "duration_ms", "flags", "failed_conn_info", "label"]
    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader(); writer.writerows(accepted)
    return len(accepted), uncovered


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zeek_log", help="JSON Zeek conn.log from an authorised capture")
    parser.add_argument("timeline", help="Reviewed start,end,label CSV")
    parser.add_argument("--out", required=True, help="Normalized labeled CSV to write")
    parser.add_argument("--assume-uncovered-benign", action="store_true", help="Label gaps BENIGN only when capture conditions are known normal")
    args = parser.parse_args()
    accepted, uncovered = convert(args.zeek_log, args.timeline, args.out, args.assume_uncovered_benign)
    print(f"Wrote {accepted} labeled flows to {args.out}; skipped {uncovered} uncovered flows.")


if __name__ == "__main__":
    main()
