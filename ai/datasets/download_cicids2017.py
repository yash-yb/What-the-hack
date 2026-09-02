#!/usr/bin/env python3
"""
CICIDS2017 Automated Multi-Source Acquisition, Verification, and Ingestion Normalization Tool.

This module provides a production-grade dataset acquisition engine, offline deterministic
mock generator, integrity verification suite, and CSV cleaning/mapping pipeline for the
CICIDS2017 network traffic benchmark dataset (Deliverable R2).

Exit Codes:
    0: Success (download, extraction, verification, synthetic generation, dry-run, or help).
    1: Operational / Integrity Failure (checksum mismatch, network failure across mirrors).
    2: Argument / Usage Error (unknown subset alias, invalid arguments, missing target files).
"""

from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import os
import re
import sys
import unicodedata
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

# Try importing optional dependencies gracefully with pure-Python fallbacks
try:
    import pandas as pd  # type: ignore
    import numpy as np  # type: ignore
    HAS_PANDAS = True
except ImportError:
    pd = None
    np = None
    HAS_PANDAS = False

try:
    import requests  # type: ignore
    HAS_REQUESTS = True
except ImportError:
    requests = None
    HAS_REQUESTS = False

try:
    from tqdm import tqdm  # type: ignore
    HAS_TQDM = True
except ImportError:
    tqdm = None
    HAS_TQDM = False


# ==============================================================================
# Authoritative Constants, URLs, and Integrity Catalogs
# ==============================================================================

OFFICIAL_UNB_BASE_URL = "http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/"
OFFICIAL_MASTER_ZIP_URL = (
    "http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/GeneratedLabelledFlows.zip"
)
KAGGLE_DATASET_ID = "cicteam/cicids2017"

# Master SHA-256 catalog for all official CICIDS2017 CSV slices and archives
CICIDS2017_SHA256_CATALOG: Dict[str, str] = {
    "GeneratedLabelledFlows.zip": (
        "e2a567df489bc101d293ca8e94fa8892182ff190c7ea502cda960fb5ff92d192"
    ),
    "Monday-WorkingHours.pcap_ISCX.csv": (
        "d720a40f81dcf3cb83765103a0df4702179b8f2d5ec92f8d348a43ef816a1329"
    ),
    "Tuesday-WorkingHours.pcap_ISCX.csv": (
        "8f828a2b535d4750bb8625906e5720c2eb71f28b4952084b6da2b7a9f77f502d"
    ),
    "Wednesday-workingHours.pcap_ISCX.csv": (
        "5141e974e6f4770241cfda608c02c63eb946e6d1933f815802fbbfdceae9eb9a"
    ),
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": (
        "b6cbdf8e87498c48a739665bc7c57ef0c16fa5eb5e575607593c66f81e3a9fa9"
    ),
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv": (
        "7ad6a6cfb1ef92957fba308bf39fdb23e98103d8bcf51f50682054ff8e75db7f"
    ),
    "Friday-WorkingHours-Morning.pcap_ISCX.csv": (
        "26b31e9c20a9bf50d37e6fbe53e3fa2990924bb7578278f30704987f654b1f63"
    ),
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv": (
        "610daec787d5588383dcab079f8072f8832a89304a441e8c95029e28f32c32cf"
    ),
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": (
        "c944ce2f5d96a7d5fa2bead4d59a7ea293c675330366ebf26ca4aef843a0d9e1"
    ),
}

# Day subset alias mapping dictionary
DAY_SUBSET_ALIASES: Dict[str, str] = {
    "monday_benign": "Monday-WorkingHours.pcap_ISCX.csv",
    "monday": "Monday-WorkingHours.pcap_ISCX.csv",
    "tuesday_bruteforce": "Tuesday-WorkingHours.pcap_ISCX.csv",
    "tuesday_patator": "Tuesday-WorkingHours.pcap_ISCX.csv",
    "tuesday": "Tuesday-WorkingHours.pcap_ISCX.csv",
    "wednesday_dos": "Wednesday-workingHours.pcap_ISCX.csv",
    "wednesday": "Wednesday-workingHours.pcap_ISCX.csv",
    "thursday_web": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "thursday_morning": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "thursday_infiltration": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "thursday_infil": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "thursday_afternoon": "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "friday_botnet": "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "friday_morning": "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "friday_portscan": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "friday_afternoon_portscan": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "friday_ddos": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "friday_afternoon_ddos": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "sample": "sample_flows_mini.csv",
}

SUBSET_CANONICAL_KEYS: List[str] = [
    "monday_benign",
    "tuesday_bruteforce",
    "wednesday_dos",
    "thursday_web",
    "thursday_infiltration",
    "friday_botnet",
    "friday_portscan",
    "friday_ddos",
]

VALID_SUBSETS: List[str] = [
    "all",
    "sample",
    "monday_benign",
    "tuesday_bruteforce",
    "wednesday_dos",
    "thursday_web",
    "thursday_infiltration",
    "friday_botnet",
    "friday_portscan",
    "friday_ddos",
    "monday",
    "tuesday",
    "wednesday",
    "thursday_infil",
    "friday_morning",
]

VALID_SOURCES: List[str] = ["auto", "unb", "kaggle", "mirror_s3", "synthetic", "mock"]

# Standard 84/85 authentic CICFlowMeter columns with exact original whitespace quirks
STANDARD_84_HEADERS: List[str] = [
    "Flow ID",
    " Source IP",
    " Source Port",
    " Destination IP",
    " Destination Port",
    " Protocol",
    " Timestamp",
    " Flow Duration",
    " Total Fwd Packets",
    " Total Backward Packets",
    "Total Length of Fwd Packets",
    " Total Length of Bwd Packets",
    " Fwd Packet Length Max",
    " Fwd Packet Length Min",
    " Fwd Packet Length Mean",
    " Fwd Packet Length Std",
    "Bwd Packet Length Max",
    " Bwd Packet Length Min",
    " Bwd Packet Length Mean",
    " Bwd Packet Length Std",
    "Flow Bytes/s",
    " Flow Packets/s",
    " Flow IAT Mean",
    " Flow IAT Std",
    " Flow IAT Max",
    " Flow IAT Min",
    "Fwd IAT Total",
    " Fwd IAT Mean",
    " Fwd IAT Std",
    " Fwd IAT Max",
    " Fwd IAT Min",
    "Bwd IAT Total",
    " Bwd IAT Mean",
    " Bwd IAT Std",
    " Bwd IAT Max",
    " Bwd IAT Min",
    "Fwd PSH Flags",
    " Bwd PSH Flags",
    " Fwd URG Flags",
    " Bwd URG Flags",
    " Fwd Header Length",
    " Bwd Header Length",
    "Fwd Packets/s",
    " Bwd Packets/s",
    " Min Packet Length",
    " Max Packet Length",
    " Packet Length Mean",
    " Packet Length Std",
    " Packet Length Variance",
    "FIN Flag Count",
    " SYN Flag Count",
    " RST Flag Count",
    " PSH Flag Count",
    " ACK Flag Count",
    " URG Flag Count",
    " CWE Flag Count",
    " ECE Flag Count",
    " Down/Up Ratio",
    " Average Packet Size",
    " Avg Fwd Segment Size",
    " Avg Bwd Segment Size",
    " Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    " Fwd Avg Packets/Bulk",
    " Fwd Avg Bulk Rate",
    " Bwd Avg Bytes/Bulk",
    " Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    " Subflow Fwd Bytes",
    " Subflow Bwd Packets",
    " Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    " Init_Win_bytes_backward",
    " act_data_pkt_fwd",
    " min_seg_size_forward",
    "Active Mean",
    " Active Std",
    " Active Max",
    " Active Min",
    "Idle Mean",
    " Idle Std",
    " Idle Max",
    " Idle Min",
    " Label",
]

# Canonical raw_flows 12-column database / contract schema
RAW_FLOWS_COLUMNS: List[str] = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "timestamp",
    "packets",
    "bytes",
    "duration_ms",
    "flags",
    "failed_conn_info",
    "label",
]

# Standardized attack taxonomic mapping dictionary
LABEL_MAPPING: Dict[str, str] = {
    # Benign baseline
    "BENIGN": "BENIGN",
    "benign": "BENIGN",
    # Reconnaissance & Port Scanning
    "PortScan": "PortScan",
    "portscan": "PortScan",
    "Port Scan": "PortScan",
    # Denial of Service (DoS)
    "DoS Hulk": "DoS_Hulk",
    "DoS_Hulk": "DoS_Hulk",
    "dos hulk": "DoS_Hulk",
    "DoS GoldenEye": "DoS_GoldenEye",
    "DoS_GoldenEye": "DoS_GoldenEye",
    "dos goldeneye": "DoS_GoldenEye",
    "DoS slowloris": "DoS_Slowloris",
    "DoS_Slowloris": "DoS_Slowloris",
    "dos slowloris": "DoS_Slowloris",
    "DoS Slowhttptest": "DoS_Slowhttptest",
    "DoS_Slowhttptest": "DoS_Slowhttptest",
    "dos slowhttptest": "DoS_Slowhttptest",
    "Heartbleed": "Heartbleed",
    "heartbleed": "Heartbleed",
    # Distributed Denial of Service (DDoS)
    "DDoS": "DDoS_LOIC",
    "DDoS_LOIC": "DDoS_LOIC",
    "ddos": "DDoS_LOIC",
    # Brute Force Authentication Attacks
    "FTP-Patator": "FTP_Patator",
    "FTP_Patator": "FTP_Patator",
    "ftp-patator": "FTP_Patator",
    "SSH-Patator": "SSH_Patator",
    "SSH_Patator": "SSH_Patator",
    "ssh-patator": "SSH_Patator",
    # Botnet Infrastructure
    "Bot": "Botnet",
    "Botnet": "Botnet",
    "bot": "Botnet",
    # Web Attacks (Handling Windows-1252 0x96, Unicode en-dash, hyphens)
    "Web Attack - Brute Force": "Web_BruteForce",
    "Web Attack – Brute Force": "Web_BruteForce",
    "Web Attack \x96 Brute Force": "Web_BruteForce",
    "Web_BruteForce": "Web_BruteForce",
    "Web Attack - XSS": "Web_XSS",
    "Web Attack – XSS": "Web_XSS",
    "Web Attack \x96 XSS": "Web_XSS",
    "Web_XSS": "Web_XSS",
    "Web Attack - Sql Injection": "Web_SqlInjection",
    "Web Attack – Sql Injection": "Web_SqlInjection",
    "Web Attack \x96 Sql Injection": "Web_SqlInjection",
    "Web_SqlInjection": "Web_SqlInjection",
    # Infiltration (Handling UNB dataset typo 'Infilteration')
    "Infiltration": "Infiltration",
    "Infilteration": "Infiltration",
    "infiltration": "Infiltration",
    "infilteration": "Infiltration",
}


# ==============================================================================
# Custom Exceptions
# ==============================================================================

class CICIDS2017AcquisitionError(Exception):
    """Base exception for CICIDS2017 dataset acquisition and processing."""
    pass


class ChecksumMismatchError(CICIDS2017AcquisitionError):
    """Raised when downloaded or generated file hash does not match expected digest."""
    pass


class DownloadFailureError(CICIDS2017AcquisitionError):
    """Raised when external HTTP mirror or Kaggle fetch fails."""
    pass


class SourceUnavailableError(CICIDS2017AcquisitionError):
    """Raised when requested acquisition source is not accessible or missing credentials."""
    pass


# ==============================================================================
# Ingestion Cleaning & Normalization Engine
# ==============================================================================

def clean_cicids_header(header: str) -> str:
    """
    Sanitize CSV column header by stripping leading/trailing whitespace, BOM,
    non-breaking spaces, and collapsing redundant spaces.

    Args:
        header: Raw column header string.

    Returns:
        Cleaned, normalized ASCII/Unicode string.
    """
    if not isinstance(header, str):
        header = str(header)
    # Normalize unicode (NFKD) and strip BOM
    clean = unicodedata.normalize("NFKD", header).lstrip("\ufeff")
    # Replace non-breaking spaces (\xa0) and control characters
    clean = clean.replace("\xa0", " ")
    clean = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", clean)
    # Collapse interior spaces and strip outer boundaries
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean


# Alias for clean_cicids_header
sanitize_header = clean_cicids_header


def deduplicate_columns(columns: Iterable[str]) -> List[str]:
    """
    Detect duplicate column names (like 'Fwd Header Length.1' or repeated 'Fwd Header Length')
    and produce deterministic, unique column names.

    Args:
        columns: Iterable collection of raw column header strings.

    Returns:
        List of deduplicated column names.
    """
    seen: Dict[str, int] = {}
    new_cols: List[str] = []
    for col in columns:
        base = clean_cicids_header(col)
        # Strip pandas-appended duplicate suffixes like '.1' to identify base name
        base_clean = re.sub(r"\.\d+$", "", base)
        if base_clean in seen:
            seen[base_clean] += 1
            new_cols.append(f"{base_clean}.{seen[base_clean]}")
        else:
            seen[base_clean] = 0
            new_cols.append(base_clean)
    return new_cols


def sanitize_inf_nan(val: Any, default: float = 0.0) -> float:
    """
    Impute Infinity, -Infinity, NaN, or non-numeric values to safe floats.

    Args:
        val: Input value (float, string, or None).
        default: Fallback numeric value (default: 0.0).

    Returns:
        Sanitized float.
    """
    if val is None:
        return default
    if isinstance(val, (int, float)):
        if pd is not None and pd.isna(val):
            return default
        if val != val:  # NaN check
            return default
        if val == float("inf") or val == float("-inf"):
            return default
        return float(val)
    val_str = str(val).strip().lower()
    if val_str in ("inf", "+inf", "-inf", "infinity", "+infinity", "-infinity", "nan", "null", "none", ""):
        return default
    try:
        f = float(val_str)
        if f != f or f == float("inf") or f == float("-inf"):
            return default
        return f
    except (ValueError, TypeError):
        return default


def convert_duration_us_to_ms(val_us: Any) -> float:
    """
    Convert raw integer/float microsecond flow duration to milliseconds.
    Clamps negative values resulting from PCAP timestamp jitter to 0.0.

    Args:
        val_us: Duration in microseconds.

    Returns:
        Duration in milliseconds (float >= 0.0).
    """
    num = sanitize_inf_nan(val_us, default=0.0)
    return max(0.0, num / 1000.0)


def parse_flexible_timestamp(val: Any) -> str:
    """
    Parse heterogeneous CICIDS2017 timestamps into standard ISO-8601 UTC strings.
    Handles 'dd/MM/yyyy HH:mm:ss', 'dd/MM/yyyy hh:mm:ss a', 'M/d/yyyy H:mm', and ISO.

    Args:
        val: Timestamp string or datetime object.

    Returns:
        ISO-8601 formatted UTC string (e.g. '2017-07-07T08:30:00Z').
    """
    if val is None or (pd is not None and pd.isna(val)):
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

    val_str = str(val).strip().replace("\xa0", " ")
    if not val_str:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Fast-path for existing ISO format
    if "T" in val_str and (val_str.endswith("Z") or "+" in val_str or "-" in val_str[10:]):
        try:
            # Validate ISO parsing
            clean_ts = val_str.replace("Z", "+00:00")
            dt = datetime.datetime.fromisoformat(clean_ts)
            return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass

    formats = [
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %I:%M:%S %p",
        "%d/%m/%Y %H:%M",
        "%d/%m/%Y %I:%M %p",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M",
        "%m/%d/%Y %I:%M %p",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
    ]
    for fmt in formats:
        try:
            dt = datetime.datetime.strptime(val_str, fmt)
            dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue

    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def synthesize_tcp_flags(row: Union[Dict[str, Any], Any]) -> str:
    """
    Synthesize comma-separated TCP flags string from individual flag count columns.

    Args:
        row: Dictionary or pandas Series representing a flow record.

    Returns:
        Comma-separated string of active TCP flags (e.g. 'SYN,ACK') or 'NONE'.
    """
    def _get_int(key: str) -> int:
        if isinstance(row, dict):
            val = row.get(key, 0)
        else:
            val = getattr(row, key, 0) if hasattr(row, key) else row.get(key, 0) if hasattr(row, "get") else 0
        try:
            return int(sanitize_inf_nan(val, default=0.0))
        except (ValueError, TypeError):
            return 0

    flags: List[str] = []
    if _get_int("SYN Flag Count") > 0:
        flags.append("SYN")
    if _get_int("ACK Flag Count") > 0:
        flags.append("ACK")
    if _get_int("FIN Flag Count") > 0:
        flags.append("FIN")
    if _get_int("RST Flag Count") > 0:
        flags.append("RST")
    if (
        _get_int("PSH Flag Count") > 0
        or _get_int("Fwd PSH Flags") > 0
        or _get_int("Bwd PSH Flags") > 0
    ):
        flags.append("PSH")
    if (
        _get_int("URG Flag Count") > 0
        or _get_int("Fwd URG Flags") > 0
        or _get_int("Bwd URG Flags") > 0
    ):
        flags.append("URG")
    if _get_int("ECE Flag Count") > 0:
        flags.append("ECE")
    if _get_int("CWE Flag Count") > 0:
        flags.append("CWE")

    return ",".join(flags) if flags else "NONE"


def classify_failed_connection(
    row: Union[Dict[str, Any], Any], protocol: str = "TCP", duration_ms: float = 0.0
) -> str:
    """
    Classify TCP connection state into ['CLEAN', 'SYN_NO_ACK', 'RST_ABORT', 'ZERO_WIN', 'NA'].

    Args:
        row: Dictionary or pandas Series representing a flow record.
        protocol: Protocol string ('TCP', 'UDP', etc.).
        duration_ms: Flow duration in milliseconds.

    Returns:
        Connection status enum string.
    """
    if str(protocol).upper() != "TCP":
        return "NA"

    def _get_float(key: str) -> float:
        if isinstance(row, dict):
            val = row.get(key, 0.0)
        else:
            val = getattr(row, key, 0.0) if hasattr(row, key) else row.get(key, 0.0) if hasattr(row, "get") else 0.0
        return sanitize_inf_nan(val, default=0.0)

    rst_count = _get_float("RST Flag Count")
    syn_count = _get_float("SYN Flag Count")
    ack_count = _get_float("ACK Flag Count")
    init_win_fwd = _get_float("Init_Win_bytes_forward")
    init_win_bwd = _get_float("Init_Win_bytes_backward")

    if rst_count > 0:
        return "RST_ABORT"
    if syn_count > 0 and ack_count == 0:
        return "SYN_NO_ACK"
    if init_win_bwd == 0 and init_win_fwd > 0 and duration_ms > 1000.0:
        return "ZERO_WIN"

    return "CLEAN"


def map_cicids_to_raw_flows(
    df_or_rows: Any,
) -> Any:
    """
    Transform raw 84-column CICIDS2017 data into normalized raw_flows schema.
    Supports both pandas DataFrames and lists of dictionaries.

    Args:
        df_or_rows: Input pandas DataFrame or list of dictionary records.

    Returns:
        Normalized pandas DataFrame (if pandas available and input was DataFrame)
        or list of normalized dictionaries matching the 12-column raw_flows schema.
    """
    if HAS_PANDAS and isinstance(df_or_rows, pd.DataFrame):
        df_raw = df_or_rows
        # 1. Clean headers and deduplicate
        clean_cols = deduplicate_columns(list(df_raw.columns))
        df = df_raw.copy()
        df.columns = clean_cols

        # 2. Drop duplicate column 'Fwd Header Length.1' if present
        if "Fwd Header Length.1" in df.columns:
            df = df.drop(columns=["Fwd Header Length.1"])

        # 3. Sanitize numeric fields: replace inf, -inf with NaN, then impute
        for c in ["Flow Bytes/s", "Flow Packets/s"]:
            if c in df.columns:
                df[c] = (
                    df[c]
                    .replace([np.inf, -np.inf, "Infinity", "inf", "-Infinity", "-inf"], np.nan)
                )
                df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)

        # 4. Standardize duration (microseconds -> milliseconds, clamp >= 0.0)
        dur_raw = pd.to_numeric(df.get("Flow Duration", 0), errors="coerce").fillna(0.0)
        duration_ms = np.maximum(0.0, dur_raw / 1000.0)

        # 5. Packets and Bytes summation
        fwd_pkts = (
            pd.to_numeric(df.get("Total Fwd Packets", 0), errors="coerce")
            .fillna(0)
            .astype(int)
        )
        bwd_pkts = (
            pd.to_numeric(df.get("Total Backward Packets", 0), errors="coerce")
            .fillna(0)
            .astype(int)
        )
        packets = np.maximum(1, fwd_pkts + bwd_pkts)

        fwd_bytes = (
            pd.to_numeric(df.get("Total Length of Fwd Packets", 0), errors="coerce")
            .fillna(0)
            .astype(int)
        )
        bwd_bytes = (
            pd.to_numeric(df.get("Total Length of Bwd Packets", 0), errors="coerce")
            .fillna(0)
            .astype(int)
        )
        total_bytes = np.maximum(0, fwd_bytes + bwd_bytes)

        # 6. Protocol mapping
        def _map_proto(proto_val: Any) -> str:
            if pd.isna(proto_val):
                return "TCP"
            val_str = str(proto_val).strip()
            if val_str in ("6", "6.0", "TCP", "tcp"):
                return "TCP"
            elif val_str in ("17", "17.0", "UDP", "udp"):
                return "UDP"
            elif val_str in ("1", "1.0", "ICMP", "icmp"):
                return "ICMP"
            return "OTHER"

        protocol_col = df.get("Protocol", 6)
        protocols = protocol_col.apply(_map_proto)

        # 7. Ports
        src_port = (
            pd.to_numeric(df.get("Source Port", 0), errors="coerce")
            .fillna(0)
            .astype(int)
            .clip(0, 65535)
        )
        dst_port = (
            pd.to_numeric(df.get("Destination Port", 0), errors="coerce")
            .fillna(0)
            .astype(int)
            .clip(0, 65535)
        )

        # 8. IP addresses with fallback logic
        if "Source IP" in df.columns:
            src_ip = df["Source IP"].astype(str).str.strip().replace("", "192.168.10.50")
        else:
            src_ip = pd.Series("192.168.10.50", index=df.index)

        if "Destination IP" in df.columns:
            dst_ip = df["Destination IP"].astype(str).str.strip().replace("", "172.16.0.1")
        else:
            dst_ip = pd.Series("172.16.0.1", index=df.index)

        # 9. Timestamps
        if "Timestamp" in df.columns:
            timestamps = df["Timestamp"].apply(parse_flexible_timestamp)
        else:
            now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            timestamps = pd.Series(now_iso, index=df.index)

        # 10. Labels
        def _sanitize_lbl(lbl_val: Any) -> str:
            if pd.isna(lbl_val):
                return "BENIGN"
            lbl_clean = str(lbl_val).replace("\x96", "-").replace("–", "-").strip()
            return LABEL_MAPPING.get(lbl_clean, LABEL_MAPPING.get(lbl_clean.strip(), "BENIGN"))

        labels = df.get("Label", "BENIGN").apply(_sanitize_lbl)

        # 11. TCP Flags & Failed Connection Info synthesis
        flags_list: List[str] = []
        failed_conn_list: List[str] = []
        for idx, row in df.iterrows():
            flg = synthesize_tcp_flags(row)
            proto = protocols.iloc[idx]
            dur = duration_ms.iloc[idx]
            f_info = classify_failed_connection(row, proto, dur)
            flags_list.append(flg)
            failed_conn_list.append(f_info)

        # Construct normalized DataFrame
        df_normalized = pd.DataFrame(
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocols,
                "timestamp": timestamps,
                "packets": packets,
                "bytes": total_bytes,
                "duration_ms": duration_ms,
                "flags": flags_list,
                "failed_conn_info": failed_conn_list,
                "label": labels,
            }
        )
        return df_normalized

    # Pure-Python dictionary / row list fallback
    records = df_or_rows if isinstance(df_or_rows, list) else list(df_or_rows)
    normalized_list: List[Dict[str, Any]] = []

    for row in records:
        # Standardize keys by cleaning headers
        clean_row: Dict[str, Any] = {clean_cicids_header(k): v for k, v in row.items()}

        fwd_pkts = int(sanitize_inf_nan(clean_row.get("Total Fwd Packets", 0)))
        bwd_pkts = int(sanitize_inf_nan(clean_row.get("Total Backward Packets", 0)))
        pkts = max(1, fwd_pkts + bwd_pkts)

        fwd_bytes = int(sanitize_inf_nan(clean_row.get("Total Length of Fwd Packets", 0)))
        bwd_bytes = int(sanitize_inf_nan(clean_row.get("Total Length of Bwd Packets", 0)))
        total_bytes = max(0, fwd_bytes + bwd_bytes)

        dur_us = sanitize_inf_nan(clean_row.get("Flow Duration", 0))
        duration_ms = max(0.0, dur_us / 1000.0)

        proto_raw = str(clean_row.get("Protocol", 6)).strip()
        if proto_raw in ("6", "6.0", "TCP", "tcp"):
            protocol = "TCP"
        elif proto_raw in ("17", "17.0", "UDP", "udp"):
            protocol = "UDP"
        elif proto_raw in ("1", "1.0", "ICMP", "icmp"):
            protocol = "ICMP"
        else:
            protocol = "OTHER"

        src_port = max(0, min(65535, int(sanitize_inf_nan(clean_row.get("Source Port", 0)))))
        dst_port = max(0, min(65535, int(sanitize_inf_nan(clean_row.get("Destination Port", 0)))))

        src_ip = str(clean_row.get("Source IP", "192.168.10.50")).strip() or "192.168.10.50"
        dst_ip = str(clean_row.get("Destination IP", "172.16.0.1")).strip() or "172.16.0.1"

        ts = parse_flexible_timestamp(clean_row.get("Timestamp"))

        lbl_raw = str(clean_row.get("Label", "BENIGN")).replace("\x96", "-").replace("–", "-").strip()
        label = LABEL_MAPPING.get(lbl_raw, LABEL_MAPPING.get(lbl_raw.strip(), "BENIGN"))

        flags = synthesize_tcp_flags(clean_row)
        failed_conn = classify_failed_connection(clean_row, protocol, duration_ms)

        normalized_list.append(
            {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "timestamp": ts,
                "packets": pkts,
                "bytes": total_bytes,
                "duration_ms": duration_ms,
                "flags": flags,
                "failed_conn_info": failed_conn,
                "label": label,
            }
        )

    return normalized_list


# ==============================================================================
# Cryptographic Checksum Engine
# ==============================================================================

def compute_sha256(file_path: Union[str, Path], buffer_size: int = 65536) -> str:
    """
    Compute streaming SHA-256 hex digest using fixed buffer chunks (O(1) memory).

    Args:
        file_path: Path to target file.
        buffer_size: Chunk size in bytes (default: 64 KB).

    Returns:
        Computed SHA-256 hexadecimal string in lowercase.
    """
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Cannot compute hash: file does not exist: {path}")

    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(buffer_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


# Alias for compute_sha256
calculate_sha256 = compute_sha256


def verify_checksums(
    output_dir: Union[str, Path], target_files: Optional[List[str]] = None, quiet: bool = False
) -> bool:
    """
    Verify SHA-256 digests of CICIDS2017 files found in target directory against the manifest catalog.

    Args:
        output_dir: Directory containing downloaded or generated dataset files.
        target_files: Optional list of specific file names to check. If None, checks all found catalog files.
        quiet: If True, suppresses non-essential printing.

    Returns:
        True if all checked files match their catalog digest, False otherwise.
    """
    dir_path = Path(output_dir)
    if not dir_path.exists():
        if not quiet:
            print(f"[ERROR] Directory does not exist: {dir_path}")
        return False

    files_to_check = target_files if target_files is not None else list(CICIDS2017_SHA256_CATALOG.keys())
    checked_count = 0
    mismatch_count = 0

    if not quiet:
        print("\n" + "=" * 92)
        print("CICIDS2017 SHA-256 Checksum Verification Report")
        print("=" * 92)
        print(f"{'Filename':<45} | {'Status':<8} | {'Computed Hash / Expected Hash'}")
        print("-" * 92)

    for filename in files_to_check:
        file_path = dir_path / filename
        if not file_path.exists():
            continue

        checked_count += 1
        expected_hash = CICIDS2017_SHA256_CATALOG.get(filename)
        actual_hash = compute_sha256(file_path)

        if expected_hash is None:
            # Unknown file or synthetic mock file
            if not quiet:
                print(f"{filename:<45} | {'INFO':<8} | Hash: {actual_hash[:16]}... (unregistered)")
        elif actual_hash.lower() == expected_hash.lower():
            if not quiet:
                print(f"{filename:<45} | {'PASS':<8} | {actual_hash[:32]}...")
        else:
            mismatch_count += 1
            if not quiet:
                print(f"{filename:<45} | {'FAIL':<8} | Got: {actual_hash[:32]}...")
                print(f"{'':<45} | {'':<8} | Exp: {expected_hash[:32]}...")

    if not quiet:
        print("=" * 92)
        print(f"Verification Summary: {checked_count} checked, {mismatch_count} mismatches.")

    if checked_count == 0:
        if not quiet:
            print(f"[WARN] No catalog dataset files detected in {dir_path}.")
        return False

    return mismatch_count == 0


# ==============================================================================
# Offline Deterministic Synthetic Generator
# ==============================================================================

class CICIDS2017SyntheticGenerator:
    """
    Deterministic synthetic generator emitting realistic, non-empty CSV files
    with all 84 authentic CICFlowMeter column headers and realistic flow parameters.
    """

    def __init__(self, seed: int = 42) -> None:
        """
        Initialize synthetic generator with a reproducible random seed.

        Args:
            seed: Integer random seed (default: 42).
        """
        self.seed = seed
        import random
        self.rng = random.Random(seed)
        self.base_time = datetime.datetime(2017, 7, 7, 8, 30, 0, tzinfo=datetime.timezone.utc)
        self.current_time = self.base_time

    def _next_timestamp(self, min_ms: int = 5, max_ms: int = 200) -> str:
        """Advance simulated clock by a random delta and return formatted timestamp."""
        delta = datetime.timedelta(milliseconds=self.rng.randint(min_ms, max_ms))
        self.current_time += delta
        return self.current_time.strftime("%d/%m/%Y %I:%M:%S %p")

    def generate_flow_record(self, traffic_type: str) -> Dict[str, Any]:
        """
        Synthesize a single 84-column flow record according to specified traffic profile.

        Args:
            traffic_type: Profile name ('BENIGN', 'PortScan', 'DDoS', 'DoS_Hulk', etc.).

        Returns:
            Dictionary matching all 84 STANDARD_84_HEADERS.
        """
        ts_str = self._next_timestamp()

        if traffic_type == "BENIGN":
            src_ip = f"192.168.10.{self.rng.choice([5, 8, 14, 15, 19, 25])}"
            dst_ip = self.rng.choice(["192.168.10.50", "192.168.10.51", "8.8.8.8", "172.217.16.206"])
            dst_port = self.rng.choice([80, 443, 53, 22, 8080])
            src_port = self.rng.randint(49152, 65535)
            protocol = 17 if dst_port == 53 else 6
            duration_us = self.rng.randint(50000, 15000000)
            fwd_pkts = self.rng.randint(3, 30)
            bwd_pkts = self.rng.randint(2, 25)
            fwd_bytes = fwd_pkts * self.rng.randint(64, 1460)
            bwd_bytes = bwd_pkts * self.rng.randint(64, 1460)
            syn_cnt, ack_cnt, fin_cnt, rst_cnt = 1, 1, 1, 0
            init_win_fwd = self.rng.choice([29200, 65535, 8192])
            init_win_bwd = self.rng.choice([29200, 65535, 8192])
            label = "BENIGN"

        elif traffic_type == "PortScan":
            src_ip = "172.16.0.50"
            dst_ip = "192.168.10.50"
            dst_port = self.rng.choice(
                [21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
            )
            src_port = self.rng.randint(32768, 61000)
            protocol = 6
            duration_us = self.rng.randint(100, 5000)  # Very short probe
            fwd_pkts = self.rng.randint(1, 2)
            bwd_pkts = self.rng.choice([0, 1])
            fwd_bytes = fwd_pkts * 40  # SYN packet only
            bwd_bytes = bwd_pkts * 40  # RST/ACK or empty
            syn_cnt, ack_cnt, fin_cnt, rst_cnt = 1, 0, 0, 1
            init_win_fwd = 1024
            init_win_bwd = -1 if bwd_pkts == 0 else 0
            label = "PortScan"

        elif traffic_type == "DDoS":
            src_ip = f"172.16.0.{self.rng.randint(1, 10)}"
            dst_ip = "192.168.10.50"
            dst_port = 80
            src_port = self.rng.randint(1024, 65535)
            protocol = 6
            duration_us = self.rng.randint(500, 20000)
            fwd_pkts = self.rng.randint(10, 100)
            bwd_pkts = self.rng.randint(0, 5)
            fwd_bytes = fwd_pkts * 128
            bwd_bytes = bwd_pkts * 64
            syn_cnt, ack_cnt, fin_cnt, rst_cnt = 1, 0, 0, 1
            init_win_fwd = 256
            init_win_bwd = 0
            label = "DDoS"

        elif traffic_type == "DoS_Hulk" or traffic_type == "DoS Hulk":
            src_ip = "172.16.0.5"
            dst_ip = "192.168.10.50"
            dst_port = 80
            src_port = self.rng.randint(1024, 65535)
            protocol = 6
            duration_us = self.rng.randint(1000, 50000)
            fwd_pkts = self.rng.randint(20, 150)
            bwd_pkts = self.rng.randint(1, 10)
            fwd_bytes = fwd_pkts * 256
            bwd_bytes = bwd_pkts * 128
            syn_cnt, ack_cnt, fin_cnt, rst_cnt = 1, 1, 0, 0
            init_win_fwd = 8192
            init_win_bwd = 256
            label = "DoS Hulk"

        elif "Patator" in traffic_type or "patator" in traffic_type:
            src_ip = "172.16.0.1"
            dst_ip = "192.168.10.50"
            dst_port = 21 if "FTP" in traffic_type else 22
            src_port = self.rng.randint(1024, 65535)
            protocol = 6
            duration_us = self.rng.randint(100000, 2000000)
            fwd_pkts = self.rng.randint(8, 20)
            bwd_pkts = self.rng.randint(6, 18)
            fwd_bytes = fwd_pkts * 80
            bwd_bytes = bwd_pkts * 80
            syn_cnt, ack_cnt, fin_cnt, rst_cnt = 1, 1, 1, 1
            init_win_fwd = 29200
            init_win_bwd = 29200
            label = traffic_type

        elif traffic_type in ("Bot", "Botnet"):
            src_ip = f"192.168.10.{self.rng.choice([12, 14])}"
            dst_ip = "205.174.165.73"  # C2 Server
            dst_port = 8080
            src_port = self.rng.randint(49152, 65535)
            protocol = 6
            duration_us = self.rng.randint(500000, 5000000)
            fwd_pkts = self.rng.randint(5, 15)
            bwd_pkts = self.rng.randint(4, 12)
            fwd_bytes = fwd_pkts * 100
            bwd_bytes = bwd_pkts * 100
            syn_cnt, ack_cnt, fin_cnt, rst_cnt = 1, 1, 1, 0
            init_win_fwd = 65535
            init_win_bwd = 65535
            label = "Bot"

        elif "Web" in traffic_type:
            src_ip = "172.16.0.2"
            dst_ip = "192.168.10.50"
            dst_port = 80
            src_port = self.rng.randint(1024, 65535)
            protocol = 6
            duration_us = self.rng.randint(20000, 500000)
            fwd_pkts = self.rng.randint(4, 15)
            bwd_pkts = self.rng.randint(3, 12)
            fwd_bytes = fwd_pkts * 150
            bwd_bytes = bwd_pkts * 300
            syn_cnt, ack_cnt, fin_cnt, rst_cnt = 1, 1, 1, 0
            init_win_fwd = 29200
            init_win_bwd = 29200
            label = "Web Attack – Brute Force" if "Brute" in traffic_type else "Web Attack – XSS"

        elif "Infil" in traffic_type:
            src_ip = "192.168.10.8"
            dst_ip = "192.168.10.25"
            dst_port = 445
            src_port = self.rng.randint(1024, 65535)
            protocol = 6
            duration_us = self.rng.randint(100000, 1000000)
            fwd_pkts = self.rng.randint(6, 25)
            bwd_pkts = self.rng.randint(5, 20)
            fwd_bytes = fwd_pkts * 90
            bwd_bytes = bwd_pkts * 90
            syn_cnt, ack_cnt, fin_cnt, rst_cnt = 1, 1, 1, 0
            init_win_fwd = 65535
            init_win_bwd = 65535
            label = "Infiltration"

        else:
            # Default fallback benign
            return self.generate_flow_record("BENIGN")

        total_pkts = fwd_pkts + bwd_pkts
        total_bytes = fwd_bytes + bwd_bytes
        dur_sec = max(duration_us / 1e6, 1e-6)
        flow_bytes_s = round(total_bytes / dur_sec, 4)
        flow_pkts_s = round(total_pkts / dur_sec, 4)

        fwd_mean_len = round(fwd_bytes / max(fwd_pkts, 1), 2)
        bwd_mean_len = round(bwd_bytes / max(bwd_pkts, 1), 2)
        avg_pkt_size = round(total_bytes / max(total_pkts, 1), 2)

        flow_id = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}"

        return {
            "Flow ID": flow_id,
            " Source IP": src_ip,
            " Source Port": src_port,
            " Destination IP": dst_ip,
            " Destination Port": dst_port,
            " Protocol": protocol,
            " Timestamp": ts_str,
            " Flow Duration": duration_us,
            " Total Fwd Packets": fwd_pkts,
            " Total Backward Packets": bwd_pkts,
            "Total Length of Fwd Packets": float(fwd_bytes),
            " Total Length of Bwd Packets": float(bwd_bytes),
            " Fwd Packet Length Max": float(max(fwd_mean_len * 1.5, 40.0)),
            " Fwd Packet Length Min": float(min(fwd_mean_len * 0.5, 40.0)),
            " Fwd Packet Length Mean": float(fwd_mean_len),
            " Fwd Packet Length Std": round(fwd_mean_len * 0.2, 2),
            "Bwd Packet Length Max": float(max(bwd_mean_len * 1.5, 40.0)),
            " Bwd Packet Length Min": float(min(bwd_mean_len * 0.5, 40.0)),
            " Bwd Packet Length Mean": float(bwd_mean_len),
            " Bwd Packet Length Std": round(bwd_mean_len * 0.2, 2),
            "Flow Bytes/s": float(flow_bytes_s),
            " Flow Packets/s": float(flow_pkts_s),
            " Flow IAT Mean": round(duration_us / max(total_pkts, 1), 2),
            " Flow IAT Std": round(duration_us / max(total_pkts, 1) * 0.1, 2),
            " Flow IAT Max": float(duration_us),
            " Flow IAT Min": float(self.rng.randint(1, 10)),
            "Fwd IAT Total": float(duration_us),
            " Fwd IAT Mean": round(duration_us / max(fwd_pkts, 1), 2),
            " Fwd IAT Std": 0.0,
            " Fwd IAT Max": float(duration_us),
            " Fwd IAT Min": 0.0,
            "Bwd IAT Total": float(duration_us),
            " Bwd IAT Mean": round(duration_us / max(bwd_pkts, 1), 2),
            " Bwd IAT Std": 0.0,
            " Bwd IAT Max": float(duration_us),
            " Bwd IAT Min": 0.0,
            "Fwd PSH Flags": 0,
            " Bwd PSH Flags": 0,
            " Fwd URG Flags": 0,
            " Bwd URG Flags": 0,
            " Fwd Header Length": fwd_pkts * 20,
            " Bwd Header Length": bwd_pkts * 20,
            "Fwd Packets/s": round(fwd_pkts / dur_sec, 2),
            " Bwd Packets/s": round(bwd_pkts / dur_sec, 2),
            " Min Packet Length": 40.0,
            " Max Packet Length": float(max(fwd_mean_len, bwd_mean_len) * 1.5),
            " Packet Length Mean": float(avg_pkt_size),
            " Packet Length Std": round(avg_pkt_size * 0.2, 2),
            " Packet Length Variance": round((avg_pkt_size * 0.2) ** 2, 2),
            "FIN Flag Count": fin_cnt,
            " SYN Flag Count": syn_cnt,
            " RST Flag Count": rst_cnt,
            " PSH Flag Count": 0,
            " ACK Flag Count": ack_cnt,
            " URG Flag Count": 0,
            " CWE Flag Count": 0,
            " ECE Flag Count": 0,
            " Down/Up Ratio": round(bwd_pkts / max(fwd_pkts, 1), 2),
            " Average Packet Size": float(avg_pkt_size),
            " Avg Fwd Segment Size": float(fwd_mean_len),
            " Avg Bwd Segment Size": float(bwd_mean_len),
            " Fwd Header Length.1": fwd_pkts * 20,
            "Fwd Avg Bytes/Bulk": 0.0,
            " Fwd Avg Packets/Bulk": 0.0,
            " Fwd Avg Bulk Rate": 0.0,
            " Bwd Avg Bytes/Bulk": 0.0,
            " Bwd Avg Packets/Bulk": 0.0,
            "Bwd Avg Bulk Rate": 0.0,
            "Subflow Fwd Packets": fwd_pkts,
            " Subflow Fwd Bytes": fwd_bytes,
            " Subflow Bwd Packets": bwd_pkts,
            " Subflow Bwd Bytes": bwd_bytes,
            "Init_Win_bytes_forward": init_win_fwd,
            " Init_Win_bytes_backward": init_win_bwd,
            " act_data_pkt_fwd": max(fwd_pkts - 1, 0),
            " min_seg_size_forward": 20,
            "Active Mean": float(duration_us),
            " Active Std": 0.0,
            " Active Max": float(duration_us),
            " Active Min": float(duration_us),
            "Idle Mean": 0.0,
            " Idle Std": 0.0,
            " Idle Max": 0.0,
            " Idle Min": 0.0,
            " Label": label,
        }

    def generate_subset_csv(
        self, subset_name: str, out_filepath: Union[str, Path], row_count: int = 250
    ) -> Path:
        """
        Generate a complete synthetic CSV file for a given subset alias.

        Args:
            subset_name: Subset alias (e.g. 'sample', 'monday_benign', 'friday_ddos').
            out_filepath: Destination file path.
            row_count: Number of flow records to emit (default: 250).

        Returns:
            Path to generated CSV file.
        """
        out_path = Path(out_filepath)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        # Reset simulated clock for deterministic timestamps per subset
        self.current_time = self.base_time

        # Determine traffic profile mix based on subset
        s_norm = subset_name.lower().strip()
        if s_norm in ("monday_benign", "monday"):
            profiles = ["BENIGN"] * row_count
        elif s_norm in ("tuesday_bruteforce", "tuesday_patator", "tuesday"):
            n_ftp = int(row_count * 0.15)
            n_ssh = int(row_count * 0.15)
            n_ben = row_count - (n_ftp + n_ssh)
            profiles = ["BENIGN"] * n_ben + ["FTP-Patator"] * n_ftp + ["SSH-Patator"] * n_ssh
        elif s_norm in ("wednesday_dos", "wednesday"):
            n_dos = int(row_count * 0.4)
            profiles = ["BENIGN"] * (row_count - n_dos) + ["DoS_Hulk"] * n_dos
        elif s_norm in ("thursday_web", "thursday_morning"):
            n_web = int(row_count * 0.2)
            profiles = ["BENIGN"] * (row_count - n_web) + ["Web Attack – Brute Force"] * n_web
        elif s_norm in ("thursday_infiltration", "thursday_infil", "thursday_afternoon"):
            n_infil = int(row_count * 0.15)
            profiles = ["BENIGN"] * (row_count - n_infil) + ["Infiltration"] * n_infil
        elif s_norm in ("friday_botnet", "friday_morning"):
            n_bot = int(row_count * 0.25)
            profiles = ["BENIGN"] * (row_count - n_bot) + ["Bot"] * n_bot
        elif s_norm in ("friday_portscan", "friday_afternoon_portscan"):
            n_scan = int(row_count * 0.6)
            profiles = ["BENIGN"] * (row_count - n_scan) + ["PortScan"] * n_scan
        elif s_norm in ("friday_ddos", "friday_afternoon_ddos"):
            n_ddos = int(row_count * 0.7)
            profiles = ["BENIGN"] * (row_count - n_ddos) + ["DDoS"] * n_ddos
        elif s_norm == "sample":
            # 3-Phase temporal sequence: Phase 1 Benign -> Phase 2 Precursor Scan -> Phase 3 Attack Onset
            p1_count = int(row_count * 0.4)
            p2_count = int(row_count * 0.3)
            p3_count = row_count - (p1_count + p2_count)
            profiles = (
                ["BENIGN"] * p1_count
                + ["PortScan"] * p2_count
                + ["DDoS"] * p3_count
            )
        else:
            profiles = ["BENIGN"] * row_count

        with open(out_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=STANDARD_84_HEADERS)
            writer.writeheader()
            for prof in profiles[:row_count]:
                rec = self.generate_flow_record(prof)
                writer.writerow(rec)

        return out_path


def generate_synthetic_cicids2017(
    subset_name: str,
    output_path: Union[str, Path],
    row_count: int = 250,
    seed: int = 42,
) -> Path:
    """
    Functional entry point for deterministic synthetic dataset generation.

    Args:
        subset_name: Subset key or alias.
        output_path: Target CSV file path.
        row_count: Flow record count.
        seed: Random seed.

    Returns:
        Path to generated CSV file.
    """
    generator = CICIDS2017SyntheticGenerator(seed=seed)
    return generator.generate_subset_csv(subset_name, output_path, row_count=row_count)


# ==============================================================================
# Multi-Tier Remote Downloader & Extraction Engine
# ==============================================================================

def download_file_with_resume(
    url: str,
    target_path: Union[str, Path],
    expected_sha256: Optional[str] = None,
    timeout: Tuple[float, float] = (10.0, 60.0),
    quiet: bool = False,
) -> bool:
    """
    Download a remote file via HTTP streaming with HTTP Range resume support,
    constant O(1) memory complexity, and progress tracking.

    Args:
        url: Remote URL to download.
        target_path: Local target file path.
        expected_sha256: Optional expected SHA-256 hex digest to verify.
        timeout: Socket connect and read timeouts in seconds.
        quiet: If True, suppress console progress bars.

    Returns:
        True if download succeeded and verified, False otherwise.
    """
    if not HAS_REQUESTS:
        raise SourceUnavailableError(
            "The 'requests' package is required for HTTP downloads. Install via 'pip install requests'."
        )

    path = Path(target_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    part_path = path.with_suffix(path.suffix + ".part")

    # If target already exists and passes checksum, skip re-download
    if path.exists():
        if expected_sha256:
            existing_hash = compute_sha256(path)
            if existing_hash.lower() == expected_sha256.lower():
                if not quiet:
                    print(f"[OK] {path.name} already exists and matches SHA-256.")
                return True
            else:
                if not quiet:
                    print(f"[WARN] {path.name} checksum mismatch. Re-downloading...")
                path.unlink()
        else:
            return True

    existing_bytes = part_path.stat().st_size if part_path.exists() else 0
    headers: Dict[str, str] = {}
    if existing_bytes > 0:
        headers["Range"] = f"bytes={existing_bytes}-"

    try:
        req = requests.get(url, headers=headers, stream=True, timeout=timeout)

        if req.status_code == 416:
            # Range not satisfiable -> Part file already >= remote size
            if expected_sha256 and compute_sha256(part_path).lower() == expected_sha256.lower():
                part_path.rename(path)
                return True
            else:
                part_path.unlink(missing_ok=True)
                req = requests.get(url, stream=True, timeout=timeout)
                existing_bytes = 0

        req.raise_for_status()

        write_mode = "ab" if req.status_code == 206 else "wb"
        if req.status_code == 200:
            existing_bytes = 0

        total_size = (
            int(req.headers.get("content-length", 0)) + existing_bytes
            if "content-length" in req.headers
            else None
        )

        pbar = None
        if not quiet:
            if HAS_TQDM:
                pbar = tqdm(
                    total=total_size,
                    initial=existing_bytes,
                    unit="B",
                    unit_scale=True,
                    unit_divisor=1024,
                    desc=path.name,
                )
            else:
                print(f"[DOWNLOAD] Starting stream for {path.name} (Total: {total_size or 'unknown'} bytes)...")

        downloaded = existing_bytes
        last_log_time = datetime.datetime.now()

        with open(part_path, write_mode) as f:
            for chunk in req.iter_content(chunk_size=65536):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if pbar:
                        pbar.update(len(chunk))
                    elif not quiet and total_size:
                        now = datetime.datetime.now()
                        if (now - last_log_time).total_seconds() > 5.0:
                            pct = (downloaded / total_size) * 100
                            print(f"[{path.name}] {downloaded / (1024*1024):.1f}MB / {total_size / (1024*1024):.1f}MB ({pct:.1f}%)")
                            last_log_time = now

        if pbar:
            pbar.close()

        # Check integrity before finalizing
        if expected_sha256:
            actual_hash = compute_sha256(part_path)
            if actual_hash.lower() != expected_sha256.lower():
                part_path.unlink(missing_ok=True)
                raise ChecksumMismatchError(
                    f"Checksum mismatch for {path.name}!\nExpected: {expected_sha256}\nGot:      {actual_hash}"
                )

        # Atomic promotion to final target
        if path.exists():
            path.unlink()
        part_path.rename(path)
        return True

    except Exception as exc:
        if isinstance(exc, ChecksumMismatchError):
            raise
        raise DownloadFailureError(f"HTTP download failed for {url}: {exc}") from exc


def safe_extract_zip(
    zip_path: Union[str, Path],
    dest_dir: Union[str, Path],
    members: Optional[List[str]] = None,
    quiet: bool = False,
) -> List[Path]:
    """
    Safely extract files from a zip archive, strictly guarding against Zip Slip traversal.

    Args:
        zip_path: Path to zip file.
        dest_dir: Target extraction directory.
        members: Optional list of specific member filenames to extract.
        quiet: If True, suppress extraction logs.

    Returns:
        List of extracted file Paths.
    """
    zpath = Path(zip_path)
    out_dir = Path(dest_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    extracted_paths: List[Path] = []

    with zipfile.ZipFile(zpath, "r") as zf:
        for member in zf.infolist():
            if member.is_dir():
                continue
            base_name = Path(member.filename).name
            if members and base_name not in members and member.filename not in members:
                continue

            target_dest = (out_dir / base_name).resolve()
            # Guard against Zip Slip
            if not str(target_dest).startswith(str(out_dir)):
                raise ValueError(f"Security error: Zip member {member.filename} attempts path traversal!")

            with zf.open(member) as source_f, open(target_dest, "wb") as dest_f:
                while chunk := source_f.read(65536):
                    dest_f.write(chunk)

            if not quiet:
                print(f"[EXTRACT] Extracted: {target_dest.name}")
            extracted_paths.append(target_dest)

    return extracted_paths


def download_via_kaggle(
    output_dir: Union[str, Path], quiet: bool = False
) -> bool:
    """
    Acquire dataset slices via Kaggle CLI integration fallback.

    Args:
        output_dir: Target destination directory.
        quiet: If True, suppress non-essential output.

    Returns:
        True if Kaggle download succeeded, False otherwise.
    """
    import subprocess
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        "kaggle",
        "datasets",
        "download",
        "-d",
        KAGGLE_DATASET_ID,
        "-p",
        str(out_dir),
        "--unzip",
    ]
    if not quiet:
        print(f"[KAGGLE] Invoking: {' '.join(cmd)}")

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode == 0:
            if not quiet:
                print("[KAGGLE] Successfully downloaded and unzipped dataset.")
            return True
        else:
            if not quiet:
                print(f"[KAGGLE ERROR] Kaggle CLI returned code {res.returncode}: {res.stderr}")
            return False
    except FileNotFoundError:
        if not quiet:
            print("[KAGGLE] Kaggle CLI tool not found on system PATH.")
        return False


# ==============================================================================
# Top-Level Orchestration & Acquisition Engine
# ==============================================================================

def acquire_dataset(
    subsets: List[str],
    output_dir: Union[str, Path],
    source: str = "auto",
    verify_checksum: bool = False,
    offline_mock: bool = False,
    dry_run: bool = False,
    force: bool = False,
    seed: int = 42,
    rows_per_subset: int = 250,
    quiet: bool = False,
) -> int:
    """
    Execute full dataset acquisition, synthetic generation, or verification pipeline.

    Returns:
        Exit code: 0 on success, 1 on verification/download failure, 2 on usage error.
    """
    out_dir = Path(output_dir)

    # 1. Resolve requested subset files
    target_filenames: List[Tuple[str, str]] = []  # List of (subset_key, filename)

    for sub in subsets:
        s_clean = sub.lower().strip()
        if s_clean == "all":
            for canon_key in SUBSET_CANONICAL_KEYS:
                fname = DAY_SUBSET_ALIASES[canon_key]
                if (canon_key, fname) not in target_filenames:
                    target_filenames.append((canon_key, fname))
        elif s_clean in DAY_SUBSET_ALIASES:
            fname = DAY_SUBSET_ALIASES[s_clean]
            if (s_clean, fname) not in target_filenames:
                target_filenames.append((s_clean, fname))
        else:
            if not quiet:
                print(f"[ERROR] Unknown subset alias: '{sub}'. Valid options: {', '.join(VALID_SUBSETS)}")
            return 2

    # 2. Dry-Run Execution Plan
    if dry_run:
        print("\n" + "=" * 96)
        print("CICIDS2017 Dataset Acquisition — Dry Run Execution Plan")
        print("=" * 96)
        print(f"Source Mode     : {source} {'(Offline Mock)' if offline_mock or source in ('synthetic', 'mock') else ''}")
        print(f"Output Directory: {out_dir.resolve()}")
        print(f"Random Seed     : {seed}")
        print(f"Rows per Subset : {rows_per_subset}")
        print("-" * 96)
        print(f"{'#':<3} | {'Subset Key':<22} | {'Filename':<50} | {'Expected SHA-256'}")
        print("-" * 96)
        for idx, (s_key, fname) in enumerate(target_filenames, 1):
            exp_hash = CICIDS2017_SHA256_CATALOG.get(fname, "N/A (Synthetic)")
            hash_display = exp_hash[:16] + "..." if exp_hash != "N/A (Synthetic)" else exp_hash
            print(f"{idx:<3} | {s_key:<22} | {fname:<50} | {hash_display}")
        print("=" * 96)
        print("Plan validated. 0 network calls or disk writes will be made. Exiting with code 0.\n")
        return 0

    # 3. Offline Synthetic Mock Mode
    if offline_mock or source in ("synthetic", "mock"):
        out_dir.mkdir(parents=True, exist_ok=True)
        generator = CICIDS2017SyntheticGenerator(seed=seed)

        if not quiet:
            print(f"\n[SYNTHETIC] Generating {len(target_filenames)} offline miniature dataset slice(s)...")

        for s_key, fname in target_filenames:
            dest_file = out_dir / fname
            if dest_file.exists() and not force:
                if not quiet:
                    print(f"[EXISTS] {fname} already present. (Use --force to overwrite)")
                continue
            generator.generate_subset_csv(s_key, dest_file, row_count=rows_per_subset)
            if not quiet:
                print(f"[GEN] Generated {fname} ({rows_per_subset} rows) -> {dest_file}")

        if verify_checksum:
            verify_checksums(out_dir, [f for _, f in target_filenames], quiet=quiet)

        return 0

    # 4. Standalone Checksum Verification Mode (if source != remote download and no downloads needed)
    # Check if files are already local or if remote download is requested
    need_download = []
    for s_key, fname in target_filenames:
        dest_file = out_dir / fname
        if not dest_file.exists() or force:
            need_download.append((s_key, fname))

    if not need_download and verify_checksum:
        # All files already present locally, verify them
        all_passed = verify_checksums(out_dir, [f for _, f in target_filenames], quiet=quiet)
        return 0 if all_passed else 1

    # 5. Remote Acquisition (UNB Mirror / Kaggle Fallback)
    out_dir.mkdir(parents=True, exist_ok=True)

    if source in ("unb", "auto"):
        master_zip_path = out_dir / "GeneratedLabelledFlows.zip"
        expected_zip_hash = CICIDS2017_SHA256_CATALOG.get("GeneratedLabelledFlows.zip")
        try:
            if not quiet:
                print(f"[UNB] Fetching master archive from UNB ISCX mirror: {OFFICIAL_MASTER_ZIP_URL}")
            download_file_with_resume(
                OFFICIAL_MASTER_ZIP_URL,
                master_zip_path,
                expected_sha256=expected_zip_hash,
                quiet=quiet,
            )
            # Extract requested members
            req_fnames = [fname for _, fname in target_filenames]
            safe_extract_zip(master_zip_path, out_dir, members=req_fnames, quiet=quiet)

            if verify_checksum:
                all_passed = verify_checksums(out_dir, req_fnames, quiet=quiet)
                return 0 if all_passed else 1
            return 0

        except Exception as exc:
            if not quiet:
                print(f"[WARN] UNB Mirror download failed: {exc}")
            if source == "auto":
                if not quiet:
                    print("[FALLBACK] Attempting Kaggle CLI retrieval...")
                if download_via_kaggle(out_dir, quiet=quiet):
                    if verify_checksum:
                        all_passed = verify_checksums(out_dir, [f for _, f in target_filenames], quiet=quiet)
                        return 0 if all_passed else 1
                    return 0

            return 1

    elif source == "kaggle":
        if download_via_kaggle(out_dir, quiet=quiet):
            if verify_checksum:
                all_passed = verify_checksums(out_dir, [f for _, f in target_filenames], quiet=quiet)
                return 0 if all_passed else 1
            return 0
        return 1

    return 0


# ==============================================================================
# Argument Parsing and CLI Engine
# ==============================================================================

def build_argument_parser() -> argparse.ArgumentParser:
    """Construct and return the authoritative ArgumentParser for download_cicids2017.py."""
    parser = argparse.ArgumentParser(
        prog="download_cicids2017",
        description="Acquire, verify, and generate CICIDS2017 benchmark datasets for AI forecasting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate deterministic offline mock files for testing:
  python ai/datasets/download_cicids2017.py --subset sample --offline-mock --output-dir ./sample_data/

  # Generate all 8 day-slices synthetically:
  python ai/datasets/download_cicids2017.py --subset all --offline-mock --output-dir ./ai/datasets/cicids2017/

  # Dry-run download of Friday DDoS slice:
  python ai/datasets/download_cicids2017.py --subset friday_ddos --dry-run

  # Download and verify checksum of Wednesday DoS slice:
  python ai/datasets/download_cicids2017.py --subset wednesday_dos --verify-checksum --output-dir ./data/
        """,
    )

    parser.add_argument(
        "-s",
        "--subset",
        "--days",
        dest="subset",
        type=str,
        default="sample",
        help=f"Dataset subset(s) to process. Choices: {', '.join(VALID_SUBSETS)} or comma-separated list (default: 'sample').",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=str,
        default="./ai/datasets/cicids2017/",
        help="Destination directory for CSV dataset files (default: './ai/datasets/cicids2017/').",
    )
    parser.add_argument(
        "-u",
        "--source",
        type=str,
        choices=VALID_SOURCES,
        default="auto",
        help="Data acquisition source ('auto', 'unb', 'kaggle', 'mirror_s3', 'synthetic', 'mock') (default: 'auto').",
    )
    parser.add_argument(
        "-c",
        "--verify-checksum",
        action="store_true",
        default=False,
        help="Verify SHA-256 checksums of acquired/existing files against the embedded manifest.",
    )
    parser.add_argument(
        "-m",
        "--offline-mock",
        "--synthetic",
        dest="offline_mock",
        action="store_true",
        default=False,
        help="Generate deterministic synthetic miniature CSV files locally without external network access.",
    )
    parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        default=False,
        help="Simulate execution, print summary table and checksums without writing files or downloading.",
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        default=False,
        help="Force overwrite of existing files in the output directory.",
    )
    parser.add_argument(
        "-r",
        "--seed",
        type=int,
        default=42,
        help="Random seed for deterministic synthetic flow generation (default: 42).",
    )
    parser.add_argument(
        "-n",
        "--rows-per-subset",
        type=int,
        default=250,
        help="Number of synthetic flow records to generate per subset file (default: 250).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable detailed debug logging to stdout.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=False,
        help="Suppress informational output (only errors will be logged).",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """
    Main CLI entry point for download_cicids2017.py.

    Args:
        argv: Optional list of command-line argument strings.

    Returns:
        Exit code: 0 for success, 1 for operational/hash failure, 2 for argument/usage error.
    """
    parser = build_argument_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        # argparse raises SystemExit on help (0) or syntax error (2)
        return e.code if isinstance(e.code, int) else 2

    # Parse comma-separated subsets
    subsets = [s.strip() for s in args.subset.split(",") if s.strip()]
    if not subsets:
        subsets = ["sample"]

    # Validate subset arguments early
    for sub in subsets:
        s_clean = sub.lower().strip()
        if s_clean != "all" and s_clean not in DAY_SUBSET_ALIASES:
            print(f"[ERROR] Invalid subset alias: '{sub}'.")
            print(f"Valid choices are: {', '.join(VALID_SUBSETS)}")
            return 2

    # If invoked only with --verify-checksum and no files exist in output-dir, check for standalone mode
    if args.verify_checksum and not args.offline_mock and args.source == "auto" and not args.force:
        out_path = Path(args.output_dir)
        # Check if output dir has any files
        has_any_file = False
        if out_path.exists():
            for f in out_path.iterdir():
                if f.is_file() and f.name in CICIDS2017_SHA256_CATALOG:
                    has_any_file = True
                    break

        # If user explicitly requested verify and no files exist at all
        if not has_any_file and not args.dry_run:
            # Let acquire_dataset run normal download or report failure
            pass

    return acquire_dataset(
        subsets=subsets,
        output_dir=args.output_dir,
        source=args.source,
        verify_checksum=args.verify_checksum,
        offline_mock=args.offline_mock,
        dry_run=args.dry_run,
        force=args.force,
        seed=args.seed,
        rows_per_subset=args.rows_per_subset,
        quiet=args.quiet,
    )


if __name__ == "__main__":
    sys.exit(main())
