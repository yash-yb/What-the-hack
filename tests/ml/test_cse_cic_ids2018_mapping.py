import pandas as pd

from ai.datasets.download_cicids2017 import map_cicids_to_raw_flows


def test_cse_cic_ids2018_abbreviated_headers_and_labels_normalize_without_data_loss():
    source = pd.DataFrame([{
        "Src IP": "10.0.0.1", "Dst IP": "10.0.0.2", "Src Port": 50000, "Dst Port": 80,
        "Protocol": 6, "Timestamp": "14/02/2018 10:00:00", "Flow Duration": 125000,
        "Tot Fwd Pkts": 3, "Tot Bwd Pkts": 2, "TotLen Fwd Pkts": 300, "TotLen Bwd Pkts": 200,
        "Label": "DoS attacks-Hulk",
    }])
    normalized = map_cicids_to_raw_flows(source)
    row = normalized.iloc[0]
    assert row["src_ip"] == "10.0.0.1" and row["dst_ip"] == "10.0.0.2"
    assert row["packets"] == 5 and row["bytes"] == 500 and row["duration_ms"] == 125
    assert row["label"] == "DoS_Hulk"
