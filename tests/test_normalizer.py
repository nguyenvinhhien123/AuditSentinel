
from pathlib import Path
import shutil

import polars as pl

from src.training.normalizer import (
    normalize_records,
    normalize_record,
    save_normalized_parquet,
)


def main():
    print("=" * 55)
    print("          AuditSentinel DATA NORMALIZER TEST")
    print("=" * 55)

    # TEST 1: Normalize column names.
    print("\n[TEST 1] Column Name Normalization")

    record = {
        "User Name": "admin",
        "SQL Action": " LOGIN ",
        "Event Status": " SUCCESS ",
    }

    result = normalize_record(record)

    assert "user_name" in result
    assert "sql_action" in result
    assert result["sql_action"] == "login"
    assert result["event_status"] == " SUCCESS ".strip().lower()

    print("[PASS] Column Name Normalization")

    # TEST 2: Normalize missing values.
    print("\n[TEST 2] Missing Value Normalization")

    records = [
        {"username": "admin", "status": "N/A"},
        {"username": "guest", "status": "NULL"},
        {"username": "root", "status": ""},
    ]

    result = normalize_records(records)

    assert result[0]["status"] is None
    assert result[1]["status"] is None
    assert result[2]["status"] is None

    print("[PASS] Missing Value Normalization")

    # TEST 3: Normalize IP addresses.
    print("\n[TEST 3] IP Address Normalization")

    records = [
        {"src_ip": "192.168.1.10"},
        {"src_ip": "2001:db8::1"},
        {"src_ip": "invalid-ip"},
    ]

    result = normalize_records(records)

    assert result[0]["src_ip"] == "192.168.1.10"
    assert result[1]["src_ip"] == "2001:db8::1"
    assert result[2]["src_ip"] == "invalid-ip"

    print("[PASS] IP Address Normalization")

    # TEST 4: Normalize timestamps.
    print("\n[TEST 4] Timestamp Normalization")

    records = [
        {"timestamp": "2026-10-30T10:00:00+07:00"},
    ]

    result = normalize_records(records)

    assert result[0]["timestamp"] == "2026-10-30T03:00:00Z"

    print("[PASS] Timestamp Normalization")

    # TEST 5: Preserve original records.
    print("\n[TEST 5] Original Data Preservation")

    original = {
        "SQL Action": " LOGIN ",
        "Source IP": "192.168.1.10",
    }

    original_copy = original.copy()

    normalize_record(original)

    assert original == original_copy

    print("[PASS] Original Data Preservation")

    # TEST 6: Save normalized data to Parquet.
    print("\n[TEST 6] Parquet Export")

    output_path = Path(
        "dataset/processed/normalizer_test.parquet"
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)

    records = normalize_records([
        {
            "User Name": "admin",
            "SQL Action": "LOGIN",
            "Source IP": "192.168.1.10",
        },
        {
            "User Name": "guest",
            "SQL Action": "LOGOUT",
            "Source IP": "192.168.1.20",
        },
    ])

    result = save_normalized_parquet(records, output_path)

    assert result["status"] == "SAVED"
    assert output_path.exists()

    loaded = pl.read_parquet(output_path)

    assert loaded.height == 2
    assert "user_name" in loaded.columns
    assert "sql_action" in loaded.columns

    print("[PASS] Parquet Export")

    print("\n" + "=" * 55)
    print("ALL NORMALIZER TESTS PASSED")
    print("=" * 55)


if __name__ == "__main__":
    main()
