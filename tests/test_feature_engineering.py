
from src.training.feature_engineering import (
    extract_features,
    transform_records,
)


def main():
    print("=" * 55)
    print("       AuditSentinel FEATURE ENGINEERING TEST")
    print("=" * 55)

    # TEST 1: Normal SELECT query.
    print("\n[TEST 1] SQL Feature Extraction")

    record = {
        "username": "admin",
        "src_ip": "192.168.1.10",
        "timestamp": "2026-10-30T10:30:00Z",
        "sql_action": "SELECT",
        "query": "SELECT * FROM users WHERE id=1",
        "status": "success",
    }

    features = extract_features(record)

    assert features["sql_action_code"] == 1
    assert features["has_where"] == 1
    assert features["query_length"] > 0

    print("[PASS] SQL Feature Extraction")

    # TEST 2: Suspicious SQL indicators.
    print("\n[TEST 2] Suspicious SQL Indicators")

    record = {
        "query": "SELECT * FROM users UNION SELECT * FROM accounts",
    }

    features = extract_features(record)

    assert features["has_union"] == 1

    print("[PASS] Suspicious SQL Indicators")

    # TEST 3: Failed authentication.
    print("\n[TEST 3] Authentication Status")

    record = {
        "username": "admin",
        "status": "login failed",
    }

    features = extract_features(record)

    assert features["is_failed"] == 1
    assert features["username_present"] == 1

    print("[PASS] Authentication Status")

    # TEST 4: Timestamp extraction.
    print("\n[TEST 4] Timestamp Features")

    record = {
        "timestamp": "2026-10-30T23:00:00Z",
    }

    features = extract_features(record)

    assert features["timestamp_valid"] == 1
    assert features["hour_utc"] == 23
    assert features["is_night"] == 1

    print("[PASS] Timestamp Features")

    # TEST 5: Invalid timestamp.
    print("\n[TEST 5] Invalid Timestamp")

    record = {
        "timestamp": "not-a-timestamp",
    }

    features = extract_features(record)

    assert features["timestamp_valid"] == 0

    print("[PASS] Invalid Timestamp")

    # TEST 6: Batch transformation.
    print("\n[TEST 6] Batch Transformation")

    records = [
        {
            "sql_action": "SELECT",
            "query": "SELECT * FROM users",
        },
        {
            "sql_action": "DELETE",
            "query": "DELETE FROM users WHERE id=1",
        },
    ]

    result = transform_records(records)

    assert len(result) == 2
    assert result[0]["sql_action_code"] == 1
    assert result[1]["sql_action_code"] == 4

    print("[PASS] Batch Transformation")

    # TEST 7: No automatic attack labels.
    print("\n[TEST 7] No Automatic Attack Labels")

    assert all(
        "label" not in row and "is_attack" not in row
        for row in result
    )

    print("[PASS] No Automatic Attack Labels")

    print("\n" + "=" * 55)
    print("ALL FEATURE ENGINEERING TESTS PASSED")
    print("=" * 55)

# TEST 8: TRUNCATE SQL action.
    print("\n[TEST 8] TRUNCATE SQL Action")

    record = {
        "sql_action": "TRUNCATE",
        "query": "TRUNCATE TABLE users",
    }

    features = extract_features(record)

    assert features["sql_action_code"] == 11

    print("[PASS] TRUNCATE SQL Action")
    
if __name__ == "__main__":
    main()
