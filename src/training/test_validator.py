
from pathlib import Path

from src.reader.parser import parse_file
from src.training.validator import (
    validate_records,
    validate_parsed_data,
)


def main():
    print("=" * 55)
    print("          AuditSentinel DATA VALIDATOR TEST")
    print("=" * 55)

    # TEST 1: Missing values.
    print("\n[TEST 1] Missing Values")

    records = [
        {"username": "admin", "action": "login"},
        {"username": "guest", "action": None},
        {"username": "", "action": "query"},
    ]

    report = validate_records(records)

    assert report["missing_by_column"]["username"]["missing"] == 1
    assert report["missing_by_column"]["action"]["missing"] == 1

    print("[PASS] Missing Values")

    # TEST 2: Duplicate records.
    print("\n[TEST 2] Duplicate Detection")

    records = [
        {"username": "admin", "action": "login"},
        {"username": "admin", "action": "login"},
        {"username": "guest", "action": "logout"},
    ]

    report = validate_records(records)

    assert report["duplicate_records"] == 1

    print("[PASS] Duplicate Detection")

    # TEST 3: Inconsistent data types.
    print("\n[TEST 3] Type Detection")

    records = [
        {"user_id": 100},
        {"user_id": 200},
        {"user_id": "unknown"},
    ]

    report = validate_records(records)

    assert "user_id" in report["inconsistent_columns"]

    print("[PASS] Type Detection")

    # TEST 4: Required columns.
    print("\n[TEST 4] Required Columns")

    records = [
        {"username": "admin", "action": "login"},
    ]

    report = validate_records(
        records,
        required_columns=["username", "action", "timestamp"]
    )

    assert "timestamp" in report["missing_required_columns"]

    print("[PASS] Required Columns")

    # TEST 5: Empty records.
    print("\n[TEST 5] Empty Records")

    records = [
        {"username": None, "action": ""},
        {"username": "admin", "action": "login"},
    ]

    report = validate_records(records)

    assert report["empty_records"] == 1

    print("[PASS] Empty Records")

    # TEST 6: Validate parser output.
    print("\n[TEST 6] Parser Integration")

    sample_file = Path("dataset/samples/validator_test.csv")
    sample_file.parent.mkdir(parents=True, exist_ok=True)

    sample_file.write_text(
        "username,action\n"
        "admin,login\n"
        "guest,logout\n"
        "admin,login\n",
        encoding="utf-8"
    )

    parsed = parse_file(sample_file)

    report = validate_parsed_data(
        parsed,
        required_columns=["username", "action"]
    )

    print("Validation status:", report["status"])
    print("Records:", report["total_records"])
    print("Duplicates:", report["duplicate_records"])

    assert report["status"] == "WARNING"
    assert report["duplicate_records"] == 1
    assert report["validation_scope"] == "PARSER_PREVIEW_ONLY"

    print("[PASS] Parser Integration")

    print("\n" + "=" * 55)
    print("ALL VALIDATOR TESTS PASSED")
    print("=" * 55)


if __name__ == "__main__":
    main()
