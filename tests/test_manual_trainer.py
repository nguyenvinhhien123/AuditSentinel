
from pathlib import Path

from src.training.manual_trainer import manual_train


def create_records(count=120, include_labels=True):
    records = []

    for index in range(count):
        is_attack = index % 2 == 1

        if is_attack:
            query = "SELECT * FROM users UNION SELECT * FROM accounts"
            status = "failed"
            label = "attack"
        else:
            query = "SELECT id, name FROM users WHERE id=10"
            status = "success"
            label = "normal"

        record = {
            "username": f"user_{index % 10}",
            "src_ip": f"192.168.1.{(index % 200) + 1}",
            "timestamp": f"2026-10-30T{index % 24:02d}:30:00Z",
            "sql_action": "SELECT",
            "query": query,
            "status": status,
        }

        if include_labels:
            record["label"] = label

        records.append(record)

    return records


def main():
    print("=" * 60)
    print("          AuditSentinel MANUAL TRAINER TEST")
    print("=" * 60)

    output_dir = Path("dataset/samples/manual_training_models")

    # TEST 1: Supervised Manual Training
    print("\n[TEST 1] Manual Random Forest Training")

    records = create_records()

    result = manual_train(
        records=records,
        mode="supervised",
        label_column="label",
        output_dir=output_dir / "supervised",
        n_estimators=150,
        max_depth=10,
        test_size=0.2,
        cpu_threads=2,
    )

    print("Algorithm:", result["algorithm"])
    print("Parameters:", result["metadata"]["parameters"])
    print("Accuracy:", result["metrics"]["accuracy"])

    assert result["status"] == "TRAINED"
    assert result["algorithm"] == "RandomForestClassifier"
    assert result["metadata"]["parameters"]["n_estimators"] == 150
    assert Path(result["model_path"]).exists()
    assert Path(result["metadata_path"]).exists()

    print("[PASS] Manual Random Forest Training")

    # TEST 2: Unsupervised Manual Training
    print("\n[TEST 2] Manual Isolation Forest Training")

    records = create_records(include_labels=False)

    result = manual_train(
        records=records,
        mode="unsupervised",
        output_dir=output_dir / "unsupervised",
        n_estimators=120,
        contamination=0.08,
        test_size=0.2,
        cpu_threads=2,
    )

    print("Algorithm:", result["algorithm"])
    print("Evaluation:", result["evaluation"])

    assert result["status"] == "TRAINED"
    assert result["algorithm"] == "IsolationForest"
    assert result["metadata"]["parameters"]["n_estimators"] == 120
    assert Path(result["model_path"]).exists()

    print("[PASS] Manual Isolation Forest Training")

    # TEST 3: Missing Label Protection
    print("\n[TEST 3] Missing Label Protection")

    records = create_records()
    records[0]["label"] = None

    try:
        manual_train(
            records=records,
            mode="supervised",
            label_column="label",
            output_dir=output_dir / "invalid",
        )
        raise AssertionError("Missing labels should be rejected")

    except ValueError as exc:
        assert "Missing labels" in str(exc)

    print("[PASS] Missing Label Protection")

    # TEST 4: Invalid Parameter Protection
    print("\n[TEST 4] Invalid Parameter Protection")

    try:
        manual_train(
            records=create_records(),
            mode="supervised",
            label_column="label",
            n_estimators=5,
            output_dir=output_dir / "invalid_parameters",
        )
        raise AssertionError("Invalid n_estimators should be rejected")

    except ValueError as exc:
        assert "n_estimators" in str(exc)

    print("[PASS] Invalid Parameter Protection")

    # TEST 5: Invalid Training Mode
    print("\n[TEST 5] Invalid Mode Protection")

    try:
        manual_train(
            records=create_records(),
            mode="unknown",
            output_dir=output_dir / "invalid_mode",
        )
        raise AssertionError("Invalid mode should be rejected")

    except ValueError as exc:
        assert "mode must be" in str(exc)

    print("[PASS] Invalid Mode Protection")

    print("\n" + "=" * 60)
    print("ALL MANUAL TRAINER TESTS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    main()
