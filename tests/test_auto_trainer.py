
from pathlib import Path
import shutil

from src.training.auto_trainer import auto_train


def create_synthetic_records(count=120, include_labels=True):
    """Create synthetic database audit-log records."""

    records = []

    for index in range(count):
        is_attack = index % 2 == 1

        if is_attack:
            query = (
                "SELECT * FROM users "
                "UNION SELECT * FROM accounts"
            )
            action = "SELECT"
            status = "failed"
            label = "attack"
        else:
            query = "SELECT id, name FROM users WHERE id=10"
            action = "SELECT"
            status = "success"
            label = "normal"

        record = {
            "username": f"user_{index % 10}",
            "src_ip": f"192.168.1.{(index % 200) + 1}",
            "timestamp": f"2026-10-30T{index % 24:02d}:30:00Z",
            "sql_action": action,
            "query": query,
            "status": status,
        }

        if include_labels:
            record["label"] = label

        records.append(record)

    return records


def main():
    print("=" * 60)
    print("           AuditSentinel AUTO TRAINER TEST")
    print("=" * 60)

    output_dir = Path("dataset/samples/auto_training_models")

    # TEST 1: Supervised training.
    print("\n[TEST 1] Supervised Training")

    supervised_records = create_synthetic_records(
        include_labels=True
    )

    supervised_result = auto_train(
        records=supervised_records,
        label_column="label",
        output_dir=output_dir / "supervised",
        cpu_threads=2,
        random_state=42,
    )

    print("Algorithm:", supervised_result["algorithm"])
    print("Accuracy:", supervised_result["metrics"]["accuracy"])
    print("F1:", supervised_result["metrics"]["f1_weighted"])

    assert supervised_result["status"] == "TRAINED"
    assert supervised_result["mode"] == "supervised"
    assert supervised_result["algorithm"] == "RandomForestClassifier"
    assert Path(supervised_result["model_path"]).exists()
    assert Path(supervised_result["metadata_path"]).exists()

    print("[PASS] Supervised Training")

    # TEST 2: Unsupervised training.
    print("\n[TEST 2] Unsupervised Training")

    unsupervised_records = create_synthetic_records(
        include_labels=False
    )

    unsupervised_result = auto_train(
        records=unsupervised_records,
        label_column=None,
        output_dir=output_dir / "unsupervised",
        cpu_threads=2,
        random_state=42,
        contamination=0.05,
    )

    print("Algorithm:", unsupervised_result["algorithm"])
    print("Evaluation:", unsupervised_result["evaluation"])

    assert unsupervised_result["status"] == "TRAINED"
    assert unsupervised_result["mode"] == "unsupervised"
    assert unsupervised_result["algorithm"] == "IsolationForest"
    assert Path(unsupervised_result["model_path"]).exists()

    print("[PASS] Unsupervised Training")

    # TEST 3: Reject missing labels.
    print("\n[TEST 3] Missing Label Protection")

    invalid_records = create_synthetic_records(
        include_labels=True
    )

    invalid_records[0]["label"] = None

    try:
        auto_train(
            records=invalid_records,
            label_column="label",
            output_dir=output_dir / "invalid",
        )
        raise AssertionError("Missing labels should be rejected")

    except ValueError as exc:
        assert "Missing labels" in str(exc)

    print("[PASS] Missing Label Protection")

    # TEST 4: Reject single-class labels.
    print("\n[TEST 4] Single Class Protection")

    single_class_records = create_synthetic_records(
        include_labels=True
    )

    for record in single_class_records:
        record["label"] = "normal"

    try:
        auto_train(
            records=single_class_records,
            label_column="label",
            output_dir=output_dir / "single_class",
        )
        raise AssertionError("Single-class data should be rejected")

    except ValueError as exc:
        assert "at least 2 classes" in str(exc)

    print("[PASS] Single Class Protection")

    print("\n" + "=" * 60)
    print("ALL AUTO TRAINER TESTS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    main()
