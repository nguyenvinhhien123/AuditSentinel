
from pathlib import Path
import shutil

from src.training.auto_trainer import auto_train
from src.registry.model_registry import ModelRegistry
from src.detection.engine import DetectionEngine


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
    print("          AuditSentinel DETECTION ENGINE TEST")
    print("=" * 60)

    base_dir = Path("dataset/samples/detection_engine_test")

    if base_dir.exists():
        shutil.rmtree(base_dir)

    base_dir.mkdir(parents=True, exist_ok=True)

    registry = ModelRegistry(
        registry_path=base_dir / "registry.json"
    )

    engine = DetectionEngine(registry)

    # TEST 1: Reject detection when no model is active.
    print("\n[TEST 1] No Active Model Protection")

    try:
        engine.detect({
            "query": "SELECT * FROM users",
        })

        raise AssertionError("Detection without a model should fail")

    except RuntimeError as exc:
        assert "No active detection model" in str(exc)

    print("[PASS] No Active Model Protection")

    # TEST 2: Train and register supervised model.
    print("\n[TEST 2] Register Supervised Model")

    training_records = create_records(
        count=120,
        include_labels=True,
    )

    training_result = auto_train(
        records=training_records,
        label_column="label",
        output_dir=base_dir / "supervised_model",
        cpu_threads=2,
    )

    registration = registry.register_model(
        training_result["model_path"],
        name="Detection Test Supervised Model",
    )

    assert registration["status"] == "REGISTERED"

    registry.activate_model(registration["model_id"])

    print("[PASS] Register Supervised Model")

    # TEST 3: Detect one record.
    print("\n[TEST 3] Single Record Detection")

    record = {
        "username": "admin",
        "src_ip": "192.168.1.10",
        "timestamp": "2026-10-30T23:30:00Z",
        "sql_action": "SELECT",
        "query": "SELECT * FROM users UNION SELECT * FROM accounts",
        "status": "failed",
    }

    result = engine.detect(record)

    print("Prediction:", result["predicted_label"])
    print("Verdict:", result["verdict"])
    print("Confidence:", result["confidence"])

    assert result["mode"] == "supervised"
    assert result["verdict"] in {
        "SUSPICIOUS",
        "NORMAL",
        "REVIEW",
    }
    assert 0 <= result["confidence"] <= 1

    print("[PASS] Single Record Detection")

    # TEST 4: Detect a batch.
    print("\n[TEST 4] Batch Detection")

    batch = create_records(
        count=20,
        include_labels=False,
    )

    batch_result = engine.detect_batch(batch)

    print("Records:", batch_result["records_analyzed"])
    print("Alerts:", batch_result["alerts"])

    assert batch_result["status"] == "COMPLETED"
    assert batch_result["records_analyzed"] == 20
    assert len(batch_result["results"]) == 20
    assert batch_result["alerts"] <= 20

    print("[PASS] Batch Detection")

    # TEST 5: Handle unknown predicted labels safely.
    print("\n[TEST 5] Unknown Label Handling")

    assert (
        DetectionEngine._classify_supervised_label("unclassified")
        == "REVIEW"
    )

    print("[PASS] Unknown Label Handling")

    # TEST 6: Register and activate an unsupervised model.
    print("\n[TEST 6] Unsupervised Detection")

    unlabeled_records = create_records(
        count=120,
        include_labels=False,
    )

    unsupervised_training = auto_train(
        records=unlabeled_records,
        label_column=None,
        output_dir=base_dir / "unsupervised_model",
        cpu_threads=2,
    )

    unsupervised_registration = registry.register_model(
        unsupervised_training["model_path"],
        name="Detection Test Isolation Forest",
    )

    registry.activate_model(
        unsupervised_registration["model_id"]
    )

    unsupervised_result = engine.detect_batch(
        unlabeled_records[:15],
        mode="unsupervised",
    )

    assert unsupervised_result["status"] == "COMPLETED"
    assert unsupervised_result["mode"] == "unsupervised"
    assert len(unsupervised_result["results"]) == 15
    assert all(
        "anomaly_score" in item
        for item in unsupervised_result["results"]
    )
    assert all(
        "risk_score" in item
        and (
            item["risk_score"] is None
            or 0 <= item["risk_score"] <= 100
        )
        for item in unsupervised_result["results"]
    )

    print("[PASS] Unsupervised Detection")

    # TEST 7: Reject invalid input.
    print("\n[TEST 7] Invalid Input Protection")

    try:
        engine.detect_batch([])
        raise AssertionError("Empty batch should be rejected")

    except ValueError as exc:
        assert "non-empty list" in str(exc)

    print("[PASS] Invalid Input Protection")

    # TEST 8: Detect model tampering.
    print("\n[TEST 8] Model Integrity Protection")

    active_model = registry.get_active_model("unsupervised")
    model_path = (
        registry.project_root / active_model["model_path"]
    )

    original_bytes = model_path.read_bytes()

    try:
        model_path.write_bytes(original_bytes + b"TAMPERED")

        try:
            engine.detect_batch(
                unlabeled_records[:5],
                mode="unsupervised",
            )

            raise AssertionError(
                "Tampered model should not be used"
            )

        except RuntimeError as exc:
            assert "integrity" in str(exc).lower()

    finally:
        model_path.write_bytes(original_bytes)

    # Confirm that detection works after restoration.
    restored_result = engine.detect_batch(
        unlabeled_records[:5],
        mode="unsupervised",
    )

    assert restored_result["status"] == "COMPLETED"

    print("[PASS] Model Integrity Protection")

    print("\n" + "=" * 60)
    print("ALL DETECTION ENGINE TESTS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    main()
