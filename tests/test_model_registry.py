
from pathlib import Path
import shutil

from src.training.auto_trainer import auto_train
from src.training.manual_trainer import manual_train
from src.registry.model_registry import ModelRegistry


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
    print("          AuditSentinel MODEL REGISTRY TEST")
    print("=" * 60)

    base_dir = Path("dataset/samples/model_registry_test")

    if base_dir.exists():
        shutil.rmtree(base_dir)

    base_dir.mkdir(parents=True, exist_ok=True)

    registry = ModelRegistry(
        registry_path=base_dir / "registry.json"
    )

    records = create_records()

    # TEST 1: Create Auto model and register it.
    print("\n[TEST 1] Register Auto Model")

    auto_result = auto_train(
        records=records,
        label_column="label",
        output_dir=base_dir / "auto_model",
        cpu_threads=2,
    )

    auto_registration = registry.register_model(
        auto_result["model_path"],
        name="Auto Random Forest",
    )

    assert auto_registration["status"] == "REGISTERED"
    assert auto_registration["model_id"]

    auto_id = auto_registration["model_id"]

    print("[PASS] Register Auto Model")

    # TEST 2: Register Manual model.
    print("\n[TEST 2] Register Manual Model")

    manual_result = manual_train(
        records=records,
        mode="supervised",
        label_column="label",
        output_dir=base_dir / "manual_model",
        n_estimators=120,
        max_depth=10,
        cpu_threads=2,
    )

    manual_registration = registry.register_model(
        manual_result["model_path"],
        name="Manual Random Forest",
    )

    assert manual_registration["status"] == "REGISTERED"

    manual_id = manual_registration["model_id"]

    print("[PASS] Register Manual Model")

    # TEST 3: List models.
    print("\n[TEST 3] List Registered Models")

    models = registry.list_models(mode="supervised")

    assert len(models) == 2
    assert all(
        model["mode"] == "supervised"
        for model in models
    )

    print("[PASS] List Registered Models")

    # TEST 4: Verify model checksum.
    print("\n[TEST 4] Verify Model Integrity")

    verification = registry.verify_model(auto_id)

    assert verification["valid"] is True
    assert verification["status"] == "VERIFIED"

    print("[PASS] Verify Model Integrity")

    # TEST 5: Activate model.
    print("\n[TEST 5] Activate Auto Model")

    activation = registry.activate_model(auto_id)

    assert activation["status"] == "ACTIVATED"

    active_model = registry.get_active_model("supervised")

    assert active_model["model_id"] == auto_id
    assert active_model["status"] == "active"

    print("[PASS] Activate Auto Model")

    # TEST 6: Switch active model.
    print("\n[TEST 6] Switch Active Model")

    switch = registry.activate_model(manual_id)

    assert switch["status"] == "ACTIVATED"
    assert switch["previous_model_id"] == auto_id

    active_model = registry.get_active_model("supervised")

    assert active_model["model_id"] == manual_id

    old_model = next(
        item for item in registry.list_models()
        if item["model_id"] == auto_id
    )

    assert old_model["status"] == "registered"

    print("[PASS] Switch Active Model")

    # TEST 7: Deactivate model.
    print("\n[TEST 7] Deactivate Active Model")

    result = registry.deactivate_model("supervised")

    assert result["status"] == "DEACTIVATED"
    assert registry.get_active_model("supervised") is None

    print("[PASS] Deactivate Active Model")

    # TEST 8: Reject unknown model.
    print("\n[TEST 8] Reject Unknown Model")

    try:
        registry.activate_model("unknown-model-id")
        raise AssertionError("Unknown model should be rejected")

    except KeyError:
        pass

    print("[PASS] Reject Unknown Model")

    # TEST 9: Detect modified model file.
    print("\n[TEST 9] Detect Model Tampering")

    model_file = Path(auto_result["model_path"])
    original_bytes = model_file.read_bytes()

    try:
        model_file.write_bytes(original_bytes + b"TAMPERED")

        verification = registry.verify_model(auto_id)

        assert verification["valid"] is False
        assert verification["status"] == "CHECKSUM_MISMATCH"

    finally:
        model_file.write_bytes(original_bytes)

    assert registry.verify_model(auto_id)["valid"] is True

    print("[PASS] Detect Model Tampering")

    # TEST 10: Reject path outside project.
    print("\n[TEST 10] Reject External Registry Path")

    try:
        ModelRegistry(
            registry_path=Path("..") / "outside_registry.json"
        )
        raise AssertionError("External registry path should be rejected")

    except ValueError:
        pass

    print("[PASS] Reject External Registry Path")

    print("\n" + "=" * 60)
    print("ALL MODEL REGISTRY TESTS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    main()
