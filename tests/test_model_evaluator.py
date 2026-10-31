
from pathlib import Path
import shutil

from src.training.auto_trainer import auto_train
from src.training.manual_trainer import manual_train
from src.training.model_evaluator import (
    evaluate_saved_model,
    compare_saved_models,
)


def create_records(start=0, count=120, include_labels=True):
    records = []

    for index in range(start, start + count):
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
    print("        AuditSentinel MODEL EVALUATOR TEST")
    print("=" * 60)

    base_dir = Path("dataset/samples/model_evaluator_test")

    if base_dir.exists():
        shutil.rmtree(base_dir)

    # Separate training and evaluation records.
    training_records = create_records(
        start=0,
        count=120,
        include_labels=True,
    )

    evaluation_records = create_records(
        start=1000,
        count=40,
        include_labels=True,
    )

    # TEST 1: Create Auto supervised model.
    print("\n[TEST 1] Create Auto Supervised Model")

    auto_result = auto_train(
        records=training_records,
        label_column="label",
        output_dir=base_dir / "auto_supervised",
        cpu_threads=2,
    )

    assert auto_result["status"] == "TRAINED"
    print("[PASS] Create Auto Supervised Model")

    # TEST 2: Create Manual supervised model.
    print("\n[TEST 2] Create Manual Supervised Model")

    manual_result = manual_train(
        records=training_records,
        mode="supervised",
        label_column="label",
        output_dir=base_dir / "manual_supervised",
        n_estimators=120,
        max_depth=10,
        cpu_threads=2,
    )

    assert manual_result["status"] == "TRAINED"
    print("[PASS] Create Manual Supervised Model")

    # TEST 3: Evaluate a saved supervised model.
    print("\n[TEST 3] Evaluate Supervised Model")

    evaluation = evaluate_saved_model(
        model_path=auto_result["model_path"],
        records=evaluation_records,
    )

    print("Accuracy:", evaluation["metrics"]["accuracy"])
    print("F1:", evaluation["metrics"]["f1_weighted"])

    assert evaluation["status"] == "EVALUATED"
    assert evaluation["mode"] == "supervised"
    assert "f1_weighted" in evaluation["metrics"]

    print("[PASS] Evaluate Supervised Model")

    # TEST 4: Compare Auto and Manual supervised models.
    print("\n[TEST 4] Compare Supervised Models")

    comparison = compare_saved_models(
        model_paths=[
            auto_result["model_path"],
            manual_result["model_path"],
        ],
        records=evaluation_records,
        report_path=base_dir / "supervised_comparison.json",
    )

    print("Comparison:", comparison["comparison"])

    assert comparison["status"] == "COMPLETED"
    assert comparison["comparison"]["best_model"] is not None
    assert Path(comparison["report_path"]).exists()

    print("[PASS] Compare Supervised Models")

    # TEST 5: Evaluate unsupervised model.
    print("\n[TEST 5] Evaluate Unsupervised Model")

    unlabeled_training = create_records(
        start=0,
        count=120,
        include_labels=False,
    )

    unlabeled_evaluation = create_records(
        start=1000,
        count=40,
        include_labels=False,
    )

    unsupervised_result = auto_train(
        records=unlabeled_training,
        label_column=None,
        output_dir=base_dir / "auto_unsupervised",
        cpu_threads=2,
    )

    unsupervised_evaluation = evaluate_saved_model(
        model_path=unsupervised_result["model_path"],
        records=unlabeled_evaluation,
    )

    assert unsupervised_evaluation["status"] == "EVALUATED"
    assert unsupervised_evaluation["mode"] == "unsupervised"
    assert "anomaly_rate" in unsupervised_evaluation["evaluation"]

    print("[PASS] Evaluate Unsupervised Model")

    # TEST 6: Compare two unsupervised models descriptively.
    print("\n[TEST 6] Compare Unsupervised Models")

    manual_unsupervised = manual_train(
        records=unlabeled_training,
        mode="unsupervised",
        output_dir=base_dir / "manual_unsupervised",
        n_estimators=120,
        contamination=0.08,
        cpu_threads=2,
    )

    unsupervised_comparison = compare_saved_models(
        model_paths=[
            unsupervised_result["model_path"],
            manual_unsupervised["model_path"],
        ],
        records=unlabeled_evaluation,
        report_path=base_dir / "unsupervised_comparison.json",
    )

    assert unsupervised_comparison["status"] == "COMPLETED"
    assert (
        unsupervised_comparison["comparison"]["best_model"]
        is None
    )

    print("[PASS] Compare Unsupervised Models")

    # TEST 7: Reject mixed model modes.
    print("\n[TEST 7] Reject Mixed Model Modes")

    try:
        compare_saved_models(
            model_paths=[
                auto_result["model_path"],
                unsupervised_result["model_path"],
            ],
            records=evaluation_records,
            report_path=base_dir / "invalid_comparison.json",
        )

        raise AssertionError("Mixed model modes should be rejected")

    except ValueError as exc:
        assert "Cannot compare" in str(exc)

    print("[PASS] Reject Mixed Model Modes")

    print("\n" + "=" * 60)
    print("ALL MODEL EVALUATOR TESTS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    main()
