
from pathlib import Path
from datetime import datetime, timezone
import json

import joblib
import numpy as np

from src.training.auto_trainer import _build_feature_matrix
from src.training.evaluator import evaluate_classifier


def _load_trusted_artifact(model_path):
    """
    Load a model artifact created by this project.
    Never use this function on untrusted .joblib files.
    """

    path = Path(model_path)

    if not path.is_file():
        raise FileNotFoundError(f"Model file not found: {path}")

    artifact = joblib.load(path)

    if not isinstance(artifact, dict):
        raise ValueError("Invalid model artifact")

    required = {"model", "feature_names", "metadata"}

    if not required.issubset(artifact):
        raise ValueError("Model artifact is missing required fields")

    return artifact


def _align_features(records, expected_features):
    """
    Align incoming records to the feature columns used during training.
    Missing expected features are filled with zero.
    Extra incoming features are ignored.
    """

    matrix, current_features = _build_feature_matrix(records)

    feature_index = {
        name: index
        for index, name in enumerate(current_features)
    }

    aligned = np.zeros(
        (matrix.shape[0], len(expected_features)),
        dtype=np.float32,
    )

    for target_index, feature_name in enumerate(expected_features):
        source_index = feature_index.get(feature_name)

        if source_index is not None:
            aligned[:, target_index] = matrix[:, source_index]

    return aligned


def evaluate_saved_model(
    model_path,
    records,
    label_column=None,
):
    """
    Evaluate a saved model on supplied records.

    Supervised models require ground-truth labels.
    Unsupervised models report anomaly statistics only.
    """

    if not isinstance(records, list) or not records:
        raise ValueError("records must be a non-empty list")

    if not all(isinstance(record, dict) for record in records):
        raise TypeError("Every record must be a dictionary")

    artifact = _load_trusted_artifact(model_path)

    model = artifact["model"]
    feature_names = artifact["feature_names"]
    metadata = artifact["metadata"]

    mode = metadata.get("mode")

    if mode not in {"supervised", "unsupervised"}:
        raise ValueError("Unknown model training mode")

    X = _align_features(records, feature_names)

    if mode == "supervised":
        saved_label_column = metadata.get("label_column")

        selected_label = label_column or saved_label_column

        if not selected_label:
            raise ValueError("A label column is required")

        labels = [record.get(selected_label) for record in records]

        if any(
            value is None or str(value).strip() == ""
            for value in labels
        ):
            raise ValueError("Evaluation records contain missing labels")

        y_true = [str(value).strip() for value in labels]
        predictions = model.predict(X).tolist()

        metrics = evaluate_classifier(y_true, predictions)

        return {
            "status": "EVALUATED",
            "mode": "supervised",
            "algorithm": metadata.get("algorithm"),
            "model_path": str(model_path),
            "records_evaluated": len(records),
            "metrics": metrics,
        }

    predictions = model.predict(X)
    scores = model.decision_function(X)

    anomaly_count = int(np.sum(predictions == -1))
    normal_count = int(np.sum(predictions == 1))

    return {
        "status": "EVALUATED",
        "mode": "unsupervised",
        "algorithm": metadata.get("algorithm"),
        "model_path": str(model_path),
        "records_evaluated": len(records),
        "evaluation": {
            "anomaly_count": anomaly_count,
            "normal_count": normal_count,
            "anomaly_rate": round(
                anomaly_count / len(records), 4
            ),
            "mean_anomaly_score": round(
                float(np.mean(scores)), 4
            ),
            "note": (
                "Anomaly flags are not confirmed attacks. "
                "Ground-truth labels are not used."
            ),
        },
    }


def compare_saved_models(
    model_paths,
    records,
    label_column=None,
    report_path="reports/model_comparison.json",
):
    """
    Evaluate multiple saved models on the same records.

    Supervised models are ranked by weighted F1-score.
    Unsupervised models are compared descriptively only.
    """

    if not isinstance(model_paths, list) or len(model_paths) < 2:
        raise ValueError("At least two model paths are required")

    results = [
        evaluate_saved_model(
            model_path,
            records,
            label_column=label_column,
        )
        for model_path in model_paths
    ]

    modes = {result["mode"] for result in results}

    if len(modes) != 1:
        raise ValueError(
            "Cannot compare supervised and unsupervised models directly"
        )

    mode = results[0]["mode"]

    if mode == "supervised":
        ranking = sorted(
            results,
            key=lambda item: item["metrics"]["f1_weighted"],
            reverse=True,
        )

        comparison = {
            "comparison_method": "weighted_f1",
            "best_model": ranking[0]["model_path"],
            "ranking": [
                {
                    "model_path": item["model_path"],
                    "f1_weighted": item["metrics"]["f1_weighted"],
                    "accuracy": item["metrics"]["accuracy"],
                    "precision_weighted": item["metrics"]["precision_weighted"],
                    "recall_weighted": item["metrics"]["recall_weighted"],
                }
                for item in ranking
            ],
        }

    else:
        comparison = {
            "comparison_method": "descriptive_only",
            "best_model": None,
            "note": (
                "Unsupervised models have no ground-truth labels here. "
                "Anomaly rate alone cannot determine which model is better."
            ),
            "models": [
                {
                    "model_path": item["model_path"],
                    "anomaly_rate": item["evaluation"]["anomaly_rate"],
                    "mean_anomaly_score": item["evaluation"]["mean_anomaly_score"],
                }
                for item in results
            ],
        }

    report = {
        "status": "COMPLETED",
        "mode": mode,
        "records_evaluated": len(records),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "comparison": comparison,
        "results": results,
    }

    output = Path(report_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False,
        )

    report["report_path"] = str(output)

    return report
