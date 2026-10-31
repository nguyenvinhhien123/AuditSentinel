
from datetime import datetime, timezone

import numpy as np

from sklearn.ensemble import (
    RandomForestClassifier,
    IsolationForest,
)
from sklearn.model_selection import train_test_split

from src.training.auto_trainer import (
    _build_feature_matrix,
    _save_model,
)
from src.training.evaluator import evaluate_classifier


def manual_train(
    records,
    mode,
    output_dir="models/detection/manual",
    test_size=0.2,
    random_state=42,
    cpu_threads=2,
    n_estimators=100,
    max_depth=None,
    contamination=0.05,
    label_column=None,
):
    """
    Train a model with user-selected algorithm parameters.

    mode="supervised":
        Random Forest; requires label_column.

    mode="unsupervised":
        Isolation Forest; does not use labels.
    """

    if not isinstance(records, list) or len(records) < 10:
        raise ValueError("At least 10 records are required")

    if not all(isinstance(record, dict) for record in records):
        raise TypeError("Every record must be a dictionary")

    if mode not in {"supervised", "unsupervised"}:
        raise ValueError("mode must be supervised or unsupervised")

    if not 0.1 <= test_size <= 0.4:
        raise ValueError("test_size must be between 0.1 and 0.4")

    if cpu_threads < 1:
        raise ValueError("cpu_threads must be at least 1")

    if not isinstance(n_estimators, int) or not 10 <= n_estimators <= 1000:
        raise ValueError("n_estimators must be an integer from 10 to 1000")

    if max_depth is not None:
        if not isinstance(max_depth, int) or max_depth < 1:
            raise ValueError("max_depth must be a positive integer or None")

    if not 0.0 < contamination <= 0.5:
        raise ValueError("contamination must be greater than 0 and <= 0.5")

    X, feature_names = _build_feature_matrix(records)

    if X.shape[1] == 0:
        raise ValueError("No usable features were generated")

    indices = np.arange(len(records))
    created_at = datetime.now(timezone.utc).isoformat()

    # --------------------------------------------------
    # SUPERVISED: RANDOM FOREST
    # --------------------------------------------------

    if mode == "supervised":
        if not label_column:
            raise ValueError(
                "label_column is required for supervised training"
            )

        labels = [record.get(label_column) for record in records]

        if any(
            label is None or str(label).strip() == ""
            for label in labels
        ):
            raise ValueError("Missing labels found in label column")

        y = np.asarray([str(label).strip() for label in labels])

        classes, counts = np.unique(y, return_counts=True)

        if len(classes) < 2:
            raise ValueError("Supervised training requires at least 2 classes")

        if np.min(counts) < 2:
            raise ValueError("Every class needs at least 2 records")

        try:
            train_indices, test_indices = train_test_split(
                indices,
                test_size=test_size,
                random_state=random_state,
                stratify=y,
            )
        except ValueError as exc:
            raise ValueError(
                f"Unable to create stratified train/test split: {exc}"
            ) from exc

        model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=cpu_threads,
            class_weight="balanced",
        )

        model.fit(X[train_indices], y[train_indices])

        predictions = model.predict(X[test_indices])

        metrics = evaluate_classifier(
            y[test_indices].tolist(),
            predictions.tolist(),
        )

        metadata = {
            "training_mode": "manual",
            "mode": "supervised",
            "algorithm": "RandomForestClassifier",
            "label_column": label_column,
            "classes": classes.tolist(),
            "parameters": {
                "n_estimators": n_estimators,
                "max_depth": max_depth,
                "test_size": test_size,
                "random_state": random_state,
                "cpu_threads": cpu_threads,
            },
            "total_records": len(records),
            "training_records": len(train_indices),
            "testing_records": len(test_indices),
            "feature_count": len(feature_names),
            "feature_names": feature_names,
            "created_at": created_at,
            "metrics": metrics,
        }

        saved = _save_model(
            model,
            feature_names,
            metadata,
            output_dir,
        )

        return {
            "status": "TRAINED",
            "mode": "supervised",
            "algorithm": "RandomForestClassifier",
            "metrics": metrics,
            "metadata": metadata,
            **saved,
        }

    # --------------------------------------------------
    # UNSUPERVISED: ISOLATION FOREST
    # --------------------------------------------------

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=cpu_threads,
    )

    train_indices, test_indices = train_test_split(
        indices,
        test_size=test_size,
        random_state=random_state,
    )

    model.fit(X[train_indices])

    predictions = model.predict(X[test_indices])
    scores = model.decision_function(X[test_indices])

    anomaly_count = int(np.sum(predictions == -1))
    normal_count = int(np.sum(predictions == 1))

    evaluation = {
        "anomaly_count": anomaly_count,
        "normal_count": normal_count,
        "anomaly_rate": round(
            anomaly_count / len(test_indices), 4
        ),
        "mean_anomaly_score": round(
            float(np.mean(scores)), 4
        ),
        "note": (
            "No ground-truth labels were used. "
            "Anomaly flags are not confirmed attacks."
        ),
    }

    metadata = {
        "training_mode": "manual",
        "mode": "unsupervised",
        "algorithm": "IsolationForest",
        "parameters": {
            "n_estimators": n_estimators,
            "contamination": contamination,
            "test_size": test_size,
            "random_state": random_state,
            "cpu_threads": cpu_threads,
        },
        "total_records": len(records),
        "training_records": len(train_indices),
        "testing_records": len(test_indices),
        "feature_count": len(feature_names),
        "feature_names": feature_names,
        "created_at": created_at,
        "evaluation": evaluation,
    }

    saved = _save_model(
        model,
        feature_names,
        metadata,
        output_dir,
    )

    return {
        "status": "TRAINED",
        "mode": "unsupervised",
        "algorithm": "IsolationForest",
        "evaluation": evaluation,
        "metadata": metadata,
        **saved,
    }
