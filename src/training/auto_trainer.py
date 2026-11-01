
from pathlib import Path
from datetime import datetime, timezone
import json
import math

import joblib
import numpy as np

from sklearn.ensemble import (
    IsolationForest,
    RandomForestClassifier,
)
from sklearn.model_selection import train_test_split

from src.training.feature_engineering import transform_records
from src.training.evaluator import evaluate_classifier


def _build_feature_matrix(records):
    """Extract numeric features and build a consistent matrix."""

    feature_rows = transform_records(records)

    if not feature_rows:
        raise ValueError("No feature rows were generated")

    feature_names = sorted({
        name
        for row in feature_rows
        for name in row
    })

    matrix = []

    for row in feature_rows:
        values = []

        for name in feature_names:
            value = row.get(name, 0)

            if isinstance(value, bool):
                value = int(value)

            if not isinstance(value, (int, float)):
                raise ValueError(
                    f"Non-numeric feature detected: {name}"
                )

            if not math.isfinite(float(value)):
                raise ValueError(
                    f"Invalid numeric feature detected: {name}"
                )

            values.append(float(value))

        matrix.append(values)

    return np.asarray(matrix, dtype=np.float32), feature_names


def _save_model(model, feature_names, metadata, output_dir):
    """Save a trusted local model artifact and its metadata."""

    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)

    model_path = directory / "auto_model.joblib"
    metadata_path = directory / "auto_model_metadata.json"

    artifact = {
        "model": model,
        "feature_names": feature_names,
        "metadata": metadata,
    }

    joblib.dump(artifact, model_path)

    with metadata_path.open("w", encoding="utf-8") as file:
        json.dump(
            metadata,
            file,
            indent=4,
            ensure_ascii=False,
        )

    return {
        "model_path": str(model_path),
        "metadata_path": str(metadata_path),
    }


def auto_train(
    records,
    label_column=None,
    output_dir="models/detection",
    test_size=0.2,
    random_state=42,
    cpu_threads=2,
    contamination=0.05,
):
    """
    Automatically select supervised or unsupervised training.

    label_column=None:
        Use Isolation Forest.

    label_column="label":
        Use Random Forest if valid labels are available.

    Original input records are never modified.
    """

    if not isinstance(records, list) or len(records) < 10:
        raise ValueError(
            "At least 10 dictionary records are required"
        )

    if not all(isinstance(record, dict) for record in records):
        raise TypeError("Every record must be a dictionary")

    if test_size is not None and not 0.1 <= test_size <= 0.4:
        raise ValueError("test_size must be between 0.1 and 0.4")

    if not 0.0 < contamination <= 0.5:
        raise ValueError("contamination must be greater than 0 and <= 0.5")

    if cpu_threads < 1:
        raise ValueError("cpu_threads must be at least 1")

    X, feature_names = _build_feature_matrix(records)

    if X.shape[1] == 0:
        raise ValueError("No usable features were generated")

    indices = np.arange(len(records))
    if test_size is None:
        train_indices = indices
        test_indices = np.asarray([], dtype=int)
    else:
        train_indices, test_indices = train_test_split(
            indices,
            test_size=test_size,
            random_state=random_state,
        )

    X_train = X[train_indices]
    X_test = X[test_indices]

    created_at = datetime.now(timezone.utc).isoformat()

    # --------------------------------------------------
    # SUPERVISED TRAINING
    # --------------------------------------------------

    if label_column is not None:
        labels = [
            record.get(label_column)
            for record in records
        ]

        if any(label is None or str(label).strip() == "" for label in labels):
            raise ValueError(
                f"Missing labels found in column: {label_column}"
            )

        classes, counts = np.unique(
            np.asarray(labels, dtype=str),
            return_counts=True,
        )

        if len(classes) < 2:
            raise ValueError(
                "Supervised training requires at least 2 classes"
            )

        if np.min(counts) < 2:
            raise ValueError(
                "Every class needs at least 2 records"
            )

        y = np.asarray(labels, dtype=str)
        if test_size is not None:
            try:
                train_indices, test_indices = train_test_split(
                    indices,
                    test_size=test_size,
                    random_state=random_state,
                    stratify=y,
                )
            except ValueError as exc:
                raise ValueError(
                    f"Cannot create a valid stratified split: {exc}"
                ) from exc

        X_train = X[train_indices]
        X_test = X[test_indices]
        y_train = y[train_indices]
        y_test = y[test_indices]

        model = RandomForestClassifier(
            n_estimators=100,
            random_state=random_state,
            n_jobs=cpu_threads,
            class_weight="balanced",
        )

        model.fit(X_train, y_train)

        metrics = None
        if len(test_indices):
            predictions = model.predict(X_test)
            metrics = evaluate_classifier(
                y_test.tolist(),
                predictions.tolist(),
            )

        metadata = {
            "mode": "supervised",
            "algorithm": "RandomForestClassifier",
            "label_column": label_column,
            "classes": classes.tolist(),
            "total_records": len(records),
            "training_records": len(train_indices),
            "testing_records": len(test_indices),
            "feature_count": len(feature_names),
            "feature_names": feature_names,
            "random_state": random_state,
            "cpu_threads": cpu_threads,
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
    # UNSUPERVISED TRAINING
    # --------------------------------------------------

    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=random_state,
        n_jobs=cpu_threads,
    )

    model.fit(X_train)

    if len(test_indices):
        predictions = model.predict(X_test)
        anomaly_scores = model.decision_function(X_test)
        anomaly_count = int(np.sum(predictions == -1))
        normal_count = int(np.sum(predictions == 1))
        evaluation = {
            "anomaly_count": anomaly_count,
            "normal_count": normal_count,
            "anomaly_rate": round(
                anomaly_count / len(test_indices), 4
            ),
            "mean_anomaly_score": round(
                float(np.mean(anomaly_scores)), 4
            ),
            "note": (
                "No ground-truth labels were supplied. "
                "These are anomaly flags, not confirmed attacks."
            ),
        }
    else:
        evaluation = {
            "note": (
                "All supplied training records were used. "
                "Evaluate against a separate labeled test split."
            ),
        }

    metadata = {
        "mode": "unsupervised",
        "algorithm": "IsolationForest",
        "total_records": len(records),
        "training_records": len(train_indices),
        "testing_records": len(test_indices),
        "feature_count": len(feature_names),
        "feature_names": feature_names,
        "contamination": contamination,
        "random_state": random_state,
        "cpu_threads": cpu_threads,
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
        "evaluation": metadata["evaluation"],
        "metadata": metadata,
        **saved,
    }
