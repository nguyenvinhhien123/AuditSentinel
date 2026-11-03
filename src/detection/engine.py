
from pathlib import Path

import joblib
import numpy as np

from src.detection.classification import (
    NORMAL_LABELS,
    SUSPICIOUS_LABELS,
    classify_supervised_label,
)
from src.training.auto_trainer import _build_feature_matrix


class DetectionEngine:
    """
    Detect suspicious database activity using an active registered model.

    Supervised mode:
        Predicts the class and confidence.

    Unsupervised mode:
        Detects anomalies using Isolation Forest.

    This engine does not block users, IP addresses, or database queries.
    """

    def __init__(self, registry):
        self.registry = registry
        self._cached_model_id = None
        self._cached_checksum = None
        self._cached_artifact = None

    def _load_active_model(self, mode):
        model_record = self.registry.get_active_model(mode)

        if model_record is None:
            raise RuntimeError(
                f"No active {mode} model is registered"
            )

        verification = self.registry.verify_model(
            model_record["model_id"]
        )

        if not verification["valid"]:
            raise RuntimeError(
                "Model integrity verification failed"
            )

        checksum = verification["actual_sha256"]

        if (
            self._cached_model_id == model_record["model_id"]
            and self._cached_checksum == checksum
            and self._cached_artifact is not None
        ):
            return self._cached_artifact, model_record

        model_path = (
            self.registry.project_root
            / model_record["model_path"]
        ).resolve()

        try:
            model_path.relative_to(self.registry.project_root)
        except ValueError as exc:
            raise ValueError(
                "Model path is outside the project directory"
            ) from exc

        if not model_path.is_file():
            raise FileNotFoundError(
                f"Model file not found: {model_path}"
            )

        artifact = joblib.load(model_path)

        if not isinstance(artifact, dict):
            raise ValueError("Invalid model artifact")

        if not {"model", "feature_names", "metadata"}.issubset(
            artifact
        ):
            raise ValueError(
                "Model artifact is missing required fields"
            )

        metadata = artifact["metadata"]

        if metadata.get("mode") != mode:
            raise ValueError(
                "Model mode does not match registry mode"
            )

        if metadata.get("algorithm") != model_record["algorithm"]:
            raise ValueError(
                "Model algorithm does not match registry metadata"
            )

        if not isinstance(artifact["feature_names"], list):
            raise ValueError("Invalid model feature schema")

        self._cached_model_id = model_record["model_id"]
        self._cached_checksum = checksum
        self._cached_artifact = artifact

        return artifact, model_record

    @staticmethod
    def _align_features(records, expected_features):
        matrix, current_features = _build_feature_matrix(records)

        feature_index = {
            name: index
            for index, name in enumerate(current_features)
        }

        aligned = np.zeros(
            (matrix.shape[0], len(expected_features)),
            dtype=np.float32,
        )

        for target_index, feature_name in enumerate(
            expected_features
        ):
            source_index = feature_index.get(feature_name)

            if source_index is not None:
                aligned[:, target_index] = matrix[:, source_index]

        return aligned

    @staticmethod
    def _classify_supervised_label(label):
        return classify_supervised_label(label)

    def detect(self, record, mode=None):
        """Analyze one database audit-log record."""

        if not isinstance(record, dict):
            raise TypeError("record must be a dictionary")

        result = self.detect_batch([record], mode=mode)

        return result["results"][0]

    def detect_batch(self, records, mode=None):
        """Analyze multiple database audit-log records."""

        if not isinstance(records, list) or not records:
            raise ValueError("records must be a non-empty list")

        if not all(isinstance(record, dict) for record in records):
            raise TypeError("Every record must be a dictionary")

        if mode is None:
            # Prefer supervised model when available.
            if self.registry.get_active_model("supervised"):
                mode = "supervised"
            elif self.registry.get_active_model("unsupervised"):
                mode = "unsupervised"
            else:
                raise RuntimeError("No active detection model is available")

        if mode not in {"supervised", "unsupervised"}:
            raise ValueError(
                "mode must be supervised or unsupervised"
            )

        artifact, model_record = self._load_active_model(mode)

        model = artifact["model"]
        feature_names = artifact["feature_names"]

        X = self._align_features(records, feature_names)

        results = []

        if mode == "supervised":
            predictions = model.predict(X)

            probabilities = None

            if hasattr(model, "predict_proba"):
                probabilities = model.predict_proba(X)

            for index, prediction in enumerate(predictions):
                label = str(prediction)

                confidence = None
                class_probabilities = {}

                if probabilities is not None:
                    confidence = round(
                        float(np.max(probabilities[index])),
                        4,
                    )

                    class_probabilities = {
                        str(class_name): round(float(probability), 4)
                        for class_name, probability in zip(
                            model.classes_,
                            probabilities[index],
                        )
                    }

                verdict = self._classify_supervised_label(label)

                results.append({
                    "record_index": index,
                    "mode": "supervised",
                    "predicted_label": label,
                    "verdict": verdict,
                    "confidence": confidence,
                    "class_probabilities": class_probabilities,
                    "alert": verdict == "SUSPICIOUS",
                })

        else:
            predictions = model.predict(X)
            scores = model.decision_function(X)

            for index, prediction in enumerate(predictions):
                is_anomaly = int(prediction) == -1

                results.append({
                    "record_index": index,
                    "mode": "unsupervised",
                    "verdict": (
                        "ANOMALY" if is_anomaly else "NORMAL_PATTERN"
                    ),
                    "anomaly_score": round(
                        float(scores[index]),
                        6,
                    ),
                    "alert": is_anomaly,
                    "note": (
                        "An anomaly is not necessarily a confirmed attack."
                    ),
                })

        alert_count = sum(
            result["alert"] for result in results
        )

        return {
            "status": "COMPLETED",
            "model_id": model_record["model_id"],
            "model_name": model_record["name"],
            "algorithm": model_record["algorithm"],
            "mode": mode,
            "records_analyzed": len(records),
            "alerts": alert_count,
            "normal_or_reviewed": len(records) - alert_count,
            "results": results,
        }
