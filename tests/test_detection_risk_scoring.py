import unittest
from unittest.mock import patch

import numpy as np

from src.detection.engine import DetectionEngine


class FakeModel:
    classes_ = np.array(["normal", "attack"])

    def predict(self, _features):
        return np.array(["attack", "normal"])

    def predict_proba(self, _features):
        return np.array([
            [0.05, 0.95],
            [0.99, 0.01],
        ])


class TestDetectionRiskScoring(unittest.TestCase):
    def test_batch_results_include_score_and_normals_are_unscored(self):
        engine = DetectionEngine(registry=None)
        artifact = {
            "model": FakeModel(),
            "feature_names": [],
        }
        model_record = {
            "model_id": "test-model",
            "name": "Test model",
            "algorithm": "test",
        }
        with (
            patch.object(
                engine,
                "_load_active_model",
                return_value=(artifact, model_record),
            ),
            patch.object(
                engine,
                "_align_features",
                return_value=np.zeros((2, 1), dtype=np.float32),
            ),
        ):
            result = engine.detect_batch(
                [
                    {"sql_action": "DROP"},
                    {"sql_action": "SELECT"},
                ],
                mode="supervised",
            )

        flagged, normal = result["results"]
        self.assertEqual(flagged["risk_score"], 95.0)
        self.assertEqual(flagged["risk_score_band"], "CRITICAL")
        self.assertIsNone(normal["risk_score"])
        self.assertEqual(normal["risk_score_band"], "NONE")


if __name__ == "__main__":
    unittest.main()
