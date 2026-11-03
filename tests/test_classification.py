import unittest

from src.detection.classification import (
    classification_explanation,
    classify_result,
)


class ClassificationTests(unittest.TestCase):
    def test_detector_verdicts_separate_anomaly_and_normal(self):
        self.assertEqual(classify_result({"verdict": "ANOMALY"}), "Anomaly")
        self.assertEqual(classify_result({"verdict": "SUSPICIOUS"}), "Anomaly")
        self.assertEqual(classify_result({"verdict": "NORMAL_PATTERN"}), "Normal")
        self.assertEqual(classify_result({"verdict": "NORMAL"}), "Normal")

    def test_supervised_labels_and_unknown_predictions(self):
        self.assertEqual(
            classify_result({"predicted_label": "malicious"}),
            "Anomaly",
        )
        self.assertEqual(
            classify_result({"predicted_label": "intrusion attempt"}),
            "Anomaly",
        )
        self.assertEqual(
            classify_result({"predicted_label": "benign"}),
            "Normal",
        )
        self.assertEqual(
            classify_result({"predicted_label": "clean"}),
            "Normal",
        )
        self.assertEqual(
            classify_result({"verdict": "REVIEW", "predicted_label": "?"}),
            "Review",
        )

    def test_anomaly_explanation_does_not_claim_confirmed_attack(self):
        explanation = classification_explanation({"verdict": "ANOMALY"})
        self.assertIn("not proof of an attack", explanation)


if __name__ == "__main__":
    unittest.main()
