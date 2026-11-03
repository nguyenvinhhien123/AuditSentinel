import unittest

from src.risk_scoring import (
    calculate_risk_score,
    severity_from_risk_score,
)


class TestRiskScoring(unittest.TestCase):
    def test_confidence_and_read_only_operation_calculate_expected_score(self):
        result = calculate_risk_score(
            confidence=0.85,
            context={"sql_action": "SELECT"},
            verdict="SUSPICIOUS",
        )

        self.assertEqual(result["risk_likelihood"], 0.85)
        self.assertEqual(result["impact_rating"], 2)
        self.assertEqual(result["impact_factor"], 0.25)
        self.assertEqual(result["risk_score"], 21.2)
        self.assertEqual(result["risk_score_band"], "MEDIUM")
        self.assertEqual(
            result["risk_score_formula"],
            "round(100 * likelihood * impact_factor, 1)",
        )

    def test_write_operation_has_higher_impact_than_read(self):
        result = calculate_risk_score(
            confidence=0.75,
            context={"sql_action": "DELETE"},
            verdict="SUSPICIOUS",
        )

        self.assertEqual(result["risk_likelihood"], 0.75)
        self.assertEqual(result["impact_rating"], 4)
        self.assertEqual(result["impact_factor"], 0.65)
        self.assertEqual(result["risk_score"], 48.8)
        self.assertEqual(result["risk_score_band"], "HIGH")

    def test_destructive_operation_at_high_confidence_is_critical(self):
        result = calculate_risk_score(
            confidence=0.95,
            context={"sql_action": "DROP"},
            verdict="SUSPICIOUS",
        )

        self.assertEqual(result["impact_factor"], 1.0)
        self.assertEqual(result["risk_score"], 95.0)
        self.assertEqual(result["risk_score_band"], "CRITICAL")

    def test_anomaly_margin_produces_a_deterministic_score(self):
        result = calculate_risk_score(
            anomaly_score=-0.035,
            context={"query": "SELECT * FROM accounts"},
            verdict="ANOMALY",
        )

        self.assertEqual(result["risk_likelihood"], 0.8)
        self.assertEqual(
            result["risk_likelihood_basis"],
            "isolation_forest_decision_margin",
        )
        self.assertEqual(result["risk_score"], 20.0)
        self.assertEqual(result["risk_score_band"], "MEDIUM")

    def test_verdict_fallback_and_missing_impact_are_marked_estimated(self):
        result = calculate_risk_score(verdict="REVIEW")

        self.assertEqual(result["risk_likelihood"], 0.3)
        self.assertEqual(result["impact_rating"], 3)
        self.assertEqual(result["impact_factor"], 0.5)
        self.assertTrue(result["impact_estimated"])
        self.assertEqual(result["risk_score"], 15.0)
        self.assertEqual(result["risk_score_band"], "LOW")

    def test_normal_results_do_not_receive_a_risk_score(self):
        result = calculate_risk_score(
            confidence=0.99,
            verdict="NORMAL",
        )

        self.assertIsNone(result["risk_score"])
        self.assertEqual(result["risk_score_band"], "NONE")
        self.assertIsNone(severity_from_risk_score(result["risk_score"]))

    def test_severity_thresholds_follow_risk_score_bands(self):
        self.assertEqual(severity_from_risk_score(19.9), "LOW")
        self.assertEqual(severity_from_risk_score(20), "MEDIUM")
        self.assertEqual(severity_from_risk_score(40), "HIGH")
        self.assertEqual(severity_from_risk_score(70), "CRITICAL")

    def test_invalid_inputs_do_not_create_a_score_without_a_verdict(self):
        result = calculate_risk_score(confidence=1.5)

        self.assertIsNone(result["risk_score"])
        self.assertEqual(result["risk_score_band"], "UNKNOWN")
        self.assertIn("Not calculated", result["risk_score_note"])


if __name__ == "__main__":
    unittest.main()
