
import json
import unittest
from unittest.mock import patch, Mock

from src.investigation.engine import InvestigationEngine


def sample_alert():
    return {
        "alert_id": "test-alert-001",
        "severity": "CRITICAL",
        "mode": "supervised",
        "verdict": "SUSPICIOUS",
        "predicted_label": "attack",
        "confidence": 0.97,
        "model_name": "Random Forest",
        "context": {
            "username": "admin",
            "src_ip": "192.168.1.100",
            "query": "SELECT * FROM users UNION SELECT * FROM passwords",
            "password": "must_not_be_sent",
        },
    }


def sample_report():
    return {
        "incident_summary": "Possible SQL injection attempt.",
        "attack_type": "SQL Injection",
        "risk_level": "HIGH",
        "confidence": "MEDIUM",
        "evidence": [
            "SQL query contains UNION keyword."
        ],
        "analysis": [
            "The query may be attempting to combine results from another table."
        ],
        "recommended_actions": [
            "Review database audit logs.",
            "Inspect the affected application endpoint."
        ],
        "false_positive_considerations": [
            "The query may be a legitimate administrative operation."
        ],
        "additional_data_needed": [
            "Application request logs.",
            "Database session history."
        ],
    }


class TestInvestigationEngine(unittest.TestCase):

    def setUp(self):
        self.engine = InvestigationEngine()

    def test_prepare_alert(self):
        prepared = self.engine._prepare_alert(sample_alert())

        self.assertEqual(
            prepared["alert_id"],
            "test-alert-001",
        )

        self.assertNotIn(
            "password",
            prepared["context"],
        )

    def test_reject_invalid_alert(self):
        with self.assertRaises(TypeError):
            self.engine._prepare_alert("invalid")

    def test_prompt_contains_alert_data(self):
        prepared = self.engine._prepare_alert(sample_alert())
        prompt = self.engine._build_prompt(prepared)

        self.assertIn("test-alert-001", prompt)
        self.assertIn("untrusted data", prompt.lower())

    def test_extract_valid_json(self):
        report = sample_report()

        result = self.engine._extract_json(
            json.dumps(report)
        )

        self.assertEqual(
            result["attack_type"],
            "SQL Injection",
        )

    def test_extract_json_from_markdown(self):
        report = sample_report()

        content = (
            "Here is the result:\n"
            "```json\n"
            + json.dumps(report)
            + "\n```"
        )

        result = self.engine._extract_json(content)

        self.assertEqual(
            result["risk_level"],
            "HIGH",
        )

    def test_reject_invalid_json(self):
        with self.assertRaises(ValueError):
            self.engine._extract_json("not json")

    def test_validate_report(self):
        result = self.engine._validate_report(
            sample_report()
        )

        self.assertEqual(
            result["risk_level"],
            "HIGH",
        )

    def test_calculate_risk_score_from_confidence(self):
        result = self.engine._calculate_risk_score({
            "severity": "HIGH",
            "confidence": 0.85,
            "context": {"query": "DROP TABLE users"},
        })

        self.assertEqual(result["risk_score"], 100.0)
        self.assertEqual(result["risk_score_band"], "CRITICAL")
        self.assertEqual(
            result["risk_likelihood_basis"],
            "detector_confidence",
        )
        self.assertEqual(result["impact_rating"], 5)

    def test_calculate_risk_score_from_anomaly_margin(self):
        result = self.engine._calculate_risk_score({
            "severity": "MEDIUM",
            "verdict": "ANOMALY",
            "anomaly_score": -0.035,
            "context": {"query": "SELECT * FROM users"},
        })

        self.assertEqual(result["risk_score"], 29.2)
        self.assertEqual(result["risk_score_band"], "MEDIUM")
        self.assertEqual(
            result["risk_likelihood_basis"],
            "isolation_forest_decision_margin",
        )
        self.assertEqual(
            result["impact_rating"],
            2,
        )

    def test_risk_score_is_bounded_to_zero_through_one_hundred(self):
        self.assertEqual(
            self.engine._calculate_risk_score({
                "confidence": 0,
                "context": {"query": "SELECT 1"},
            })["risk_score"],
            4.2,
        )
        self.assertEqual(
            self.engine._calculate_risk_score({
                "anomaly_score": -0.5,
                "context": {"query": "DROP TABLE users"},
            })["risk_score"],
            100.0,
        )

    def test_risk_score_requires_valid_inputs(self):
        for alert in (
            {"severity": "HIGH"},
            {"severity": "HIGH", "confidence": 1.2},
        ):
            with self.subTest(alert=alert):
                result = self.engine._calculate_risk_score(alert)
                self.assertIsNone(result["risk_score"])
                self.assertEqual(result["risk_score_band"], "UNKNOWN")
                self.assertIn("no valid", result["risk_score_note"])

    def test_normal_detector_result_has_no_risk_score(self):
        result = self.engine._calculate_risk_score({
            "verdict": "NORMAL",
            "confidence": 0.99,
        })

        self.assertIsNone(result["risk_score"])
        self.assertEqual(result["risk_score_band"], "NONE")

    def test_investigation_adds_deterministic_risk_score(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "message": {
                "content": json.dumps(sample_report())
            }
        }

        with patch(
            "src.investigation.engine.requests.post",
            return_value=response,
        ):
            result = self.engine.investigate({
                **sample_alert(),
                "severity": "HIGH",
                "confidence": 0.85,
                "context": {"query": "DROP TABLE users"},
            })

        self.assertEqual(result["report"]["risk_score"], 100.0)
        self.assertEqual(result["report"]["risk_score_band"], "CRITICAL")

    def test_investigation_scores_unsupervised_alert(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "message": {
                "content": json.dumps(sample_report())
            }
        }

        with patch(
            "src.investigation.engine.requests.post",
            return_value=response,
        ):
            result = self.engine.investigate({
                **sample_alert(),
                "confidence": None,
                "anomaly_score": -0.025,
                "context": {"query": "SELECT * FROM users"},
            })

        self.assertEqual(result["report"]["risk_score"], 20.8)
        self.assertEqual(result["report"]["risk_score_band"], "MEDIUM")

    def test_reject_missing_report_fields(self):
        with self.assertRaises(ValueError):
            self.engine._validate_report({
                "incident_summary": "Test",
            })

    def test_reject_invalid_risk_level(self):
        report = sample_report()
        report["risk_level"] = "EXTREME"

        with self.assertRaises(ValueError):
            self.engine._validate_report(report)

    @patch("src.investigation.engine.requests.post")
    def test_investigate_success(self, mock_post):
        response = Mock()

        response.raise_for_status.return_value = None
        response.json.return_value = {
            "message": {
                "content": json.dumps(sample_report())
            }
        }

        mock_post.return_value = response

        result = self.engine.investigate(
            sample_alert()
        )

        self.assertEqual(
            result["status"],
            "COMPLETED",
        )

        self.assertEqual(
            result["report"]["attack_type"],
            "SQL Injection",
        )

        call_payload = mock_post.call_args.kwargs["json"]

        self.assertEqual(
            call_payload["model"],
            "qwen2.5:1.5b",
        )

        self.assertNotIn(
            "must_not_be_sent",
            call_payload["messages"][1]["content"],
        )

    @patch("src.investigation.engine.requests.post")
    def test_ollama_connection_error(self, mock_post):
        import requests

        mock_post.side_effect = requests.ConnectionError(
            "Connection refused"
        )

        with self.assertRaises(RuntimeError):
            self.engine.investigate(sample_alert())

    @patch("src.investigation.engine.requests.get")
    def test_check_connection(self, mock_get):
        response = Mock()

        response.raise_for_status.return_value = None
        response.json.return_value = {
            "models": [
                {"name": "qwen2.5:1.5b"}
            ]
        }

        mock_get.return_value = response

        result = self.engine.check_connection()

        self.assertTrue(result["connected"])
        self.assertIn(
            "qwen2.5:1.5b",
            result["models"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
