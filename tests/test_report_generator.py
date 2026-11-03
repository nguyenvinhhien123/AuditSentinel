import json
import tempfile
import unittest
from pathlib import Path

from src.reporting.report_generator import ReportGenerator


class ReportGeneratorTests(unittest.TestCase):
    def test_build_report_excludes_raw_alert_context(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            project_root = Path(temporary_directory)
            alerts_path = project_root / "logs" / "alerts.jsonl"
            alerts_path.parent.mkdir(parents=True)
            alerts_path.write_text(
                json.dumps({
                    "alert_id": "alert-1",
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "status": "NEW",
                    "severity": "HIGH",
                    "mode": "supervised",
                    "verdict": "SUSPICIOUS",
                    "predicted_label": "attack",
                    "record_index": 12,
                    "model_name": "test model",
                    "context": {
                        "src_ip": "192.0.2.1",
                        "username": "sensitive-user",
                        "query": "SELECT secret FROM data",
                    },
                }) + "\n",
                encoding="utf-8",
            )

            report = ReportGenerator(project_root).build_report()

            self.assertEqual(report["alerts"]["total"], 1)
            self.assertEqual(len(report["alerts"]["latest"]), 1)
            self.assertEqual(
                report["alerts"]["latest"][0]["classification"],
                "Anomaly",
            )
            serialized_report = json.dumps(report)
            self.assertNotIn("192.0.2.1", serialized_report)
            self.assertNotIn("sensitive-user", serialized_report)
            self.assertNotIn("SELECT secret", serialized_report)

    def test_write_html_report_escapes_values_and_requires_matching_extension(self):
        report = {
            "title": "AuditSentinel Operational Report",
            "generated_at": "2026-01-01T00:00:00+00:00",
            "scope": "Local summary",
            "alerts": {
                "total": 1,
                "open": 1,
                "by_status": {"NEW": 1},
                "by_severity": {"HIGH": 1},
                "latest": [{
                    "created_at": "2026-01-01",
                    "severity": "HIGH",
                    "status": "NEW",
                    "classification": "Anomaly",
                    "mode": "supervised",
                    "verdict": "<script>alert(1)</script>",
                    "record_index": 1,
                    "model_name": "test",
                }],
            },
            "models": [],
            "prevention_simulations": [],
            "safety_note": "Simulation only",
        }

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "report.html"
            written_path = ReportGenerator().write_report(
                report,
                output_path,
                "html",
            )
            contents = written_path.read_text(encoding="utf-8")

            self.assertIn("&lt;script&gt;", contents)
            self.assertIn("<th>Classification</th>", contents)
            self.assertNotIn("<script>alert(1)</script>", contents)
            with self.assertRaises(ValueError):
                ReportGenerator().write_report(
                    report,
                    Path(temporary_directory) / "report.txt",
                    "html",
                )

    def test_write_json_report_preserves_structured_data(self):
        report = {"title": "AuditSentinel Operational Report", "alerts": {"total": 0}}

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "report.json"
            ReportGenerator().write_report(report, output_path, "json")

            self.assertEqual(
                json.loads(output_path.read_text(encoding="utf-8")),
                report,
            )

    def test_report_uses_selected_session_data_and_shared_model_registry(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            project_root = Path(temporary_directory)
            session_root = project_root / "sessions" / "session-1"
            legacy_alerts = project_root / "logs" / "alerts.jsonl"
            session_alerts = session_root / "logs" / "alerts.jsonl"
            for path, alert_id in (
                (legacy_alerts, "legacy-alert"),
                (session_alerts, "session-alert"),
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    json.dumps({
                        "alert_id": alert_id,
                        "created_at": "2026-01-01T00:00:00+00:00",
                        "status": "NEW",
                        "severity": "HIGH",
                    }) + "\n",
                    encoding="utf-8",
                )

            report = ReportGenerator(
                project_root=project_root,
                session_root=session_root,
            ).build_report()

            self.assertEqual(report["alerts"]["total"], 1)
            self.assertEqual(
                report["alerts"]["latest"][0]["alert_id"],
                "session-alert",
            )
            self.assertTrue((project_root / "models" / "registry.json").is_file())


if __name__ == "__main__":
    unittest.main()
