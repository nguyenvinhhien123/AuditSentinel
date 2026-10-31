
import json
import tempfile
import unittest

from pathlib import Path

from src.reader.quarantine import QuarantineManager


class TestQuarantineManager(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.temp_dir.name)

        self.output = (
            self.base / "quarantine" / "rejected_records.jsonl"
        )

        self.manager = QuarantineManager(self.output)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_quarantine_single_record(self):
        record = {
            "username": "admin",
            "sql_action": "SELECT",
        }

        result = self.manager.quarantine(
            record=record,
            reason="Invalid normalized column names",
            source_file="sample.csv",
            batch_number=1,
            record_number=5,
            error_type="ValueError",
        )

        self.assertEqual(result["status"], "QUARANTINED")
        self.assertTrue(self.output.exists())

        entry = json.loads(
            self.output.read_text(encoding="utf-8").strip()
        )

        self.assertEqual(entry["record"], record)
        self.assertEqual(entry["source_file"], "sample.csv")
        self.assertEqual(entry["batch_number"], 1)
        self.assertEqual(entry["record_number"], 5)
        self.assertEqual(entry["error_type"], "ValueError")

    def test_quarantine_multiple_records(self):
        records = [
            {"username": "admin"},
            {"username": "guest"},
            {"username": "root"},
        ]

        result = self.manager.quarantine_many(
            records=records,
            reason="Invalid records",
            source_file="sample.csv",
            batch_number=2,
        )

        self.assertEqual(
            result["records_quarantined"],
            3,
        )

        lines = self.output.read_text(
            encoding="utf-8"
        ).splitlines()

        self.assertEqual(len(lines), 3)

    def test_append_records(self):
        self.manager.quarantine(
            {"username": "admin"},
            "First error",
        )

        self.manager.quarantine(
            {"username": "guest"},
            "Second error",
        )

        lines = self.output.read_text(
            encoding="utf-8"
        ).splitlines()

        self.assertEqual(len(lines), 2)

    def test_statistics(self):
        self.manager.quarantine(
            {"username": "admin"},
            "Invalid record",
        )

        stats = self.manager.get_statistics()

        self.assertEqual(stats["total_rejected"], 1)
        self.assertTrue(stats["file_exists"])

    def test_empty_reason_rejected(self):
        with self.assertRaises(ValueError):
            self.manager.quarantine(
                {"username": "admin"},
                "",
            )

    def test_original_record_preserved(self):
        original = {
            "SQL Action": " SELECT ",
            "Source IP": "192.168.1.10",
        }

        original_copy = original.copy()

        self.manager.quarantine(
            original,
            "Test preservation",
        )

        self.assertEqual(original, original_copy)


if __name__ == "__main__":
    unittest.main()
