
import json
import tempfile
import unittest

from pathlib import Path

import polars as pl

from src.reader.ingestion import ingest_file


class TestJSONLQuarantine(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.temp_dir.name)

        self.input_dir = self.base / "input"
        self.output_dir = self.base / "processed"
        self.quarantine_dir = self.base / "quarantine"

        self.input_dir.mkdir()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_invalid_jsonl_line_quarantined(self):
        source = self.input_dir / "sample.jsonl"

        valid_record_1 = json.dumps({
            "username": "admin",
            "action": "SELECT",
        })

        invalid_record = '{"username": "guest", "action": '

        valid_record_2 = json.dumps({
            "username": "root",
            "action": "DELETE",
        })

        source.write_text(
            "\n".join([
                valid_record_1,
                invalid_record,
                valid_record_2,
            ]),
            encoding="utf-8",
        )

        report = ingest_file(
            file_path=source,
            output_dir=self.output_dir,
            quarantine_dir=self.quarantine_dir,
            batch_size=2,
            strict=False,
        )

        self.assertEqual(
            report["status"],
            "COMPLETED_WITH_ERRORS",
        )

        self.assertEqual(
            report["total_records_read"],
            2,
        )

        self.assertEqual(
            report["saved_records"],
            2,
        )

        self.assertEqual(
            report["skipped_stream_records"],
            1,
        )

        self.assertEqual(
            report["quarantined_records"],
            1,
        )

        quarantine_file = Path(
            report["quarantine_file"]
        )

        self.assertTrue(quarantine_file.exists())

        entries = [
            json.loads(line)
            for line in quarantine_file.read_text(
                encoding="utf-8"
            ).splitlines()
        ]

        self.assertEqual(len(entries), 1)

        self.assertEqual(
            entries[0]["record"]["raw_line"],
            invalid_record,
        )

        self.assertEqual(
            entries[0]["record_number"],
            2,
        )

        self.assertEqual(
            entries[0]["error_type"],
            "JSONLParseError",
        )

        # Verify both valid records were saved.
        saved_records = []

        for item in report["parquet_files"]:
            dataframe = pl.read_parquet(item["file"])
            saved_records.extend(
                dataframe.to_dicts()
            )

        self.assertEqual(len(saved_records), 2)

    def test_strict_mode_quarantines_before_stopping(self):
        source = self.input_dir / "strict.jsonl"

        invalid_record = '{"username": "admin"'

        source.write_text(
            invalid_record + "\n",
            encoding="utf-8",
        )

        report = ingest_file(
            file_path=source,
            output_dir=self.output_dir,
            quarantine_dir=self.quarantine_dir,
            batch_size=2,
            strict=True,
        )

        self.assertEqual(
            report["status"],
            "ERROR",
        )

        self.assertEqual(
            report["skipped_stream_records"],
            1,
        )

        self.assertEqual(
            report["quarantined_records"],
            1,
        )

        quarantine_file = Path(
            report["quarantine_file"]
        )

        entries = [
            json.loads(line)
            for line in quarantine_file.read_text(
                encoding="utf-8"
            ).splitlines()
        ]

        self.assertEqual(len(entries), 1)

        self.assertEqual(
            entries[0]["record"]["raw_line"],
            invalid_record,
        )


if __name__ == "__main__":
    unittest.main()
