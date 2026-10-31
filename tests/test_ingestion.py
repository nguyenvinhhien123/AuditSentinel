
import csv
import json
import tempfile
import unittest

from pathlib import Path

import polars as pl

from src.reader.ingestion import ingest_file


class TestIngestion(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.temp_dir.name)

        self.input_dir = self.base / "input"
        self.output_dir = self.base / "processed"
        self.quarantine_dir = self.base / "quarantine"

        self.input_dir.mkdir()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_csv_ingestion(self):
        source = self.input_dir / "sample.csv"

        with source.open(
            "w",
            encoding="utf-8",
            newline="",
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=[
                    "User Name",
                    "SQL Action",
                    "Source IP",
                ],
            )

            writer.writeheader()

            writer.writerows([
                {
                    "User Name": "admin",
                    "SQL Action": "SELECT",
                    "Source IP": "192.168.1.10",
                },
                {
                    "User Name": "guest",
                    "SQL Action": "DELETE",
                    "Source IP": "192.168.1.20",
                },
                {
                    "User Name": "root",
                    "SQL Action": "DROP",
                    "Source IP": "192.168.1.30",
                },
            ])

        report = ingest_file(
            source,
            output_dir=self.output_dir,
            batch_size=2,
            quarantine_dir=self.quarantine_dir,
        )

        self.assertEqual(report["status"], "COMPLETED")
        self.assertEqual(report["total_records_read"], 3)
        self.assertEqual(report["saved_records"], 3)
        self.assertEqual(len(report["parquet_files"]), 2)

        self.assertTrue(
            Path(report["report_file"]).exists()
        )

        first_file = Path(
            report["parquet_files"][0]["file"]
        )

        dataframe = pl.read_parquet(first_file)

        self.assertIn("user_name", dataframe.columns)
        self.assertIn("sql_action", dataframe.columns)
        self.assertIn("source_ip", dataframe.columns)

    def test_jsonl_ingestion(self):
        source = self.input_dir / "sample.jsonl"

        records = [
            {"User Name": "admin", "SQL Action": "SELECT"},
            {"User Name": "guest", "SQL Action": "DELETE"},
            {"User Name": "root", "SQL Action": "DROP"},
        ]

        source.write_text(
            "\n".join(
                json.dumps(record)
                for record in records
            ),
            encoding="utf-8",
        )

        report = ingest_file(
            source,
            output_dir=self.output_dir,
            batch_size=2,
            quarantine_dir=self.quarantine_dir,
        )

        self.assertEqual(report["status"], "COMPLETED")
        self.assertEqual(report["saved_records"], 3)

    def test_invalid_normalization_record(self):
        source = self.input_dir / "invalid.csv"

        source.write_text(
            "User Name,SQL Action,user_name\n"
            "admin,SELECT,another\n",
            encoding="utf-8",
        )

        report = ingest_file(
            source,
            output_dir=self.output_dir,
            batch_size=10,
            strict=False,
            quarantine_dir=self.quarantine_dir,
        )

        self.assertEqual(
            report["status"],
            "COMPLETED_WITH_ERRORS",
        )

        self.assertEqual(report["normalization_errors"], 1)
        self.assertEqual(report["saved_records"], 0)
        self.assertEqual(report["quarantined_records"], 1)

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
        self.assertEqual(entries[0]["record_number"], 1)

        self.assertEqual(
            entries[0]["record"]["User Name"],
            "admin",
        )

    def test_original_file_preserved(self):
        source = self.input_dir / "sample.csv"

        original_content = (
            "User Name,SQL Action\n"
            "admin,SELECT\n"
        )

        source.write_text(
            original_content,
            encoding="utf-8",
        )

        ingest_file(
            source,
            output_dir=self.output_dir,
            batch_size=10,
            quarantine_dir=self.quarantine_dir,
        )

        self.assertEqual(
            source.read_text(encoding="utf-8"),
            original_content,
        )

    def test_unique_ingestion_directories(self):
        source = self.input_dir / "sample.csv"

        source.write_text(
            "username,action\n"
            "admin,login\n",
            encoding="utf-8",
        )

        first = ingest_file(
            source,
            output_dir=self.output_dir,
            quarantine_dir=self.quarantine_dir,
        )

        second = ingest_file(
            source,
            output_dir=self.output_dir,
            quarantine_dir=self.quarantine_dir,
        )

        self.assertNotEqual(
            first["output_directory"],
            second["output_directory"],
        )

    def test_quarantine_report_statistics(self):
        source = self.input_dir / "invalid.csv"

        source.write_text(
            "User Name,SQL Action,user_name\n"
            "admin,SELECT,another\n",
            encoding="utf-8",
        )

        report = ingest_file(
            source,
            output_dir=self.output_dir,
            strict=False,
            quarantine_dir=self.quarantine_dir,
        )

        saved_report = json.loads(
            Path(report["report_file"]).read_text(
                encoding="utf-8"
            )
        )

        self.assertEqual(
            saved_report["quarantined_records"],
            1,
        )

        self.assertEqual(
            saved_report["quarantine_statistics"][
                "total_rejected"
            ],
            1,
        )


if __name__ == "__main__":
    unittest.main()
