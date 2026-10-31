
import csv
import tempfile
import unittest

from pathlib import Path

from src.reader.ingestion import ingest_file


class TestIngestionStress(unittest.TestCase):

    def test_100k_records(self):
        total_records = 100_000
        batch_size = 5_000

        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            source = base / "large_dataset.csv"
            output = base / "processed"

            # Generate a synthetic CSV dataset.
            with source.open(
                "w",
                encoding="utf-8",
                newline="",
            ) as file:
                writer = csv.writer(file)

                writer.writerow([
                    "timestamp",
                    "username",
                    "sql_action",
                    "src_ip",
                    "status",
                ])

                for i in range(total_records):
                    writer.writerow([
                        "2026-10-30T10:00:00Z",
                        f"user_{i % 1000}",
                        ["SELECT", "INSERT", "UPDATE", "DELETE"][i % 4],
                        f"192.168.{(i // 254) % 255}.{(i % 254) + 1}",
                        "SUCCESS",
                    ])

            report = ingest_file(
                source,
                output_dir=output,
                batch_size=batch_size,
            )

            expected_batches = (
                total_records + batch_size - 1
            ) // batch_size

            self.assertEqual(
                report["status"],
                "COMPLETED",
            )

            self.assertEqual(
                report["total_records_read"],
                total_records,
            )

            self.assertEqual(
                report["saved_records"],
                total_records,
            )

            self.assertEqual(
                report["batches_processed"],
                expected_batches,
            )

            self.assertEqual(
                len(report["parquet_files"]),
                expected_batches,
            )

            self.assertTrue(
                Path(report["report_file"]).exists()
            )

            print("\n===== STRESS TEST REPORT =====")
            print("Input records:", report["total_records_read"])
            print("Saved records:", report["saved_records"])
            print("Batches:", report["batches_processed"])
            print("Expected batches:", expected_batches)
            print("Status:", report["status"])


if __name__ == "__main__":
    unittest.main()
