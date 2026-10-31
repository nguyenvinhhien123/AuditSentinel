
import json
import tempfile
import unittest

from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from src.reader.streaming import (
    StreamingReader,
    StreamingReadError,
)


class TestStreamingReader(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    # TEST 1: CSV batch reading
    def test_csv_batches(self):
        path = self.base / "sample.csv"

        path.write_text(
            "username,query\n"
            "admin,SELECT 1\n"
            "user,SELECT 2\n"
            "guest,SELECT 3\n",
            encoding="utf-8",
        )

        reader = StreamingReader(batch_size=2)
        batches = list(reader.iter_batches(path))

        self.assertEqual(len(batches), 2)
        self.assertEqual(len(batches[0]), 2)
        self.assertEqual(len(batches[1]), 1)
        self.assertEqual(reader.stats["total_records"], 3)
        self.assertEqual(reader.stats["total_batches"], 2)
        self.assertEqual(reader.stats["status"], "COMPLETED")

    # TEST 2: TSV batch reading
    def test_tsv_batches(self):
        path = self.base / "sample.tsv"

        path.write_text(
            "username\tquery\n"
            "admin\tSELECT 1\n"
            "user\tSELECT 2\n",
            encoding="utf-8",
        )

        reader = StreamingReader(batch_size=1)
        batches = list(reader.iter_batches(path))

        self.assertEqual(len(batches), 2)
        self.assertEqual(reader.stats["total_records"], 2)
        self.assertEqual(reader.stats["total_batches"], 2)

    # TEST 3: JSONL batch reading
    def test_jsonl_batches(self):
        path = self.base / "sample.jsonl"

        records = [
            {"username": "admin", "query": "SELECT 1"},
            {"username": "user", "query": "SELECT 2"},
            {"username": "guest", "query": "SELECT 3"},
        ]

        path.write_text(
            "\n".join(
                json.dumps(item) for item in records
            ),
            encoding="utf-8",
        )

        reader = StreamingReader(batch_size=2)
        batches = list(reader.iter_batches(path))

        self.assertEqual(len(batches), 2)
        self.assertEqual(reader.stats["total_records"], 3)
        self.assertEqual(reader.stats["total_batches"], 2)

    # TEST 4: JSONL invalid record - strict mode
    def test_jsonl_invalid_line_strict(self):
        path = self.base / "invalid.jsonl"

        path.write_text(
            '{"username": "admin"}\n'
            '{"username": invalid}\n',
            encoding="utf-8",
        )

        reader = StreamingReader(
            batch_size=2,
            strict=True,
        )

        with self.assertRaises(StreamingReadError):
            list(reader.iter_batches(path))

        self.assertEqual(reader.stats["error_count"], 1)
        self.assertEqual(reader.stats["status"], "ERROR")

    # TEST 5: JSONL invalid record - skip mode
    def test_jsonl_invalid_line_skip(self):
        path = self.base / "invalid.jsonl"

        path.write_text(
            '{"username": "admin"}\n'
            '{"username": invalid}\n'
            '{"username": "user"}\n',
            encoding="utf-8",
        )

        reader = StreamingReader(
            batch_size=2,
            strict=False,
        )

        batches = list(reader.iter_batches(path))

        self.assertEqual(reader.stats["total_records"], 2)
        self.assertEqual(reader.stats["skipped_records"], 1)
        self.assertEqual(reader.stats["error_count"], 1)

        self.assertEqual(
            reader.stats["status"],
            "COMPLETED_WITH_ERRORS",
        )

    # TEST 6: Parquet batch reading
    def test_parquet_batches(self):
        path = self.base / "sample.parquet"

        table = pa.table({
            "username": [
                "admin",
                "user1",
                "user2",
                "guest",
                "root",
            ],
            "query": [
                "SELECT 1",
                "SELECT 2",
                "DELETE FROM users",
                "SELECT 4",
                "DROP TABLE users",
            ],
        })

        pq.write_table(table, path)

        reader = StreamingReader(batch_size=2)
        batches = list(reader.iter_batches(path))

        self.assertEqual(len(batches), 3)
        self.assertEqual(reader.stats["total_records"], 5)
        self.assertEqual(reader.stats["total_batches"], 3)
        self.assertEqual(reader.stats["status"], "COMPLETED")

    # TEST 7: Invalid batch size
    def test_invalid_batch_size(self):
        with self.assertRaises(ValueError):
            StreamingReader(batch_size=0)

        with self.assertRaises(ValueError):
            StreamingReader(batch_size=-1)

    # TEST 8: Unsupported format
    def test_unsupported_format(self):
        path = self.base / "sample.txt"

        path.write_text(
            "hello",
            encoding="utf-8",
        )

        reader = StreamingReader()

        with self.assertRaises(StreamingReadError):
            list(reader.iter_batches(path))


if __name__ == "__main__":
    unittest.main()
