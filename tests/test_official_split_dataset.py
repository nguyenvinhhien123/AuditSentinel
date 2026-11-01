import tempfile
import unittest
from pathlib import Path

from src.training.auto_trainer import auto_train
from src.training.dataset import (
    select_dataset_records,
    select_training_records,
)
from src.training.evaluator import (
    binary_detection_metrics,
    normalize_binary_label,
)
from src.training.manual_trainer import manual_train


class TestOfficialSplitDataset(unittest.TestCase):
    def setUp(self):
        self.train_records = [
            {
                "full_query": f"SELECT airport_id FROM airports WHERE id = {index}",
                "label": "0",
                "split": "train",
            }
            for index in range(12)
        ]
        self.test_records = [
            {
                "full_query": "SELECT airport_id FROM airports",
                "label": "0",
                "split": "test",
            },
            {
                "full_query": (
                    "SELECT * FROM airports WHERE id = 1 "
                    "UNION SELECT password FROM users"
                ),
                "label": "1",
                "split": "test",
            },
        ]

    def test_training_uses_train_split_and_normalizes_query_column(self):
        records, uses_official_split = select_training_records([
            self.train_records + self.test_records,
        ])

        self.assertTrue(uses_official_split)
        self.assertEqual(len(records), len(self.train_records))
        self.assertEqual(records[0]["query"], records[0]["full_query"])
        self.assertTrue(all(row["split"] == "train" for row in records))

    def test_detection_uses_only_test_split(self):
        records, uses_official_split = select_dataset_records(
            self.train_records + self.test_records,
            "test",
        )

        self.assertTrue(uses_official_split)
        self.assertEqual(len(records), len(self.test_records))
        self.assertTrue(all(row["split"] == "test" for row in records))
        self.assertTrue(all("query" in row for row in records))

    def test_unsupervised_training_can_fit_all_official_training_rows(self):
        records, _ = select_training_records([
            self.train_records + self.test_records,
        ])

        with tempfile.TemporaryDirectory() as directory:
            result = auto_train(
                records,
                output_dir=Path(directory),
                test_size=None,
                random_state=42,
            )

        self.assertEqual(result["metadata"]["training_records"], 12)
        self.assertEqual(result["metadata"]["testing_records"], 0)
        self.assertIn("separate labeled test split", result["evaluation"]["note"])

    def test_manual_unsupervised_training_can_fit_all_training_rows(self):
        records, _ = select_training_records([
            self.train_records + self.test_records,
        ])

        with tempfile.TemporaryDirectory() as directory:
            result = manual_train(
                records,
                mode="unsupervised",
                output_dir=Path(directory),
                n_estimators=10,
                test_size=None,
                random_state=42,
            )

        self.assertEqual(result["metadata"]["training_records"], 12)
        self.assertEqual(result["metadata"]["testing_records"], 0)
        self.assertIn("separate labeled test split", result["evaluation"]["note"])

    def test_binary_test_labels_and_metrics(self):
        self.assertEqual(normalize_binary_label("0"), "normal")
        self.assertEqual(normalize_binary_label("1"), "attack")
        self.assertIsNone(normalize_binary_label("other"))

        result = binary_detection_metrics({
            "true_positive": 8,
            "false_positive": 2,
            "true_negative": 7,
            "false_negative": 3,
        })

        self.assertEqual(result["records_evaluated"], 20)
        self.assertEqual(result["accuracy"], 0.75)
        self.assertEqual(result["precision_attack"], 0.8)
        self.assertEqual(result["recall_attack"], 0.7273)


if __name__ == "__main__":
    unittest.main()
