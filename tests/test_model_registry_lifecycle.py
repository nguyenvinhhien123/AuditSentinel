import json
import tempfile
import unittest
from pathlib import Path

from src.registry.model_registry import ModelRegistry


class ModelRegistryLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.project_root = Path(self.temporary_directory.name)
        self.registry = ModelRegistry(project_root=self.project_root)
        self.model_path = self.project_root / "models" / "sample" / "model.joblib"
        self.metadata_path = (
            self.project_root / "models" / "sample" / "auto_model_metadata.json"
        )
        self.model_path.parent.mkdir(parents=True)
        self.model_path.write_bytes(b"test model")
        self.metadata_path.write_text(
            json.dumps({
                "mode": "supervised",
                "algorithm": "RandomForestClassifier",
            }),
            encoding="utf-8",
        )
        registration = self.registry.register_model(
            self.model_path,
            name="Original name",
        )
        self.model_id = registration["model_id"]

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_rename_model_updates_display_name(self):
        result = self.registry.rename_model(self.model_id, "  New name  ")

        self.assertEqual(result["status"], "RENAMED")
        self.assertEqual(result["name"], "New name")
        self.assertEqual(self.registry.list_models()[0]["name"], "New name")
        self.assertTrue(self.model_path.is_file())

    def test_rename_model_rejects_empty_or_unknown_models(self):
        with self.assertRaises(ValueError):
            self.registry.rename_model(self.model_id, "  ")
        with self.assertRaises(KeyError):
            self.registry.rename_model("unknown", "New name")

    def test_delete_model_removes_active_model_and_its_files(self):
        self.registry.activate_model(self.model_id)

        result = self.registry.delete_model(self.model_id)

        self.assertEqual(result["status"], "DELETED")
        self.assertTrue(result["deactivated"])
        self.assertEqual(self.registry.list_models(), [])
        self.assertIsNone(self.registry.get_active_model("supervised"))
        self.assertFalse(self.model_path.exists())
        self.assertFalse(self.metadata_path.exists())

    def test_delete_model_rejects_unknown_model(self):
        with self.assertRaises(KeyError):
            self.registry.delete_model("unknown")


if __name__ == "__main__":
    unittest.main()
