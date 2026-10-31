import json
import tempfile
import unittest
from pathlib import Path

from src.sessions.manager import LEGACY_SESSION_ID, SessionManager


class SessionManagerTests(unittest.TestCase):
    def test_existing_data_is_legacy_session_and_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            project_root = Path(temporary_directory)
            logs = project_root / "logs"
            logs.mkdir()
            alerts = logs / "alerts.jsonl"
            alerts.write_text('{"alert_id":"old-alert"}\n', encoding="utf-8")

            manager = SessionManager(project_root)
            legacy = manager.active_session()

            self.assertEqual(legacy.session_id, LEGACY_SESSION_ID)
            self.assertTrue(legacy.is_legacy)
            self.assertEqual(legacy.root, project_root.resolve())
            self.assertEqual(
                alerts.read_text(encoding="utf-8"),
                '{"alert_id":"old-alert"}\n',
            )

    def test_new_sessions_are_isolated_and_active_session_persists(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            project_root = Path(temporary_directory)
            manager = SessionManager(project_root)
            legacy_alerts = project_root / "logs" / "alerts.jsonl"
            legacy_alerts.parent.mkdir(parents=True)
            legacy_alerts.write_text(
                '{"alert_id":"legacy-alert"}\n',
                encoding="utf-8",
            )

            created = manager.create_session("Incident 2026-11")

            self.assertEqual(manager.active_session(), created)
            self.assertFalse(created.is_legacy)
            self.assertTrue((created.root / "logs").is_dir())
            self.assertTrue(
                (created.root / "reports" / "investigations").is_dir()
            )
            self.assertFalse((created.root / "logs" / "alerts.jsonl").exists())
            self.assertIn(created, manager.list_sessions())

            reopened = SessionManager(project_root)
            self.assertEqual(reopened.active_session(), created)
            self.assertEqual(
                legacy_alerts.read_text(encoding="utf-8"),
                '{"alert_id":"legacy-alert"}\n',
            )

            reopened.set_active_session(LEGACY_SESSION_ID)
            self.assertEqual(
                reopened.active_session().session_id,
                LEGACY_SESSION_ID,
            )

    def test_invalid_session_names_and_ids_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            manager = SessionManager(temporary_directory)

            for name in ("", "  ", "x" * 81):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    manager.create_session(name)

            for session_id in ("../escape", "", "a" * 65):
                with self.subTest(session_id=session_id), self.assertRaises(
                    ValueError
                ):
                    manager.set_active_session(session_id)

    def test_session_index_is_json_and_references_only_contained_paths(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            manager = SessionManager(temporary_directory)
            session = manager.create_session("test")
            data = json.loads(manager.index_path.read_text(encoding="utf-8"))

            self.assertEqual(data["active_session_id"], session.session_id)
            self.assertTrue(
                session.root.is_relative_to(manager.sessions_root.resolve())
            )

    def test_ui_state_is_saved_and_restored_for_each_session(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            manager = SessionManager(temporary_directory)
            manager.save_state(LEGACY_SESSION_ID, {
                "detection_dataset_path": "D:\\audit\\old.csv",
            })
            session = manager.create_session("new case")

            self.assertEqual(manager.get_state(session.session_id), {})
            manager.save_state(session.session_id, {
                "detection_dataset_path": "D:\\audit\\new.csv",
                "prevention_dataset_path": "D:\\audit\\new.csv",
            })

            self.assertEqual(
                manager.get_state(session.session_id),
                {
                    "detection_dataset_path": "D:\\audit\\new.csv",
                    "prevention_dataset_path": "D:\\audit\\new.csv",
                },
            )
            self.assertEqual(
                manager.get_state(LEGACY_SESSION_ID),
                {"detection_dataset_path": "D:\\audit\\old.csv"},
            )

    def test_ui_state_rejects_unexpected_fields_and_non_text_paths(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            manager = SessionManager(temporary_directory)

            with self.assertRaises(ValueError):
                manager.save_state("legacy", {"unexpected": "value"})
            with self.assertRaises(ValueError):
                manager.save_state("legacy", {"dataset_path": 42})


if __name__ == "__main__":
    unittest.main()
