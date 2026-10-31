from __future__ import annotations

import json
import re
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


LEGACY_SESSION_ID = "legacy"


@dataclass(frozen=True)
class SessionContext:
    session_id: str
    name: str
    root: Path
    created_at: str
    is_legacy: bool = False


class SessionManager:
    """Keep incident data separate while sharing the project's model registry."""

    def __init__(self, project_root: str | Path):
        self.project_root = Path(project_root).resolve()
        self.sessions_root = self.project_root / "sessions"
        self.index_path = self.sessions_root / "index.json"
        self.sessions_root.mkdir(parents=True, exist_ok=True)
        if not self.index_path.exists():
            now = datetime.now(timezone.utc).isoformat()
            self._write_index({
                "version": 1,
                "active_session_id": LEGACY_SESSION_ID,
                "sessions": [{
                    "session_id": LEGACY_SESSION_ID,
                    "name": "Existing Data",
                    "created_at": now,
                    "is_legacy": True,
                }],
            })

    def _read_index(self) -> dict:
        try:
            with self.index_path.open("r", encoding="utf-8") as file:
                data = json.load(file)
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Cannot read session index: {exc}"
            ) from exc
        if not isinstance(data, dict) or not isinstance(data.get("sessions"), list):
            raise ValueError("Invalid session index structure")
        if not isinstance(data.get("active_session_id"), str):
            raise ValueError("Session index has no active session ID")
        return data

    def _write_index(self, data: dict) -> None:
        self.sessions_root.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=self.sessions_root,
                prefix=".index-",
                suffix=".tmp",
                delete=False,
            ) as file:
                temporary_path = Path(file.name)
                json.dump(data, file, ensure_ascii=False, indent=2)
                file.write("\n")
            temporary_path.replace(self.index_path)
        except OSError as exc:
            raise RuntimeError(
                f"Cannot save session index: {exc}"
            ) from exc
        finally:
            if temporary_path is not None and temporary_path.exists():
                temporary_path.unlink()

    @staticmethod
    def _validate_name(name: str) -> str:
        if not isinstance(name, str):
            raise TypeError("Session name must be text")
        normalized = name.strip()
        if not normalized or len(normalized) > 80:
            raise ValueError("Session name must contain 1-80 characters")
        if any(ord(character) < 32 for character in normalized):
            raise ValueError("Session name contains unsupported characters")
        return normalized

    @staticmethod
    def _validate_session_id(session_id: str) -> str:
        if not isinstance(session_id, str) or not re.fullmatch(
            r"[A-Za-z0-9_-]{1,64}",
            session_id,
        ):
            raise ValueError("Invalid session ID")
        return session_id

    def list_sessions(self) -> list[SessionContext]:
        data = self._read_index()
        result = []
        found_ids = set()
        for item in data["sessions"]:
            if not isinstance(item, dict):
                raise ValueError("Invalid session entry")
            session_id = self._validate_session_id(item.get("session_id"))
            if session_id in found_ids:
                raise ValueError("Duplicate session ID in session index")
            found_ids.add(session_id)
            is_legacy = item.get("is_legacy") is True
            root = (
                self.project_root
                if is_legacy
                else (self.sessions_root / session_id).resolve()
            )
            if not is_legacy:
                try:
                    root.relative_to(self.sessions_root.resolve())
                except ValueError as exc:
                    raise ValueError(
                        "Session path is outside the sessions directory"
                    ) from exc
            result.append(SessionContext(
                session_id=session_id,
                name=self._validate_name(item.get("name")),
                root=root,
                created_at=str(item.get("created_at", "")),
                is_legacy=is_legacy,
            ))
        if LEGACY_SESSION_ID not in found_ids:
            raise ValueError("The existing-data session is missing")
        return result

    def get_session(self, session_id: str) -> SessionContext:
        session_id = self._validate_session_id(session_id)
        for session in self.list_sessions():
            if session.session_id == session_id:
                return session
        raise KeyError(f"Unknown session ID: {session_id}")

    def active_session(self) -> SessionContext:
        data = self._read_index()
        return self.get_session(data["active_session_id"])

    def set_active_session(self, session_id: str) -> SessionContext:
        session = self.get_session(session_id)
        data = self._read_index()
        data["active_session_id"] = session.session_id
        self._write_index(data)
        return session

    def get_state(self, session_id: str) -> dict[str, str]:
        session_id = self._validate_session_id(session_id)
        data = self._read_index()
        item = next(
            (
                entry for entry in data["sessions"]
                if isinstance(entry, dict)
                and entry.get("session_id") == session_id
            ),
            None,
        )
        if item is None:
            raise KeyError(f"Unknown session ID: {session_id}")
        state = item.get("ui_state", {})
        if not isinstance(state, dict):
            raise ValueError("Invalid session UI state")
        allowed_keys = {
            "dataset_path",
            "training_dataset_path",
            "detection_dataset_path",
            "prevention_dataset_path",
        }
        if any(
            key not in allowed_keys or not isinstance(value, str)
            for key, value in state.items()
        ):
            raise ValueError("Invalid session UI state")
        return state

    def save_state(self, session_id: str, state: dict[str, str]) -> None:
        session_id = self._validate_session_id(session_id)
        if not isinstance(state, dict):
            raise TypeError("Session UI state must be a dictionary")
        allowed_keys = {
            "dataset_path",
            "training_dataset_path",
            "detection_dataset_path",
            "prevention_dataset_path",
        }
        if any(
            key not in allowed_keys
            or not isinstance(value, str)
            or len(value) > 4096
            for key, value in state.items()
        ):
            raise ValueError("Invalid session UI state")

        data = self._read_index()
        item = next(
            (
                entry for entry in data["sessions"]
                if isinstance(entry, dict)
                and entry.get("session_id") == session_id
            ),
            None,
        )
        if item is None:
            raise KeyError(f"Unknown session ID: {session_id}")
        item["ui_state"] = {
            key: value
            for key, value in state.items()
            if value.strip()
        }
        self._write_index(data)

    def create_session(self, name: str) -> SessionContext:
        name = self._validate_name(name)
        data = self._read_index()
        session_id = uuid.uuid4().hex
        created_at = datetime.now(timezone.utc).isoformat()
        session_root = (self.sessions_root / session_id).resolve()
        try:
            session_root.relative_to(self.sessions_root.resolve())
        except ValueError as exc:
            raise ValueError("Invalid session storage path") from exc

        session_root.mkdir(parents=True, exist_ok=False)
        try:
            (session_root / "logs").mkdir()
            (session_root / "reports" / "investigations").mkdir(
                parents=True
            )
            data["sessions"].append({
                "session_id": session_id,
                "name": name,
                "created_at": created_at,
                "is_legacy": False,
                "ui_state": {},
            })
            data["active_session_id"] = session_id
            self._write_index(data)
        except (OSError, RuntimeError):
            shutil.rmtree(session_root, ignore_errors=True)
            raise

        return SessionContext(
            session_id=session_id,
            name=name,
            root=session_root,
            created_at=created_at,
            is_legacy=False,
        )
