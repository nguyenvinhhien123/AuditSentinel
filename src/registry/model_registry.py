
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import os
import uuid


class ModelRegistry:
    """
    Manage locally trained AuditSentinel model artifacts.

    The registry stores metadata and checksums.
    It does not load or execute model files.
    """

    def __init__(
        self,
        registry_path="models/registry.json",
        project_root=None,
    ):
        self.project_root = (
            Path(project_root).resolve()
            if project_root
            else Path(__file__).resolve().parents[2]
        )

        registry = Path(registry_path)

        if not registry.is_absolute():
            registry = self.project_root / registry

        self.registry_path = registry.resolve()

        if not self._is_inside_project(self.registry_path):
            raise ValueError(
                "Registry file must be inside the project directory"
            )

        self.registry_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        if not self.registry_path.exists():
            self._write_data({
                "version": 1,
                "models": [],
                "active_models": {},
            })

    def _is_inside_project(self, path):
        try:
            path.relative_to(self.project_root)
            return True
        except ValueError:
            return False

    def _read_data(self):
        try:
            with self.registry_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                data = json.load(file)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(
                f"Cannot read model registry: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise ValueError("Invalid registry structure")

        if not isinstance(data.get("models"), list):
            raise ValueError("Registry models must be a list")

        if not isinstance(data.get("active_models"), dict):
            raise ValueError("Registry active_models must be an object")

        return data

    def _write_data(self, data):
        temporary_path = self.registry_path.with_suffix(".tmp")

        try:
            with temporary_path.open(
                "w",
                encoding="utf-8",
            ) as file:
                json.dump(
                    data,
                    file,
                    indent=4,
                    ensure_ascii=False,
                )

            os.replace(temporary_path, self.registry_path)

        finally:
            if temporary_path.exists():
                temporary_path.unlink()

    @staticmethod
    def _calculate_sha256(file_path):
        digest = hashlib.sha256()

        with file_path.open("rb") as file:
            for chunk in iter(
                lambda: file.read(1024 * 1024),
                b"",
            ):
                digest.update(chunk)

        return digest.hexdigest()

    def _resolve_project_file(self, file_path):
        path = Path(file_path)

        if not path.is_absolute():
            path = self.project_root / path

        path = path.resolve()

        if not self._is_inside_project(path):
            raise ValueError(
                "Model files must be inside the project directory"
            )

        if not path.is_file():
            raise FileNotFoundError(
                f"Model file not found: {path}"
            )

        return path

    def register_model(self, model_path, name=None):
        """Register a model and its metadata without loading it."""

        artifact_path = self._resolve_project_file(model_path)

        metadata_path = artifact_path.parent / (
            "auto_model_metadata.json"
        )

        if not metadata_path.is_file():
            raise FileNotFoundError(
                "Model metadata file not found"
            )

        with metadata_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            metadata = json.load(file)

        mode = metadata.get("mode")
        algorithm = metadata.get("algorithm")

        if mode not in {"supervised", "unsupervised"}:
            raise ValueError("Invalid model mode in metadata")

        if not algorithm:
            raise ValueError("Model algorithm is missing")

        data = self._read_data()

        checksum = self._calculate_sha256(artifact_path)

        # Avoid duplicate registration of the same file.
        for existing in data["models"]:
            if existing.get("sha256") == checksum:
                return {
                    "status": "ALREADY_REGISTERED",
                    "model_id": existing["model_id"],
                    "model": existing,
                }

        model_id = str(uuid.uuid4())

        model_record = {
            "model_id": model_id,
            "name": name or f"{algorithm}-{model_id[:8]}",
            "mode": mode,
            "algorithm": algorithm,
            "model_path": str(
                artifact_path.relative_to(self.project_root)
            ),
            "metadata_path": str(
                metadata_path.relative_to(self.project_root)
            ),
            "sha256": checksum,
            "registered_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "status": "registered",
            "training_mode": metadata.get(
                "training_mode",
                "auto",
            ),
        }

        data["models"].append(model_record)

        self._write_data(data)

        return {
            "status": "REGISTERED",
            "model_id": model_id,
            "model": model_record,
        }

    def list_models(self, mode=None):
        """Return registered models, optionally filtered by mode."""

        data = self._read_data()
        models = data["models"]

        if mode is not None:
            if mode not in {"supervised", "unsupervised"}:
                raise ValueError("Invalid model mode")

            models = [
                model
                for model in models
                if model.get("mode") == mode
            ]

        return models

    @staticmethod
    def _validate_model_name(name):
        if not isinstance(name, str):
            raise TypeError("Model name must be text")
        normalized = name.strip()
        if not normalized or len(normalized) > 120:
            raise ValueError("Model name must contain 1-120 characters")
        if any(ord(character) < 32 for character in normalized):
            raise ValueError("Model name contains unsupported characters")
        return normalized

    def rename_model(self, model_id, name):
        """Update a model's display name without changing its artifact."""

        name = self._validate_model_name(name)
        data = self._read_data()
        model = next(
            (
                item
                for item in data["models"]
                if item["model_id"] == model_id
            ),
            None,
        )
        if model is None:
            raise KeyError(f"Unknown model ID: {model_id}")

        model["name"] = name
        self._write_data(data)
        return {
            "status": "RENAMED",
            "model_id": model_id,
            "name": name,
        }

    def delete_model(self, model_id):
        """Remove a model from the registry and delete its unshared files."""

        data = self._read_data()
        model = next(
            (
                item
                for item in data["models"]
                if item["model_id"] == model_id
            ),
            None,
        )
        if model is None:
            raise KeyError(f"Unknown model ID: {model_id}")

        model_paths = {
            model.get("model_path"),
            model.get("metadata_path"),
        }
        paths_to_delete = []
        for stored_path in model_paths:
            if not isinstance(stored_path, str) or not stored_path:
                continue
            path = Path(stored_path)
            if not path.is_absolute():
                path = self.project_root / path
            if path.is_symlink():
                raise ValueError("Model files cannot be symbolic links")
            path = path.resolve()
            if not self._is_inside_project(path):
                raise ValueError(
                    "Model files must be inside the project directory"
                )
            if path == self.registry_path:
                raise ValueError("Model file path conflicts with the registry")
            if path.exists() and not path.is_file():
                raise ValueError("Model artifact path is not a file")

            shared = any(
                other.get(key)
                and (self.project_root / other[key]).resolve() == path
                for other in data["models"]
                if other is not model
                for key in ("model_path", "metadata_path")
            )
            if path.exists() and not shared:
                paths_to_delete.append(path)

        staged_files = []
        try:
            for path in paths_to_delete:
                staged_path = path.with_name(
                    f".{path.name}.deleting-{uuid.uuid4().hex}"
                )
                path.rename(staged_path)
                staged_files.append((path, staged_path))

            data["models"] = [
                item for item in data["models"]
                if item["model_id"] != model_id
            ]
            deactivated = model_id in data["active_models"].values()
            data["active_models"] = {
                mode: active_id
                for mode, active_id in data["active_models"].items()
                if active_id != model_id
            }
            self._write_data(data)
        except (OSError, ValueError):
            for original_path, staged_path in reversed(staged_files):
                if staged_path.exists():
                    staged_path.rename(original_path)
            raise

        try:
            for _, staged_path in staged_files:
                staged_path.unlink()
        except OSError as exc:
            raise RuntimeError(
                "The model was removed from the registry, but a model file "
                f"could not be deleted: {exc}"
            ) from exc

        return {
            "status": "DELETED",
            "model_id": model_id,
            "name": model.get("name"),
            "mode": model.get("mode"),
            "deactivated": deactivated,
        }

    def verify_model(self, model_id):
        """Verify that a registered model still matches its checksum."""

        data = self._read_data()

        model = next(
            (
                item
                for item in data["models"]
                if item["model_id"] == model_id
            ),
            None,
        )

        if model is None:
            raise KeyError(f"Unknown model ID: {model_id}")

        path = self._resolve_project_file(
            model["model_path"]
        )

        actual_checksum = self._calculate_sha256(path)

        valid = actual_checksum == model["sha256"]

        return {
            "model_id": model_id,
            "valid": valid,
            "expected_sha256": model["sha256"],
            "actual_sha256": actual_checksum,
            "status": "VERIFIED" if valid else "CHECKSUM_MISMATCH",
        }

    def activate_model(self, model_id):
        """Set one registered model as active for its mode."""

        data = self._read_data()

        model = next(
            (
                item
                for item in data["models"]
                if item["model_id"] == model_id
            ),
            None,
        )

        if model is None:
            raise KeyError(f"Unknown model ID: {model_id}")

        verification = self.verify_model(model_id)

        if not verification["valid"]:
            raise ValueError(
                "Model integrity check failed. Activation rejected."
            )

        mode = model["mode"]

        previous_id = data["active_models"].get(mode)

        if previous_id:
            for item in data["models"]:
                if item["model_id"] == previous_id:
                    item["status"] = "registered"

        data["active_models"][mode] = model_id
        model["status"] = "active"

        self._write_data(data)

        return {
            "status": "ACTIVATED",
            "mode": mode,
            "model_id": model_id,
            "previous_model_id": previous_id,
        }

    def get_active_model(self, mode):
        """Get the active model record for a training mode."""

        if mode not in {"supervised", "unsupervised"}:
            raise ValueError("Invalid model mode")

        data = self._read_data()
        model_id = data["active_models"].get(mode)

        if not model_id:
            return None

        return next(
            (
                item
                for item in data["models"]
                if item["model_id"] == model_id
            ),
            None,
        )

    def deactivate_model(self, mode):
        """Deactivate the active model for a mode."""

        if mode not in {"supervised", "unsupervised"}:
            raise ValueError("Invalid model mode")

        data = self._read_data()
        model_id = data["active_models"].pop(mode, None)

        if model_id is None:
            return {
                "status": "NO_ACTIVE_MODEL",
                "mode": mode,
            }

        for model in data["models"]:
            if model["model_id"] == model_id:
                model["status"] = "registered"
                break

        self._write_data(data)

        return {
            "status": "DEACTIVATED",
            "mode": mode,
            "model_id": model_id,
        }
