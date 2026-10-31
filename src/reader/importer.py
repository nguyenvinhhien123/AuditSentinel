
from pathlib import Path
import os

from src.reader.detector import detect_format
from src.reader.safety import validate_file


IGNORED_DIRECTORIES = {
    ".venv",
    "venv",
    "__pycache__",
    ".git",
    "node_modules",
}

MAX_FILES_TO_SCAN = 100_000


def scan_path(source_path):
    """
    Scan one file or all files inside a directory.
    This function does not copy, move, extract or execute files.
    """

    source = Path(source_path).expanduser()

    if not source.exists():
        raise FileNotFoundError(f"Path does not exist: {source}")

    if source.is_symlink():
        raise ValueError("Symbolic links are not allowed.")

    if source.is_file():
        files = [source]

    elif source.is_dir():
        files = []

        for root, directories, filenames in os.walk(
            source,
            followlinks=False
        ):
            # Skip unnecessary or potentially sensitive directories.
            directories[:] = [
                name for name in directories
                if name not in IGNORED_DIRECTORIES
                and not (Path(root) / name).is_symlink()
            ]

            for filename in filenames:
                file_path = Path(root) / filename

                if file_path.is_symlink():
                    continue

                files.append(file_path)

                if len(files) >= MAX_FILES_TO_SCAN:
                    break

            if len(files) >= MAX_FILES_TO_SCAN:
                break

    else:
        raise ValueError("Path must be a regular file or directory.")

    results = []

    for file_path in files:
        valid, message = validate_file(file_path)
        detection = detect_format(file_path)

        if not valid:
            status = "INVALID"
        elif detection["status"] == "SUPPORTED":
            status = "SUPPORTED"
        else:
            status = "UNSUPPORTED"

        results.append({
            "file": str(file_path),
            "name": file_path.name,
            "format": detection.get("format", "unknown"),
            "extension": detection.get("extension", ""),
            "size_bytes": detection.get("size_bytes", 0),
            "status": status,
            "message": message,
        })

    return {
        "source": str(source.resolve()),
        "total_files": len(results),
        "supported": sum(
            item["status"] == "SUPPORTED" for item in results
        ),
        "unsupported": sum(
            item["status"] == "UNSUPPORTED" for item in results
        ),
        "invalid": sum(
            item["status"] == "INVALID" for item in results
        ),
        "scan_limit_reached": len(results) >= MAX_FILES_TO_SCAN,
        "files": results,
    }
