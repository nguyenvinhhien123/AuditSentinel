
from pathlib import Path
import csv
import json

from src.reader.detector import detect_format
from src.reader.safety import validate_file, read_text_preview


def analyze_file(file_path):
    path = Path(file_path)

    valid, message = validate_file(path)

    if not valid:
        return {
            "file": str(path),
            "status": "ERROR",
            "message": message,
        }

    info = detect_format(path)
    file_format = info["format"]

    result = {
        "file": str(path),
        "format": file_format,
        "size_mb": round(path.stat().st_size / 1024**2, 2),
        "status": "ANALYZED",
        "preview": None,
        "details": {},
    }

    try:
        if file_format in ("text", "log", "python_source", "sql"):
            content = read_text_preview(path)

            result["preview"] = content[:1000]
            result["details"]["characters_previewed"] = len(content)

            if file_format == "python_source":
                result["details"]["execution"] = "NEVER_EXECUTED"

        elif file_format == "json":
            content = read_text_preview(path)

            if path.stat().st_size > 1024 * 1024:
                result["status"] = "PREVIEW_ONLY"
                result["message"] = (
                    "JSON file is larger than 1 MB. "
                    "Full parsing requires a streaming parser."
                )
                result["preview"] = content[:1000]
            else:
                data = json.loads(content)
                result["preview"] = str(data)[:1000]
                result["details"]["data_type"] = type(data).__name__

        elif file_format == "jsonl":
            content = read_text_preview(path)

            lines = [
                line for line in content.splitlines()
                if line.strip()
            ]

            result["preview"] = lines[:5]
            result["details"]["preview_lines"] = len(lines)

        elif file_format in ("csv", "tsv"):
            delimiter = "\t" if file_format == "tsv" else ","

            with path.open(
                "r",
                encoding="utf-8-sig",
                errors="replace",
                newline=""
            ) as file:
                reader = csv.reader(file, delimiter=delimiter)
                rows = []

                for index, row in enumerate(reader):
                    rows.append(row)
                    if index >= 5:
                        break

            result["preview"] = rows
            result["details"]["columns"] = (
                len(rows[0]) if rows else 0
            )
            result["details"]["preview_rows"] = len(rows)

        else:
            result["status"] = "FORMAT_DETECTED"
            result["message"] = (
                "Format recognized, specialized parser "
                "will be implemented in the next stage."
            )

    except Exception as exc:
        result["status"] = "PARSE_ERROR"
        result["message"] = str(exc)

    return result
