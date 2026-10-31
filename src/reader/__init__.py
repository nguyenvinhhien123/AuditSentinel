
from pathlib import Path

SUPPORTED_FORMATS = {
    ".csv": "csv",
    ".tsv": "tsv",
    ".json": "json",
    ".jsonl": "jsonl",
    ".ndjson": "jsonl",
    ".txt": "text",
    ".log": "log",
    ".xml": "xml",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".parquet": "parquet",
    ".xlsx": "excel",
    ".xls": "excel",
    ".py": "python_source",
    ".sql": "sql",
    ".zip": "zip",
}

def detect_format(file_path):
    path = Path(file_path)

    if not path.exists():
        return {"format": "unknown", "status": "NOT_FOUND"}

    if not path.is_file():
        return {"format": "unknown", "status": "NOT_A_FILE"}

    extension = path.suffix.lower()
    detected = SUPPORTED_FORMATS.get(extension, "unknown")

    # Check common binary signatures.
    try:
        with path.open("rb") as f:
            signature = f.read(8)
    except OSError as exc:
        return {
            "format": "unknown",
            "status": "READ_ERROR",
            "error": str(exc),
        }

    if signature.startswith(b"PAR1"):
        detected = "parquet"
    elif signature.startswith(b"PK\x03\x04"):
        if extension == ".xlsx":
            detected = "excel"
        else:
            detected = "zip"
    elif signature.startswith(b"\xD0\xCF\x11\xE0"):
        if extension == ".xls":
            detected = "excel"
        else:
            detected = "unknown"

    return {
        "format": detected,
        "extension": extension,
        "size_bytes": path.stat().st_size,
        "status": "SUPPORTED" if detected != "unknown" else "UNSUPPORTED",
    }
