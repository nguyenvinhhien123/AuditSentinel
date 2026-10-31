
from pathlib import Path

MAX_FILE_SIZE = 10 * 1024**3
MAX_TEXT_PREVIEW = 1024 * 1024


def validate_file(file_path):
    path = Path(file_path)

    if not path.exists():
        return False, "File does not exist"

    if not path.is_file():
        return False, "Path is not a file"

    try:
        size = path.stat().st_size
    except OSError as exc:
        return False, f"Cannot access file: {exc}"

    if size == 0:
        return False, "Empty file"

    if size > MAX_FILE_SIZE:
        return False, "File exceeds maximum size limit"

    return True, "OK"


def read_text_preview(file_path, limit=MAX_TEXT_PREVIEW):
    valid, message = validate_file(file_path)

    if not valid:
        raise ValueError(message)

    path = Path(file_path)

    with path.open("rb") as file:
        raw = file.read(limit)

    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue

    return raw.decode("utf-8", errors="replace")
