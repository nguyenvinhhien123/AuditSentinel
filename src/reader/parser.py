
from pathlib import Path
import csv
import json

import polars as pl
import pyarrow.parquet as pq
import yaml
from openpyxl import load_workbook
from defusedxml import ElementTree as SafeET

from src.reader.detector import detect_format
from src.reader.safety import validate_file, read_text_preview


DEFAULT_PREVIEW_ROWS = 5
MAX_PREVIEW_BYTES = 1024 * 1024


def _result(path, file_format):
    return {
        "file": str(path),
        "format": file_format,
        "status": "PARSED",
        "preview": [],
        "details": {},
        "message": "",
    }


def _parse_delimited(path, delimiter, preview_rows):
    rows = []

    with path.open(
        "r",
        encoding="utf-8-sig",
        errors="replace",
        newline=""
    ) as file:
        reader = csv.reader(file, delimiter=delimiter)

        for index, row in enumerate(reader):
            rows.append(row)

            if index >= preview_rows:
                break

    return {
        "preview": rows,
        "details": {
            "columns": len(rows[0]) if rows else 0,
            "preview_rows": max(len(rows) - 1, 0),
            "header": rows[0] if rows else [],
        },
    }


def _parse_json(path):
    size = path.stat().st_size

    if size > MAX_PREVIEW_BYTES:
        return {
            "status": "PREVIEW_ONLY",
            "message": "JSON exceeds 1 MB. Full streaming JSON parsing is not enabled.",
            "preview": read_text_preview(path)[:1000],
            "details": {"size_bytes": size},
        }

    with path.open("r", encoding="utf-8-sig") as file:
        data = json.load(file)

    if isinstance(data, list):
        preview = data[:DEFAULT_PREVIEW_ROWS]
    else:
        preview = data

    return {
        "preview": preview,
        "details": {
            "data_type": type(data).__name__,
            "items": len(data) if isinstance(data, (list, dict)) else None,
        },
    }


def _parse_jsonl(path):
    rows = []

    with path.open("r", encoding="utf-8-sig", errors="replace") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                return {
                    "status": "PARSE_ERROR",
                    "message": f"Invalid JSON on line {line_number}: {exc}",
                    "preview": rows,
                    "details": {},
                }

            if len(rows) < DEFAULT_PREVIEW_ROWS:
                rows.append(item)

    return {
        "preview": rows,
        "details": {
            "preview_rows": len(rows),
            "reading_mode": "LINE_BY_LINE",
        },
    }


def _parse_excel(path):
    if path.suffix.lower() != ".xlsx":
        return {
            "status": "UNSUPPORTED_PARSER",
            "message": "Legacy .xls parsing is not enabled yet.",
            "preview": [],
            "details": {},
        }

    workbook = load_workbook(
        filename=path,
        read_only=True,
        data_only=True
    )

    try:
        sheet = workbook.active
        rows = []

        for index, row in enumerate(sheet.iter_rows(values_only=True)):
            rows.append(list(row))

            if index >= DEFAULT_PREVIEW_ROWS:
                break

        return {
            "preview": rows,
            "details": {
                "sheet": sheet.title,
                "preview_rows": len(rows),
                "reading_mode": "READ_ONLY",
            },
        }
    finally:
        workbook.close()


def _parse_parquet(path):
    parquet_file = pq.ParquetFile(path)
    rows = []

    for batch in parquet_file.iter_batches(
        batch_size=DEFAULT_PREVIEW_ROWS
    ):
        rows.extend(batch.to_pylist())
        break

    return {
        "preview": rows,
        "details": {
            "columns": parquet_file.schema.names,
            "row_groups": parquet_file.num_row_groups,
            "metadata_rows": parquet_file.metadata.num_rows,
            "reading_mode": "BATCH",
        },
    }


def _parse_xml(path):
    rows = []
    element_count = 0

    for event, element in SafeET.iterparse(path, events=("end",)):
        element_count += 1

        if len(rows) < DEFAULT_PREVIEW_ROWS:
            rows.append({
                "tag": element.tag,
                "attributes": dict(element.attrib),
                "text": (element.text or "").strip()[:300],
            })

        element.clear()

    return {
        "preview": rows,
        "details": {
            "elements_seen": element_count,
            "reading_mode": "ITERPARSE",
        },
    }


def _parse_yaml(path):
    if path.stat().st_size > MAX_PREVIEW_BYTES:
        return {
            "status": "PREVIEW_ONLY",
            "message": "YAML exceeds 1 MB. Full parsing is disabled.",
            "preview": read_text_preview(path)[:1000],
            "details": {},
        }

    with path.open("r", encoding="utf-8-sig") as file:
        data = yaml.safe_load(file)

    return {
        "preview": data,
        "details": {
            "data_type": type(data).__name__,
        },
    }


def _parse_text(path, file_format):
    content = read_text_preview(path)

    return {
        "preview": content[:1000],
        "details": {
            "characters_previewed": len(content),
            "reading_mode": "BOUNDED_TEXT_PREVIEW",
            "execution": (
                "NEVER_EXECUTED"
                if file_format == "python_source"
                else "NOT_APPLICABLE"
            ),
        },
    }


def parse_file(file_path):
    path = Path(file_path)

    valid, message = validate_file(path)

    if not valid:
        return {
            "file": str(path),
            "status": "ERROR",
            "message": message,
        }

    detection = detect_format(path)
    file_format = detection["format"]

    if file_format == "unknown":
        return {
            "file": str(path),
            "format": "unknown",
            "status": "UNSUPPORTED",
            "message": "Unknown file format.",
        }

    result = _result(path, file_format)

    try:
        if file_format == "csv":
            parsed = _parse_delimited(path, ",", DEFAULT_PREVIEW_ROWS)

        elif file_format == "tsv":
            parsed = _parse_delimited(path, "\t", DEFAULT_PREVIEW_ROWS)

        elif file_format == "json":
            parsed = _parse_json(path)

        elif file_format == "jsonl":
            parsed = _parse_jsonl(path)

        elif file_format == "excel":
            parsed = _parse_excel(path)

        elif file_format == "parquet":
            parsed = _parse_parquet(path)

        elif file_format == "xml":
            parsed = _parse_xml(path)

        elif file_format == "yaml":
            parsed = _parse_yaml(path)

        elif file_format in ("text", "log", "sql", "python_source"):
            parsed = _parse_text(path, file_format)

        else:
            return {
                **result,
                "status": "PARSER_NOT_IMPLEMENTED",
                "message": f"No parser implemented for: {file_format}",
            }

        result.update(parsed)
        result["size_bytes"] = path.stat().st_size

        if "status" not in parsed:
            result["status"] = "PARSED"

        return result

    except Exception as exc:
        result["status"] = "PARSE_ERROR"
        result["message"] = f"{type(exc).__name__}: {exc}"
        return result
