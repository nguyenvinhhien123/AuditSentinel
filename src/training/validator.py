
import json
from collections import Counter
from datetime import datetime


NULL_VALUES = {"", "null", "none", "nan", "n/a"}


def is_missing(value):
    if value is None:
        return True

    if isinstance(value, str):
        return value.strip().lower() in NULL_VALUES

    return False


def detect_value_type(value):
    if value is None:
        return "null"

    if isinstance(value, bool):
        return "boolean"

    if isinstance(value, int):
        return "integer"

    if isinstance(value, float):
        return "float"

    if isinstance(value, str):
        text = value.strip()

        if not text:
            return "null"

        try:
            int(text)
            return "integer"
        except ValueError:
            pass

        try:
            float(text)
            return "float"
        except ValueError:
            pass

        if text.lower() in {"true", "false"}:
            return "boolean"

        try:
            datetime.fromisoformat(text.replace("Z", "+00:00"))
            return "datetime"
        except ValueError:
            pass

        return "string"

    if isinstance(value, (dict, list)):
        return "nested"

    return "other"


def convert_preview_to_records(parsed):
    """
    Convert parser preview output into a list of dictionaries.
    Only processes the preview returned by the parser.
    """

    if not isinstance(parsed, dict):
        return None, "Invalid parser result"

    file_format = parsed.get("format")
    preview = parsed.get("preview")

    if parsed.get("status") not in {"PARSED", "PREVIEW_ONLY"}:
        return None, "Parser result is not ready for validation"

    if file_format in {"csv", "tsv", "excel"}:
        if not isinstance(preview, list) or len(preview) < 2:
            return [], "No data rows available in preview"

        headers = [
            str(column).strip() if column is not None else ""
            for column in preview[0]
        ]

        records = []

        for row in preview[1:]:
            # Ignore completely empty rows.
            if not any(not is_missing(value) for value in row):
                continue

            record = {}

            for index, header in enumerate(headers):
                if not header:
                    header = f"unnamed_column_{index + 1}"

                record[header] = (
                    row[index] if index < len(row) else None
                )

            records.append(record)

        return records, "OK"

    if file_format in {"jsonl", "parquet"}:
        if isinstance(preview, list):
            if all(isinstance(item, dict) for item in preview):
                return preview, "OK"

        return None, "Preview is not a list of structured records"

    if file_format == "json":
        if isinstance(preview, dict):
            return [preview], "OK"

        if isinstance(preview, list):
            if all(isinstance(item, dict) for item in preview):
                return preview, "OK"

        return None, "JSON preview is not a collection of records"

    if file_format == "yaml":
        if isinstance(preview, dict):
            return [preview], "OK"

        if isinstance(preview, list):
            if all(isinstance(item, dict) for item in preview):
                return preview, "OK"

        return None, "YAML preview is not a collection of records"

    if file_format == "xml":
        if isinstance(preview, list) and all(
            isinstance(item, dict) for item in preview
        ):
            return preview, "OK"

        return None, "XML preview is not structured as records"

    return None, "Unstructured format requires a specialized validator"


def validate_records(records, required_columns=None):
    """
    Validate a list of dictionary records.
    Does not modify the input records.
    """

    required_columns = required_columns or []

    if not isinstance(records, list):
        return {
            "status": "ERROR",
            "message": "Records must be a list",
        }

    if not records:
        return {
            "status": "EMPTY",
            "total_records": 0,
            "message": "No records available",
        }

    if not all(isinstance(record, dict) for record in records):
        return {
            "status": "ERROR",
            "message": "Every record must be a dictionary",
        }

    columns = list(dict.fromkeys(
        key for record in records for key in record.keys()
    ))

    missing_required = [
        column for column in required_columns
        if column not in columns
    ]

    missing_by_column = {}
    type_profile = {}
    inconsistent_columns = []

    for column in columns:
        values = [
            record.get(column)
            for record in records
        ]

        missing_count = sum(
            is_missing(value) for value in values
        )

        missing_by_column[column] = {
            "missing": missing_count,
            "present": len(records) - missing_count,
            "missing_percent": round(
                missing_count / len(records) * 100, 2
            ),
        }

        types = Counter(
            detect_value_type(value)
            for value in values
            if not is_missing(value)
        )

        type_profile[column] = dict(types)

        if len(types) > 1:
            inconsistent_columns.append(column)

    # Detect exact duplicate records.
    seen = set()
    duplicate_count = 0

    for record in records:
        fingerprint = json.dumps(
            record,
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        )

        if fingerprint in seen:
            duplicate_count += 1
        else:
            seen.add(fingerprint)

    empty_records = sum(
        not any(
            not is_missing(value)
            for value in record.values()
        )
        for record in records
    )

    warnings = []

    if duplicate_count:
        warnings.append(
            f"{duplicate_count} duplicate records detected"
        )

    if inconsistent_columns:
        warnings.append(
            "Inconsistent data types: "
            + ", ".join(inconsistent_columns)
        )

    if missing_required:
        warnings.append(
            "Missing required columns: "
            + ", ".join(missing_required)
        )

    if empty_records:
        warnings.append(
            f"{empty_records} empty records detected"
        )

    return {
        "status": "WARNING" if warnings else "VALID",
        "total_records": len(records),
        "total_columns": len(columns),
        "columns": columns,
        "missing_by_column": missing_by_column,
        "type_profile": type_profile,
        "inconsistent_columns": inconsistent_columns,
        "duplicate_records": duplicate_count,
        "empty_records": empty_records,
        "missing_required_columns": missing_required,
        "warnings": warnings,
    }


def validate_parsed_data(parsed, required_columns=None):
    records, message = convert_preview_to_records(parsed)

    if records is None:
        return {
            "status": "SKIPPED",
            "message": message,
        }

    report = validate_records(
        records,
        required_columns=required_columns,
    )

    report["file"] = parsed.get("file")
    report["format"] = parsed.get("format")
    report["validation_scope"] = "PARSER_PREVIEW_ONLY"

    if message != "OK":
        report["message"] = message

    return report
