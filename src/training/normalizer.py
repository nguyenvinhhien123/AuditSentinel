
import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path

import polars as pl


NULL_VALUES = {
    "",
    "null",
    "none",
    "nan",
    "n/a",
    "na",
    "nil",
}

LOWERCASE_FIELDS = {
    "action",
    "event",
    "event_type",
    "event_status",
    "command",
    "operation",
    "status",
    "sql_action",
    "method",
}

IP_FIELDS = {
    "ip",
    "src_ip",
    "source_ip",
    "dst_ip",
    "dest_ip",
    "destination_ip",
    "client_ip",
    "server_ip",
    "remote_ip",
    "local_ip",
}

TIMESTAMP_FIELDS = {
    "timestamp",
    "time",
    "event_time",
    "created_at",
    "updated_at",
    "datetime",
    "logged_at",
}


def normalize_column_name(name):
    """Convert a column name to lowercase snake_case."""

    name = str(name).strip().lower()
    name = re.sub(r"[^a-z0-9]+", "_", name)
    name = re.sub(r"_+", "_", name)

    return name.strip("_")


def normalize_timestamp(value):
    """Convert supported ISO timestamps to UTC ISO format."""

    if isinstance(value, datetime):
        parsed = value

    elif isinstance(value, str):
        text = value.strip()

        try:
            parsed = datetime.fromisoformat(
                text.replace("Z", "+00:00")
            )
        except ValueError:
            return value

    else:
        return value

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    parsed = parsed.astimezone(timezone.utc)

    return parsed.isoformat().replace("+00:00", "Z")


def normalize_ip(value):
    """Validate and standardize an IP address."""

    if not isinstance(value, str):
        return value

    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        # Preserve invalid values for investigation.
        return value.strip()


def normalize_value(column, value):
    """Normalize a value based on its column name."""

    if value is None:
        return None

    if isinstance(value, str):
        value = value.strip()

        if value.lower() in NULL_VALUES:
            return None

    if column in LOWERCASE_FIELDS and isinstance(value, str):
        return value.lower()

    if column in IP_FIELDS:
        return normalize_ip(value)

    if column in TIMESTAMP_FIELDS:
        return normalize_timestamp(value)

    return value


def normalize_record(record):
    """Normalize one dictionary without modifying the original."""

    if not isinstance(record, dict):
        raise TypeError("Each record must be a dictionary")

    normalized = {}

    for original_key, original_value in record.items():
        column = normalize_column_name(original_key)

        if not column:
            column = "unnamed_column"

        if column in normalized:
            raise ValueError(
                f"Column name collision after normalization: {column}"
            )

        normalized[column] = normalize_value(
            column,
            original_value,
        )

    return normalized


def normalize_records(records):
    """Normalize a list of dictionary records."""

    if not isinstance(records, list):
        raise TypeError("Records must be a list")

    normalized_records = []

    for record in records:
        normalized_records.append(normalize_record(record))

    return normalized_records


def save_normalized_parquet(records, output_path):
    """
    Save normalized records to Parquet.

    This function builds a DataFrame in memory.
    Use only for small batches, not the entire 6GB dataset.
    """

    if not records:
        raise ValueError("Cannot save an empty dataset")

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    dataframe = pl.DataFrame(records)
    dataframe.write_parquet(output)

    return {
        "status": "SAVED",
        "path": str(output),
        "rows": dataframe.height,
        "columns": dataframe.width,
        "size_bytes": output.stat().st_size,
    }
