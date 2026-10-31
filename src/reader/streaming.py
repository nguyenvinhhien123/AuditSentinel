
import csv
import json
from pathlib import Path

import pyarrow.parquet as pq

from src.reader.detector import detect_format
from src.reader.safety import validate_file


SUPPORTED_STREAM_FORMATS = {"csv", "tsv", "jsonl", "parquet"}
MAX_STORED_ERRORS = 100


class StreamingReadError(Exception):
    """Raised when a streaming input cannot be processed safely."""


class StreamingReader:
    """
    Read supported dataset files incrementally.

    Supported formats:
        CSV, TSV, JSONL, NDJSON, Parquet

    Each yielded batch is a list of dictionaries.

    on_reject:
        Optional callback called when a JSONL line is invalid.

        Callback arguments:
            raw_line
            line_number
            error_message
    """

    def __init__(
        self,
        batch_size=5000,
        strict=True,
        on_reject=None,
    ):
        if (
            not isinstance(batch_size, int)
            or isinstance(batch_size, bool)
        ):
            raise ValueError(
                "batch_size must be an integer"
            )

        if batch_size <= 0:
            raise ValueError(
                "batch_size must be greater than zero"
            )

        if on_reject is not None and not callable(on_reject):
            raise ValueError(
                "on_reject must be callable or None"
            )

        if not isinstance(strict, bool):
            raise ValueError(
                "strict must be a boolean"
            )

        self.batch_size = batch_size
        self.strict = strict
        self.on_reject = on_reject
        self.stats = {}

    def _reset_stats(self, path, file_format):
        self.stats = {
            "file": str(path),
            "format": file_format,
            "batch_size": self.batch_size,
            "total_records": 0,
            "total_batches": 0,
            "skipped_records": 0,
            "error_count": 0,
            "errors": [],
            "status": "READING",
        }

    def _record_error(self, message):
        self.stats["error_count"] += 1

        if len(self.stats["errors"]) < MAX_STORED_ERRORS:
            self.stats["errors"].append(message)

    def _yield_batches(self, records):
        batch = []

        for record in records:
            batch.append(record)

            if len(batch) >= self.batch_size:
                self.stats["total_batches"] += 1
                self.stats["total_records"] += len(batch)

                yield batch
                batch = []

        if batch:
            self.stats["total_batches"] += 1
            self.stats["total_records"] += len(batch)

            yield batch

    def _iter_delimited(self, path, delimiter):
        with path.open(
            "r",
            encoding="utf-8-sig",
            errors="replace",
            newline="",
        ) as file:

            reader = csv.DictReader(
                file,
                delimiter=delimiter,
            )

            if not reader.fieldnames:
                raise StreamingReadError(
                    "CSV/TSV file has no header row."
                )

            for row in reader:
                # Preserve extra fields.
                if None in row:
                    row["_extra_fields"] = row.pop(None)

                yield row

    def _iter_jsonl(self, path):
        with path.open(
            "r",
            encoding="utf-8-sig",
            errors="replace",
        ) as file:

            for line_number, line in enumerate(
                file,
                start=1,
            ):
                if not line.strip():
                    continue

                try:
                    record = json.loads(line)

                    if not isinstance(record, dict):
                        raise ValueError(
                            "Each JSONL record must be an object."
                        )

                    yield record

                except (
                    json.JSONDecodeError,
                    ValueError,
                ) as exc:

                    self.stats["skipped_records"] += 1

                    error_message = (
                        f"Line {line_number}: {exc}"
                    )

                    # Always update statistics first.
                    self._record_error(error_message)

                    # Send the original invalid line to the caller.
                    if self.on_reject is not None:
                        self.on_reject(
                            line.rstrip("\r\n"),
                            line_number,
                            error_message,
                        )

                    # Strict mode stops after the rejected line
                    # has been delivered to the callback.
                    if self.strict:
                        self.stats["status"] = "ERROR"

                        raise StreamingReadError(
                            error_message
                        ) from exc

    def _iter_parquet(self, path):
        parquet_file = pq.ParquetFile(path)

        for record_batch in parquet_file.iter_batches(
            batch_size=self.batch_size,
            use_threads=False,
        ):
            for record in record_batch.to_pylist():
                yield record

    def iter_batches(self, file_path):
        """
        Yield batches from a supported dataset file.

        strict=True:
            Stop immediately when malformed JSONL is found.

        strict=False:
            Quarantine malformed JSONL through on_reject
            and continue reading valid records.
        """

        path = Path(file_path)

        valid, message = validate_file(path)

        if not valid:
            raise StreamingReadError(message)

        detection = detect_format(path)
        file_format = detection.get(
            "format",
            "unknown",
        )

        if file_format not in SUPPORTED_STREAM_FORMATS:
            raise StreamingReadError(
                f"Unsupported streaming format: {file_format}"
            )

        self._reset_stats(path, file_format)

        try:
            if file_format == "csv":
                records = self._iter_delimited(
                    path,
                    ",",
                )

            elif file_format == "tsv":
                records = self._iter_delimited(
                    path,
                    "\t",
                )

            elif file_format == "jsonl":
                records = self._iter_jsonl(path)

            elif file_format == "parquet":
                records = self._iter_parquet(path)

            else:
                raise StreamingReadError(
                    f"No streaming reader for: {file_format}"
                )

            for batch in self._yield_batches(records):
                yield batch

            self.stats["status"] = (
                "COMPLETED_WITH_ERRORS"
                if self.stats["error_count"] > 0
                else "COMPLETED"
            )

        except Exception:
            self.stats["status"] = "ERROR"
            raise

    def get_statistics(self):
        """Return a copy of current streaming statistics."""

        return {
            **self.stats,
            "errors": list(
                self.stats.get("errors", [])
            ),
        }
