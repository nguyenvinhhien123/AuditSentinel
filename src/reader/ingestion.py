
import json
import uuid

from datetime import datetime, timezone
from pathlib import Path

from src.reader.streaming import StreamingReader
from src.reader.quarantine import QuarantineManager
from src.training.normalizer import (
    normalize_record,
    save_normalized_parquet,
)
from src.training.validator import validate_records


MAX_ERROR_SAMPLES = 100


def _utc_now():
    return datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )


def _save_report(report, output_path):
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            ensure_ascii=False,
            indent=2,
            default=str,
        )


def ingest_file(
    file_path,
    output_dir="dataset/processed",
    batch_size=5000,
    strict=True,
    required_columns=None,
    quarantine_dir=None,
):
    """
    Stream, normalize, validate, quarantine and save a dataset.

    Supported input formats:
        CSV, TSV, JSONL, Parquet

    Rejected normalization records and malformed JSONL lines
    are stored in a separate quarantine JSONL file.

    Original input files are never modified.
    """

    source = Path(file_path)

    if not source.exists() or not source.is_file():
        raise FileNotFoundError(
            f"Input file does not exist: {source}"
        )

    if source.is_symlink():
        raise ValueError(
            "Symbolic links are not allowed."
        )

    run_id = (
        f"ingestion_{_utc_now()}_"
        f"{uuid.uuid4().hex[:8]}"
    )

    run_dir = Path(output_dir) / run_id

    run_dir.mkdir(
        parents=True,
        exist_ok=False,
    )

    quarantine_root = (
        Path(quarantine_dir)
        if quarantine_dir is not None
        else Path(output_dir).parent / "quarantine"
    )

    quarantine_path = (
        quarantine_root
        / run_id
        / "rejected_records.jsonl"
    )

    quarantine_manager = QuarantineManager(
        output_path=quarantine_path
    )

    report_path = run_dir / "ingestion_report.json"

    report = {
        "run_id": run_id,
        "source_file": str(source.resolve()),
        "output_directory": str(run_dir),
        "started_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "completed_at": None,
        "status": "RUNNING",
        "batch_size": batch_size,
        "batches_processed": 0,
        "total_records_read": 0,
        "normalized_records": 0,
        "saved_records": 0,
        "normalization_errors": 0,
        "validation_warnings": 0,
        "skipped_stream_records": 0,
        "parquet_files": [],
        "batch_reports": [],
        "errors": [],
        "quarantine_file": str(quarantine_path),
        "quarantined_records": 0,
        "quarantine_statistics": {},
        "streaming_statistics": {},
    }

    def add_error(message):
        if len(report["errors"]) < MAX_ERROR_SAMPLES:
            report["errors"].append(str(message))

    # Callback for malformed JSONL lines.
    def handle_stream_rejection(
        raw_line,
        line_number,
        error_message,
    ):
        quarantine_manager.quarantine(
            record={
                "raw_line": raw_line,
            },
            reason=error_message,
            source_file=str(source),
            batch_number=None,
            record_number=line_number,
            error_type="JSONLParseError",
        )

    reader = StreamingReader(
        batch_size=batch_size,
        strict=strict,
        on_reject=handle_stream_rejection,
    )

    global_record_number = 0

    try:
        for batch_number, batch in enumerate(
            reader.iter_batches(source),
            start=1,
        ):
            report["batches_processed"] += 1

            normalized_batch = []

            # STEP 1: Normalize each record individually.
            for record in batch:
                global_record_number += 1

                try:
                    normalized = normalize_record(record)

                    normalized_batch.append(normalized)

                except Exception as exc:
                    report["normalization_errors"] += 1

                    error_message = (
                        f"{type(exc).__name__}: {exc}"
                    )

                    add_error(
                        f"Batch {batch_number}, "
                        f"record {global_record_number}: "
                        f"{error_message}"
                    )

                    # Quarantine the original record.
                    quarantine_manager.quarantine(
                        record=record,
                        reason=error_message,
                        source_file=str(source),
                        batch_number=batch_number,
                        record_number=global_record_number,
                        error_type=type(exc).__name__,
                    )

                    if strict:
                        raise

            report["normalized_records"] += len(
                normalized_batch
            )

            if not normalized_batch:
                report["batch_reports"].append({
                    "batch": batch_number,
                    "input_records": len(batch),
                    "normalized_records": 0,
                    "saved_records": 0,
                    "status": "NO_VALID_RECORDS",
                })

                continue

            # STEP 2: Validate normalized records.
            validation = validate_records(
                normalized_batch,
                required_columns=required_columns,
            )

            if validation["status"] == "WARNING":
                report["validation_warnings"] += 1

            if validation["status"] == "ERROR":
                raise ValueError(
                    f"Batch {batch_number} validation failed."
                )

            # STEP 3: Save normalized batch to Parquet.
            output_file = (
                run_dir
                / f"part_{batch_number:06d}.parquet"
            )

            save_result = save_normalized_parquet(
                normalized_batch,
                output_file,
            )

            report["saved_records"] += save_result["rows"]

            report["parquet_files"].append({
                "file": str(output_file),
                "rows": save_result["rows"],
                "size_bytes": save_result["size_bytes"],
            })

            report["batch_reports"].append({
                "batch": batch_number,
                "input_records": len(batch),
                "normalized_records": len(normalized_batch),
                "saved_records": save_result["rows"],
                "validation_status": validation["status"],
                "duplicate_records": validation.get(
                    "duplicate_records", 0
                ),
                "empty_records": validation.get(
                    "empty_records", 0
                ),
                "missing_required_columns": validation.get(
                    "missing_required_columns", []
                ),
                "warnings": validation.get(
                    "warnings", []
                ),
                "status": "SAVED",
            })

        report["streaming_statistics"] = (
            reader.get_statistics()
        )

        report["total_records_read"] = (
            reader.stats.get("total_records", 0)
        )

        report["skipped_stream_records"] = (
            reader.stats.get("skipped_records", 0)
        )

        report["quarantined_records"] = (
            quarantine_manager.total_rejected
        )

        has_errors = (
            report["normalization_errors"] > 0
            or report["skipped_stream_records"] > 0
        )

        has_warnings = (
            report["validation_warnings"] > 0
        )

        if has_errors:
            report["status"] = "COMPLETED_WITH_ERRORS"

        elif has_warnings:
            report["status"] = "COMPLETED_WITH_WARNINGS"

        else:
            report["status"] = "COMPLETED"

    except Exception as exc:
        report["status"] = "ERROR"

        add_error(
            f"{type(exc).__name__}: {exc}"
        )

        report["streaming_statistics"] = (
            reader.get_statistics()
        )

        report["total_records_read"] = (
            reader.stats.get("total_records", 0)
        )

        report["skipped_stream_records"] = (
            reader.stats.get("skipped_records", 0)
        )

        report["quarantined_records"] = (
            quarantine_manager.total_rejected
        )

    finally:
        report["quarantined_records"] = (
            quarantine_manager.total_rejected
        )

        report["quarantine_statistics"] = (
            quarantine_manager.get_statistics()
        )

        report["completed_at"] = (
            datetime.now(timezone.utc).isoformat()
        )

        _save_report(
            report,
            report_path,
        )

    report["report_file"] = str(report_path)

    return report
