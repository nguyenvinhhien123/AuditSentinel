
import json

from datetime import datetime, timezone
from pathlib import Path


class QuarantineManager:
    """
    Store rejected records in JSONL format.

    Each rejected record is stored as an independent JSON line.
    Original input data is not modified.
    """

    def __init__(self, output_path="dataset/quarantine/rejected_records.jsonl"):
        self.output_path = Path(output_path)

        self.output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        if self.output_path.exists() and self.output_path.is_symlink():
            raise ValueError("Quarantine output cannot be a symbolic link.")

        self.total_rejected = 0

    def quarantine(
        self,
        record,
        reason,
        source_file=None,
        batch_number=None,
        record_number=None,
        error_type=None,
    ):
        """
        Store one rejected record.

        Returns metadata about the stored record.
        """

        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("A rejection reason is required.")

        if not self.output_path.parent.is_dir():
            raise ValueError("Quarantine directory is unavailable.")

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_file": str(source_file) if source_file is not None else None,
            "batch_number": batch_number,
            "record_number": record_number,
            "error_type": error_type,
            "reason": reason.strip(),
            "record": record,
        }

        serialized = json.dumps(
            entry,
            ensure_ascii=False,
            default=str,
        )

        # Append one JSON object per line.
        with self.output_path.open(
            "a",
            encoding="utf-8",
            newline="\n",
        ) as file:
            file.write(serialized + "\n")

        self.total_rejected += 1

        return {
            "status": "QUARANTINED",
            "path": str(self.output_path),
            "total_rejected": self.total_rejected,
        }

    def quarantine_many(
        self,
        records,
        reason,
        source_file=None,
        batch_number=None,
        start_record_number=1,
        error_type=None,
    ):
        """
        Store multiple rejected records.
        """

        if not isinstance(records, list):
            raise TypeError("records must be a list.")

        results = []

        for index, record in enumerate(records):
            result = self.quarantine(
                record=record,
                reason=reason,
                source_file=source_file,
                batch_number=batch_number,
                record_number=start_record_number + index,
                error_type=error_type,
            )

            results.append(result)

        return {
            "status": "COMPLETED",
            "records_quarantined": len(results),
            "results": results,
        }

    def get_statistics(self):
        """Return quarantine statistics."""

        return {
            "total_rejected": self.total_rejected,
            "output_path": str(self.output_path),
            "file_exists": self.output_path.exists(),
        }
