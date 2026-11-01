from __future__ import annotations


def _normalized_keys(record: dict) -> dict[str, object]:
    return {
        str(key).strip().lower(): value
        for key, value in record.items()
    }


def prepare_dataset_record(record: dict) -> tuple[dict, bool, str]:
    normalized = _normalized_keys(record)
    is_official_split = "full_query" in normalized and "split" in normalized
    split = str(normalized.get("split") or "").strip().lower()

    if "full_query" not in normalized or "query" in normalized:
        return record, is_official_split, split

    prepared = dict(record)
    prepared["query"] = normalized["full_query"]
    return prepared, is_official_split, split


def select_dataset_records(
    records: list[dict],
    split: str,
) -> tuple[list[dict], bool]:
    selected_records = []
    uses_official_split = False

    for record in records:
        prepared, is_official_split, record_split = prepare_dataset_record(
            record
        )
        if is_official_split:
            uses_official_split = True
            if record_split != split:
                continue
        selected_records.append(prepared)

    return selected_records, uses_official_split


def select_training_records(batches) -> tuple[list[dict], bool]:
    records = []
    uses_official_split = False

    for batch in batches:
        selected, batch_uses_official_split = select_dataset_records(
            batch,
            "train",
        )
        records.extend(selected)
        uses_official_split = (
            uses_official_split or batch_uses_official_split
        )

    return records, uses_official_split
