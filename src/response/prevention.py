import hashlib
import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path


INDICATOR_FIELDS = {
    "source_ip": (
        "src_ip",
        "src_ip_addr",
        "source_ip",
        "source_ip_address",
        "client_ip",
        "client_addr",
        "ip",
        "ip_address",
        "remote_ip",
        "remote_addr",
    ),
    "db_user": (
        "username",
        "user_name",
        "db_user",
        "db_username",
        "database_user",
        "session_user",
        "user",
        "account",
        "account_name",
        "login",
        "principal",
    ),
}

PREVENTION_ACTIONS = {
    "source_ip": "BLOCK_SOURCE_IP",
    "db_user": "SUSPEND_DB_USER",
}
MAX_POLICY_PROPOSALS = 10_000
DECISION_PREVIEW_LIMIT = 5_000


class PreventionSimulator:
    """Create operator-approved containment plans for offline audit datasets."""

    def __init__(self, audit_path="logs/prevention_simulations.jsonl"):
        self.audit_path = Path(audit_path)

    @staticmethod
    def _validate_batch(records, detection):
        if not isinstance(records, list) or not records:
            raise ValueError("Detection batches must be non-empty lists")
        if not all(isinstance(record, dict) for record in records):
            raise TypeError("Every audit record must be a dictionary")
        if not isinstance(detection, dict):
            raise TypeError("Detector output must be a dictionary")
        if detection.get("status") != "COMPLETED":
            raise ValueError("Detection output is not completed")
        results = detection.get("results")
        if not isinstance(results, list) or len(results) != len(records):
            raise ValueError(
                "Detection results must match the audit record count"
            )
        if not all(isinstance(result, dict) for result in results):
            raise TypeError("Every detection result must be a dictionary")
        return results

    @staticmethod
    def _indicator_value(record, indicator_type):
        fields = INDICATOR_FIELDS[indicator_type]
        normalized_record = {
            str(key).strip().lower(): value
            for key, value in record.items()
        }
        for field in fields:
            value = normalized_record.get(field)
            if value is None:
                continue
            value = str(value).strip()
            if not value or value.lower() in {
                "null",
                "none",
                "n/a",
                "na",
                "nan",
                "nil",
                "-",
            }:
                continue
            if indicator_type == "source_ip":
                try:
                    return str(ipaddress.ip_address(value))
                except ValueError:
                    continue
            if len(value) > 256:
                continue
            return value.casefold()
        return None

    @staticmethod
    def _policy_id(indicator_type, value):
        return hashlib.sha256(
            f"{indicator_type}:{value}".encode("utf-8")
        ).hexdigest()

    def build_plan_batches(
        self,
        batches,
        detector,
        indicator_type,
        mode=None,
    ):
        """Build a bounded-memory plan from a stream of audit-log batches."""
        selected_types = (
            tuple(INDICATOR_FIELDS)
            if indicator_type == "both"
            else (indicator_type,)
        )
        if indicator_type not in {*INDICATOR_FIELDS, "both"}:
            raise ValueError(
                "indicator_type must be source_ip, db_user, or both"
            )

        proposals = {}
        records_analyzed = 0
        alert_records = 0
        alerts_without_indicator = 0
        model_id = None
        model_mode = None

        for records in batches:
            detection = detector.detect_batch(records, mode=mode)
            results = self._validate_batch(records, detection)
            if model_id is None:
                model_id = detection.get("model_id")
                model_mode = detection.get("mode")
            elif detection.get("model_id") != model_id:
                raise ValueError(
                    "Active model changed while building the prevention plan"
                )

            for record, result in zip(records, results):
                index = records_analyzed
                records_analyzed += 1
                if result.get("alert") is True:
                    alert_records += 1

                found_indicator = False
                for selected_type in selected_types:
                    value = self._indicator_value(record, selected_type)
                    if value is None:
                        continue
                    found_indicator = True
                    policy_id = self._policy_id(selected_type, value)
                    proposal = proposals.get(policy_id)
                    if result.get("alert") is True and proposal is None:
                        if len(proposals) >= MAX_POLICY_PROPOSALS:
                            raise ValueError(
                                "The dataset produced too many unique policy "
                                "candidates. Refine the dataset before review."
                            )
                        proposal = {
                            "policy_id": policy_id,
                            "action": PREVENTION_ACTIONS[selected_type],
                            "indicator_type": selected_type,
                            "indicator": value,
                            "indicator_fingerprint": policy_id,
                            "trigger_record_index": index,
                            "trigger_count": 0,
                            "future_matching_records": 0,
                        }
                        proposals[policy_id] = proposal
                    if proposal is not None:
                        if result.get("alert") is True:
                            proposal["trigger_count"] += 1
                        if index > proposal["trigger_record_index"]:
                            proposal["future_matching_records"] += 1
                if result.get("alert") is True and not found_indicator:
                    alerts_without_indicator += 1

        if records_analyzed == 0:
            raise ValueError("The selected file contains no usable audit records.")

        return {
            "status": "READY_FOR_REVIEW",
            "mode": "OFFLINE_SIMULATION",
            "model_mode": model_mode,
            "model_id": model_id,
            "indicator_type": indicator_type,
            "action": (
                "MULTI_INDICATOR_CONTAINMENT"
                if indicator_type == "both"
                else PREVENTION_ACTIONS[indicator_type]
            ),
            "records_analyzed": records_analyzed,
            "alert_records": alert_records,
            "alerts_without_indicator": alerts_without_indicator,
            "proposals": list(proposals.values()),
            "real_system_changes": False,
        }

    def simulate_batches(
        self,
        batches_factory,
        detector,
        indicator_type,
        approved_policy_ids,
        approved_by,
        expected_model_id=None,
        expected_policy_ids=None,
        snapshot_is_valid=None,
        mode=None,
    ):
        """Revalidate and simulate selected policies without retaining records."""
        approved_by = self._safe_operator(approved_by)
        if not isinstance(approved_policy_ids, list) or not all(
            isinstance(policy_id, str) for policy_id in approved_policy_ids
        ):
            raise TypeError("approved_policy_ids must be a list of strings")

        plan = self.build_plan_batches(
            batches_factory(),
            detector,
            indicator_type,
            mode=mode,
        )
        if expected_model_id and plan["model_id"] != expected_model_id:
            raise ValueError(
                "The active model changed after plan review. Rebuild and review the plan."
            )
        proposals = {
            proposal["policy_id"]: proposal
            for proposal in plan["proposals"]
        }
        approved = set(approved_policy_ids)
        if approved.difference(proposals):
            raise ValueError("Approval contains unknown or stale policy IDs")
        if (
            expected_policy_ids is not None
            and set(expected_policy_ids) != set(proposals)
        ):
            raise ValueError(
                "The prevention plan changed after review. Rebuild and review the plan."
            )

        selected_types = (
            tuple(INDICATOR_FIELDS)
            if indicator_type == "both"
            else (indicator_type,)
        )
        active_policies = {}
        decision_preview = []
        would_be_blocked = 0
        records_analyzed = 0
        for records in batches_factory():
            detection = detector.detect_batch(records, mode=plan["model_mode"])
            results = self._validate_batch(records, detection)
            if detection.get("model_id") != plan["model_id"]:
                raise ValueError(
                    "The active model changed during prevention simulation"
                )
            for record, result in zip(records, results):
                index = records_analyzed
                records_analyzed += 1
                current_policy_ids = []
                for selected_type in selected_types:
                    value = self._indicator_value(record, selected_type)
                    if value is None:
                        continue
                    policy_id = self._policy_id(selected_type, value)
                    if policy_id in active_policies:
                        current_policy_ids.append(policy_id)

                if current_policy_ids:
                    policy_id = current_policy_ids[0]
                    would_be_blocked += 1
                    decision = {
                        "record_index": index,
                        "decision": "WOULD_BE_BLOCKED",
                        "action": proposals[policy_id]["action"],
                        "indicator_fingerprint": policy_id,
                        "trigger_record_index": active_policies[policy_id],
                        "detected_alert": result.get("alert") is True,
                    }
                else:
                    decision = {
                        "record_index": index,
                        "decision": "OBSERVED",
                        "indicator_fingerprints": [
                            self._policy_id(
                                selected_type,
                                value,
                            )
                            for selected_type in selected_types
                            if (
                                (value := self._indicator_value(
                                    record,
                                    selected_type,
                                ))
                                is not None
                            )
                            and self._policy_id(selected_type, value) in approved
                        ],
                        "detected_alert": result.get("alert") is True,
                    }
                    if result.get("alert") is True:
                        for policy_id in decision["indicator_fingerprints"]:
                            active_policies.setdefault(policy_id, index)
                if len(decision_preview) < DECISION_PREVIEW_LIMIT:
                    decision_preview.append(decision)

        if records_analyzed != plan["records_analyzed"]:
            raise ValueError(
                "The dataset changed while prevention simulation was running"
            )
        if snapshot_is_valid is not None and snapshot_is_valid() is not True:
            raise ValueError(
                "The dataset changed during prevention simulation"
            )

        run = {
            "run_id": str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "SIMULATED",
            "mode": "OFFLINE_SIMULATION",
            "action": plan["action"],
            "indicator_type": indicator_type,
            "approved_by": approved_by,
            "approved_policy_ids": sorted(approved),
            "records_analyzed": records_analyzed,
            "alert_records": plan["alert_records"],
            "policies_proposed": len(proposals),
            "policies_approved": len(approved),
            "would_be_blocked": would_be_blocked,
            "decision_preview_count": len(decision_preview),
            "decisions_truncated": records_analyzed > len(decision_preview),
            "real_system_changes": False,
            "decisions": decision_preview,
        }
        self._append_audit_record({
            key: value
            for key, value in run.items()
            if key != "decisions"
        })
        return {"plan": plan, "simulation": run}

    @staticmethod
    def _safe_operator(operator):
        if not isinstance(operator, str):
            raise TypeError("approved_by must be a string")
        operator = operator.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", operator):
            raise ValueError(
                "approved_by must be 1-128 safe identifier characters"
            )
        return operator

    def _append_audit_record(self, record):
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self.audit_path.open("a", encoding="utf-8") as file:
                file.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError as exc:
            raise RuntimeError(
                f"Cannot write prevention simulation audit: {exc}"
            ) from exc

    def list_runs(self, limit=100):
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError("limit must be a positive integer")
        if not self.audit_path.exists():
            return []
        runs = []
        try:
            with self.audit_path.open("r", encoding="utf-8") as file:
                for line_number, line in enumerate(file, start=1):
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ValueError(
                            f"Invalid prevention audit JSON on line {line_number}"
                        ) from exc
                    if not isinstance(record, dict):
                        raise ValueError(
                            f"Invalid prevention audit record on line {line_number}"
                        )
                    runs.append(record)
        except OSError as exc:
            raise RuntimeError(
                f"Cannot read prevention simulation audit: {exc}"
            ) from exc
        return list(reversed(runs[-limit:]))
