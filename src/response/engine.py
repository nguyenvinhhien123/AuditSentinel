
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


class ResponseEngine:
    """
    Safe response orchestration engine.

    This version only creates, approves and simulates response actions.
    It never blocks IPs, changes database accounts or executes commands.
    """

    VALID_ACTIONS = {
        "REVIEW_DATABASE_LOGS",
        "REVIEW_DB_USER_PERMISSIONS",
        "ENABLE_ENHANCED_MONITORING",
        "ESCALATE_TO_ADMIN",
    }

    VALID_STATUSES = {
        "PENDING_APPROVAL",
        "APPROVED",
        "REJECTED",
        "SIMULATED",
    }

    def __init__(
        self,
        storage_path="logs/response_actions.jsonl",
        simulation_mode=True,
        require_approval=True,
    ):
        if simulation_mode is not True:
            raise ValueError(
                "Real execution is not supported by this version. "
                "simulation_mode must be True."
            )

        if not isinstance(require_approval, bool):
            raise TypeError("require_approval must be a boolean")

        self.storage_path = Path(storage_path)
        self.simulation_mode = True
        self.require_approval = require_approval

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _safe_id(value, field_name):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field_name} must be a non-empty string")

        value = value.strip()

        if len(value) > 128:
            raise ValueError(f"{field_name} is too long")

        if not all(
            char.isalnum() or char in "-_"
            for char in value
        ):
            raise ValueError(f"Invalid {field_name}")

        return value

    def _read_actions(self):
        if not self.storage_path.exists():
            return []

        actions = []

        with self.storage_path.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                if not line.strip():
                    continue

                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Corrupted response log at line {line_number}"
                    ) from exc

                if not isinstance(item, dict):
                    raise ValueError(
                        f"Invalid response record at line {line_number}"
                    )

                actions.append(item)

        return actions

    def _write_actions(self, actions):
        self.storage_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with self.storage_path.open("w", encoding="utf-8") as file:
            for action in actions:
                file.write(
                    json.dumps(action, ensure_ascii=False) + "\n"
                )

    def _append_action(self, action):
        self.storage_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with self.storage_path.open("a", encoding="utf-8") as file:
            file.write(
                json.dumps(action, ensure_ascii=False) + "\n"
            )

    @staticmethod
    def _select_actions(alert, investigation_report):
        """
        Select predefined safe recommendations.
        Never execute or interpret LLM-generated commands.
        """

        severity = str(alert.get("severity", "")).upper()
        verdict = str(alert.get("verdict", "")).upper()

        report = investigation_report.get("report", {})
        attack_type = str(
            report.get("attack_type", "")
        ).lower()

        selected = [
            "REVIEW_DATABASE_LOGS",
            "ENABLE_ENHANCED_MONITORING",
        ]

        if (
            severity in {"HIGH", "CRITICAL"}
            or verdict == "SUSPICIOUS"
            or "sql injection" in attack_type
        ):
            selected.extend([
                "REVIEW_DB_USER_PERMISSIONS",
                "ESCALATE_TO_ADMIN",
            ])

        return list(dict.fromkeys(selected))

    def propose_response(self, alert, investigation_report):
        """Create response proposals from an alert and investigation."""

        if not isinstance(alert, dict):
            raise TypeError("alert must be a dictionary")

        if not isinstance(investigation_report, dict):
            raise TypeError(
                "investigation_report must be a dictionary"
            )

        alert_id = self._safe_id(
            alert.get("alert_id"),
            "alert_id",
        )

        if investigation_report.get("status") != "COMPLETED":
            raise ValueError(
                "Investigation must be completed before response planning"
            )

        report = investigation_report.get("report")

        if not isinstance(report, dict):
            raise ValueError("Invalid investigation report")

        action_types = self._select_actions(
            alert,
            investigation_report,
        )

        created = []

        for action_type in action_types:
            if action_type not in self.VALID_ACTIONS:
                continue

            action = {
                "action_id": str(uuid.uuid4()),
                "alert_id": alert_id,
                "action_type": action_type,
                "status": (
                    "PENDING_APPROVAL"
                    if self.require_approval
                    else "APPROVED"
                ),
                "simulation_mode": True,
                "require_approval": self.require_approval,
                "created_at": self._now(),
                "updated_at": self._now(),
                "approved_by": None,
                "execution_result": None,
            }

            self._append_action(action)
            created.append(action)

        return {
            "status": "CREATED",
            "alert_id": alert_id,
            "action_count": len(created),
            "actions": created,
        }

    def list_actions(self, alert_id=None, status=None, limit=100):
        """List response actions with optional filters."""

        if not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")

        if alert_id is not None:
            alert_id = self._safe_id(alert_id, "alert_id")

        if status is not None:
            status = status.upper()

            if status not in self.VALID_STATUSES:
                raise ValueError("Invalid status")

        actions = self._read_actions()

        if alert_id:
            actions = [
                item for item in actions
                if item.get("alert_id") == alert_id
            ]

        if status:
            actions = [
                item for item in actions
                if item.get("status") == status
            ]

        actions.sort(
            key=lambda item: item.get("created_at", ""),
            reverse=True,
        )

        return actions[:limit]

    def _find_action(self, action_id):
        action_id = self._safe_id(action_id, "action_id")
        actions = self._read_actions()

        for index, action in enumerate(actions):
            if action.get("action_id") == action_id:
                return actions, index, action

        return actions, None, None

    def approve_action(self, action_id, approved_by):
        """Approve a pending action. Does not execute it."""

        approved_by = self._safe_id(
            approved_by,
            "approved_by",
        )

        actions, index, action = self._find_action(action_id)

        if action is None:
            return {
                "status": "NOT_FOUND",
                "action_id": action_id,
            }

        if action.get("status") != "PENDING_APPROVAL":
            return {
                "status": "INVALID_STATE",
                "action_id": action_id,
                "current_status": action.get("status"),
            }

        action["status"] = "APPROVED"
        action["approved_by"] = approved_by
        action["updated_at"] = self._now()

        self._write_actions(actions)

        return {
            "status": "APPROVED",
            "action": action,
        }

    def reject_action(self, action_id, rejected_by, reason):
        """Reject a pending action."""

        rejected_by = self._safe_id(
            rejected_by,
            "rejected_by",
        )

        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("A rejection reason is required")

        if len(reason) > 1000:
            raise ValueError("Rejection reason is too long")

        actions, index, action = self._find_action(action_id)

        if action is None:
            return {
                "status": "NOT_FOUND",
                "action_id": action_id,
            }

        if action.get("status") != "PENDING_APPROVAL":
            return {
                "status": "INVALID_STATE",
                "action_id": action_id,
                "current_status": action.get("status"),
            }

        action["status"] = "REJECTED"
        action["approved_by"] = rejected_by
        action["rejection_reason"] = reason.strip()
        action["updated_at"] = self._now()

        self._write_actions(actions)

        return {
            "status": "REJECTED",
            "action": action,
        }

    def execute_action(self, action_id):
        """
        Simulate an approved action.

        No external command, firewall, account or database operation
        is performed.
        """

        actions, index, action = self._find_action(action_id)

        if action is None:
            return {
                "status": "NOT_FOUND",
                "action_id": action_id,
            }

        if action.get("status") != "APPROVED":
            return {
                "status": "NOT_APPROVED",
                "action_id": action_id,
                "current_status": action.get("status"),
            }

        simulation_result = {
            "mode": "SIMULATION",
            "executed": False,
            "message": (
                "Action simulated successfully. "
                "No real system changes were performed."
            ),
        }

        action["status"] = "SIMULATED"
        action["execution_result"] = simulation_result
        action["updated_at"] = self._now()

        self._write_actions(actions)

        return {
            "status": "SIMULATED",
            "action": action,
            "execution_result": simulation_result,
        }

    def get_statistics(self):
        """Return action counts grouped by status and type."""

        actions = self._read_actions()

        by_status = {
            status: 0 for status in self.VALID_STATUSES
        }

        by_type = {
            action_type: 0 for action_type in self.VALID_ACTIONS
        }

        for action in actions:
            status = action.get("status")
            action_type = action.get("action_type")

            if status in by_status:
                by_status[status] += 1

            if action_type in by_type:
                by_type[action_type] += 1

        return {
            "total_actions": len(actions),
            "by_status": by_status,
            "by_type": by_type,
            "simulation_mode": True,
        }
