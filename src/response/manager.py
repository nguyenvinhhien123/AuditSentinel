
from src.detection.alert_manager import AlertManager
from src.investigation.manager import InvestigationManager
from src.response.engine import ResponseEngine


class ResponseManager:
    """Orchestrate alert investigation and safe response actions."""

    def __init__(
        self,
        alert_manager=None,
        investigation_manager=None,
        response_engine=None,
    ):
        self.alert_manager = alert_manager or AlertManager()

        self.investigation_manager = (
            investigation_manager or InvestigationManager(
                alert_manager=self.alert_manager
            )
        )

        self.response_engine = response_engine or ResponseEngine()

    def process_alert(self, alert_id):
        """
        Investigate an existing alert and create response proposals.

        This method does not approve or execute any action.
        """

        alert = self.investigation_manager.get_alert(alert_id)

        if alert is None:
            return {
                "status": "NOT_FOUND",
                "alert_id": alert_id,
            }

        investigation = (
            self.investigation_manager.investigate_alert(alert_id)
        )

        if investigation.get("status") != "COMPLETED":
            return {
                "status": "INVESTIGATION_FAILED",
                "alert_id": alert_id,
                "investigation": investigation,
            }

        proposals = self.response_engine.propose_response(
            alert,
            investigation,
        )

        return {
            "status": "COMPLETED",
            "alert_id": alert_id,
            "investigation": investigation,
            "response": proposals,
        }

    def approve_action(self, action_id, approved_by):
        return self.response_engine.approve_action(
            action_id,
            approved_by,
        )

    def reject_action(self, action_id, rejected_by, reason):
        return self.response_engine.reject_action(
            action_id,
            rejected_by,
            reason,
        )

    def simulate_action(self, action_id):
        """Simulate an approved action without real system changes."""

        return self.response_engine.execute_action(action_id)

    def list_actions(self, alert_id=None, status=None, limit=100):
        return self.response_engine.list_actions(
            alert_id=alert_id,
            status=status,
            limit=limit,
        )

    def get_statistics(self):
        return self.response_engine.get_statistics()
