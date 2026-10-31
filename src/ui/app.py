
import json

from pathlib import Path

from src.reader.importer import scan_path
from src.reader.analyzer import analyze_file
from src.reader.ingestion import ingest_file

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Header,
    Footer,
    Static,
    Button,
    DataTable,
    Select,
    Input,
)

from src.detection.alert_manager import AlertManager
from src.investigation.manager import InvestigationManager


class DBIDSApp(App):
    """AuditSentinel SOC terminal dashboard."""

    TITLE = "AuditSentinel"
    SUB_TITLE = "Database Audit Log Intelligence"

    CSS = """
    Screen {
        background: #10131c;
    }

    #sidebar {
        width: 27;
        background: #191e2b;
        border-right: solid #343c50;
        padding: 1;
    }

    #brand {
        height: 4;
        content-align: center middle;
        color: #a78bfa;
        text-style: bold;
        border-bottom: solid #343c50;
        margin-bottom: 1;
    }

    .menu-button {
        width: 100%;
        margin-bottom: 1;
        background: #242b3b;
        color: #dbe4f0;
        border: none;
    }

    .menu-button:hover {
        background: #39425a;
    }

    #main {
        width: 1fr;
        padding: 1 2;
    }

    #page-title {
        height: 3;
        color: #a78bfa;
        text-style: bold;
        border-bottom: solid #343c50;
        margin-bottom: 1;
    }

    #summary {
        height: 7;
        background: #191e2b;
        border: round #343c50;
        padding: 1;
        margin-bottom: 1;
    }

    #data-title {
        height: 2;
        color: #dbe4f0;
        text-style: bold;
    }

    #data-table {
        height: 1fr;
        min-height: 10;
        background: #191e2b;
        border: round #343c50;
    }

    #system-status {
        height: 3;
        color: #a3aab9;
        border-top: solid #343c50;
        padding-top: 1;
    }

    #alert-controls {
        height: auto;
        padding: 1 0;
    }

    #alert-actions {
        height: auto;
        padding: 1 0;
    }

    #alert-details {
        height: 12;
        min-height: 8;
        overflow-y: auto;
        background: #191e2b;
        border: round #343c50;
        padding: 1;
        margin-top: 1;
    }

    .filter {
        width: 1fr;
        margin-right: 1;
    }

    .action-button {
        margin-right: 1;
    }

    #resolution-input {
        width: 1fr;
        margin-right: 1;
    }

    #investigation-controls {
        height: auto;
        padding: 1 0;
    }

    #investigation-details {
        height: 1fr;
        min-height: 10;
        overflow-y: auto;
        background: #191e2b;
        border: round #343c50;
        padding: 1;
        margin-top: 1;
    }
    """

    MENU_ITEMS = [
        ("Dashboard", "dashboard"),
        ("Alert Monitoring", "alerts"),
        ("AI Investigation", "investigation"),
        ("Response Management", "response"),
        ("Dataset & Training", "training"),
        ("System Status", "system"),
    ]

    def __init__(self):
        super().__init__()

        # Alert management
        self.alert_manager = AlertManager()

        # AI investigation management
        self.investigation_manager = InvestigationManager(
            alert_manager=self.alert_manager
        )

         # UI state
        self.selected_alert_id = None
        self.visible_alerts = {}
        self.current_page = "DASHBOARD"

        # Dataset Import state
        self.dataset_scan_results = []
        self.selected_dataset_file = None
        self.dataset_scan_summary = None

    # --------------------------------------------------
    # USER INTERFACE
    # --------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()

        with Horizontal():
            with Vertical(id="sidebar"):
                yield Static(
                    "AuditSentinel\nSOC TERMINAL",
                    id="brand",
                )

                for label, page_id in self.MENU_ITEMS:
                    yield Button(
                        label,
                        id=page_id,
                        classes="menu-button",
                    )

            with Vertical(id="main"):
                yield Static(
                    "DASHBOARD",
                    id="page-title",
                )

                yield Static(
                    "Initializing AuditSentinel...",
                    id="summary",
                )

                # Alert filters
                with Horizontal(id="alert-controls"):
                    yield Select(
                        [
                            ("All Severities", "ALL"),
                            ("CRITICAL", "CRITICAL"),
                            ("HIGH", "HIGH"),
                            ("MEDIUM", "MEDIUM"),
                            ("LOW", "LOW"),
                        ],
                        value="ALL",
                        id="severity-filter",
                        classes="filter",
                    )

                    yield Select(
                        [
                            ("All Statuses", "ALL"),
                            ("NEW", "NEW"),
                            ("ACKNOWLEDGED", "ACKNOWLEDGED"),
                            ("RESOLVED", "RESOLVED"),
                        ],
                        value="ALL",
                        id="status-filter",
                        classes="filter",
                    )

                    yield Button(
                        "Refresh",
                        id="refresh-alerts",
                        classes="action-button",
                    )

                yield Static(
                    "SYSTEM OVERVIEW",
                    id="data-title",
                )

                yield DataTable(
                    id="data-table",
                    cursor_type="row",
                )

                # Alert actions
                with Horizontal(id="alert-actions"):
                    yield Button(
                        "Acknowledge",
                        id="ack-alert",
                        classes="action-button",
                    )

                    yield Input(
                        placeholder="Resolution note (required to resolve)",
                        id="resolution-input",
                    )

                    yield Button(
                        "Resolve",
                        id="resolve-alert",
                        classes="action-button",
                    )

                yield Static(
                    "Select an alert to view its details.",
                    id="alert-details",
                )

                # AI Investigation controls
                with Horizontal(id="investigation-controls"):
                    yield Button(
                        "Investigate Selected Alert",
                        id="run-investigation",
                        classes="action-button",
                    )

                yield Static(
                    "Select an alert from Alert Monitoring to begin investigation.",
                    id="investigation-details",
                )

                yield Static(
                    "SYSTEM: LOCAL | MODE: SIMULATION",
                    id="system-status",
                )

        yield Footer()

    # --------------------------------------------------
    # INITIALIZATION
    # --------------------------------------------------

    def on_mount(self) -> None:
        table = self.query_one("#data-table", DataTable)

        table.add_columns(
            "Alert ID",
            "Severity",
            "Status",
            "Created At",
            "Username",
            "Source IP",
        )

        self.set_alert_controls_visible(False)
        self.set_investigation_controls_visible(False)

        self.show_dashboard()

    def set_alert_controls_visible(self, visible: bool) -> None:
        control_ids = [
            "#alert-controls",
            "#alert-actions",
            "#alert-details",
        ]

        for selector in control_ids:
            self.query_one(selector).display = visible

    def set_investigation_controls_visible(
        self,
        visible: bool,
    ) -> None:
        self.query_one("#investigation-controls").display = visible
        self.query_one("#investigation-details").display = visible

    # --------------------------------------------------
    # BUTTON EVENTS
    # --------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        page_id = event.button.id

        # Keep investigation controls visible when clicking
        # the investigation execution button.
        if page_id not in {"investigation", "run-investigation"}:
            self.set_investigation_controls_visible(False)

        if page_id == "dashboard":
            self.set_alert_controls_visible(False)
            self.show_dashboard()

        elif page_id == "alerts":
            self.set_alert_controls_visible(True)
            self.show_alerts()

        elif page_id == "refresh-alerts":
            self.load_alerts()

        elif page_id == "ack-alert":
            self.update_selected_alert("ACKNOWLEDGED")

        elif page_id == "resolve-alert":
            self.update_selected_alert("RESOLVED")

        elif page_id == "investigation":
            self.set_alert_controls_visible(False)
            self.set_investigation_controls_visible(True)
            self.show_investigation()

        elif page_id == "run-investigation":
            self.start_investigation()

        elif page_id == "response":
            self.set_alert_controls_visible(False)

            self.show_page(
                "RESPONSE MANAGEMENT",
                "Review and manage proposed response actions.",
                [
                    (
                        "Response Engine",
                        "Ready",
                        "Response proposal engine",
                    ),
                    (
                        "Approval",
                        "Required",
                        "Manual approval enabled",
                    ),
                    (
                        "Execution",
                        "Simulation",
                        "No real system changes",
                    ),
                ],
            )

        elif page_id == "training":
            self.set_alert_controls_visible(False)

            self.show_page(
                "DATASET & TRAINING",
                "Dataset import and machine learning management.",
                [
                    (
                        "Universal Reader",
                        "Ready",
                        "Multi-format reader",
                    ),
                    (
                        "Auto Training",
                        "Ready",
                        "Automatic model training",
                    ),
                    (
                        "Manual Training",
                        "Ready",
                        "Configurable training",
                    ),
                ],
            )

        elif page_id == "system":
            self.set_alert_controls_visible(False)

            self.show_page(
                "SYSTEM STATUS",
                "Local AuditSentinel environment.",
                [
                    (
                        "Application",
                        "Ready",
                        "AuditSentinel",
                    ),
                    (
                        "ML Device",
                        "Auto",
                        "CPU/GPU selection configured",
                    ),
                    (
                        "LLM Provider",
                        "Ollama",
                        "Local inference provider",
                    ),
                    (
                        "Response Mode",
                        "Simulation",
                        "Safety mode enabled",
                    ),
                ],
            )

    # --------------------------------------------------
    # PAGE NAVIGATION
    # --------------------------------------------------

    def show_page(
        self,
        title: str,
        summary: str,
        rows: list,
    ) -> None:
        self.current_page = title

        self.query_one("#page-title", Static).update(title)
        self.query_one("#summary", Static).update(summary)

        table = self.query_one("#data-table", DataTable)
        table.clear()

        for row in rows:
            table.add_row(*row)

        self.query_one("#data-title", Static).update(
            "SYSTEM OVERVIEW"
        )

        self.query_one("#system-status", Static).update(
            "SYSTEM: LOCAL | RESPONSE: SIMULATION | APPROVAL: REQUIRED"
        )

    # --------------------------------------------------
    # DASHBOARD
    # --------------------------------------------------

    def show_dashboard(self) -> None:
        try:
            stats = self.alert_manager.get_statistics()

            summary = (
                "[bold cyan]AuditSentinel SOC DASHBOARD[/bold cyan]\n\n"
                f"Total Alerts: {stats['total_alerts']}    "
                f"Open Alerts: {stats['open_alerts']}\n"
                f"CRITICAL: {stats['severity_counts']['CRITICAL']}    "
                f"HIGH: {stats['severity_counts']['HIGH']}    "
                f"MEDIUM: {stats['severity_counts']['MEDIUM']}    "
                f"LOW: {stats['severity_counts']['LOW']}"
            )

            rows = [
                (
                    "Alert Manager",
                    "Connected",
                    "Live alert storage",
                ),
                (
                    "Detection Engine",
                    "Ready",
                    "Threat detection module",
                ),
                (
                    "AI Investigation",
                    "Configured",
                    "Ollama integration",
                ),
                (
                    "Response Engine",
                    "Simulation",
                    "Manual approval required",
                ),
                (
                    "Dataset Reader",
                    "Ready",
                    "Universal file reader",
                ),
            ]

        except Exception as exc:
            summary = f"Unable to load alert statistics: {exc}"
            rows = []

        self.show_page(
            "SOC DASHBOARD",
            summary,
            rows,
        )

    # --------------------------------------------------
    # ALERT MONITORING
    # --------------------------------------------------

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id in {
            "severity-filter",
            "status-filter",
        }:
            if self.current_page == "ALERT MONITORING":
                self.load_alerts()

    def show_alerts(self) -> None:
        self.current_page = "ALERT MONITORING"

        self.query_one("#page-title", Static).update(
            "ALERT MONITORING"
        )

        self.query_one("#data-title", Static).update(
            "LIVE ALERT RECORDS"
        )

        self.query_one("#alert-details", Static).update(
            "Select an alert row to view its details."
        )

        self.load_alerts()

    def load_alerts(self) -> None:
        try:
            severity = self.query_one(
                "#severity-filter",
                Select,
            ).value

            status = self.query_one(
                "#status-filter",
                Select,
            ).value

            alerts = self.alert_manager.list_alerts(
                severity=None if severity == "ALL" else severity,
                status=None if status == "ALL" else status,
                limit=100,
            )

            table = self.query_one("#data-table", DataTable)
            table.clear()

            self.visible_alerts = {}
            self.selected_alert_id = None

            for alert in alerts:
                alert_id = alert.get("alert_id", "UNKNOWN")
                context = alert.get("context", {})

                if not isinstance(context, dict):
                    context = {}

                self.visible_alerts[alert_id] = alert

                table.add_row(
                    alert_id,
                    alert.get("severity", "UNKNOWN"),
                    alert.get("status", "UNKNOWN"),
                    alert.get("created_at", "UNKNOWN"),
                    str(context.get("username", "-")),
                    str(context.get("src_ip", "-")),
                    key=alert_id,
                )

            stats = self.alert_manager.get_statistics()

            self.query_one("#summary", Static).update(
                "[bold cyan]ALERT MONITORING[/bold cyan]\n\n"
                f"Showing: {len(alerts)}    "
                f"Total: {stats['total_alerts']}    "
                f"Open: {stats['open_alerts']}\n"
                f"CRITICAL: {stats['severity_counts']['CRITICAL']}    "
                f"HIGH: {stats['severity_counts']['HIGH']}    "
                f"MEDIUM: {stats['severity_counts']['MEDIUM']}    "
                f"LOW: {stats['severity_counts']['LOW']}"
            )

            self.query_one("#system-status", Static).update(
                "ALERT STORAGE: CONNECTED | SOURCE: logs/alerts.jsonl"
            )

            self.query_one("#alert-details", Static).update(
                "Select an alert row to view its details."
            )

        except Exception as exc:
            self.query_one("#summary", Static).update(
                f"[bold red]ALERT LOAD ERROR[/bold red]\n{exc}"
            )

    def on_data_table_row_selected(
        self,
        event: DataTable.RowSelected,
    ) -> None:
        alert_id = event.row_key.value

        alert = self.visible_alerts.get(alert_id)

        if alert is None:
            return

        self.selected_alert_id = alert_id

        details = json.dumps(
            alert,
            indent=2,
            ensure_ascii=False,
            default=str,
        )

        self.query_one("#alert-details", Static).update(
            f"[bold cyan]SELECTED ALERT[/bold cyan]\n{details}"
        )

    def update_selected_alert(self, new_status: str) -> None:
        if not self.selected_alert_id:
            self.query_one("#alert-details", Static).update(
                "[bold yellow]Please select an alert first.[/bold yellow]"
            )
            return

        try:
            resolution = None

            if new_status == "RESOLVED":
                resolution = self.query_one(
                    "#resolution-input",
                    Input,
                ).value.strip()

                if not resolution:
                    self.query_one("#alert-details", Static).update(
                        "[bold yellow]A resolution note is required.[/bold yellow]"
                    )
                    return

            result = self.alert_manager.update_status(
                alert_id=self.selected_alert_id,
                new_status=new_status,
                resolution=resolution,
            )

            self.query_one("#alert-details", Static).update(
                "[bold green]Alert updated successfully.[/bold green]\n"
                f"Alert ID: {result['alert']['alert_id']}\n"
                f"New Status: {result['alert']['status']}"
            )

            if new_status == "RESOLVED":
                self.query_one("#resolution-input", Input).value = ""

            self.load_alerts()

        except (ValueError, KeyError) as exc:
            self.query_one("#alert-details", Static).update(
                f"[bold red]UPDATE FAILED[/bold red]\n{exc}"
            )

        except Exception as exc:
            self.query_one("#alert-details", Static).update(
                f"[bold red]SYSTEM ERROR[/bold red]\n{exc}"
            )

    # --------------------------------------------------
    # AI INVESTIGATION
    # --------------------------------------------------

    def show_investigation(self) -> None:
        self.current_page = "AI INVESTIGATION"

        self.query_one("#page-title", Static).update(
            "AI INVESTIGATION"
        )

        table = self.query_one("#data-table", DataTable)
        table.clear()

        if not self.selected_alert_id:
            summary = (
                "[bold yellow]NO ALERT SELECTED[/bold yellow]\n\n"
                "Please open Alert Monitoring and select an alert first."
            )

            self.query_one(
                "#run-investigation",
                Button,
            ).disabled = True

        else:
            summary = (
                "[bold cyan]AI SECURITY INVESTIGATION[/bold cyan]\n\n"
                f"Selected Alert: {self.selected_alert_id}\n"
                "Provider: Ollama\n"
                "Model: Qwen 2.5 1.5B"
            )

            table.add_row(
                "Selected Alert",
                "-",
                "-",
                "-",
                "-",
                self.selected_alert_id,
            )

            self.query_one(
                "#run-investigation",
                Button,
            ).disabled = False

        self.query_one("#summary", Static).update(summary)

        self.query_one("#data-title", Static).update(
            "INVESTIGATION TARGET"
        )

        self.query_one("#investigation-details", Static).update(
            "Ready to investigate.\n\n"
            "Select an alert and click Investigate Selected Alert."
        )

    def start_investigation(self) -> None:
        if not self.selected_alert_id:
            self.query_one(
                "#investigation-details",
                Static,
            ).update(
                "[bold yellow]Please select an alert first.[/bold yellow]"
            )
            return

        alert_id = self.selected_alert_id

        self.query_one(
            "#run-investigation",
            Button,
        ).disabled = True

        self.query_one(
            "#investigation-details",
            Static,
        ).update(
            "[bold cyan]AI INVESTIGATION RUNNING...[/bold cyan]\n\n"
            f"Alert ID: {alert_id}\n"
            "Connecting to Ollama...\n"
            "Analyzing database security evidence...\n\n"
            "Please wait."
        )

        self.investigate_alert_worker(alert_id)

    @work(
        thread=True,
        exclusive=True,
        group="investigation",
    )
    def investigate_alert_worker(self, alert_id: str) -> None:
        try:
            result = self.investigation_manager.investigate_alert(
                alert_id
            )

            self.call_from_thread(
                self.show_investigation_result,
                result,
            )

        except Exception as exc:
            self.call_from_thread(
                self.show_investigation_error,
                str(exc),
            )

    def show_investigation_result(self, result: dict) -> None:
        self.query_one(
            "#run-investigation",
            Button,
        ).disabled = False

        report = result.get("report", result)

        formatted_report = json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
            default=str,
        )

        status = result.get("status", "UNKNOWN")
        report_id = result.get("report_id", "N/A")
        report_path = result.get("report_path", "N/A")

        self.query_one("#summary", Static).update(
            "[bold green]INVESTIGATION COMPLETED[/bold green]\n\n"
            f"Alert ID: {result.get('alert_id', 'N/A')}\n"
            f"Report ID: {report_id}\n"
            f"Status: {status}"
        )

        self.query_one(
            "#investigation-details",
            Static,
        ).update(
            "[bold cyan]AI INVESTIGATION REPORT[/bold cyan]\n\n"
            f"Report Path: {report_path}\n\n"
            f"{formatted_report}"
        )

        self.query_one("#system-status", Static).update(
            "AI INVESTIGATION: COMPLETED | PROVIDER: OLLAMA"
        )

    def show_investigation_error(self, error: str) -> None:
        self.query_one(
            "#run-investigation",
            Button,
        ).disabled = False

        self.query_one(
            "#investigation-details",
            Static,
        ).update(
            "[bold red]INVESTIGATION FAILED[/bold red]\n\n"
            f"{error}\n\n"
            "Check whether Ollama is running and the configured model is available."
        )

        self.query_one("#system-status", Static).update(
            "AI INVESTIGATION: FAILED | CHECK OLLAMA"
        )


if __name__ == "__main__":
    DBIDSApp().run()
