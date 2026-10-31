from __future__ import annotations

import json
import hashlib
import sys
from pathlib import Path
from uuid import uuid4

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QProgressBar,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QComboBox,
    QLineEdit,
    QInputDialog,
    QSpinBox,
)


INGESTION_EXTENSIONS = {".csv", ".tsv", ".jsonl", ".ndjson", ".parquet"}
APP_ROOT = Path(__file__).resolve().parents[2]
CUSTOM_APP_ICON = APP_ROOT / "assets" / "auditsentinel.ico"
DEFAULT_APP_ICON = APP_ROOT / "assets" / "auditsentinel-default.ico"
APP_ICON = (
    CUSTOM_APP_ICON
    if CUSTOM_APP_ICON.is_file()
    else DEFAULT_APP_ICON
)


def fingerprint_file(file_path: str) -> str:
    digest = hashlib.sha256()
    with Path(file_path).open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class TaskWorker(QThread):
    """Run file, training, detection, and investigation work off the UI thread."""

    succeeded = Signal(object)
    failed = Signal(str)
    status = Signal(str)

    def __init__(
        self,
        task: str,
        path: str = "",
        payload: dict | None = None,
        parent=None,
    ):
        super().__init__(parent)
        self.task = task
        self.path = path
        self.payload = payload or {}

    def run(self) -> None:
        try:
            if self.task == "scan":
                from src.reader.importer import scan_path

                self.status.emit("Scanning files...")
                result = scan_path(self.path)
                self.succeeded.emit(result)

            elif self.task == "preview":
                from src.reader.parser import parse_file

                self.status.emit("Parsing preview...")
                result = parse_file(self.path)
                self.succeeded.emit(result)

            elif self.task == "ingest":
                from src.reader.ingestion import ingest_file

                self.status.emit("Running ingestion pipeline...")
                result = ingest_file(
                    file_path=self.path,
                    output_dir=APP_ROOT / "dataset" / "processed",
                    batch_size=5000,
                    strict=False,
                )
                self.succeeded.emit(result)

            elif self.task == "train":
                from src.reader.streaming import StreamingReader
                from src.training.auto_trainer import auto_train
                from src.training.manual_trainer import manual_train
                from src.registry.model_registry import ModelRegistry

                self.status.emit("Reading training records...")
                reader = StreamingReader(batch_size=5000, strict=True)
                records = [
                    record
                    for batch in reader.iter_batches(self.path)
                    for record in batch
                ]
                if len(records) < 10:
                    raise ValueError(
                        "Training requires at least 10 audit records."
                    )

                training_mode = self.payload["training_mode"]
                model_mode = self.payload["model_mode"]
                label_column = self.payload["label_column"] or None
                output_dir = (
                    APP_ROOT
                    / "models"
                    / "detection"
                    / training_mode
                    / model_mode
                    / f"run_{uuid4().hex[:12]}"
                )
                self.status.emit(
                    f"Training {model_mode} model on {len(records)} records..."
                )

                if training_mode == "auto":
                    result = auto_train(
                        records,
                        label_column=label_column,
                        output_dir=output_dir,
                    )
                else:
                    result = manual_train(
                        records,
                        mode=model_mode,
                        label_column=label_column,
                        n_estimators=self.payload["n_estimators"],
                        output_dir=output_dir,
                    )

                registry = ModelRegistry(project_root=APP_ROOT)
                result["registration"] = registry.register_model(
                    result["model_path"],
                    name=f"{training_mode.title()} {result['algorithm']}",
                )
                result["records_loaded"] = len(records)
                self.succeeded.emit(result)

            elif self.task == "detect":
                from src.reader.streaming import StreamingReader
                from src.registry.model_registry import ModelRegistry
                from src.detection.engine import DetectionEngine
                from src.detection.alert_manager import AlertManager
                from src.agents import DetectionAgent

                session_root = Path(self.payload["session_root"])
                self.status.emit("Reading audit records...")
                reader = StreamingReader(batch_size=5000, strict=True)
                records = [
                    record
                    for batch in reader.iter_batches(self.path)
                    for record in batch
                ]
                if not records:
                    raise ValueError(
                        "The selected file contains no usable audit records."
                    )

                registry = ModelRegistry(project_root=APP_ROOT)
                self.status.emit(
                    f"Analyzing {len(records)} records..."
                )
                agent = DetectionAgent(
                    detector=DetectionEngine(registry),
                    alert_manager=AlertManager(
                        storage_path=session_root / "logs" / "alerts.jsonl"
                    ),
                )
                self.succeeded.emit(agent.run(
                    records,
                    mode=self.payload.get("mode") or None,
                ))

            elif self.task == "plan_prevention":
                from src.reader.streaming import StreamingReader
                from src.reader.safety import validate_file
                from src.registry.model_registry import ModelRegistry
                from src.detection.engine import DetectionEngine
                from src.response.prevention import PreventionSimulator

                session_root = Path(self.payload["session_root"])
                self.status.emit("Reading offline audit dataset...")
                valid, message = validate_file(Path(self.path))
                if not valid:
                    raise ValueError(message)
                source_fingerprint = fingerprint_file(self.path)
                reader = StreamingReader(batch_size=5000, strict=True)
                detector = DetectionEngine(
                    ModelRegistry(project_root=APP_ROOT)
                )
                self.status.emit(
                    "Evaluating active model and building reviewable policies..."
                )
                plan = PreventionSimulator(
                    audit_path=session_root
                    / "logs"
                    / "prevention_simulations.jsonl"
                ).build_plan_batches(
                    reader.iter_batches(self.path),
                    detector,
                    self.payload["indicator_type"],
                    mode=self.payload.get("mode") or None,
                )
                if fingerprint_file(self.path) != source_fingerprint:
                    raise ValueError(
                        "The dataset changed while the prevention plan was being built. Rebuild the plan."
                    )
                self.succeeded.emit({
                    "plan": plan,
                    "source_fingerprint": source_fingerprint,
                })

            elif self.task == "simulate_prevention":
                from src.reader.streaming import StreamingReader
                from src.reader.safety import validate_file
                from src.registry.model_registry import ModelRegistry
                from src.detection.engine import DetectionEngine
                from src.response.prevention import PreventionSimulator

                session_root = Path(self.payload["session_root"])
                self.status.emit("Revalidating offline policy plan...")
                valid, message = validate_file(Path(self.path))
                if not valid:
                    raise ValueError(message)
                source_fingerprint = fingerprint_file(self.path)
                if source_fingerprint != self.payload["source_fingerprint"]:
                    raise ValueError(
                        "The dataset changed after plan review. Rebuild and review the plan."
                    )
                detector = DetectionEngine(
                    ModelRegistry(project_root=APP_ROOT)
                )
                simulator = PreventionSimulator(
                    audit_path=session_root
                    / "logs"
                    / "prevention_simulations.jsonl"
                )
                self.status.emit("Simulating approved policies...")
                result = simulator.simulate_batches(
                    lambda: StreamingReader(
                        batch_size=5000,
                        strict=True,
                    ).iter_batches(self.path),
                    detector,
                    self.payload["indicator_type"],
                    self.payload["approved_policy_ids"],
                    self.payload["approved_by"],
                    expected_model_id=self.payload["model_id"],
                    expected_policy_ids=self.payload["policy_ids"],
                    snapshot_is_valid=lambda: (
                        fingerprint_file(self.path) == source_fingerprint
                    ),
                    mode=self.payload.get("mode") or None,
                )
                self.succeeded.emit({
                    "plan": result["plan"],
                    "simulation": result["simulation"],
                })

            elif self.task == "generate_report":
                from src.reporting.report_generator import ReportGenerator

                session_root = Path(self.payload["session_root"])
                self.status.emit("Collecting local report data...")
                generator = ReportGenerator(
                    project_root=APP_ROOT,
                    session_root=session_root,
                )
                report = generator.build_report()
                output_path = generator.write_report(
                    report,
                    self.path,
                    self.payload["format"],
                )
                self.succeeded.emit({
                    "status": "COMPLETED",
                    "format": self.payload["format"],
                    "path": str(output_path),
                    "generated_at": report["generated_at"],
                })

            elif self.task == "investigate":
                from src.detection.alert_manager import AlertManager
                from src.investigation.manager import InvestigationManager
                from src.agents import InvestigationAgent

                session_root = Path(self.payload["session_root"])
                self.status.emit("Running local AI investigation...")
                manager = InvestigationManager(
                    alert_manager=AlertManager(
                        storage_path=session_root / "logs" / "alerts.jsonl"
                    ),
                    report_dir=session_root / "reports" / "investigations",
                )
                agent = InvestigationAgent(manager)
                self.succeeded.emit(agent.run(self.payload["alert_id"]))

            elif self.task == "propose_response":
                from src.detection.alert_manager import AlertManager
                from src.investigation.manager import InvestigationManager
                from src.response.engine import ResponseEngine
                from src.agents import ResponseAgent

                session_root = Path(self.payload["session_root"])
                alerts = AlertManager(
                    storage_path=session_root / "logs" / "alerts.jsonl"
                )
                investigations = InvestigationManager(
                    alert_manager=alerts,
                    report_dir=session_root / "reports" / "investigations",
                )
                engine = ResponseEngine(
                    storage_path=session_root / "logs" / "response_actions.jsonl",
                    simulation_mode=True,
                    require_approval=True,
                )
                agent = ResponseAgent(
                    investigation_manager=investigations,
                    response_engine=engine,
                )
                self.succeeded.emit(agent.run(self.payload["alert_id"]))

            else:
                raise ValueError(f"Unknown task: {self.task}")

        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class DatasetPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.scan_results: list[dict] = []
        self.selected_file: str | None = None
        self.worker: TaskWorker | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 26, 28, 24)
        layout.setSpacing(12)

        heading = QLabel("Dataset Manager")
        heading.setObjectName("pageHeading")
        description = QLabel(
            "Scan local Audit Log files, inspect a bounded preview, "
            "and import supported files into the ingestion pipeline."
        )
        description.setObjectName("pageDescription")
        description.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(description)

        source_row = QHBoxLayout()
        self.file_button = QPushButton("Select File")
        self.folder_button = QPushButton("Select Folder")
        self.scan_button = QPushButton("Scan Selected Path")
        self.preview_button = QPushButton("Preview Selected File")
        self.import_button = QPushButton("Import Selected File")
        self.preview_button.setEnabled(False)
        self.import_button.setEnabled(False)

        source_row.addWidget(self.file_button)
        source_row.addWidget(self.folder_button)
        source_row.addWidget(self.scan_button)
        source_row.addStretch()
        layout.addLayout(source_row)

        self.path_label = QLabel("No file or folder selected.")
        self.path_label.setObjectName("pathLabel")
        self.path_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        layout.addWidget(self.path_label)

        action_row = QHBoxLayout()
        action_row.addWidget(self.preview_button)
        action_row.addWidget(self.import_button)
        action_row.addStretch()
        layout.addLayout(action_row)

        self.summary_label = QLabel("No scan results yet.")
        self.summary_label.setObjectName("summaryLabel")
        layout.addWidget(self.summary_label)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["File Name", "Format", "Size (MB)", "Status", "Path"]
        )
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )
        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setMinimumHeight(190)
        layout.addWidget(self.table, 2)

        preview_title = QLabel("Preview / Operation Result")
        preview_title.setObjectName("sectionHeading")
        layout.addWidget(preview_title)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText(
            "Select a file and click Preview Selected File."
        )
        self.output.setMinimumHeight(150)
        layout.addWidget(self.output, 2)

        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        self.status_label = QLabel("Ready.")
        self.status_label.setObjectName("statusLabel")
        layout.addWidget(self.status_label)

        self.file_button.clicked.connect(self.choose_file)
        self.folder_button.clicked.connect(self.choose_folder)
        self.scan_button.clicked.connect(self.start_scan)
        self.preview_button.clicked.connect(self.start_preview)
        self.import_button.clicked.connect(self.start_ingestion)
        self.table.itemSelectionChanged.connect(self.on_selection_changed)

    def choose_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Audit Log File",
            "",
            "Supported and known files (*)",
        )
        if path:
            self.path_label.setText(path)
            self.start_scan(path)

    def choose_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(
            self,
            "Select Dataset Folder",
            "",
        )
        if path:
            self.path_label.setText(path)
            self.start_scan(path)

    def start_scan(self, explicit_path: str | None = None) -> None:
        path = explicit_path or self.path_label.text().strip()
        if not path or path == "No file or folder selected.":
            QMessageBox.warning(
                self,
                "Dataset Manager",
                "Please select a file or folder first.",
            )
            return
        self._start_worker("scan", path)

    def start_preview(self) -> None:
        if not self.selected_file:
            QMessageBox.warning(
                self,
                "Dataset Manager",
                "Select a file from the scan results first.",
            )
            return
        self._start_worker("preview", self.selected_file)

    def start_ingestion(self) -> None:
        if not self.selected_file:
            QMessageBox.warning(
                self,
                "Dataset Manager",
                "Select a file from the scan results first.",
            )
            return

        extension = Path(self.selected_file).suffix.lower()
        if extension not in INGESTION_EXTENSIONS:
            QMessageBox.warning(
                self,
                "Unsupported ingestion format",
                "This file can be scanned or previewed, but the current "
                "ingestion pipeline supports only CSV, TSV, JSONL and Parquet.",
            )
            return

        answer = QMessageBox.question(
            self,
            "Confirm ingestion",
            "Import this file into dataset/processed?\n\n"
            "The original source file will not be moved or deleted.",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        self._start_worker("ingest", self.selected_file)

    def _start_worker(self, task: str, path: str) -> None:
        if self.worker is not None and self.worker.isRunning():
            QMessageBox.information(
                self,
                "Task in progress",
                "Please wait for the current operation to finish.",
            )
            return
        if (
            self.main_window is not None
            and self.main_window.workflow_worker is not None
            and self.main_window.workflow_worker.isRunning()
        ):
            QMessageBox.information(
                self,
                "Task in progress",
                "Wait for the current model or investigation task to finish.",
            )
            return

        self._set_busy(True)
        self.output.setPlainText(f"{task.title()} started:\n{path}")
        self.worker = TaskWorker(task, path, parent=self)
        self.worker.status.connect(self.status_label.setText)
        self.worker.succeeded.connect(
            lambda result, current_task=task: self._on_success(
                current_task, result
            )
        )
        self.worker.failed.connect(self._on_failure)
        self.worker.finished.connect(lambda: self._set_busy(False))
        self.worker.start()

    def _on_success(self, task: str, result: object) -> None:
        if task == "scan":
            self._display_scan(result)
        elif task == "preview":
            self._display_preview(result)
        elif task == "ingest":
            self._display_ingestion(result)

    def _on_failure(self, message: str) -> None:
        self.status_label.setText("Operation failed.")
        self.output.setPlainText(message)
        QMessageBox.critical(self, "AuditSentinel Error", message)

    def _display_scan(self, result: dict) -> None:
        self.scan_results = result.get("files", [])
        self.selected_file = None
        self.table.setRowCount(0)

        for record in self.scan_results[:5000]:
            row = self.table.rowCount()
            self.table.insertRow(row)

            size_mb = record.get("size_bytes", 0) / (1024 * 1024)
            values = [
                record.get("name", ""),
                record.get("format", "unknown"),
                f"{size_mb:.3f}",
                record.get("status", "UNKNOWN"),
                record.get("file", ""),
            ]

            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                self.table.setItem(row, column, item)

        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setStretchLastSection(True)

        self.summary_label.setText(
            f"Files: {result.get('total_files', 0)} | "
            f"Supported: {result.get('supported', 0)} | "
            f"Unsupported: {result.get('unsupported', 0)} | "
            f"Invalid: {result.get('invalid', 0)}"
        )
        if len(self.scan_results) > 5000:
            self.summary_label.setText(
                self.summary_label.text()
                + " | Display limited to first 5,000 rows"
            )

        self.status_label.setText("Scan completed.")
        self.output.setPlainText(
            "Scan completed.\n\n"
            + json.dumps(
                {
                    key: value
                    for key, value in result.items()
                    if key != "files"
                },
                indent=2,
                ensure_ascii=False,
            )
        )

    def on_selection_changed(self) -> None:
        selected = self.table.selectedItems()
        if not selected:
            self.selected_file = None
            self.preview_button.setEnabled(False)
            self.import_button.setEnabled(False)
            return

        row = selected[0].row()
        path_item = self.table.item(row, 4)
        status_item = self.table.item(row, 3)

        self.selected_file = path_item.text() if path_item else None
        extension = Path(self.selected_file).suffix.lower() if self.selected_file else ""
        status = status_item.text() if status_item else ""

        valid_selection = bool(self.selected_file and status != "INVALID")
        self.preview_button.setEnabled(valid_selection)
        self.import_button.setEnabled(
            valid_selection and extension in INGESTION_EXTENSIONS
        )

    def _display_preview(self, result: dict) -> None:
        self.status_label.setText(
            f"Preview status: {result.get('status', 'UNKNOWN')}"
        )
        self.output.setPlainText(
            json.dumps(result, indent=2, ensure_ascii=False, default=str)
        )

    def _display_ingestion(self, result: dict) -> None:
        self.status_label.setText(
            f"Ingestion status: {result.get('status', 'UNKNOWN')}"
        )
        self.output.setPlainText(
            json.dumps(result, indent=2, ensure_ascii=False, default=str)
        )
        QMessageBox.information(
            self,
            "Ingestion finished",
            "The ingestion operation has returned a result. "
            "Review the report and output paths in the result panel.",
        )

    def _set_busy(self, busy: bool) -> None:
        self.progress.setRange(0, 0 if busy else 1)
        if not busy:
            self.progress.setValue(1)
        for widget in (
            self.file_button,
            self.folder_button,
            self.scan_button,
            self.preview_button,
            self.import_button,
        ):
            widget.setEnabled(not busy)
        if not busy:
            self.on_selection_changed()


class DataPage(QWidget):
    """Shared table and result layout for operational pages."""

    def __init__(
        self,
        title: str,
        description: str,
        columns: list[str],
        parent=None,
    ):
        super().__init__(parent)
        self.main_window = parent
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 26, 28, 24)
        layout.setSpacing(12)

        heading = QLabel(title)
        heading.setObjectName("pageHeading")
        summary = QLabel(description)
        summary.setObjectName("pageDescription")
        summary.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(summary)

        self.controls = QHBoxLayout()
        self.controls.setSpacing(8)
        layout.addLayout(self.controls)

        self.status_label = QLabel("Ready.")
        self.status_label.setObjectName("pageStatus")
        layout.addWidget(self.status_label)

        self.table = QTableWidget(0, len(columns))
        self.table.setHorizontalHeaderLabels(columns)
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )
        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setMinimumHeight(190)
        layout.addWidget(self.table, 3)

        details_heading = QLabel("Details")
        details_heading.setObjectName("sectionHeading")
        layout.addWidget(details_heading)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setMinimumHeight(140)
        layout.addWidget(self.output, 2)

    def set_rows(self, rows: list[list[object]]) -> None:
        self.table.setRowCount(len(rows))
        for row_index, values in enumerate(rows):
            for column_index, value in enumerate(values):
                item = QTableWidgetItem(str(value if value is not None else "-"))
                item.setToolTip(item.text())
                self.table.setItem(row_index, column_index, item)
        self.table.resizeColumnsToContents()

    def selected_value(self, column: int = 0) -> str | None:
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            return None
        item = self.table.item(selected[0].row(), column)
        return item.text() if item is not None else None

    def show_json(self, result: object) -> None:
        self.output.setPlainText(
            json.dumps(result, indent=2, ensure_ascii=False, default=str)
        )

    def report_error(self, message: str) -> None:
        self.status_label.setText("Operation failed.")
        self.output.setPlainText(message)
        QMessageBox.critical(self, "AuditSentinel Error", message)


class ModelTrainingPage(DataPage):
    def __init__(self, parent=None):
        super().__init__(
            "ML Training",
            "Train an audit-log classifier or anomaly detector. Training reads "
            "the selected dataset into memory; use a dataset sized for this machine.",
            ["Training result"],
            parent,
        )
        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText("Select CSV, TSV, JSONL or Parquet")
        choose_button = QPushButton("Choose dataset")
        choose_button.clicked.connect(self.choose_dataset)
        self.controls.addWidget(self.file_path, 2)
        self.controls.addWidget(choose_button)

        self.training_mode = QComboBox()
        self.training_mode.addItem("Automatic", "auto")
        self.training_mode.addItem("Manual", "manual")
        self.model_mode = QComboBox()
        self.model_mode.addItem("Unsupervised / anomaly", "unsupervised")
        self.model_mode.addItem("Supervised / labeled", "supervised")
        self.label_column = QLineEdit("label")
        self.label_column.setPlaceholderText("Label column for supervised training")
        self.estimators = QSpinBox()
        self.estimators.setRange(10, 1000)
        self.estimators.setValue(100)
        train_button = QPushButton("Train and register")
        train_button.setObjectName("primaryButton")
        train_button.clicked.connect(self.train_model)
        for widget in (
            self.training_mode,
            self.model_mode,
            self.label_column,
            self.estimators,
            train_button,
        ):
            self.controls.addWidget(widget)

    def choose_dataset(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select training dataset",
            str(APP_ROOT / "dataset"),
            "Audit datasets (*.csv *.tsv *.jsonl *.ndjson *.parquet)",
        )
        if path:
            self.file_path.setText(path)

    def train_model(self) -> None:
        path = self.file_path.text().strip()
        if not path:
            self.report_error("Select a training dataset first.")
            return
        if Path(path).suffix.lower() not in INGESTION_EXTENSIONS:
            self.report_error(
                "Training supports CSV, TSV, JSONL and Parquet audit datasets."
            )
            return
        self.main_window.run_background(
            "train",
            path,
            {
                "training_mode": self.training_mode.currentData(),
                "model_mode": self.model_mode.currentData(),
                "label_column": (
                    self.label_column.text().strip()
                    if self.model_mode.currentData() == "supervised"
                    else ""
                ),
                "n_estimators": self.estimators.value(),
            },
            self.on_trained,
            self,
        )

    def on_trained(self, result: dict) -> None:
        self.status_label.setText(
            f"Trained and registered {result['algorithm']} "
            f"({result['records_loaded']} records)."
        )
        self.show_json(result)
        self.main_window.refresh_registry()
        self.main_window.refresh_dashboard()


class ModelRegistryPage(DataPage):
    def __init__(self, parent=None):
        super().__init__(
            "Model Registry",
            "Verify model checksums and explicitly activate models for detection.",
            ["Model ID", "Name", "Mode", "Algorithm", "State"],
            parent,
        )
        refresh_button = QPushButton("Refresh")
        verify_button = QPushButton("Verify selected")
        activate_button = QPushButton("Activate selected")
        deactivate_button = QPushButton("Deactivate selected mode")
        for button, callback in (
            (refresh_button, self.refresh),
            (verify_button, self.verify_selected),
            (activate_button, self.activate_selected),
            (deactivate_button, self.deactivate_selected),
        ):
            self.controls.addWidget(button)
            button.clicked.connect(callback)
        self.refresh()

    def refresh(self) -> None:
        from src.registry.model_registry import ModelRegistry

        self.models = ModelRegistry(project_root=APP_ROOT).list_models()
        self.set_rows([
            [
                model.get("model_id"),
                model.get("name"),
                model.get("mode"),
                model.get("algorithm"),
                model.get("status"),
            ]
            for model in self.models
        ])
        self.status_label.setText(f"Registered models: {len(self.models)}")

    def selected_model(self) -> dict | None:
        model_id = self.selected_value()
        return next(
            (model for model in self.models if model.get("model_id") == model_id),
            None,
        )

    def verify_selected(self) -> None:
        from src.registry.model_registry import ModelRegistry

        model = self.selected_model()
        if model is None:
            self.report_error("Select a registered model first.")
            return
        result = ModelRegistry(project_root=APP_ROOT).verify_model(
            model["model_id"]
        )
        self.status_label.setText(f"Integrity: {result['status']}")
        self.show_json(result)

    def activate_selected(self) -> None:
        from src.registry.model_registry import ModelRegistry

        model = self.selected_model()
        if model is None:
            self.report_error("Select a registered model first.")
            return
        result = ModelRegistry(project_root=APP_ROOT).activate_model(
            model["model_id"]
        )
        self.status_label.setText(
            f"Activated {model['mode']} model after checksum verification."
        )
        self.show_json(result)
        self.refresh()
        self.main_window.refresh_dashboard()

    def deactivate_selected(self) -> None:
        from src.registry.model_registry import ModelRegistry

        model = self.selected_model()
        if model is None:
            self.report_error("Select a registered model to choose its mode.")
            return
        result = ModelRegistry(project_root=APP_ROOT).deactivate_model(
            model["mode"]
        )
        self.status_label.setText(
            f"{model['mode'].title()} active model deactivated."
        )
        self.show_json(result)
        self.refresh()
        self.main_window.refresh_dashboard()


class DetectionPage(DataPage):
    def __init__(self, parent=None):
        super().__init__(
            "Agent 1 — Detection & Alerts",
            "Agent 1 uses the active supervised or unsupervised ML model to "
            "analyze audit logs and save suspicious/anomalous alerts. "
            "It does not block database activity.",
            ["Record", "Mode", "Verdict", "Predicted label", "Confidence / score"],
            parent,
        )
        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText("Select an audit-log file")
        choose_button = QPushButton("Choose file")
        choose_button.clicked.connect(self.choose_file)
        self.mode = QComboBox()
        self.mode.addItem("Automatic", "")
        self.mode.addItem("Supervised", "supervised")
        self.mode.addItem("Unsupervised", "unsupervised")
        run_button = QPushButton("Run detection")
        run_button.setObjectName("primaryButton")
        run_button.clicked.connect(self.run_detection)
        self.controls.addWidget(self.file_path, 2)
        self.controls.addWidget(choose_button)
        self.controls.addWidget(self.mode)
        self.controls.addWidget(run_button)

    def choose_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select audit-log dataset",
            str(APP_ROOT / "dataset"),
            "Audit datasets (*.csv *.tsv *.jsonl *.ndjson *.parquet)",
        )
        if path:
            self.file_path.setText(path)

    def run_detection(self) -> None:
        path = self.file_path.text().strip()
        if not path:
            self.report_error("Select an audit-log file first.")
            return
        if Path(path).suffix.lower() not in INGESTION_EXTENSIONS:
            self.report_error(
                "Detection supports CSV, TSV, JSONL and Parquet audit datasets."
            )
            return
        self.main_window.run_background(
            "detect",
            path,
            {"mode": self.mode.currentData()},
            self.on_detection,
            self,
        )

    def on_detection(self, result: dict) -> None:
        detection = result["detection"]
        self.set_rows([
            [
                item.get("record_index"),
                item.get("mode"),
                item.get("verdict"),
                item.get("predicted_label", "-"),
                item.get("confidence", item.get("anomaly_score", "-")),
            ]
            for item in detection["results"]
        ])
        self.status_label.setText(
            f"Analyzed {detection['records_analyzed']} records; "
            f"generated {result['alerts']['alerts_created']} alerts."
        )
        self.show_json(result)
        self.main_window.refresh_alerts()
        self.main_window.refresh_dashboard()


class AlertsPage(DataPage):
    def __init__(self, parent=None):
        super().__init__(
            "Alert Monitoring",
            "Review model-generated alerts, acknowledge them, or resolve them "
            "with a documented note.",
            ["Alert ID", "Severity", "Status", "Created", "User", "Source IP"],
            parent,
        )
        self.status_filter = QComboBox()
        self.status_filter.addItem("All statuses", "")
        for status in ("NEW", "ACKNOWLEDGED", "RESOLVED"):
            self.status_filter.addItem(status, status)
        refresh = QPushButton("Refresh")
        acknowledge = QPushButton("Acknowledge")
        self.resolution = QLineEdit()
        self.resolution.setPlaceholderText("Resolution note")
        resolve = QPushButton("Resolve")
        for widget in (self.status_filter, refresh, acknowledge, self.resolution, resolve):
            self.controls.addWidget(widget)
        refresh.clicked.connect(self.refresh)
        acknowledge.clicked.connect(self.acknowledge_selected)
        resolve.clicked.connect(self.resolve_selected)
        self.table.itemSelectionChanged.connect(self.show_selected)
        self.refresh()

    def refresh(self) -> None:
        from src.detection.alert_manager import AlertManager

        status = self.status_filter.currentData()
        self.alerts = AlertManager(
            storage_path=self.main_window.session_path("logs", "alerts.jsonl")
        ).list_alerts(status=status or None, limit=500)
        self.set_rows([
            [
                alert.get("alert_id"),
                alert.get("severity"),
                alert.get("status"),
                alert.get("created_at"),
                alert.get("context", {}).get("username", "-"),
                alert.get("context", {}).get("src_ip", "-"),
            ]
            for alert in self.alerts
        ])
        self.status_label.setText(f"Alerts shown: {len(self.alerts)}")

    def show_selected(self) -> None:
        alert_id = self.selected_value()
        alert = next(
            (item for item in self.alerts if item.get("alert_id") == alert_id),
            None,
        )
        if alert is not None:
            self.show_json(alert)

    def update_selected(self, status: str) -> None:
        alert_id = self.selected_value()
        if not alert_id:
            self.report_error("Select an alert first.")
            return
        from src.detection.alert_manager import AlertManager

        resolution = self.resolution.text().strip() if status == "RESOLVED" else None
        try:
            result = AlertManager(
                storage_path=self.main_window.session_path(
                    "logs",
                    "alerts.jsonl",
                )
            ).update_status(alert_id, status, resolution=resolution)
        except (ValueError, KeyError, OSError) as exc:
            self.report_error(f"{type(exc).__name__}: {exc}")
            return
        self.status_label.setText(f"Alert {status.lower()}.")
        self.show_json(result)
        self.refresh()
        self.main_window.refresh_dashboard()

    def acknowledge_selected(self) -> None:
        self.update_selected("ACKNOWLEDGED")

    def resolve_selected(self) -> None:
        self.update_selected("RESOLVED")


class InvestigationPage(DataPage):
    def __init__(self, parent=None):
        super().__init__(
            "Agent 2 — AI Investigation",
            "Agent 2 uses the configured local Ollama language model to analyze "
            "a selected alert and save an investigation report. It does not "
            "execute SQL or system commands.",
            ["Report ID", "Alert ID", "Investigated at", "Model", "Status"],
            parent,
        )
        self.alert_select = QComboBox()
        refresh_alerts = QPushButton("Refresh alerts")
        investigate = QPushButton("Investigate")
        investigate.setObjectName("primaryButton")
        refresh_reports = QPushButton("Refresh reports")
        for widget in (
            self.alert_select,
            refresh_alerts,
            investigate,
            refresh_reports,
        ):
            self.controls.addWidget(widget)
        refresh_alerts.clicked.connect(self.refresh_alerts)
        investigate.clicked.connect(self.investigate_selected)
        refresh_reports.clicked.connect(self.refresh_reports)
        self.table.itemSelectionChanged.connect(self.show_selected_report)
        self.refresh_alerts()
        self.refresh_reports()

    def refresh_alerts(self) -> None:
        from src.detection.alert_manager import AlertManager

        current = self.alert_select.currentData()
        alerts = AlertManager(
            storage_path=self.main_window.session_path("logs", "alerts.jsonl")
        ).list_alerts(limit=500)
        self.alert_select.clear()
        for alert in alerts:
            label = (
                f"{alert.get('severity')} | {alert.get('alert_id')} | "
                f"{alert.get('status')}"
            )
            self.alert_select.addItem(label, alert.get("alert_id"))
        index = self.alert_select.findData(current)
        if index >= 0:
            self.alert_select.setCurrentIndex(index)
        self.status_label.setText(f"Available alerts: {len(alerts)}")

    def investigate_selected(self) -> None:
        alert_id = self.alert_select.currentData()
        if not alert_id:
            self.report_error("There are no alerts to investigate.")
            return
        self.main_window.run_background(
            "investigate",
            payload={"alert_id": alert_id},
            on_success=self.on_investigation,
            page=self,
        )

    def on_investigation(self, result: dict) -> None:
        self.status_label.setText(
            f"Investigation status: {result.get('status', 'UNKNOWN')}"
        )
        self.show_json(result)
        self.refresh_reports()

    def refresh_reports(self) -> None:
        from src.investigation.manager import InvestigationManager

        reports = InvestigationManager(
            report_dir=self.main_window.session_path(
                "reports",
                "investigations",
            )
        ).list_reports(limit=500)
        self.reports = reports
        self.set_rows([
            [
                item.get("report_id"),
                item.get("alert_id"),
                item.get("investigated_at"),
                item.get("model"),
                item.get("status"),
            ]
            for item in reports
        ])
        self.status_label.setText(f"Investigation reports: {len(reports)}")

    def show_selected_report(self) -> None:
        report_id = self.selected_value()
        if not report_id:
            return
        from src.investigation.manager import InvestigationManager

        document = InvestigationManager(
            report_dir=self.main_window.session_path(
                "reports",
                "investigations",
            )
        ).get_report(report_id)
        if document is not None:
            self.show_json(document)


class ResponsePage(DataPage):
    def __init__(self, parent=None):
        super().__init__(
            "Agent 3 — Response Planning",
            "Agent 3 uses predefined rules to propose response steps from the "
            "investigation. This is not a separate AI model; approval and "
            "simulation never change a real database, account, or firewall.",
            ["Action ID", "Alert ID", "Action", "Status", "Created"],
            parent,
        )
        self.actor = QLineEdit("operator")
        self.actor.setPlaceholderText("Operator ID")
        self.reason = QLineEdit()
        self.reason.setPlaceholderText("Reason required to reject")
        refresh = QPushButton("Refresh")
        propose = QPushButton("Propose from investigation")
        propose.setObjectName("primaryButton")
        approve = QPushButton("Approve")
        reject = QPushButton("Reject")
        simulate = QPushButton("Simulate approved action")
        for widget in (
            self.actor,
            self.reason,
            refresh,
            propose,
            approve,
            reject,
            simulate,
        ):
            self.controls.addWidget(widget)
        refresh.clicked.connect(self.refresh)
        propose.clicked.connect(self.propose_response)
        approve.clicked.connect(self.approve_selected)
        reject.clicked.connect(self.reject_selected)
        simulate.clicked.connect(self.simulate_selected)
        self.table.itemSelectionChanged.connect(self.show_selected)
        self.refresh()

    def engine(self):
        from src.response.engine import ResponseEngine

        return ResponseEngine(
            storage_path=self.main_window.session_path(
                "logs",
                "response_actions.jsonl",
            ),
            simulation_mode=True,
            require_approval=True,
        )

    def refresh(self) -> None:
        self.actions = self.engine().list_actions(limit=500)
        self.set_rows([
            [
                action.get("action_id"),
                action.get("alert_id"),
                action.get("action_type"),
                action.get("status"),
                action.get("created_at"),
            ]
            for action in self.actions
        ])
        self.status_label.setText(f"Response proposals: {len(self.actions)}")

    def selected_action(self) -> dict | None:
        action_id = self.selected_value()
        return next(
            (
                action
                for action in self.actions
                if action.get("action_id") == action_id
            ),
            None,
        )

    def show_selected(self) -> None:
        action = self.selected_action()
        if action is not None:
            self.show_json(action)

    def propose_response(self) -> None:
        alert_id = self.main_window.investigation_page.alert_select.currentData()
        if not alert_id:
            self.report_error(
                "Select an alert in AI Investigation, then run its investigation first."
            )
            return
        self.main_window.run_background(
            "propose_response",
            payload={"alert_id": alert_id},
            on_success=self.on_proposed,
            page=self,
        )

    def on_proposed(self, result: dict) -> None:
        self.status_label.setText(
            f"Created {result.get('action_count', 0)} pending-approval proposals."
        )
        self.show_json(result)
        self.refresh()

    def approve_selected(self) -> None:
        action = self.selected_action()
        if action is None:
            self.report_error("Select a response proposal first.")
            return
        try:
            result = self.engine().approve_action(
                action["action_id"],
                self.actor.text().strip(),
            )
        except (ValueError, OSError) as exc:
            self.report_error(f"{type(exc).__name__}: {exc}")
            return
        self.show_json(result)
        self.status_label.setText(f"Approval status: {result['status']}")
        self.refresh()

    def reject_selected(self) -> None:
        action = self.selected_action()
        if action is None:
            self.report_error("Select a response proposal first.")
            return
        try:
            result = self.engine().reject_action(
                action["action_id"],
                self.actor.text().strip(),
                self.reason.text().strip(),
            )
        except (ValueError, OSError) as exc:
            self.report_error(f"{type(exc).__name__}: {exc}")
            return
        self.show_json(result)
        self.status_label.setText(f"Rejection status: {result['status']}")
        self.refresh()

    def simulate_selected(self) -> None:
        action = self.selected_action()
        if action is None:
            self.report_error("Select a response proposal first.")
            return
        confirmation = QMessageBox.question(
            self,
            "Confirm simulation",
            "Simulate this approved action? No real system changes will be made.",
        )
        if confirmation != QMessageBox.StandardButton.Yes:
            return
        result = self.engine().execute_action(action["action_id"])
        self.show_json(result)
        self.status_label.setText(
            f"Simulation status: {result.get('status', 'UNKNOWN')}"
        )
        self.refresh()


class PreventionPage(DataPage):
    def __init__(self, parent=None):
        super().__init__(
            "Prevention Simulation",
            "Offline Kaggle/dataset evaluation only. Review and approve policies "
            "for a source IP, a database user, or both. Approved policies affect "
            "only later rows in this simulation; no live DB or firewall is changed.",
            [
                "Proposed action",
                "Indicator",
                "Fingerprint",
                "Trigger row",
                "Later matching rows",
                "Trigger count",
            ],
            parent,
        )
        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText(
            "Select a downloaded Kaggle CSV, TSV, JSONL or Parquet dataset"
        )
        choose_button = QPushButton("Choose dataset")
        choose_button.clicked.connect(self.choose_dataset)
        self.model_mode = QComboBox()
        self.model_mode.addItem("Automatic active model", "")
        self.model_mode.addItem("Supervised", "supervised")
        self.model_mode.addItem("Unsupervised", "unsupervised")
        self.indicator_type = QComboBox()
        self.indicator_type.addItem("Source IP", "source_ip")
        self.indicator_type.addItem("Database user", "db_user")
        self.indicator_type.addItem("Source IP + DB user", "both")
        plan_button = QPushButton("Analyze and propose policies")
        plan_button.setObjectName("primaryButton")
        for widget in (
            self.file_path,
            choose_button,
            self.model_mode,
            self.indicator_type,
            plan_button,
        ):
            self.controls.addWidget(widget)
        plan_button.clicked.connect(self.build_plan)

        self.table.setSelectionMode(
            QTableWidget.SelectionMode.ExtendedSelection
        )
        self.table.setHorizontalHeaderLabels([
            "Proposed action",
            "Indicator",
            "Fingerprint",
            "Trigger row",
            "Later matching rows",
            "Trigger count",
        ])
        self.approved_by = QLineEdit()
        self.approved_by.setPlaceholderText("Approver ID")
        approve_button = QPushButton("Approve selected and simulate")
        approve_button.setObjectName("primaryButton")
        history_button = QPushButton("View simulation history")
        self.controls.addWidget(self.approved_by)
        self.controls.addWidget(approve_button)
        self.controls.addWidget(history_button)
        approve_button.clicked.connect(self.approve_and_simulate)
        history_button.clicked.connect(self.load_history)
        self.plan: dict | None = None

    def choose_dataset(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select downloaded Kaggle audit dataset",
            str(APP_ROOT / "dataset"),
            "Audit datasets (*.csv *.tsv *.jsonl *.ndjson *.parquet)",
        )
        if path:
            self.file_path.setText(path)
            self.plan = None
            self.set_rows([])
            self.output.clear()
            self.status_label.setText(
                "Dataset selected. Build a new plan before approval."
            )

    def build_plan(self) -> None:
        path = self.file_path.text().strip()
        if not path:
            self.report_error("Select a downloaded Kaggle dataset first.")
            return
        if Path(path).suffix.lower() not in INGESTION_EXTENSIONS:
            self.report_error(
                "Offline prevention supports CSV, TSV, JSONL and Parquet."
            )
            return
        self.plan = None
        self.set_rows([])
        self.main_window.run_background(
            "plan_prevention",
            path,
            {
                "mode": self.model_mode.currentData(),
                "indicator_type": self.indicator_type.currentData(),
            },
            self.on_plan_ready,
            self,
        )

    def on_plan_ready(self, result: dict) -> None:
        self.plan = result["plan"]
        self.plan["mode"] = self.plan["model_mode"]
        self.plan["source_fingerprint"] = result["source_fingerprint"]
        rows = []
        for proposal in self.plan["proposals"]:
            rows.append([
                proposal["action"],
                proposal["indicator"],
                proposal["indicator_fingerprint"][:16],
                proposal["trigger_record_index"],
                proposal["future_matching_records"],
                proposal["trigger_count"],
            ])
        self.set_rows(rows)
        for index, proposal in enumerate(self.plan["proposals"]):
            self.table.item(index, 0).setData(
                Qt.ItemDataRole.UserRole,
                proposal["policy_id"],
            )
        self.status_label.setText(
            f"Offline plan ready: {self.plan['alert_records']} alert rows, "
            f"{len(self.plan['proposals'])} candidate policies, "
            f"{self.plan['alerts_without_indicator']} alerts without a usable "
            "selected indicator. Select the policies to approve."
        )
        self.show_json({
            "plan": self.plan,
        })

    def selected_policy_ids(self) -> list[str]:
        policy_ids = []
        for selected in self.table.selectionModel().selectedRows():
            item = self.table.item(selected.row(), 0)
            policy_id = (
                item.data(Qt.ItemDataRole.UserRole)
                if item is not None
                else None
            )
            if policy_id:
                policy_ids.append(policy_id)
        return policy_ids

    def approve_and_simulate(self) -> None:
        if self.plan is None:
            self.report_error("Build and review a prevention plan first.")
            return
        path = self.file_path.text().strip()
        if not path or not Path(path).is_file():
            self.report_error(
                "The planned dataset is no longer available. Select it and rebuild the plan."
            )
            return
        approved_policy_ids = self.selected_policy_ids()
        if not approved_policy_ids:
            self.report_error(
                "Select at least one policy row to explicitly approve."
            )
            return
        approved_by = self.approved_by.text().strip()
        if not approved_by:
            self.report_error("Enter the approver ID before approving policies.")
            return
        answer = QMessageBox.question(
            self,
            "Approve offline prevention simulation",
            f"Approve {len(approved_policy_ids)} selected policy/policies "
            f"for {self.plan['records_analyzed']} offline records?\n\n"
            "This applies only to later rows in the selected dataset. "
            "No database, account, session, or firewall is changed.",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.main_window.run_background(
            "simulate_prevention",
            path,
            {
                "mode": self.plan["mode"],
                "model_id": self.plan["model_id"],
                "source_fingerprint": self.plan["source_fingerprint"],
                "indicator_type": self.plan["indicator_type"],
                "approved_policy_ids": approved_policy_ids,
                "policy_ids": [
                    proposal["policy_id"]
                    for proposal in self.plan["proposals"]
                ],
                "approved_by": approved_by,
            },
            self.on_simulation_complete,
            self,
        )

    def on_simulation_complete(self, result: dict) -> None:
        simulation = result["simulation"]
        self.status_label.setText(
            f"Simulation complete: {simulation['policies_approved']} approved "
            f"policy/policies; {simulation['would_be_blocked']} later rows "
            "would be blocked."
        )
        self.set_rows([
            [
                decision["record_index"],
                decision["decision"],
                decision.get("action", "—"),
                decision.get("trigger_record_index", "—"),
                decision.get("indicator_fingerprint", "—")[:16],
                decision["detected_alert"],
            ]
            for decision in simulation["decisions"]
        ])
        self.table.setHorizontalHeaderLabels([
            "Record row",
            "Decision",
            "Policy action",
            "Triggered by row",
            "Fingerprint",
            "Model alert",
        ])
        self.show_json({
            "plan": result["plan"],
            "simulation": simulation,
        })

    def load_history(self) -> None:
        from src.response.prevention import PreventionSimulator

        runs = PreventionSimulator(
            audit_path=self.main_window.session_path(
                "logs",
                "prevention_simulations.jsonl",
            )
        ).list_runs(limit=500)
        self.plan = None
        self.set_rows([
            [
                run.get("action"),
                run.get("approved_by"),
                run.get("run_id"),
                run.get("records_analyzed"),
                run.get("would_be_blocked"),
                run.get("created_at"),
            ]
            for run in runs
        ])
        self.table.setHorizontalHeaderLabels([
            "Action",
            "Approver",
            "Run ID",
            "Records",
            "Would be blocked",
            "Created at",
        ])
        self.status_label.setText(
            f"Offline prevention simulation runs: {len(runs)}"
        )
        self.show_json(runs)


class SystemStatusPage(DataPage):
    def __init__(self, parent=None):
        super().__init__(
            "System Status",
            "Local paths and enabled safety controls used by this desktop application.",
            ["Component", "Status", "Path / configuration"],
            parent,
        )
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        self.controls.addWidget(refresh)
        self.refresh()

    def refresh(self) -> None:
        checks = [
            ("Project root", APP_ROOT.is_dir(), str(APP_ROOT)),
            ("Raw datasets", (APP_ROOT / "dataset" / "raw").is_dir(),
             str(APP_ROOT / "dataset" / "raw")),
            ("Processed datasets", (APP_ROOT / "dataset" / "processed").is_dir(),
             str(APP_ROOT / "dataset" / "processed")),
            ("Model directory", (APP_ROOT / "models").is_dir(),
             str(APP_ROOT / "models")),
            ("Alert storage", self.main_window.session_path(
                "logs", "alerts.jsonl"
            ).is_file(), str(self.main_window.session_path(
                "logs", "alerts.jsonl"
            ))),
            ("Response execution", True, "SIMULATION ONLY; approval required"),
        ]
        self.set_rows([
            [name, "AVAILABLE" if available else "NOT FOUND", path]
            for name, available, path in checks
        ])
        self.status_label.setText("Status checks completed.")


class ReportsPage(DataPage):
    def __init__(self, parent=None):
        super().__init__(
            "Reports",
            "Export a local operational summary of alerts, registered models, "
            "and offline prevention simulations. Raw IP addresses, database "
            "usernames, and SQL queries are excluded.",
            ["Report format", "Output", "Contents"],
            parent,
        )
        html_button = QPushButton("Export HTML report")
        html_button.setObjectName("primaryButton")
        json_button = QPushButton("Export JSON report")
        self.controls.addWidget(html_button)
        self.controls.addWidget(json_button)
        html_button.clicked.connect(lambda: self.export_report("html"))
        json_button.clicked.connect(lambda: self.export_report("json"))
        self.set_rows([
            ["HTML", "Standalone .html", "View, print, or save as PDF from a browser"],
            ["JSON", "Structured .json", "Use in scripts or further analysis"],
        ])
        self.output.setPlaceholderText(
            "Reports summarize locally stored application data. "
            "Alert totals are exact; alert and simulation detail tables "
            "include up to the latest 100 entries."
        )

    def export_report(self, output_format: str) -> None:
        extension = output_format.lower()
        if extension not in {"html", "json"}:
            self.report_error("Unsupported report format.")
            return
        default_path = APP_ROOT / f"AuditSentinel-report.{extension}"
        path, _ = QFileDialog.getSaveFileName(
            self,
            f"Save {extension.upper()} report",
            str(default_path),
            f"{extension.upper()} report (*.{extension})",
        )
        if not path:
            return
        if Path(path).suffix.lower() != f".{extension}":
            path = str(Path(path).with_suffix(f".{extension}"))
        self.main_window.run_background(
            "generate_report",
            path,
            {"format": extension},
            self.on_report_exported,
            self,
        )

    def on_report_exported(self, result: dict) -> None:
        self.status_label.setText(f"Report saved: {result['path']}")
        self.show_json(result)


class DashboardPage(DataPage):
    def __init__(self, parent=None):
        super().__init__(
            "Dashboard",
            "Machine-learning based database audit-log monitoring pipeline.",
            ["Pipeline stage", "Current state", "Evidence"],
            parent,
        )
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        self.controls.addWidget(refresh)
        self.refresh()

    def refresh(self) -> None:
        from src.detection.alert_manager import AlertManager
        from src.registry.model_registry import ModelRegistry

        raw_dir = APP_ROOT / "dataset" / "raw"
        processed_dir = APP_ROOT / "dataset" / "processed"
        raw_files = sum(1 for path in raw_dir.rglob("*") if path.is_file()) if raw_dir.exists() else 0
        processed_files = (
            sum(1 for path in processed_dir.rglob("*.parquet") if path.is_file())
            if processed_dir.exists()
            else 0
        )
        alert_stats = AlertManager(
            storage_path=self.main_window.session_path("logs", "alerts.jsonl")
        ).get_statistics()
        models = ModelRegistry(project_root=APP_ROOT).list_models()
        active_models = sum(model.get("status") == "active" for model in models)
        self.set_rows([
            ["Audit ingestion", "STREAM / NORMALIZE", f"{raw_files} raw files"],
            ["Processed datasets", "PARQUET", f"{processed_files} files"],
            ["ML detection", "SUPERVISED / ANOMALY", f"{active_models} active models"],
            ["Alert monitoring", "LOCAL JSONL", f"{alert_stats['total_alerts']} total; {alert_stats['open_alerts']} open"],
            ["AI investigation", "LOCAL OLLAMA", "Uses configured local provider/model"],
            ["Response control", "SIMULATION ONLY", "Manual approval required"],
        ])
        self.status_label.setText(
            "Counts are read from local project storage; no placeholder metrics."
        )


class DBIDSDesktopApp(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("AuditSentinel")
        self.setWindowIcon(QIcon(str(APP_ICON)))
        self.resize(1180, 760)
        self.setMinimumSize(950, 650)
        self.workflow_worker: TaskWorker | None = None
        from src.sessions import SessionManager

        self.session_manager = SessionManager(APP_ROOT)
        self.current_session = self.session_manager.active_session()

        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(16, 22, 16, 18)
        sidebar_layout.setSpacing(8)

        brand = QLabel("AuditSentinel")
        brand.setObjectName("brand")
        subtitle = QLabel("Database Audit Log Intelligence")
        subtitle.setObjectName("sidebarSubtitle")
        sidebar_layout.addWidget(brand)
        sidebar_layout.addWidget(subtitle)
        sidebar_layout.addSpacing(22)

        self.stack = QStackedWidget()
        self.pages: dict[str, int] = {}
        self.nav_buttons: dict[str, QPushButton] = {}

        self.dashboard_page = DashboardPage(self)
        self.dataset_page = DatasetPage(self)
        self.training_page = ModelTrainingPage(self)
        self.registry_page = ModelRegistryPage(self)
        self.detection_page = DetectionPage(self)
        self.alerts_page = AlertsPage(self)
        self.prevention_page = PreventionPage(self)
        self.investigation_page = InvestigationPage(self)
        self.response_page = ResponsePage(self)
        self.reports_page = ReportsPage(self)
        self.system_page = SystemStatusPage(self)
        self.restore_session_state()

        page_definitions = [
            ("Dashboard", self.dashboard_page),
            ("Dataset & Ingestion", self.dataset_page),
            ("ML Training", self.training_page),
            ("Model Registry", self.registry_page),
            ("Detection & Alerts", self.detection_page),
            ("Alert Monitoring", self.alerts_page),
            ("Prevention Simulation", self.prevention_page),
            ("AI Investigation", self.investigation_page),
            ("Response Management", self.response_page),
            ("Reports", self.reports_page),
            ("System Status", self.system_page),
        ]

        for title, page in page_definitions:
            self.pages[title] = self.stack.addWidget(page)

            button = QPushButton(title)
            button.setObjectName("navButton")
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setCheckable(True)
            button.clicked.connect(self._navigation_handler(title))
            sidebar_layout.addWidget(button)
            self.nav_buttons[title] = button

        sidebar_layout.addStretch()
        footer_label = QLabel("Local Desktop • v1.0.0")
        footer_label.setObjectName("sidebarFooter")
        sidebar_layout.addWidget(footer_label)

        content = QWidget()
        content.setObjectName("contentArea")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        topbar = QFrame()
        topbar.setObjectName("topbar")
        topbar_layout = QHBoxLayout(topbar)
        topbar_layout.setContentsMargins(26, 14, 26, 14)

        self.current_page_label = QLabel("Dashboard")
        self.current_page_label.setObjectName("topbarTitle")
        self.session_selector = QComboBox()
        self.session_selector.setMinimumWidth(190)
        self.new_session_button = QPushButton("New session")
        self.new_session_button.setObjectName("primaryButton")
        status_label = QLabel("● Local system")
        status_label.setObjectName("statusLabel")
        topbar_layout.addWidget(self.current_page_label)
        topbar_layout.addStretch()
        topbar_layout.addWidget(QLabel("Session:"))
        topbar_layout.addWidget(self.session_selector)
        topbar_layout.addWidget(self.new_session_button)
        topbar_layout.addWidget(status_label)
        self.refresh_session_selector()
        self.session_selector.currentIndexChanged.connect(
            self._session_selection_changed
        )
        self.new_session_button.clicked.connect(self.create_session_dialog)

        content_layout.addWidget(topbar)
        content_layout.addWidget(self.stack, 1)
        root_layout.addWidget(sidebar)
        root_layout.addWidget(content, 1)
        self.setCentralWidget(root)

        self.setStyleSheet("""
            QWidget {
                background: #000000;
                color: #66B2FF;
                font-family: "Segoe UI";
                font-size: 9pt;
            }
            QMainWindow, QWidget#contentArea {
                background: #000000;
                color: #66B2FF;
            }
            QFrame#sidebar {
                background: #02070D;
                border-right: 1px solid #12304A;
            }
            QLabel#brand {
                color: #66B2FF;
                font-size: 18pt;
                font-weight: 700;
            }
            QLabel#sidebarSubtitle, QLabel#sidebarFooter {
                color: #4386C4;
                font-size: 8pt;
            }
            QPushButton#navButton {
                text-align: left;
                color: #66B2FF;
                background: transparent;
                border: none;
                border-radius: 3px;
                padding: 11px 12px;
            }
            QPushButton#navButton:hover {
                background: #071726;
                color: #91CAFF;
            }
            QPushButton#navButton:checked {
                background: #0A2238;
                color: #91CAFF;
                font-weight: 600;
            }
            QFrame#topbar {
                background: #030A12;
                border-bottom: 1px solid #12304A;
            }
            QLabel#topbarTitle {
                color: #91CAFF;
                font-size: 13pt;
                font-weight: 600;
            }
            QLabel#statusLabel, QLabel#pageStatus {
                color: #66B2FF;
                font-size: 9pt;
            }
            QLabel#pageHeading {
                color: #91CAFF;
                font-size: 19pt;
                font-weight: 650;
            }
            QLabel#pageDescription, QLabel#pathLabel {
                color: #5597D4;
                font-size: 9pt;
            }
            QLabel#summaryLabel, QLabel#sectionHeading {
                color: #78BBF5;
                font-weight: 600;
            }
            QFrame#infoPanel {
                background: #030A12;
                border: 1px solid #12304A;
                border-radius: 3px;
            }
            QPushButton {
                background: #071726;
                color: #66B2FF;
                border: 1px solid #17466B;
                border-radius: 3px;
                padding: 8px 12px;
            }
            QPushButton:hover {
                background: #0A2238;
                color: #91CAFF;
            }
            QPushButton#primaryButton {
                background: #0A2B49;
                color: #91CAFF;
                border: 1px solid #24689B;
                font-weight: 600;
            }
            QPushButton:disabled {
                background: #05090D;
                color: #28547A;
                border-color: #10283B;
            }
            QTableWidget, QPlainTextEdit, QLineEdit, QComboBox, QSpinBox {
                background: #000000;
                color: #66B2FF;
                border: 1px solid #12304A;
                border-radius: 3px;
                gridline-color: #10283B;
                selection-background-color: #0A2B49;
                selection-color: #A6D5FF;
                padding: 5px;
            }
            QTableWidget {
                alternate-background-color: #030A12;
            }
            QTableWidget::item {
                color: #66B2FF;
            }
            QTableWidget::item:selected {
                background: #0A2B49;
                color: #A6D5FF;
            }
            QHeaderView::section {
                background: #030A12;
                color: #78BBF5;
                padding: 7px;
                border: none;
                border-bottom: 1px solid #12304A;
            }
            QComboBox QAbstractItemView {
                background: #000000;
                color: #66B2FF;
                selection-background-color: #0A2B49;
            }
            QProgressBar {
                background: #030A12;
                color: #66B2FF;
                border: 1px solid #12304A;
                border-radius: 3px;
                height: 8px;
                text-align: center;
            }
            QProgressBar::chunk {
                background: #1768A6;
                border-radius: 2px;
            }
            QStatusBar {
                background: #02070D;
                color: #66B2FF;
            }
        """)

        self.show_page("Dashboard")

    def _navigation_handler(self, title: str):
        def navigate() -> None:
            self.show_page(title)

        return navigate

    def run_background(
        self,
        task: str,
        path: str = "",
        payload: dict | None = None,
        on_success=None,
        page=None,
    ) -> None:
        if self.workflow_worker is not None and self.workflow_worker.isRunning():
            QMessageBox.information(
                self,
                "Task in progress",
                "Wait for the current model or investigation task to finish.",
            )
            return
        if self.dataset_page.worker is not None and self.dataset_page.worker.isRunning():
            QMessageBox.information(
                self,
                "Task in progress",
                "Wait for the current dataset operation to finish.",
            )
            return

        if task in {
            "detect",
            "plan_prevention",
            "simulate_prevention",
            "investigate",
            "propose_response",
            "generate_report",
        }:
            payload = dict(payload or {})
            payload["session_root"] = str(self.current_session.root)

        worker = TaskWorker(task, path, payload, self)
        self.workflow_worker = worker
        if page is not None:
            page.status_label.setText(f"{task.title()} started.")
            worker.status.connect(page.status_label.setText)
            worker.failed.connect(page.report_error)
        else:
            worker.failed.connect(
                lambda message: QMessageBox.critical(
                    self, "AuditSentinel Error", message
                )
            )
        if on_success is not None:
            worker.succeeded.connect(on_success)
        worker.finished.connect(self._workflow_finished)
        worker.start()

    def _workflow_finished(self) -> None:
        worker = self.sender()
        if self.workflow_worker is worker:
            self.workflow_worker = None
        if worker is not None:
            worker.deleteLater()

    def refresh_registry(self) -> None:
        self.registry_page.refresh()

    def refresh_alerts(self) -> None:
        self.alerts_page.refresh()

    def refresh_dashboard(self) -> None:
        self.dashboard_page.refresh()

    def session_path(self, *parts: str) -> Path:
        return self.current_session.root.joinpath(*parts)

    def capture_session_state(self) -> dict[str, str]:
        dataset_path = self.dataset_page.path_label.text().strip()
        if dataset_path == "No file or folder selected.":
            dataset_path = ""
        return {
            "dataset_path": dataset_path,
            "training_dataset_path": self.training_page.file_path.text().strip(),
            "detection_dataset_path": self.detection_page.file_path.text().strip(),
            "prevention_dataset_path": self.prevention_page.file_path.text().strip(),
        }

    def save_current_session_state(self) -> None:
        self.session_manager.save_state(
            self.current_session.session_id,
            self.capture_session_state(),
        )

    def restore_session_state(self) -> None:
        state = self.session_manager.get_state(
            self.current_session.session_id
        )
        self.dataset_page.path_label.setText(
            state.get("dataset_path", "")
            or "No file or folder selected."
        )
        self.training_page.file_path.setText(
            state.get("training_dataset_path", "")
        )
        self.detection_page.file_path.setText(
            state.get("detection_dataset_path", "")
        )
        self.prevention_page.file_path.setText(
            state.get("prevention_dataset_path", "")
        )

    def refresh_session_selector(self) -> None:
        self.session_selector.blockSignals(True)
        self.session_selector.clear()
        for session in self.session_manager.list_sessions():
            label = session.name
            if session.is_legacy:
                label += " (dữ liệu cũ)"
            self.session_selector.addItem(label, session.session_id)
        selected_index = self.session_selector.findData(
            self.current_session.session_id
        )
        if selected_index < 0:
            self.session_selector.blockSignals(False)
            raise RuntimeError("The active work session is missing from the list")
        self.session_selector.setCurrentIndex(selected_index)
        self.session_selector.blockSignals(False)

    def _session_selection_changed(self, index: int) -> None:
        session_id = self.session_selector.itemData(index)
        if not session_id or session_id == self.current_session.session_id:
            return
        self.activate_session(session_id)

    def _session_worker_is_running(self) -> bool:
        return (
            self.workflow_worker is not None
            and self.workflow_worker.isRunning()
        ) or (
            self.dataset_page.worker is not None
            and self.dataset_page.worker.isRunning()
        )

    def activate_session(self, session_id: str) -> None:
        if self._session_worker_is_running():
            QMessageBox.information(
                self,
                "Task in progress",
                "Wait for the current operation to finish before changing sessions.",
            )
            self.refresh_session_selector()
            return
        try:
            self.save_current_session_state()
            self.current_session = self.session_manager.set_active_session(
                session_id
            )
        except (KeyError, ValueError, RuntimeError) as exc:
            self.refresh_session_selector()
            QMessageBox.critical(
                self,
                "AuditSentinel Session Error",
                f"{type(exc).__name__}: {exc}",
            )
            return
        self.restore_session_state()
        self.refresh_session_selector()
        self.refresh_session_pages()

    def create_session_dialog(self) -> None:
        if self._session_worker_is_running():
            QMessageBox.information(
                self,
                "Task in progress",
                "Wait for the current operation to finish before creating a session.",
            )
            return
        name, accepted = QInputDialog.getText(
            self,
            "Create work session",
            "Enter a name for the new session:",
        )
        if not accepted:
            return
        try:
            self.save_current_session_state()
            self.current_session = self.session_manager.create_session(name)
        except (TypeError, ValueError, RuntimeError, OSError) as exc:
            QMessageBox.critical(
                self,
                "AuditSentinel Session Error",
                f"{type(exc).__name__}: {exc}",
            )
            return
        self.restore_session_state()
        self.refresh_session_selector()
        self.refresh_session_pages()
        QMessageBox.information(
            self,
            "New session created",
            "A new empty work session is active. Previous session data has not been deleted.",
        )

    def refresh_session_pages(self) -> None:
        self.alerts_page.refresh()
        self.investigation_page.refresh_alerts()
        self.investigation_page.refresh_reports()
        self.response_page.refresh()
        self.prevention_page.load_history()
        self.system_page.refresh()
        self.dashboard_page.refresh()
        self.reports_page.status_label.setText(
            f"Ready to export a report for: {self.current_session.name}"
        )

    def closeEvent(self, event) -> None:
        try:
            self.save_current_session_state()
        except (KeyError, TypeError, ValueError, RuntimeError) as exc:
            QMessageBox.critical(
                self,
                "AuditSentinel Session Error",
                f"Could not save the current session state: {type(exc).__name__}: {exc}",
            )
            event.ignore()
            return
        event.accept()

    def show_page(self, title: str) -> None:
        self.stack.setCurrentIndex(self.pages[title])
        self.current_page_label.setText(title)
        for page_title, button in self.nav_buttons.items():
            button.setChecked(page_title == title)


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("AuditSentinel")
    app.setWindowIcon(QIcon(str(APP_ICON)))
    window = DBIDSDesktopApp()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
