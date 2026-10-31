from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QFrame,
    QStackedWidget,
    QFileDialog,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QTextEdit,
    QSplitter,
    QProgressBar,
    QAbstractItemView,
    QStatusBar,
)

from src.reader.importer import scan_path
from src.reader.parser import parse_file
from src.reader.ingestion import ingest_file


APP_NAME = "DB-AI-IDS"
APP_VERSION = "1.0.0"

SUPPORTED_IMPORT_FORMATS = {
    ".csv",
    ".tsv",
    ".jsonl",
    ".ndjson",
    ".parquet",
}


# ============================================================
# WORKER THREAD
# ============================================================

class TaskWorker(QThread):
    finished_result = Signal(object)
    failed = Signal(str)

    def __init__(self, task: str, payload: dict[str, Any]):
        super().__init__()
        self.task = task
        self.payload = payload

    def run(self):
        try:
            if self.task == "scan":
                result = scan_path(
                    self.payload["source_path"]
                )

            elif self.task == "preview":
                result = parse_file(
                    self.payload["file_path"]
                )

            elif self.task == "ingest":
                result = ingest_file(
                    file_path=self.payload["file_path"],
                    output_dir=self.payload.get(
                        "output_dir",
                        "dataset/processed",
                    ),
                    batch_size=self.payload.get(
                        "batch_size",
                        5000,
                    ),
                    strict=self.payload.get(
                        "strict",
                        False,
                    ),
                )

            else:
                raise ValueError(
                    f"Unknown worker task: {self.task}"
                )

            self.finished_result.emit(result)

        except Exception:
            self.failed.emit(traceback.format_exc())


# ============================================================
# GENERAL UI COMPONENTS
# ============================================================

def create_button(
    text: str,
    primary: bool = False,
) -> QPushButton:

    button = QPushButton(text)
    button.setCursor(Qt.PointingHandCursor)
    button.setMinimumHeight(36)

    if primary:
        button.setObjectName("PrimaryButton")
    else:
        button.setObjectName("SecondaryButton")

    return button


def create_section_title(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("SectionTitle")
    return label


def format_value(value: Any) -> str:
    if value is None:
        return "-"

    if isinstance(value, (dict, list)):
        return json.dumps(
            value,
            indent=2,
            ensure_ascii=False,
            default=str,
        )

    return str(value)


def save_json_preview(data: Any) -> str:
    try:
        return json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
            default=str,
        )
    except Exception:
        return str(data)


# ============================================================
# DASHBOARD PAGE
# ============================================================

class DashboardPage(QWidget):

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)
        layout.setSpacing(18)

        title = QLabel("Dashboard")
        title.setObjectName("PageTitle")

        subtitle = QLabel(
            "Database Audit Log Intrusion Detection System"
        )
        subtitle.setObjectName("Subtitle")

        layout.addWidget(title)
        layout.addWidget(subtitle)

        cards_layout = QGridLayout()
        cards_layout.setSpacing(14)

        self.cards = {}

        card_data = [
            ("Dataset Files", "0"),
            ("Processed Records", "0"),
            ("Detection Alerts", "0"),
            ("Active Models", "0"),
        ]

        for index, (name, value) in enumerate(card_data):
            card = QFrame()
            card.setObjectName("InfoCard")

            card_layout = QVBoxLayout(card)

            name_label = QLabel(name)
            name_label.setObjectName("CardLabel")

            value_label = QLabel(value)
            value_label.setObjectName("CardValue")

            card_layout.addWidget(name_label)
            card_layout.addWidget(value_label)

            cards_layout.addWidget(
                card,
                index // 2,
                index % 2,
            )

            self.cards[name] = value_label

        layout.addLayout(cards_layout)

        layout.addWidget(
            create_section_title("System Overview")
        )

        info = QLabel(
            "The system is designed to analyze database audit logs, "
            "detect suspicious activities using Machine Learning, "
            "and generate AI-assisted investigation reports."
        )
        info.setWordWrap(True)
        info.setObjectName("InfoText")

        layout.addWidget(info)

        layout.addStretch()


# ============================================================
# DATASET PAGE
# ============================================================

class DatasetPage(QWidget):

    def __init__(self, main_window):
        super().__init__()

        self.main_window = main_window

        self.worker: TaskWorker | None = None
        self.selected_source: str | None = None
        self.files: list[dict[str, Any]] = []
        self.current_preview: dict[str, Any] | None = None

        self._build_ui()

    # --------------------------------------------------------
    # BUILD UI
    # --------------------------------------------------------

    def _build_ui(self):

        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(14)

        title = QLabel("Dataset Manager")
        title.setObjectName("PageTitle")

        subtitle = QLabel(
            "Scan, inspect, and import database audit log datasets."
        )
        subtitle.setObjectName("Subtitle")

        main_layout.addWidget(title)
        main_layout.addWidget(subtitle)

        # Source controls
        source_frame = QFrame()
        source_frame.setObjectName("Panel")

        source_layout = QVBoxLayout(source_frame)

        source_layout.addWidget(
            create_section_title("Dataset Source")
        )

        button_layout = QHBoxLayout()

        self.select_file_button = create_button(
            "Select File"
        )

        self.select_folder_button = create_button(
            "Select Folder"
        )

        self.scan_button = create_button(
            "Scan Source",
            primary=True,
        )

        self.select_file_button.clicked.connect(
            self.select_file
        )

        self.select_folder_button.clicked.connect(
            self.select_folder
        )

        self.scan_button.clicked.connect(
            self.scan_source
        )

        button_layout.addWidget(self.select_file_button)
        button_layout.addWidget(self.select_folder_button)
        button_layout.addWidget(self.scan_button)
        button_layout.addStretch()

        source_layout.addLayout(button_layout)

        self.source_label = QLabel(
            "No source selected."
        )
        self.source_label.setObjectName("InfoText")
        self.source_label.setWordWrap(True)

        source_layout.addWidget(self.source_label)

        main_layout.addWidget(source_frame)

        # Statistics
        stats_layout = QGridLayout()
        stats_layout.setSpacing(10)

        self.total_files_label = self._create_stat_card(
            stats_layout,
            "Total Files",
            "0",
            0,
            0,
        )

        self.supported_files_label = self._create_stat_card(
            stats_layout,
            "Supported Files",
            "0",
            0,
            1,
        )

        self.unsupported_files_label = self._create_stat_card(
            stats_layout,
            "Unsupported Files",
            "0",
            0,
            2,
        )

        self.selected_files_label = self._create_stat_card(
            stats_layout,
            "Selected Files",
            "0",
            0,
            3,
        )

        main_layout.addLayout(stats_layout)

        # File table
        table_frame = QFrame()
        table_frame.setObjectName("Panel")

        table_layout = QVBoxLayout(table_frame)

        table_header = QHBoxLayout()

        table_header.addWidget(
            create_section_title("Discovered Files")
        )

        table_header.addStretch()

        self.clear_button = create_button(
            "Clear Results"
        )

        self.clear_button.clicked.connect(
            self.clear_results
        )

        table_header.addWidget(self.clear_button)

        table_layout.addLayout(table_header)

        self.file_table = QTableWidget()

        self.file_table.setColumnCount(5)

        self.file_table.setHorizontalHeaderLabels([
            "File Name",
            "Format",
            "Size",
            "Status",
            "Path",
        ])

        self.file_table.setSelectionBehavior(
            QAbstractItemView.SelectRows
        )

        self.file_table.setSelectionMode(
            QAbstractItemView.ExtendedSelection
        )

        self.file_table.setEditTriggers(
            QAbstractItemView.NoEditTriggers
        )

        self.file_table.horizontalHeader().setSectionResizeMode(
            0,
            QHeaderView.ResizeToContents,
        )

        self.file_table.horizontalHeader().setSectionResizeMode(
            1,
            QHeaderView.ResizeToContents,
        )

        self.file_table.horizontalHeader().setSectionResizeMode(
            2,
            QHeaderView.ResizeToContents,
        )

        self.file_table.horizontalHeader().setSectionResizeMode(
            3,
            QHeaderView.ResizeToContents,
        )

        self.file_table.horizontalHeader().setSectionResizeMode(
            4,
            QHeaderView.Stretch,
        )

        self.file_table.itemSelectionChanged.connect(
            self.selection_changed
        )

        table_layout.addWidget(self.file_table)

        main_layout.addWidget(table_frame, 3)

        # Preview and actions
        bottom_splitter = QSplitter(Qt.Horizontal)

        preview_frame = QFrame()
        preview_frame.setObjectName("Panel")

        preview_layout = QVBoxLayout(preview_frame)

        preview_layout.addWidget(
            create_section_title("File Preview")
        )

        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)

        self.preview_text.setPlaceholderText(
            "Select a file and click Preview Selected."
        )

        preview_layout.addWidget(self.preview_text)

        bottom_splitter.addWidget(preview_frame)

        action_frame = QFrame()
        action_frame.setObjectName("Panel")

        action_layout = QVBoxLayout(action_frame)

        action_layout.addWidget(
            create_section_title("Dataset Actions")
        )

        self.preview_button = create_button(
            "Preview Selected",
            primary=True,
        )

        self.import_button = create_button(
            "Import Selected",
            primary=True,
        )

        self.preview_button.clicked.connect(
            self.preview_selected
        )

        self.import_button.clicked.connect(
            self.import_selected
        )

        action_layout.addWidget(self.preview_button)
        action_layout.addWidget(self.import_button)

        action_layout.addSpacing(15)

        action_layout.addWidget(
            create_section_title("Import Information")
        )

        import_info = QLabel(
            "Supported import formats:\n"
            "CSV, TSV, JSONL, NDJSON, Parquet\n\n"
            "Import mode:\n"
            "Streaming ingestion\n\n"
            "Batch size:\n"
            "5,000 records"
        )

        import_info.setObjectName("InfoText")
        import_info.setWordWrap(True)

        action_layout.addWidget(import_info)

        action_layout.addStretch()

        bottom_splitter.addWidget(action_frame)
        bottom_splitter.setSizes([700, 260])

        main_layout.addWidget(bottom_splitter, 2)

        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setVisible(False)

        main_layout.addWidget(self.progress_bar)

        self.status_label = QLabel(
            "Ready."
        )
        self.status_label.setObjectName("StatusLabel")

        main_layout.addWidget(self.status_label)

    # --------------------------------------------------------
    # STATISTICS
    # --------------------------------------------------------

    def _create_stat_card(
        self,
        parent_layout,
        title,
        value,
        row,
        column,
    ):

        card = QFrame()
        card.setObjectName("InfoCard")

        layout = QVBoxLayout(card)

        title_label = QLabel(title)
        title_label.setObjectName("CardLabel")

        value_label = QLabel(value)
        value_label.setObjectName("CardValue")

        layout.addWidget(title_label)
        layout.addWidget(value_label)

        parent_layout.addWidget(
            card,
            row,
            column,
        )

        return value_label

    # --------------------------------------------------------
    # SOURCE SELECTION
    # --------------------------------------------------------

    def select_file(self):

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Dataset File",
            "",
            (
                "All Files (*.*);;"
                "CSV Files (*.csv);;"
                "JSON Files (*.json *.jsonl);;"
                "Log Files (*.log *.txt);;"
                "Parquet Files (*.parquet)"
            ),
        )

        if not file_path:
            return

        self.selected_source = file_path

        self.source_label.setText(
            f"Selected file: {file_path}"
        )

        self.status_label.setText(
            "File selected. Click Scan Source."
        )

    def select_folder(self):

        folder_path = QFileDialog.getExistingDirectory(
            self,
            "Select Dataset Folder",
        )

        if not folder_path:
            return

        self.selected_source = folder_path

        self.source_label.setText(
            f"Selected folder: {folder_path}"
        )

        self.status_label.setText(
            "Folder selected. Click Scan Source."
        )

    # --------------------------------------------------------
    # WORKER MANAGEMENT
    # --------------------------------------------------------

    def start_worker(
        self,
        task: str,
        payload: dict[str, Any],
    ):

        # Prevent starting another task while one is running.
        if (
            self.worker is not None
            and self.worker.isRunning()
        ):
            self.status_label.setText(
                "Another task is currently running."
            )
            return

        self.set_busy(True)

        self.status_label.setText(
            "Processing..."
        )

        worker = TaskWorker(
            task,
            payload,
        )

        self.worker = worker

        worker.finished_result.connect(
            self.task_finished
        )

        worker.failed.connect(
            self.task_failed
        )

        # Important: clean up the exact worker that finished.
        worker.finished.connect(
            self.worker_finished
        )

        worker.start()

    def worker_finished(self):

        worker = self.sender()

        if self.worker is worker:
            self.worker = None

        if worker is not None:
            worker.deleteLater()

        self.set_busy(False)

    def set_busy(self, busy: bool):

        self.progress_bar.setVisible(busy)

        self.select_file_button.setEnabled(
            not busy
        )

        self.select_folder_button.setEnabled(
            not busy
        )

        self.scan_button.setEnabled(
            not busy
        )

        self.preview_button.setEnabled(
            not busy
        )

        self.import_button.setEnabled(
            not busy
        )

        self.clear_button.setEnabled(
            not busy
        )

    # --------------------------------------------------------
    # SCAN
    # --------------------------------------------------------

    def scan_source(self):

        if not self.selected_source:
            QMessageBox.warning(
                self,
                "No Source Selected",
                "Please select a file or folder first.",
            )
            return

        self.start_worker(
            "scan",
            {
                "source_path": self.selected_source,
            },
        )

    # --------------------------------------------------------
    # SELECTION
    # --------------------------------------------------------

    def selection_changed(self):

        selected_rows = self.file_table.selectionModel().selectedRows()

        self.selected_files_label.setText(
            str(len(selected_rows))
        )

    def get_selected_file_paths(self) -> list[str]:

        selected_rows = (
            self.file_table.selectionModel().selectedRows()
        )

        paths = []

        for index in selected_rows:

            row = index.row()

            if row < len(self.files):
                file_info = self.files[row]

                file_path = file_info.get("path")

                if file_path:
                    paths.append(str(file_path))

        return paths

    # --------------------------------------------------------
    # PREVIEW
    # --------------------------------------------------------

    def preview_selected(self):

        selected_paths = self.get_selected_file_paths()

        if not selected_paths:
            QMessageBox.warning(
                self,
                "No File Selected",
                "Please select a file from the table first.",
            )
            return

        if len(selected_paths) > 1:
            QMessageBox.information(
                self,
                "Multiple Files Selected",
                "Please select only one file for preview.",
            )
            return

        file_path = selected_paths[0]

        self.preview_text.clear()

        self.preview_text.setPlainText(
            f"Loading preview...\n\n{file_path}"
        )

        self.start_worker(
            "preview",
            {
                "file_path": file_path,
            },
        )

    # --------------------------------------------------------
    # IMPORT
    # --------------------------------------------------------

    def import_selected(self):

        selected_paths = self.get_selected_file_paths()

        if not selected_paths:
            QMessageBox.warning(
                self,
                "No File Selected",
                "Please select at least one file.",
            )
            return

        unsupported = []

        for file_path in selected_paths:

            suffix = Path(file_path).suffix.lower()

            if suffix not in SUPPORTED_IMPORT_FORMATS:
                unsupported.append(
                    Path(file_path).name
                )

        if unsupported:

            QMessageBox.warning(
                self,
                "Unsupported Import Format",
                (
                    "The following files cannot be imported "
                    "through the current streaming ingestion module:\n\n"
                    + "\n".join(unsupported)
                ),
            )

            return

        if len(selected_paths) > 1:

            QMessageBox.information(
                self,
                "Multiple Files Selected",
                (
                    "Please import one file at a time. "
                    "This keeps each ingestion run separate."
                ),
            )

            return

        file_path = selected_paths[0]

        answer = QMessageBox.question(
            self,
            "Confirm Dataset Import",
            (
                f"Import this dataset?\n\n"
                f"{file_path}\n\n"
                f"Batch size: 5,000 records\n"
                f"Strict mode: Disabled"
            ),
        )

        if answer != QMessageBox.Yes:
            return

        self.preview_text.setPlainText(
            "Dataset ingestion started..."
        )

        self.start_worker(
            "ingest",
            {
                "file_path": file_path,
                "output_dir": "dataset/processed",
                "batch_size": 5000,
                "strict": False,
            },
        )

    # --------------------------------------------------------
    # WORKER RESULT HANDLING
    # --------------------------------------------------------

    def task_finished(self, result):

        if isinstance(result, dict):

            if "files" in result:
                self.display_scan_result(result)

            elif "file" in result:
                self.display_preview(result)

            elif (
                "status" in result
                or "total_records_read" in result
                or "parquet_files" in result
            ):
                self.display_ingestion_result(result)

            else:
                self.preview_text.setPlainText(
                    save_json_preview(result)
                )

                self.status_label.setText(
                    "Task completed."
                )

        elif isinstance(result, list):

            self.display_scan_result(result)

        else:

            self.preview_text.setPlainText(
                save_json_preview(result)
            )

            self.status_label.setText(
                "Task completed."
            )

    def task_failed(self, error: str):

        self.status_label.setText(
            "Task failed."
        )

        self.preview_text.setPlainText(error)

        QMessageBox.critical(
            self,
            "Task Failed",
            error[-4000:],
        )

    # --------------------------------------------------------
    # DISPLAY SCAN RESULTS
    # --------------------------------------------------------

    def display_scan_result(self, result):

        if isinstance(result, dict):

            files = result.get(
                "files",
                result.get("results", []),
            )

        elif isinstance(result, list):

            files = result

        else:

            files = []

        if not isinstance(files, list):
            files = []

        self.files = []

        for item in files:

            if isinstance(item, str):

                self.files.append({
                    "path": item,
                    "name": Path(item).name,
                    "format": Path(item).suffix.lower(),
                    "size": "-",
                    "status": "Discovered",
                })

            elif isinstance(item, dict):

                file_path = (
                    item.get("path")
                    or item.get("file_path")
                    or item.get("filepath")
                )

                if not file_path:
                    continue

                self.files.append({
                    **item,
                    "path": str(file_path),
                    "name": item.get(
                        "name",
                        Path(file_path).name,
                    ),
                    "format": item.get(
                        "format",
                        Path(file_path).suffix.lower(),
                    ),
                    "size": item.get(
                        "size",
                        item.get("size_bytes", "-"),
                    ),
                    "status": item.get(
                        "status",
                        "Discovered",
                    ),
                })

        self.file_table.setRowCount(
            len(self.files)
        )

        supported_count = 0

        for row, file_info in enumerate(self.files):

            file_path = file_info["path"]

            file_format = str(
                file_info.get("format", "")
            ).lower()

            if not file_format:
                file_format = Path(file_path).suffix.lower()

            supported = (
                file_format in {
                    ".csv",
                    ".tsv",
                    ".json",
                    ".jsonl",
                    ".ndjson",
                    ".txt",
                    ".log",
                    ".xml",
                    ".yaml",
                    ".yml",
                    ".parquet",
                    ".xlsx",
                    ".xls",
                    ".py",
                    ".sql",
                    ".zip",
                }
            )

            if supported:
                supported_count += 1

            values = [
                file_info.get("name", Path(file_path).name),
                file_format,
                self.format_size(file_info.get("size", "-")),
                file_info.get("status", "Discovered"),
                file_path,
            ]

            for column, value in enumerate(values):

                cell = QTableWidgetItem(
                    str(value)
                )

                cell.setToolTip(
                    str(value)
                )

                self.file_table.setItem(
                    row,
                    column,
                    cell,
                )

        self.total_files_label.setText(
            str(len(self.files))
        )

        self.supported_files_label.setText(
            str(supported_count)
        )

        self.unsupported_files_label.setText(
            str(len(self.files) - supported_count)
        )

        self.selected_files_label.setText("0")

        self.status_label.setText(
            f"Scan completed. Found {len(self.files)} files."
        )

        self.preview_text.setPlainText(
            "Scan completed.\n\n"
            f"Discovered files: {len(self.files)}\n"
            f"Supported files: {supported_count}\n\n"
            "Select a file from the table and click Preview Selected."
        )

    # --------------------------------------------------------
    # DISPLAY PREVIEW
    # --------------------------------------------------------

    def display_preview(self, result):

        self.current_preview = result

        self.preview_text.setPlainText(
            save_json_preview(result)
        )

        self.status_label.setText(
            "Preview completed successfully."
        )

    # --------------------------------------------------------
    # DISPLAY INGESTION RESULT
    # --------------------------------------------------------

    def display_ingestion_result(self, result):

        self.preview_text.setPlainText(
            save_json_preview(result)
        )

        status = result.get(
            "status",
            "UNKNOWN",
        )

        total_records = result.get(
            "total_records_read",
            0,
        )

        quarantined = result.get(
            "quarantined_records",
            0,
        )

        parquet_files = result.get(
            "parquet_files",
            [],
        )

        summary = (
            "INGESTION SUMMARY\n"
            "=================\n\n"
            f"Status: {status}\n"
            f"Records Read: {total_records}\n"
            f"Quarantined Records: {quarantined}\n"
            f"Parquet Files: {len(parquet_files)}\n\n"
            "Full report:\n\n"
            f"{save_json_preview(result)}"
        )

        self.preview_text.setPlainText(
            summary
        )

        self.status_label.setText(
            f"Ingestion completed: {status}"
        )

        QMessageBox.information(
            self,
            "Ingestion Completed",
            (
                f"Status: {status}\n"
                f"Records Read: {total_records}\n"
                f"Quarantined Records: {quarantined}"
            ),
        )

    # --------------------------------------------------------
    # UTILITIES
    # --------------------------------------------------------

    @staticmethod
    def format_size(value):

        if value is None or value == "-":
            return "-"

        try:
            size = float(value)
        except (ValueError, TypeError):
            return str(value)

        if size < 1024:
            return f"{size:.0f} B"

        if size < 1024 ** 2:
            return f"{size / 1024:.2f} KB"

        if size < 1024 ** 3:
            return f"{size / (1024 ** 2):.2f} MB"

        return f"{size / (1024 ** 3):.2f} GB"

    # --------------------------------------------------------
    # CLEAR
    # --------------------------------------------------------

    def clear_results(self):

        if (
            self.worker is not None
            and self.worker.isRunning()
        ):
            QMessageBox.warning(
                self,
                "Task Running",
                "Wait until the current task is completed.",
            )
            return

        self.files.clear()
        self.current_preview = None

        self.file_table.setRowCount(0)
        self.preview_text.clear()

        self.total_files_label.setText("0")
        self.supported_files_label.setText("0")
        self.unsupported_files_label.setText("0")
        self.selected_files_label.setText("0")

        self.status_label.setText(
            "Results cleared."
        )


# ============================================================
# PLACEHOLDER PAGE
# ============================================================

class PlaceholderPage(QWidget):

    def __init__(
        self,
        title: str,
        description: str,
    ):

        super().__init__()

        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        page_title = QLabel(title)
        page_title.setObjectName("PageTitle")

        subtitle = QLabel(description)
        subtitle.setObjectName("Subtitle")
        subtitle.setWordWrap(True)

        panel = QFrame()
        panel.setObjectName("Panel")

        panel_layout = QVBoxLayout(panel)

        message = QLabel(
            "This module is not available in the current desktop build."
        )

        message.setObjectName("InfoText")
        message.setWordWrap(True)

        panel_layout.addWidget(message)

        layout.addWidget(page_title)
        layout.addWidget(subtitle)
        layout.addWidget(panel)
        layout.addStretch()


# ============================================================
# MAIN WINDOW
# ============================================================

class MainWindow(QMainWindow):

    def __init__(self):

        super().__init__()

        self.setWindowTitle(
            f"{APP_NAME} - Database Audit Log Security"
        )

        self.resize(1450, 900)
        self.setMinimumSize(1100, 700)

        self._build_ui()
        self._apply_style()

    # --------------------------------------------------------
    # BUILD MAIN UI
    # --------------------------------------------------------

    def _build_ui(self):

        central = QWidget()
        self.setCentralWidget(central)

        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Sidebar
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(230)

        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(15, 20, 15, 15)
        sidebar_layout.setSpacing(10)

        logo = QLabel("DB-AI-IDS")
        logo.setObjectName("Logo")

        version = QLabel(
            f"Version {APP_VERSION}"
        )
        version.setObjectName("VersionLabel")

        sidebar_layout.addWidget(logo)
        sidebar_layout.addWidget(version)

        sidebar_layout.addSpacing(25)

        self.stack = QStackedWidget()

        self.navigation_buttons = []

        pages = [
            (
                "Dashboard",
                DashboardPage(),
            ),
            (
                "Dataset Manager",
                DatasetPage(self),
            ),
            (
                "Model Training",
                PlaceholderPage(
                    "Model Training",
                    "Train and evaluate supervised and unsupervised detection models.",
                ),
            ),
            (
                "Detection Engine",
                PlaceholderPage(
                    "Detection Engine",
                    "Analyze database audit logs using registered ML models.",
                ),
            ),
            (
                "Alerts",
                PlaceholderPage(
                    "Alerts",
                    "Review and manage suspicious database activities.",
                ),
            ),
            (
                "AI Investigation",
                PlaceholderPage(
                    "AI Investigation",
                    "Generate AI-assisted investigation reports using local Ollama.",
                ),
            ),
            (
                "Response Center",
                PlaceholderPage(
                    "Response Center",
                    "Review simulated response actions and approval status.",
                ),
            ),
        ]

        for index, (name, page) in enumerate(pages):

            button = QPushButton(name)

            button.setObjectName(
                "NavigationButton"
            )

            button.setCursor(
                Qt.PointingHandCursor
            )

            button.setMinimumHeight(42)

            button.clicked.connect(
                lambda checked=False, i=index:
                self.change_page(i)
            )

            sidebar_layout.addWidget(button)

            self.navigation_buttons.append(
                button
            )

            self.stack.addWidget(page)

        sidebar_layout.addStretch()

        footer = QLabel(
            "Database Security Platform"
        )

        footer.setObjectName("VersionLabel")

        sidebar_layout.addWidget(footer)

        root_layout.addWidget(sidebar)
        root_layout.addWidget(self.stack, 1)

        self.statusBar().showMessage(
            "System ready."
        )

        self.change_page(0)

    # --------------------------------------------------------
    # NAVIGATION
    # --------------------------------------------------------

    def change_page(self, index: int):

        if index < 0 or index >= self.stack.count():
            return

        self.stack.setCurrentIndex(index)

        for i, button in enumerate(
            self.navigation_buttons
        ):

            button.setProperty(
                "active",
                i == index,
            )

            button.style().unpolish(button)
            button.style().polish(button)

    # --------------------------------------------------------
    # STYLE
    # --------------------------------------------------------

    def _apply_style(self):

        self.setStyleSheet("""
            QWidget {
                background-color: #11111b;
                color: #e5e7eb;
                font-family: "Segoe UI";
                font-size: 10pt;
            }

            QMainWindow {
                background-color: #11111b;
            }

            #Sidebar {
                background-color: #171725;
                border-right: 1px solid #2b2b40;
            }

            #Logo {
                color: #a78bfa;
                font-size: 22pt;
                font-weight: bold;
            }

            #VersionLabel {
                color: #85859b;
                font-size: 9pt;
            }

            #PageTitle {
                color: #f3f4f6;
                font-size: 22pt;
                font-weight: bold;
            }

            #Subtitle {
                color: #9292a8;
                font-size: 10pt;
            }

            #SectionTitle {
                color: #f3f4f6;
                font-size: 12pt;
                font-weight: bold;
            }

            #InfoCard {
                background-color: #1b1b2b;
                border: 1px solid #303047;
                border-radius: 9px;
            }

            #CardLabel {
                color: #9999ad;
                font-size: 9pt;
            }

            #CardValue {
                color: #a78bfa;
                font-size: 23pt;
                font-weight: bold;
            }

            #Panel {
                background-color: #191927;
                border: 1px solid #303047;
                border-radius: 9px;
            }

            #InfoText {
                color: #b8b8c9;
                font-size: 10pt;
            }

            #StatusLabel {
                color: #a78bfa;
                padding: 5px;
            }

            #PrimaryButton {
                background-color: #7c3aed;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 14px;
                font-weight: bold;
            }

            #PrimaryButton:hover {
                background-color: #8b5cf6;
            }

            #PrimaryButton:disabled {
                background-color: #45405a;
                color: #999;
            }

            #SecondaryButton {
                background-color: #29293b;
                color: #e5e7eb;
                border: 1px solid #3b3b52;
                border-radius: 6px;
                padding: 8px 14px;
            }

            #SecondaryButton:hover {
                background-color: #38384e;
            }

            #SecondaryButton:disabled {
                color: #777;
            }

            #NavigationButton {
                background-color: transparent;
                color: #b5b5c8;
                border: none;
                border-radius: 6px;
                text-align: left;
                padding-left: 12px;
            }

            #NavigationButton:hover {
                background-color: #29293d;
                color: white;
            }

            #NavigationButton[active="true"] {
                background-color: #342653;
                color: #c4b5fd;
                font-weight: bold;
            }

            QTableWidget {
                background-color: #151521;
                alternate-background-color: #1c1c2b;
                color: #e5e7eb;
                border: 1px solid #303047;
                border-radius: 5px;
                gridline-color: #303047;
                selection-background-color: #493477;
                selection-color: white;
            }

            QHeaderView::section {
                background-color: #242438;
                color: #c4b5fd;
                padding: 8px;
                border: none;
                border-bottom: 1px solid #38384e;
                font-weight: bold;
            }

            QTextEdit {
                background-color: #12121d;
                color: #d1d5db;
                border: 1px solid #303047;
                border-radius: 5px;
                padding: 8px;
                selection-background-color: #493477;
            }

            QProgressBar {
                background-color: #29293b;
                border: none;
                border-radius: 4px;
                height: 7px;
                text-align: center;
            }

            QProgressBar::chunk {
                background-color: #8b5cf6;
                border-radius: 4px;
            }

            QStatusBar {
                background-color: #171725;
                color: #9999ad;
            }

            QMessageBox {
                background-color: #191927;
            }

            QSplitter::handle {
                background-color: #303047;
            }
        """)


# ============================================================
# APPLICATION ENTRY
# ============================================================

def main():

    app = QApplication(sys.argv)

    app.setApplicationName(APP_NAME)

    window = MainWindow()
    window.show()

    sys.exit(
        app.exec()
    )


if __name__ == "__main__":
    main()