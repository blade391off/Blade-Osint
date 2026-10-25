import json
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal, Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QComboBox, QTextBrowser, QFileDialog, QMessageBox, QProgressBar,
    QSplitter
)

from sources import collect
from report_export import save_html
from relationship_graph import RelationshipGraph


STYLES = """
QMainWindow, QWidget { background: #0b0e14; color: #e5edf9; font-family: Segoe UI; }
QLineEdit, QComboBox { background: #111722; color: #e5edf9; border: 1px solid #293448; border-radius: 8px; padding: 10px; }
QPushButton { background: #202a39; color: #e5edf9; border: 1px solid #344258; border-radius: 8px; padding: 9px 14px; }
QPushButton:hover { background: #2b394d; }
QPushButton#primary { background: #38d6a3; color: #07120f; font-weight: 700; border: 0; }
QTextBrowser { background: #111722; color: #dce6f5; border: 1px solid #293448; border-radius: 10px; padding: 12px; }
QProgressBar { background: #171e2a; border: 0; border-radius: 4px; height: 7px; }
QProgressBar::chunk { background: #38d6a3; border-radius: 4px; }
"""


class Worker(QObject):
    finished = Signal(list)
    failed = Signal(str)

    def __init__(self, target, kind):
        super().__init__()
        self.target = target
        self.kind = kind

    def run(self):
        try:
            self.finished.emit(collect(self.target, self.kind))
        except Exception as exc:
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BLADE OSINT 3.0")
        self.resize(1250, 820)
        self.setMinimumSize(900, 620)
        self.setStyleSheet(STYLES)
        self.results = []
        self.worker_thread = None
        self.graph_window = None

        heading = QLabel("BLADE OSINT")
        heading.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        heading.setStyleSheet("color: #38d6a3;")
        subtitle = QLabel("Public-source intelligence and investigation workspace")
        subtitle.setStyleSheet("color: #94a3b8;")

        self.target = QLineEdit()
        self.target.setPlaceholderText("Enter a domain, URL, IP, email, phone, hash, or search term")
        self.kind = QComboBox()
        self.kind.addItem("Domain", "domain")
        self.kind.addItem("URL", "url")
        self.kind.addItem("IP address", "ip")
        self.kind.addItem("Email", "email")
        self.kind.addItem("Phone", "phone")
        self.kind.addItem("File hash", "hash")
        self.kind.addItem("Name / username", "search")

        self.scan_button = QPushButton("Run investigation")
        self.scan_button.setObjectName("primary")
        self.scan_button.clicked.connect(self.start_investigation)
        self.status = QLabel("Ready")
        self.status.setStyleSheet("color: #94a3b8;")
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)

        self.results_view = QTextBrowser()
        self.results_view.setOpenExternalLinks(True)
        self.results_view.setPlaceholderText("Investigation results will appear here.")

        self.copy_button = QPushButton("Copy JSON")
        self.copy_button.clicked.connect(self.copy_json)
        self.txt_button = QPushButton("Export JSON")
        self.txt_button.clicked.connect(self.export_json)
        self.html_button = QPushButton("Export HTML report")
        self.html_button.clicked.connect(self.export_html)
        self.graph_button = QPushButton("Open relationship graph")
        self.graph_button.clicked.connect(self.open_graph)

        controls = QHBoxLayout()
        controls.addWidget(self.target, 4)
        controls.addWidget(self.kind, 1)
        controls.addWidget(self.scan_button)

        actions = QHBoxLayout()
        actions.addWidget(self.copy_button)
        actions.addWidget(self.txt_button)
        actions.addWidget(self.html_button)
        actions.addWidget(self.graph_button)
        actions.addStretch()

        root = QVBoxLayout()
        root.setContentsMargins(22, 20, 22, 20)
        root.setSpacing(12)
        root.addWidget(heading)
        root.addWidget(subtitle)
        root.addLayout(controls)
        root.addWidget(self.status)
        root.addWidget(self.progress)
        root.addWidget(self.results_view, 1)
        root.addLayout(actions)

        container = QWidget()
        container.setLayout(root)
        self.setCentralWidget(container)

    def start_investigation(self):
        target = self.target.text().strip()
        if not target:
            QMessageBox.warning(self, "Missing target", "Enter a target to investigate.")
            return
        self.scan_button.setEnabled(False)
        self.progress.setRange(0, 0)
        self.status.setText("Collecting public-source data…")
        self.results_view.clear()

        self.worker_thread = QThread(self)
        self.worker = Worker(target, self.kind.currentData())
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_finished)
        self.worker.failed.connect(self.on_failed)
        self.worker.finished.connect(self.worker_thread.quit)
        self.worker.failed.connect(self.worker_thread.quit)
        self.worker_thread.finished.connect(self.worker_thread.deleteLater)
        self.worker_thread.start()

    def on_finished(self, results):
        self.results = results
        self.scan_button.setEnabled(True)
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        self.status.setText(f"Completed · {len(results)} source results")
        self.render_results()

    def on_failed(self, message):
        self.scan_button.setEnabled(True)
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.status.setText("Investigation failed")
        QMessageBox.critical(self, "Investigation error", message)

    def render_results(self):
        cards = []
        for item in self.results:
            source = item.get("source", "Source")
            status = item.get("status", "unknown")
            summary = item.get("summary", "")
            details = json.dumps(item.get("details", {}), indent=2, ensure_ascii=False)
            url = item.get("url", "")
            link = f'<p><a href="{url}">{url}</a></p>' if url else ""
            cards.append(
                f'<section style="background:#171e2a;border:1px solid #293448;'
                f'border-radius:10px;padding:14px;margin:10px 0;">'
                f'<h3 style="color:#38d6a3;">{source}</h3>'
                f'<p><b>Status:</b> {status}</p><p>{summary}</p>{link}'
                f'<pre style="white-space:pre-wrap;overflow-wrap:anywhere;">{details}</pre></section>'
            )
        self.results_view.setHtml("".join(cards) or "No results.")

    def copy_json(self):
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(json.dumps(self.results, indent=2, ensure_ascii=False))
        self.status.setText("JSON copied to clipboard")

    def export_json(self):
        if not self.results:
            QMessageBox.information(self, "No data", "Run an investigation first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "blade-osint-report.json", "JSON files (*.json)")
        if path:
            Path(path).write_text(json.dumps(self.results, indent=2, ensure_ascii=False), encoding="utf-8")
            self.status.setText(f"Saved {path}")

    def export_html(self):
        if not self.results:
            QMessageBox.information(self, "No data", "Run an investigation first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export HTML report", "blade-osint-report.html", "HTML files (*.html)")
        if path:
            save_html(self.target.text().strip(), self.kind.currentData(), self.results, path)
            self.status.setText(f"Saved {path}")

    def open_graph(self):
        if not self.results:
            QMessageBox.information(self, "No data", "Run an investigation first.")
            return
        self.graph_window = RelationshipGraph(self.target.text().strip(), self.results, self)
        self.graph_window.show()
