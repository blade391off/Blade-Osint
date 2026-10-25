import ipaddress
import math
import re

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QPainter, QPen, QFont
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QComboBox, QTextBrowser, QGraphicsScene, QGraphicsView,
    QGraphicsEllipseItem, QGraphicsLineItem, QGraphicsTextItem, QSplitter
)

COLORS = {
    "target": "#38d6a3", "domain": "#6c91ff", "ip": "#f0a35e",
    "certificate": "#bb8af7", "organization": "#f078a5",
    "nameserver": "#52c7d9", "other": "#7e8da8",
}


def detect_type(value):
    value = str(value).strip()
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if value.lower().startswith(("http://", "https://")):
        return "domain"
    if " " not in value and "." in value and "/" not in value and re.fullmatch(r"[A-Za-z0-9._-]+", value):
        return "domain"
    return "other"


class GraphView(QGraphicsView):
    def __init__(self, scene, parent=None):
        super().__init__(scene, parent)
        self.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.TextAntialiasing)
        self.setBackgroundBrush(QBrush(QColor("#0b0e14")))
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.setFrameShape(QGraphicsView.Shape.NoFrame)

    def wheelEvent(self, event):
        self.scale(1.15 if event.angleDelta().y() > 0 else 1 / 1.15,
                   1.15 if event.angleDelta().y() > 0 else 1 / 1.15)


class RelationshipGraph(QMainWindow):
    def __init__(self, target, results, parent=None):
        super().__init__(parent)
        self.setWindowTitle("BLADE OSINT — Relationship Graph")
        self.resize(1250, 820)
        self.target, self.results = str(target), results or []
        self.nodes, self.node_details, self.node_types = {}, {}, {}
        self.edges, self.positions, self.node_items = [], {}, {}
        self.node_labels, self.edge_items = [], []
        self.scene = QGraphicsScene(self)
        self.view = GraphView(self.scene)
        self.info = QTextBrowser()
        self.info.setOpenExternalLinks(True)
        self.info.setMinimumWidth(270)
        self.info.setStyleSheet("QTextBrowser{background:#111722;color:#dce6f5;border:1px solid #293448;border-radius:10px;padding:10px;}")
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter nodes…")
        self.search.textChanged.connect(self.apply_filter)
        self.type_filter = QComboBox()
        self.type_filter.addItems(["All types", "Domains", "IP addresses", "Certificates", "Organizations", "Other"])
        self.type_filter.currentTextChanged.connect(self.apply_filter)
        self.build_data()
        self.layout_graph()
        self.draw_graph()
        title = QLabel("RELATIONSHIP GRAPH")
        title.setStyleSheet("color:#e8eef8;font-size:18px;font-weight:700;")
        subtitle = QLabel("Mouse wheel: zoom · Drag: pan · Select a node to inspect its relationships")
        subtitle.setStyleSheet("color:#94a3b8;font-size:11px;")
        self.count_label = QLabel(f"Nodes: {len(self.nodes)} · Edges: {len(self.edges)}")
        self.count_label.setStyleSheet("color:#aab5c6;")
        self.fit_button = QPushButton("Fit graph")
        self.fit_button.clicked.connect(self.fit_graph)
        self.reset_button = QPushButton("Reset zoom")
        self.reset_button.clicked.connect(self.reset_view)
        controls = QHBoxLayout()
        controls.addWidget(self.search, 2)
        controls.addWidget(self.type_filter, 1)
        controls.addWidget(self.count_label)
        controls.addWidget(self.fit_button)
        controls.addWidget(self.reset_button)
        top = QVBoxLayout()
        top.setContentsMargins(14, 12, 14, 8)
        top.addWidget(title)
        top.addWidget(subtitle)
        top.addLayout(controls)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.view)
        splitter.addWidget(self.info)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)
        root = QVBoxLayout()
        root.setContentsMargins(0, 0, 0, 0)
        root.addLayout(top)
        root.addWidget(splitter)
        container = QWidget()
        container.setLayout(root)
        container.setStyleSheet("background:#0b0e14;color:#e5edf9;")
        self.setCentralWidget(container)
        self.scene.selectionChanged.connect(self.show_selected_node)
        self.fit_graph()
        if self.target in self.node_items:
            self.node_items[self.target].setSelected(True)
            self.show_node(self.target)

    def add_node(self, label, details=None, node_type=None):
        label = str(label).strip()
        if not label or len(label) > 300:
            return None
        if label not in self.nodes:
            self.nodes[label] = True
            self.node_details[label] = {}
            self.node_types[label] = "target" if label == self.target else (node_type or detect_type(label))
        if isinstance(details, dict):
            self.node_details[label].update({str(k): v for k, v in details.items() if v not in (None, "", [], {})})
        return label

    def add_edge(self, first, second, relation, source=""):
        if not first or not second or first == second or first not in self.nodes or second not in self.nodes:
            return
        edge = (first, second, str(relation), str(source))
        if edge not in self.edges:
            self.edges.append(edge)

    def add_relation(self, value, relation, source, details=None, node_type=None):
        if value is None or isinstance(value, (dict, list, tuple, set)):
            return
        label = str(value).strip().strip("\"'")
        if not label or len(label) > 300 or label == self.target:
            return
        self.add_node(label, details, node_type)
        self.add_edge(self.target, label, relation, source)

    def build_data(self):
        self.add_node(self.target, {"description": "Original investigation target"}, "target")
        for item in self.results:
            if not isinstance(item, dict):
                continue
            source, status = str(item.get("source", "Source")), str(item.get("status", "unknown"))
            details = item.get("details", {})
            if status not in ("success", "partial") or not isinstance(details, dict):
                continue
            for key, relation in (("hostname", "Host name"), ("domain", "Domain"), ("ip", "IP address")):
                self.add_relation(details.get(key), relation, source)
            records = details.get("records", {})
            if isinstance(records, dict):
                for record_type, values in records.items():
                    if not isinstance(values, (list, tuple)):
                        continue
                    for value in values:
                        text = str(value).strip()
                        if record_type == "MX":
                            parts = text.split()
                            text = parts[-1] if parts else text
                        self.add_relation(text.rstrip("."), f"DNS {record_type}", source,
                                          node_type="nameserver" if record_type == "NS" else None)
            for key in ("name_servers", "nameservers", "aliases", "dns_names"):
                values = details.get(key, [])
                if isinstance(values, str):
                    values = [values]
                if isinstance(values, (list, tuple, set)):
                    for value in values:
                        self.add_relation(str(value).rstrip("."), key.replace("_", " ").title(), source,
                                          node_type="nameserver" if "server" in key else None)
            for key, relation in (("registrar", "Registrar"), ("org", "WHOIS organization"),
                                  ("organization", "Organization"), ("asn", "ASN"), ("isp", "Network provider")):
                value = details.get(key)
                if value and not isinstance(value, (dict, list, tuple)):
                    self.add_relation(value, relation, source,
                                      node_type="organization" if key in ("org", "organization", "isp") else None)
            connection = details.get("connection")
            if isinstance(connection, dict):
                for key in ("asn", "org", "isp", "domain"):
                    self.add_relation(connection.get(key), f"Network {key.upper()}", source,
                                      node_type="organization" if key in ("org", "isp") else None)
            fingerprint = details.get("certificate_sha256")
            if fingerprint:
                self.add_relation(fingerprint, "TLS certificate SHA-256", source, node_type="certificate")
            for key in ("issuer", "subject"):
                if details.get(key):
                    self.add_relation(str(details[key])[:180], "TLS " + key, source, node_type="certificate")
            if source == "Certificate Transparency":
                for hostname in details.get("subdomains", []):
                    self.add_relation(hostname, "Name in Certificate Transparency", source)
                for cert in details.get("certificates", []):
                    if isinstance(cert, dict):
                        cert_id = cert.get("id") or str(cert.get("fingerprint", ""))[:24]
                        self.add_relation("CT certificate " + str(cert_id), "Certificate Transparency record",
                                          source, cert, "certificate")
            data = details.get("data")
            if isinstance(data, dict):
                for key in ("host", "hostname", "domain", "ip", "query"):
                    value = data.get(key)
                    if value and not isinstance(value, (dict, list, tuple)):
                        self.add_relation(value, key, source)
        if len(self.nodes) > 100:
            keep = {self.target}
            edges = []
            for edge in self.edges:
                if len(keep) >= 100:
                    break
                keep.update(edge[:2])
                edges.append(edge)
            self.nodes = {k: True for k in keep}
            self.node_details = {k: self.node_details[k] for k in keep}
            self.node_types = {k: self.node_types[k] for k in keep}
            self.edges = edges

    def layout_graph(self):
        labels = list(self.nodes)
        if not labels:
            return
        if len(labels) == 1:
            self.positions = {labels[0]: (0, 0)}
            return
        count = len(labels)
        positions = {}
        for i, label in enumerate(labels):
            if label == self.target:
                positions[label] = [0.0, 0.0]
            else:
                angle = 2 * math.pi * i / max(1, count - 1)
                radius = 240 + 40 * (i % 4)
                positions[label] = [math.cos(angle) * radius, math.sin(angle) * radius]
        ideal = max(120.0, math.sqrt(count) * 85)
        for step in range(100):
            forces = {label: [0.0, 0.0] for label in labels}
            for i, first in enumerate(labels):
                for second in labels[i + 1:]:
                    dx = positions[first][0] - positions[second][0]
                    dy = positions[first][1] - positions[second][1]
                    distance = max(1.0, math.hypot(dx, dy))
                    force = ideal * ideal / distance
                    fx, fy = dx / distance * force, dy / distance * force
                    forces[first][0] += fx
                    forces[first][1] += fy
                    forces[second][0] -= fx
                    forces[second][1] -= fy
            for first, second, _, _ in self.edges:
                if first not in positions or second not in positions:
                    continue
                dx = positions[first][0] - positions[second][0]
                dy = positions[first][1] - positions[second][1]
                distance = max(1.0, math.hypot(dx, dy))
                force = distance * distance / ideal
                fx, fy = dx / distance * force, dy / distance * force
                forces[first][0] -= fx
                forces[first][1] -= fy
                forces[second][0] += fx
                forces[second][1] += fy
            temperature = max(1.0, 65 * (1 - step / 105))
            for label in labels:
                if label == self.target:
                    positions[label] = [0.0, 0.0]
                    continue
                fx, fy = forces[label]
                magnitude = max(1.0, math.hypot(fx, fy))
                scale = min(magnitude, temperature) / magnitude
                positions[label][0] += fx * scale
                positions[label][1] += fy * scale
        self.positions = {k: (v[0], v[1]) for k, v in positions.items()}

    def draw_graph(self):
        self.scene.clear()
        self.node_items.clear()
        self.node_labels.clear()
        self.edge_items.clear()
        for first, second, relation, source in self.edges:
            if first not in self.positions or second not in self.positions:
                continue
            x1, y1 = self.positions[first]
            x2, y2 = self.positions[second]
            line = QGraphicsLineItem(x1, y1, x2, y2)
            line.setPen(QPen(QColor("#344258"), 1.5))
            line.setZValue(-5)
            line.setToolTip(f"{first}\n{relation}\n{second}\nSource: {source}")
            self.scene.addItem(line)
            self.edge_items.append((line, first, second))
            if len(self.nodes) <= 40:
                label = QGraphicsTextItem(relation)
                label.setDefaultTextColor(QColor("#8292aa"))
                label.setFont(QFont("Segoe UI", 8))
                label.setPos((x1 + x2) / 2 + 4, (y1 + y2) / 2 + 3)
                label.setZValue(-1)
                label.setAcceptedMouseButtons(Qt.MouseButton.NoButton)
                self.scene.addItem(label)
        for label, (x, y) in self.positions.items():
            node_type = self.node_types.get(label, "other")
            radius = 32 if label == self.target else 25
            circle = QGraphicsEllipseItem(x-radius, y-radius, radius*2, radius*2)
            circle.setBrush(QBrush(QColor(COLORS.get(node_type, COLORS["other"]))))
            circle.setPen(QPen(QColor("#e4ecf8"), 1.4))
            circle.setFlag(QGraphicsEllipseItem.GraphicsItemFlag.ItemIsSelectable, True)
            circle.setData(0, label)
            circle.setZValue(2)
            circle.setToolTip(label)
            self.scene.addItem(circle)
            self.node_items[label] = circle
            text = QGraphicsTextItem(label)
            text.setDefaultTextColor(QColor("#e5edf9"))
            text.setFont(QFont("Segoe UI", 9))
            text.setTextWidth(180)
            text.setPos(x-90, y+radius+5)
            text.setZValue(3)
            text.setData(0, label)
            text.setAcceptedMouseButtons(Qt.MouseButton.NoButton)
            self.scene.addItem(text)
            self.node_labels.append((text, label))

    def apply_filter(self, *args):
        query = self.search.text().casefold().strip()
        type_map = {"Domains": "domain", "IP addresses": "ip", "Certificates": "certificate",
                    "Organizations": "organization", "Other": "other"}
        selected = self.type_filter.currentText()
        wanted = type_map.get(selected)
        for label, item in self.node_items.items():
            visible = query in label.casefold() and (selected == "All types" or label == self.target or self.node_types.get(label) == wanted)
            item.setVisible(visible)
        for text, label in self.node_labels:
            text.setVisible(self.node_items[label].isVisible())
        for line, first, second in self.edge_items:
            line.setVisible(self.node_items[first].isVisible() and self.node_items[second].isVisible())

    def fit_graph(self):
        rect = self.scene.itemsBoundingRect().adjusted(-100, -100, 100, 100)
        if not rect.isEmpty():
            self.view.fitInView(rect, Qt.AspectRatioMode.KeepAspectRatio)

    def reset_view(self):
        self.view.resetTransform()
        self.fit_graph()

    def show_selected_node(self):
        for item in self.scene.selectedItems():
            label = item.data(0)
            if label in self.node_details:
                self.show_node(label)
                return

    def show_node(self, label):
        details = self.node_details.get(label, {})
        related = []
        for first, second, relation, source in self.edges:
            if first == label:
                related.append((second, relation, source))
            elif second == label:
                related.append((first, relation, source))
        parts = [f"<h2 style='color:{COLORS.get(self.node_types.get(label), COLORS['other'])}'>{label}</h2>",
                 f"<p><b>Type:</b> {self.node_types.get(label, 'other')}</p>",
                 f"<p><b>Relationships:</b> {len(related)}</p><hr><h3>Connected nodes</h3>"]
        for name, relation, source in related:
            parts.append(f"<p><b>{name}</b><br>{relation}<br><small>Source: {source}</small></p>")
        parts.append("<hr><h3>Node details</h3>")
        for key, value in details.items():
            parts.append(f"<p><b>{key}</b><br>{str(value)[:1500]}</p>")
        self.info.setHtml("".join(parts))
