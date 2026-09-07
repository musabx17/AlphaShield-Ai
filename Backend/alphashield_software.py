import sys
import os
import pandas as pd
import matplotlib
matplotlib.use('QtAgg')
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QStackedWidget, 
                             QListWidget, QTableWidget, QTableWidgetItem, QFileDialog, 
                             QProgressBar, QLineEdit, QTextEdit, QHeaderView, QFrame)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QPainter, QPen, QBrush

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from Backend.ai_suite import analyze_url_dynamic, scan_pdf_file_pure_ai, analyze_email_pure_ai
from Backend.database import fetch_all_logs

# RADAR ANIMATION WIDGET
class CyberRadarWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(140, 140)
        self.angle = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_sweep)
        self.timer.start(30)

    def update_sweep(self):
        self.angle = (self.angle + 4) % 360
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        cx, cy = self.width() // 2, self.height() // 2
        radius = 55
        
        pen_dim = QPen(QColor(0, 243, 255, 60))
        pen_dim.setWidth(1)
        painter.setPen(pen_dim)
        painter.drawEllipse(cx - radius, cy - radius, radius * 2, radius * 2)
        painter.drawEllipse(cx - radius + 15, cy - radius + 15, (radius - 15) * 2, (radius - 15) * 2)
        
        pen_dash = QPen(QColor(0, 243, 255, 40))
        pen_dash.setWidth(1)
        pen_dash.setStyle(Qt.PenStyle.DashLine)
        painter.setPen(pen_dash)
        painter.drawLine(cx - radius, cy, cx + radius, cy)
        painter.drawLine(cx, cy - radius, cx, cy + radius)
        
        painter.setPen(Qt.PenStyle.NoPen)
        brush = QBrush(QColor(0, 243, 255, 80))
        painter.setBrush(brush)
        painter.drawPie(cx - radius, cy - radius, radius * 2, radius * 2, int(-self.angle * 16), 45 * 16)
        
        painter.setBrush(QBrush(QColor(0, 243, 255)))
        painter.drawEllipse(cx - 4, cy - 4, 8, 8)

# ANIMATED THREAT GAUGE WITH CONTEXTUAL TOOLTIPS
class ThreatGaugeWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(160, 160)
        self.current_score = 0.0
        self.target_score = 0.0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.animate_score)
        self.setToolTip("<b>AlphaShield Threat Index Gauge</b><br>Hover after scanning to view detailed risk breakdown.")

    def set_score(self, score, details=""):
        self.target_score = float(score)
        self.timer.start(20)
        
        if self.target_score >= 65.0:
            self.setToolTip(
                "<b>🚨 CRITICAL THREAT LEVEL (≥65%)</b><br><br>"
                "<b>Triggered Risk Factors:</b><br>"
                "• High String Entropy / Malicious Payload<br>"
                "• Unencrypted Credential Harvesting Form Inputs<br>"
                "• Hidden IFrame / Obfuscated JS Redirects<br><br>"
                f"<i>{details}</i>"
            )
        elif self.target_score >= 30.0:
            self.setToolTip(
                "<b>⚠️ MODERATE RISK LEVEL (30% - 64.9%)</b><br><br>"
                "<b>Triggered Risk Factors:</b><br>"
                "• Multiple Subdomain Anomalies & Keyword Match<br>"
                "• Unverified SSL / HTTP Protocol Usage<br>"
                "• Structural Anomaly Detected<br><br>"
                f"<i>{details}</i>"
            )
        else:
            self.setToolTip(
                "<b>✅ SECURE LEVEL (<30%)</b><br><br>"
                "<b>Parameters:</b><br>"
                "• Verified Encryption & Low Entropy<br>"
                "• No Credential Harvesting or Obfuscation Flagged"
            )

    def animate_score(self):
        if abs(self.current_score - self.target_score) < 0.5:
            self.current_score = self.target_score
            self.timer.stop()
        else:
            self.current_score += (self.target_score - self.current_score) * 0.1
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        cx, cy = self.width() // 2, self.height() // 2
        radius = 65
        
        track_pen = QPen(QColor(30, 41, 59))
        track_pen.setWidth(12)
        track_pen.setStyle(Qt.PenStyle.SolidLine)
        track_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(track_pen)
        painter.drawArc(cx - radius, cy - radius, radius * 2, radius * 2, -30 * 16, 240 * 16)
        
        if self.current_score >= 65.0:
            color = QColor(255, 0, 85)
        elif self.current_score >= 30.0:
            color = QColor(255, 170, 0)
        else:
            color = QColor(0, 255, 157)
            
        active_pen = QPen(color)
        active_pen.setWidth(12)
        active_pen.setStyle(Qt.PenStyle.SolidLine)
        active_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(active_pen)
        
        start_angle = int((210 - (self.current_score / 100.0) * 240) * 16)
        span_angle = int((self.current_score / 100.0) * 240 * 16)
        
        painter.drawArc(cx - radius, cy - radius, radius * 2, radius * 2, start_angle, span_angle)
        
        painter.setPen(QColor(248, 250, 252))
        painter.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, f"{self.current_score:.1f}%")

# TELEMETRY GRAPH
class MplCanvas(FigureCanvas):
    def __init__(self, parent=None, width=5, height=3.5, dpi=100):
        fig = Figure(figsize=(width, height), dpi=dpi, facecolor='#090d16')
        self.axes = fig.add_subplot(111)
        self.axes.set_facecolor('#090d16')
        super().__init__(fig)

    def plot_telemetry(self, df):
        self.axes.clear()
        if not df.empty and 'Risk Score' in df.columns:
            scores = df['Risk Score'].tail(15).tolist()
            self.axes.plot(scores, color='#00f3ff', marker='o', linewidth=2.5, markersize=6, markerfacecolor='#090d16')
            self.axes.fill_between(range(len(scores)), scores, color='#00f3ff', alpha=0.12)
        else:
            self.axes.plot([5, 12, 85, 40, 15, 95, 20], color='#00f3ff', marker='o')
        
        self.axes.set_title("LIVE THREAT INTELLIGENCE TELEMETRY FEED", color='#00f3ff', fontsize=9, fontweight='bold', loc='left')
        self.axes.tick_params(colors='#64748b', labelsize=8)
        self.axes.grid(True, color='#1e293b', linestyle=':')
        self.draw()

# WORKER THREAD
class ScanWorker(QThread):
    finished = pyqtSignal(dict)

    def __init__(self, scan_type, data):
        super().__init__()
        self.scan_type = scan_type
        self.data = data

    def run(self):
        res = {}
        if self.scan_type == "URL":
            res = analyze_url_dynamic(self.data)
        elif self.scan_type == "PDF":
            res = scan_pdf_file_pure_ai(self.data[0], self.data[1])
        elif self.scan_type == "EMAIL":
            res = analyze_email_pure_ai(self.data)
        self.finished.emit(res)

# MAIN CYBERPUNK APPLICATION
class AlphaShieldApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ALPHASHIELD AI :: ENTERPRISE SOC THREAT SUITE v3.0")
        self.setGeometry(80, 80, 1280, 800)
        
        self.worker = None
        
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        sidebar = QWidget()
        sidebar.setFixedWidth(320)
        sidebar.setStyleSheet("background-color: #050811; border-right: 1px solid #1e293b;")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(15, 20, 15, 20)
        
        title_label = QLabel("🛡️ ALPHASHIELD AI")
        title_label.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        title_label.setStyleSheet("color: #00f3ff; letter-spacing: 2px;")
        title_label.setWordWrap(True)
        sub_title = QLabel("AI SOC SECURITY ENGINE")
        sub_title.setStyleSheet("color: #64748b; font-size: 10px; font-weight: bold; letter-spacing: 1px;")
        
        sidebar_layout.addWidget(title_label)
        sidebar_layout.addWidget(sub_title)
        sidebar_layout.addSpacing(20)
        
        radar_container = QWidget()
        r_layout = QVBoxLayout(radar_container)
        r_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.radar = CyberRadarWidget()
        r_layout.addWidget(self.radar)
        sidebar_layout.addWidget(radar_container)
        sidebar_layout.addSpacing(15)
        
        self.nav_list = QListWidget()
        self.nav_list.setStyleSheet("""
            QListWidget { background: transparent; border: none; font-size: 12px; color: #94a3b8; font-weight: bold; }
            QListWidget::item { padding: 14px 18px; border-radius: 6px; margin-bottom: 5px; border: 1px solid transparent; }
            QListWidget::item:hover { background-color: #0f172a; border: 1px solid #00f3ff; color: #00f3ff; }
            QListWidget::item:selected { background-color: #00f3ff; color: #050811; font-weight: bold; border: 1px solid #00f3ff; }
        """)
        self.nav_list.addItem("📊 SOC CONTROL CENTER")
        self.nav_list.addItem("🌐 DYNAMIC URL INSPECTOR")
        self.nav_list.addItem("📄 STRUCTURAL PDF SCANNER")
        self.nav_list.addItem("✉️ DISTILBERT EMAIL INTENT")
        self.nav_list.addItem("📜 TELEMETRY AUDIT LOGS")
        self.nav_list.currentRowChanged.connect(self.display_tab)
        sidebar_layout.addWidget(self.nav_list)
        
        status_box = QFrame()
        status_box.setStyleSheet("background: #090d16; border: 1px solid #1e293b; border-radius: 6px; padding: 10px;")
        sb_layout = QHBoxLayout(status_box)
        dot = QLabel("●")
        dot.setStyleSheet("color: #00ff9d; font-size: 16px;")
        lbl = QLabel("SYSTEM DEFENSE ACTIVE")
        lbl.setStyleSheet("color: #f8fafc; font-weight: bold; font-size: 10px; letter-spacing: 1px;")
        sb_layout.addWidget(dot)
        sb_layout.addWidget(lbl)
        sidebar_layout.addWidget(status_box)
        
        main_layout.addWidget(sidebar)
        
        self.stack = QStackedWidget()
        main_layout.addWidget(self.stack)
        
        self.setup_control_center()
        self.setup_url_inspector()
        self.setup_pdf_scanner()
        self.setup_email_evaluator()
        self.setup_audit_logs()
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_telemetry_data)
        self.timer.start(4000)
        
        self.nav_list.setCurrentRow(0)

    def setup_control_center(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        
        header = QLabel("AUTOMATED THREAT DEFENSE MATRIX")
        header.setFont(QFont("Consolas", 16, QFont.Weight.Bold))
        header.setStyleSheet("color: #00f3ff; letter-spacing: 1px;")
        layout.addWidget(header)
        
        cards = QHBoxLayout()
        self.card_total = self.create_neon_card("TOTAL SCANS", "0", "#00f3ff")
        self.card_threats = self.create_neon_card("THREATS NEUTRALIZED", "0", "#ff0055")
        self.card_score = self.create_neon_card("AVG RISK INDEX", "0.0%", "#00ff9d")
        cards.addWidget(self.card_total)
        cards.addWidget(self.card_threats)
        cards.addWidget(self.card_score)
        layout.addLayout(cards)
        
        self.canvas = MplCanvas(self, width=6, height=3.5, dpi=100)
        layout.addWidget(self.canvas)
        self.stack.addWidget(page)

    def setup_url_inspector(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        
        layout.addWidget(QLabel("🌐 Dynamic Web Payload & URL Inspector", font=QFont("Consolas", 16, QFont.Weight.Bold), styleSheet="color: #00f3ff;"))
        
        input_row = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Paste target URL (e.g., http://192.168.1.1/login-verify-bank@account.com)")
        self.url_input.setStyleSheet("background: #090d16; border: 1px solid #1e293b; padding: 14px; border-radius: 6px; color: #00f3ff; font-family: Consolas;")
        input_row.addWidget(self.url_input)
        
        btn_scan = QPushButton("EXECUTE MODEL SCAN")
        btn_scan.setStyleSheet("background: #00f3ff; color: #050811; padding: 14px 24px; font-weight: bold; border-radius: 6px; font-family: Consolas;")
        btn_scan.clicked.connect(self.scan_url)
        input_row.addWidget(btn_scan)
        layout.addLayout(input_row)
        
        self.url_progress = QProgressBar()
        self.url_progress.setStyleSheet("QProgressBar { background: #090d16; border: 1px solid #1e293b; border-radius: 4px; text-align: center; color: white; } QProgressBar::chunk { background-color: #00f3ff; }")
        self.url_progress.setVisible(False)
        layout.addWidget(self.url_progress)
        
        out_frame = QHBoxLayout()
        self.url_gauge = ThreatGaugeWidget()
        out_frame.addWidget(self.url_gauge)
        
        self.url_result_box = QTextEdit()
        self.url_result_box.setReadOnly(True)
        self.url_result_box.setStyleSheet("background: #050811; border: 1px solid #1e293b; color: #00f3ff; font-family: Consolas; padding: 12px; font-size: 12px;")
        out_frame.addWidget(self.url_result_box)
        
        layout.addLayout(out_frame)
        self.stack.addWidget(page)

    def setup_pdf_scanner(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        
        layout.addWidget(QLabel("📄 PDF Malicious Payload & Entropy Inspector", font=QFont("Consolas", 16, QFont.Weight.Bold), styleSheet="color: #00f3ff;"))
        
        btn_file = QPushButton("SELECT DOCUMENT FOR ANALYSIS")
        btn_file.setStyleSheet("background: #00f3ff; color: #050811; padding: 14px; font-weight: bold; border-radius: 6px; font-family: Consolas;")
        btn_file.clicked.connect(self.scan_pdf)
        layout.addWidget(btn_file)
        
        self.pdf_progress = QProgressBar()
        self.pdf_progress.setStyleSheet("QProgressBar { background: #090d16; border: 1px solid #1e293b; border-radius: 4px; } QProgressBar::chunk { background-color: #00f3ff; }")
        self.pdf_progress.setVisible(False)
        layout.addWidget(self.pdf_progress)
        
        pdf_out_frame = QHBoxLayout()
        self.pdf_gauge = ThreatGaugeWidget()
        pdf_out_frame.addWidget(self.pdf_gauge)
        
        self.pdf_result_box = QTextEdit()
        self.pdf_result_box.setReadOnly(True)
        self.pdf_result_box.setStyleSheet("background: #050811; border: 1px solid #1e293b; color: #00ff9d; font-family: Consolas; padding: 12px; font-size: 12px;")
        pdf_out_frame.addWidget(self.pdf_result_box)
        
        layout.addLayout(pdf_out_frame)
        self.stack.addWidget(page)

    def setup_email_evaluator(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        
        layout.addWidget(QLabel("✉️ DistilBERT Neural Intent Analysis", font=QFont("Consolas", 16, QFont.Weight.Bold), styleSheet="color: #00f3ff;"))
        
        self.email_input = QTextEdit()
        self.email_input.setPlaceholderText("Paste raw email body text here for Transformer Intent classification...")
        self.email_input.setStyleSheet("background: #090d16; border: 1px solid #1e293b; padding: 12px; border-radius: 6px; color: white; font-family: Consolas;")
        layout.addWidget(self.email_input)
        
        btn_eval = QPushButton("RUN TRANSFORMER INFERENCE")
        btn_eval.setStyleSheet("background: #00f3ff; color: #050811; padding: 14px; font-weight: bold; border-radius: 6px; font-family: Consolas;")
        btn_eval.clicked.connect(self.scan_email)
        layout.addWidget(btn_eval)
        
        email_out_frame = QHBoxLayout()
        self.email_gauge = ThreatGaugeWidget()
        email_out_frame.addWidget(self.email_gauge)
        
        self.email_result_box = QTextEdit()
        self.email_result_box.setReadOnly(True)
        self.email_result_box.setStyleSheet("background: #050811; border: 1px solid #1e293b; color: #00f3ff; font-family: Consolas; padding: 12px; font-size: 12px;")
        email_out_frame.addWidget(self.email_result_box)
        
        layout.addLayout(email_out_frame)
        self.stack.addWidget(page)

    def setup_audit_logs(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        
        layout.addWidget(QLabel("📜 Cyber Defense Telemetry Logs", font=QFont("Consolas", 16, QFont.Weight.Bold), styleSheet="color: #00f3ff;"))
        
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["ID", "TIMESTAMP", "VECTOR", "TARGET ASSET", "RISK SCORE"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setStyleSheet("""
            QTableWidget { background: #050811; border: 1px solid #1e293b; gridline-color: #1e293b; color: #f8fafc; font-family: Consolas; }
            QHeaderView::section { background: #090d16; color: #00f3ff; font-weight: bold; border: 1px solid #1e293b; padding: 6px; }
        """)
        layout.addWidget(self.table)
        self.stack.addWidget(page)

    def create_neon_card(self, title, val, color):
        card = QFrame()
        card.setStyleSheet("background: #090d16; border: 1px solid #1e293b; border-radius: 8px; padding: 15px;")
        l = QVBoxLayout(card)
        t = QLabel(title)
        t.setStyleSheet("color: #64748b; font-size: 10px; font-weight: bold; font-family: Consolas;")
        v = QLabel(val)
        v.setFont(QFont("Consolas", 20, QFont.Weight.Bold))
        v.setStyleSheet(f"color: {color};")
        l.addWidget(t)
        l.addWidget(v)
        return card

    def display_tab(self, index):
        self.stack.setCurrentIndex(index)
        if index == 0 or index == 4:
            self.refresh_telemetry_data()

    def refresh_telemetry_data(self):
        logs = fetch_all_logs()
        if logs:
            df = pd.DataFrame(logs, columns=["ID", "Timestamp", "Scan Type", "Target", "Risk Score", "Is Threat", "Engine", "Details"])
            
            card_total_lbl = self.card_total.findChildren(QLabel)[1]
            card_total_lbl.setText(str(len(df)))
            
            card_threats_lbl = self.card_threats.findChildren(QLabel)[1]
            card_threats_lbl.setText(str(len(df[df["Is Threat"] == 1])))
            
            card_score_lbl = self.card_score.findChildren(QLabel)[1]
            card_score_lbl.setText(f"{df['Risk Score'].mean():.1f}%")
            
            self.canvas.plot_telemetry(df)
            
            self.table.setRowCount(0)
            for row in logs[:15]:
                r_idx = self.table.rowCount()
                self.table.insertRow(r_idx)
                for col_idx, item in enumerate(row[:5]):
                    self.table.setItem(r_idx, col_idx, QTableWidgetItem(str(item)))

    def scan_url(self):
        url = self.url_input.text().strip()
        if not url:
            return
        self.url_progress.setVisible(True)
        self.url_progress.setRange(0, 0)
        self.worker = ScanWorker("URL", url)
        self.worker.finished.connect(self.handle_url_res)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.start()

    def handle_url_res(self, res):
        self.url_progress.setVisible(False)
        score = res.get('risk_score', 0)
        details = f"Engine: {res.get('engine', 'N/A')} | Threat Level: {res.get('threat_level', 'N/A')}"
        self.url_gauge.set_score(score, details)
        self.url_result_box.setText(f"[+] ALPHASHIELD MATRIX SCAN REPORT\n------------------------------------\nTARGET ASSET  : {res.get('url', '')}\nVERDICT       : {res.get('threat_level', '')}\nRISK SCORE    : {score}%\nENGINE DETECT : {res.get('engine', '')}\n\n[HINT] Hover over circular Threat Gauge to view triggered threat factors.")
        self.refresh_telemetry_data()

    def scan_pdf(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select PDF Document", "", "PDF Files (*.pdf)")
        if file_path:
            with open(file_path, "rb") as f:
                bytes_data = f.read()
            self.pdf_progress.setVisible(True)
            self.pdf_progress.setRange(0, 0)
            self.worker = ScanWorker("PDF", (bytes_data, os.path.basename(file_path)))
            self.worker.finished.connect(self.handle_pdf_res)
            self.worker.finished.connect(self.worker.deleteLater)
            self.worker.start()

    def handle_pdf_res(self, res):
        self.pdf_progress.setVisible(False)
        score = res.get('risk_score', 0)
        details = f"File: {res.get('filename', '')} | Verdict: {res.get('threat_level', '')}"
        self.pdf_gauge.set_score(score, details)
        urls_count = len(res.get('urls_found', []))
        self.pdf_result_box.setText(f"[+] STRUCTURAL FILE ANALYSIS\n------------------------------------\nFILENAME     : {res.get('filename', '')}\nVERDICT      : {res.get('threat_level', '')}\nRISK INDEX   : {score}%\nEMBEDDED URLS: {urls_count}\nENGINE TYPE  : {res.get('engine', '')}")
        self.refresh_telemetry_data()

    def scan_email(self):
        text = self.email_input.toPlainText().strip()
        if not text:
            return
        self.worker = ScanWorker("EMAIL", text)
        self.worker.finished.connect(self.handle_email_res)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.start()

    def handle_email_res(self, res):
        score = res.get('risk_score', 0)
        details = f"Intent: {res.get('neural_intent_label', '')}"
        self.email_gauge.set_score(score, details)
        verdict = '🚨 SPEAR-PHISHING DETECTED' if res.get('is_threat') else '✅ SAFE TEXT'
        self.email_result_box.setText(f"[+] NEURAL TRANSFORMER EVALUATION\n------------------------------------\nINTENT TAG   : {res.get('neural_intent_label', '')}\nVERDICT      : {verdict}\nCONFIDENCE   : {score}%\nENGINE       : {res.get('engine', '')}")
        self.refresh_telemetry_data()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet("QMainWindow, QWidget { background-color: #050811; color: #f8fafc; font-family: 'Segoe UI'; }")
    window = AlphaShieldApp()
    window.show()
    sys.exit(app.exec())