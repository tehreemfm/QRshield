from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit,
    QFileDialog, QScrollArea, QMessageBox, QHBoxLayout
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import sys
import os
from url_checker import sus_url
from pyzbar.pyzbar import decode
from PIL import Image

class QRWorker(QThread):
    result_ready = pyqtSignal(str)

    def __init__(self, image_paths):
        super().__init__()
        self.image_paths = image_paths

    def run(self):
        for image_path in self.image_paths:
            try:
                img = Image.open(image_path)
                decoded_objs = decode(img)

                if decoded_objs:
                    for obj in decoded_objs:
                        url = obj.data.decode('utf-8')
                        result = sus_url(url)
                        display_text = f"\nImage: {os.path.basename(image_path)}\nURL: {url}\nRisk: {result['risk']}\nReasons: " + ", ".join(result['reasons']) + "\n"
                        self.result_ready.emit(display_text)
                else:
                    self.result_ready.emit(f"\nImage: {os.path.basename(image_path)}\nNo QR code detected.\n")
            except Exception as e:
                self.result_ready.emit(f"\nImage: {os.path.basename(image_path)}\nError: {str(e)}\n")

class QRCheckerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("QRShield — Phishing Risk Detector")
        self.setGeometry(100, 100, 800, 500)
        self.setStyleSheet("background-color: #f4f7f9;")

        layout = QVBoxLayout()
        self.setLayout(layout)

        title = QLabel("QRShield: QR Code Phishing Detector")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #2c3e50; margin-bottom: 10px;")
        title.setAlignment(Qt.AlignCenter)

        layout.addWidget(title)

        button_layout = QHBoxLayout()
        self.select_btn = QPushButton("Select Image(s)")
        self.select_btn.setFont(QFont("Arial", 11))
        self.select_btn.setStyleSheet("background-color: #2980b9; color: white; padding: 8px; border-radius: 5px;")
        self.select_btn.clicked.connect(self.select_images)

        self.clear_btn = QPushButton("Clear Log")
        self.clear_btn.setFont(QFont("Arial", 11))
        self.clear_btn.setStyleSheet("background-color: #c0392b; color: white; padding: 8px; border-radius: 5px;")
        self.clear_btn.clicked.connect(self.clear_log)

        button_layout.addWidget(self.select_btn)
        button_layout.addWidget(self.clear_btn)
        layout.addLayout(button_layout)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setFont(QFont("Consolas", 10))
        self.log_area.setStyleSheet("""
            QTextEdit {
                background-color: #ecf0f1;
                border: 1px solid #bdc3c7;
                padding: 10px;
            }
        """)
        layout.addWidget(self.log_area)

    def select_images(self):
        file_paths, _ = QFileDialog.getOpenFileNames(
            self, "Select Image Files", "", "Images (*.png *.jpg *.jpeg *.bmp)"
        )
        if file_paths:
            self.worker = QRWorker(file_paths)
            self.worker.result_ready.connect(self.append_log)
            self.worker.start()

    def append_log(self, text):
        self.log_area.append(text)

    def clear_log(self):
        self.log_area.clear()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = QRCheckerApp()
    window.show()
    sys.exit(app.exec_())
