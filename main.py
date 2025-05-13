import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit,
    QLineEdit, QFileDialog, QTabWidget, QHBoxLayout
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
from crypto_utils import encrypt_text, decrypt_text, encrypt_file, decrypt_file


class CryptoApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 Text & File Encoder")
        self.setGeometry(100, 100, 800, 500)
        self.setStyleSheet("background-color: #1e1e2f; color: white;")

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: 0; }
            QTabBar::tab { background: #2e2e3e; color: white; padding: 10px; font-size: 16px; }
            QTabBar::tab:selected { background: #3e3e5e; }
        """)

        self.tabs.addTab(self.create_text_tab(), "📝 Text with Secret")
        self.tabs.addTab(self.create_file_tab(), "📁 File Encryption")

        layout = QVBoxLayout()
        layout.addWidget(self.tabs)
        self.setLayout(layout)

    def create_text_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("Enter your text here...")
        self.text_input.setStyleSheet("background-color: #2b2b3b; color: white; font-size: 16px; padding: 10px;")

        self.secret_input = QLineEdit()
        self.secret_input.setPlaceholderText("Enter secret phrase...")
        self.secret_input.setStyleSheet("background-color: #2b2b3b; color: white; font-size: 16px; padding: 5px;")

        encrypt_btn = QPushButton("🔐 Encrypt")
        encrypt_btn.clicked.connect(self.handle_encrypt_text)
        decrypt_btn = QPushButton("🔓 Decrypt")
        decrypt_btn.clicked.connect(self.handle_decrypt_text)
        for btn in (encrypt_btn, decrypt_btn):
            btn.setStyleSheet("background-color: #4e4e7e; padding: 10px; font-size: 16px;")

        btn_layout = QHBoxLayout()
        btn_layout.addWidget(encrypt_btn)
        btn_layout.addWidget(decrypt_btn)

        self.result_label = QTextEdit()
        self.result_label.setReadOnly(True)
        self.result_label.setStyleSheet("background-color: #2b2b3b; color: white; font-size: 16px; padding: 10px;")

        layout.addWidget(QLabel("Text:"))
        layout.addWidget(self.text_input)
        layout.addWidget(QLabel("Secret Phrase:"))
        layout.addWidget(self.secret_input)
        layout.addLayout(btn_layout)
        layout.addWidget(QLabel("Result:"))
        layout.addWidget(self.result_label)

        tab.setLayout(layout)
        return tab

    def create_file_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        encrypt_file_btn = QPushButton("📂 Select File to Encrypt")
        encrypt_file_btn.clicked.connect(self.select_file_to_encrypt)

        decrypt_file_btn = QPushButton("📂 Select File to Decrypt")
        decrypt_file_btn.clicked.connect(self.select_file_to_decrypt)

        for btn in (encrypt_file_btn, decrypt_file_btn):
            btn.setStyleSheet("background-color: #4e4e7e; padding: 10px; font-size: 16px;")

        self.file_status = QLabel("")
        self.file_status.setWordWrap(True)
        self.file_status.setStyleSheet("font-size: 14px; margin-top: 10px;")

        layout.addWidget(encrypt_file_btn)
        layout.addWidget(decrypt_file_btn)
        layout.addWidget(self.file_status)

        tab.setLayout(layout)
        return tab

    def handle_encrypt_text(self):
        text = self.text_input.toPlainText()
        secret = self.secret_input.text()
        try:
            if text and secret:
                encrypted = encrypt_text(text, secret)
                self.result_label.setText(encrypted.hex())
            else:
                self.result_label.setText("⚠️ Please provide both text and a secret.")
        except Exception as e:
            self.result_label.setText(f"❌ Error: {e}")

    def handle_decrypt_text(self):
        hex_text = self.text_input.toPlainText()
        secret = self.secret_input.text()
        try:
            if hex_text and secret:
                decrypted = decrypt_text(bytes.fromhex(hex_text), secret)
                self.result_label.setText(decrypted)
            else:
                self.result_label.setText("⚠️ Please provide both encrypted text and a secret.")
        except Exception as e:
            self.result_label.setText(f"❌ Error: {e}")

    def select_file_to_encrypt(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select file to encrypt")
        if file_path:
            try:
                encrypt_file(file_path, self.secret_input.text())
                self.file_status.setText("✅ File encrypted successfully.")
            except Exception as e:
                self.file_status.setText(f"❌ Error: {e}")

    def select_file_to_decrypt(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select file to decrypt")
        if file_path:
            try:
                decrypt_file(file_path, self.secret_input.text())
                self.file_status.setText("✅ File decrypted successfully.")
            except Exception as e:
                self.file_status.setText(f"❌ Error: {e}")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = CryptoApp()
    window.show()
    sys.exit(app.exec_())