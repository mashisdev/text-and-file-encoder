import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout,
    QTextEdit, QLineEdit, QFileDialog, QLabel
)
from crypto_utils import encrypt_text, decrypt_text, encrypt_file, decrypt_file

class CryptoApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Encryption Tool")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.passphrase_input = QLineEdit()
        self.passphrase_input.setPlaceholderText("Enter your secret passphrase")

        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("Enter text to encrypt or decrypt")

        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)

        self.encrypt_text_btn = QPushButton("Encrypt Text")
        self.decrypt_text_btn = QPushButton("Decrypt Text")
        self.encrypt_file_btn = QPushButton("Encrypt File")
        self.decrypt_file_btn = QPushButton("Decrypt File")

        self.encrypt_text_btn.clicked.connect(self.handle_encrypt_text)
        self.decrypt_text_btn.clicked.connect(self.handle_decrypt_text)
        self.encrypt_file_btn.clicked.connect(self.handle_encrypt_file)
        self.decrypt_file_btn.clicked.connect(self.handle_decrypt_file)

        layout.addWidget(QLabel("Secret Passphrase"))
        layout.addWidget(self.passphrase_input)
        layout.addWidget(QLabel("Text"))
        layout.addWidget(self.text_input)
        layout.addWidget(self.encrypt_text_btn)
        layout.addWidget(self.decrypt_text_btn)
        layout.addWidget(self.encrypt_file_btn)
        layout.addWidget(self.decrypt_file_btn)
        layout.addWidget(QLabel("Result"))
        layout.addWidget(self.result_output)

        self.setLayout(layout)

    def handle_encrypt_text(self):
        try:
            password = self.passphrase_input.text()
            text = self.text_input.toPlainText()
            encrypted = encrypt_text(text, password)
            self.result_output.setPlainText(encrypted.hex())
        except Exception as e:
            self.result_output.setPlainText(f"Error: {e}")

    def handle_decrypt_text(self):
        try:
            password = self.passphrase_input.text()
            data = bytes.fromhex(self.text_input.toPlainText())
            decrypted = decrypt_text(data, password)
            self.result_output.setPlainText(decrypted)
        except Exception as e:
            self.result_output.setPlainText(f"Error: {e}")

    def handle_encrypt_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a file to encrypt")
        if path:
            try:
                encrypt_file(path, self.passphrase_input.text())
                self.result_output.setPlainText("File encrypted successfully.")
            except Exception as e:
                self.result_output.setPlainText(f"Error: {e}")

    def handle_decrypt_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a file to decrypt")
        if path:
            try:
                decrypt_file(path, self.passphrase_input.text())
                self.result_output.setPlainText("File decrypted successfully.")
            except Exception as e:
                self.result_output.setPlainText(f"Error: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CryptoApp()
    window.show()
    sys.exit(app.exec_())