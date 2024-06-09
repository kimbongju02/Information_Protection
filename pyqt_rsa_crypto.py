import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

class RSACryptoApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.generate_keys()

    def initUI(self):
        self.layout = QVBoxLayout()

        self.input_label = QLabel('암호화할 문구를 입력하세요:')
        self.layout.addWidget(self.input_label)

        self.input_text = QLineEdit()
        self.layout.addWidget(self.input_text)

        self.encrypt_button = QPushButton('암호화')
        self.encrypt_button.clicked.connect(self.encrypt_text)
        self.layout.addWidget(self.encrypt_button)

        self.encrypted_label = QLabel('암호화된 문구:')
        self.layout.addWidget(self.encrypted_label)

        self.encrypted_text = QTextEdit()
        self.encrypted_text.setReadOnly(True)
        self.layout.addWidget(self.encrypted_text)

        self.decrypt_button = QPushButton('복호화')
        self.decrypt_button.clicked.connect(self.decrypt_text)
        self.layout.addWidget(self.decrypt_button)

        self.decrypted_label = QLabel('복호화된 문구:')
        self.layout.addWidget(self.decrypted_label)

        self.decrypted_text = QTextEdit()
        self.decrypted_text.setReadOnly(True)
        self.layout.addWidget(self.decrypted_text)

        self.setLayout(self.layout)
        self.setWindowTitle('RSA 암호화/복호화')
        self.setGeometry(300, 300, 400, 300)
        self.show()

    def generate_keys(self):
        self.key = RSA.generate(2048)
        self.private_key = self.key
        self.public_key = self.key.publickey()

    def encrypt_text(self):
        plain_text = self.input_text.text()
        cipher = PKCS1_OAEP.new(self.public_key)
        encrypted_bytes = cipher.encrypt(plain_text.encode('utf-8'))
        encrypted_text = b64encode(encrypted_bytes).decode('utf-8')
        self.encrypted_text.setPlainText(encrypted_text)

    def decrypt_text(self):
        encrypted_text = self.encrypted_text.toPlainText()
        encrypted_bytes = b64decode(encrypted_text)
        cipher = PKCS1_OAEP.new(self.private_key)
        decrypted_bytes = cipher.decrypt(encrypted_bytes)
        decrypted_text = decrypted_bytes.decode('utf-8')
        self.decrypted_text.setPlainText(decrypted_text)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = RSACryptoApp()
    sys.exit(app.exec_())
