import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit
from base64 import b64encode, b64decode

class RSACryptoApp(QWidget):
    def __init__(self):
        super().__init__()
        self.p = 13
        self.q = 29
        self.n = self.p * self.q
        self.tot = (self.p - 1) * (self.q - 1)
        self.e = self.generate_public_key()
        self.d = self.generate_private_key()
        self.initUI()

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

    def gcd(self, a, b):
        while b != 0:
            a, b = b, a % b
        return a

    def generate_public_key(self):
        e = 2
        while e < self.tot and self.gcd(e, self.tot) != 1:
            e += 1
        return e

    def generate_private_key(self):
        d = 1
        while (self.e * d) % self.tot != 1 or d == self.e:
            d += 1
        return d

    def encrypt_text(self):
        plain_text = self.input_text.text()
        encrypted_text = self.encrypt(plain_text)
        encrypted_text = b64encode(encrypted_text.encode('utf-8')).decode('utf-8')
        self.encrypted_text.setPlainText(encrypted_text)

    def decrypt_text(self):
        encrypted_text = self.encrypted_text.toPlainText()
        encrypted_bytes = b64decode(encrypted_text)
        decrypted_text = self.decrypt(encrypted_bytes.decode('utf-8'))
        self.decrypted_text.setPlainText(decrypted_text)

    def encrypt(self, plain_text):
        cipher_text = [chr((ord(char) ** self.e) % self.n) for char in plain_text]
        return ''.join(cipher_text)

    def decrypt(self, cipher_text):
        plain_text = [chr((ord(char) ** self.d) % self.n) for char in cipher_text]
        return ''.join(plain_text)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = RSACryptoApp()
    sys.exit(app.exec_())
