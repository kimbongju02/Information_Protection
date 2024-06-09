import sys
import os
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

class RSACryptoApp(QWidget):
    def __init__(self):
        super().__init__()
        self.private_key, self.public_key = self.generate_keys()
        self.initUI()

    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt_with_aes(self, data, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encrypted_data

    def decrypt_with_aes(self, encrypted_data, key):
        iv = encrypted_data[:16]
        encrypted_data = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        return decrypted_data

    def encrypt_hybrid(self, public_key, data):
        aes_key = os.urandom(32)  # 256비트 AES 키 생성
        encrypted_data = self.encrypt_with_aes(data, aes_key)
        
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key + encrypted_data

    def decrypt_hybrid(self, private_key, encrypted_data):
        encrypted_key = encrypted_data[:256]
        encrypted_aes_data = encrypted_data[256:]
        
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        decrypted_data = self.decrypt_with_aes(encrypted_aes_data, aes_key)
        return decrypted_data

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

    def encrypt_text(self):
        plaintext = self.input_text.text().encode()
        encrypted_data = self.encrypt_hybrid(self.public_key, plaintext)
        self.encrypted_text.setPlainText(encrypted_data.hex())

    def decrypt_text(self):
        encrypted_data = bytes.fromhex(self.encrypted_text.toPlainText())
        decrypted_data = self.decrypt_hybrid(self.private_key, encrypted_data)
        self.decrypted_text.setPlainText(decrypted_data.decode())

if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = RSACryptoApp()
    sys.exit(app.exec_())
