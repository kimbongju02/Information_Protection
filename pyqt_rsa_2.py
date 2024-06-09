import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit
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

    def encrypt_text(self):
        plain_text = self.input_text.text()
        encrypted_text = encrption(plain_text)
        encrypted_text = b64encode(encrypted_text).decode('utf-8')
        self.encrypted_text.setPlainText(encrypted_text)

    def decrypt_text(self):
        encrypted_text = self.encrypted_text.toPlainText()
        encrypted_bytes = b64decode(encrypted_text)
        decrypted_text=decryption(encrypted_bytes)
        decrypted_text = decrypted_text.decode('utf-8')
        self.decrypted_text.setPlainText(decrypted_text)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = RSACryptoApp()
    sys.exit(app.exec_())


p = 13
q = 29
n = p * q
tot = (p - 1) * (q - 1)
#최대공약수 구하는 거
def gcd(num1, num2):
    while num2 != 0:
        num1, num2 = num2, num1%num2
    return num1

#공개키
def publickey():
    global tot
    e = 2
    while e<tot and gcd(e, tot) != 1:
        e += 1
    return e

#개인키
def privatekey():
    global e
    global tot
    d = 1
    while (publickey() * d) % tot != 1 or d == publickey():
        d += 1
    return d 
    
def encrption(ori):
    oris = list(ori)
    orior = []
    eori = []
    etext = ""
    
    for orisc in range(0, len(oris)):
        orior.append(ord(oris[orisc]))
    for oriorc in range(0, len(orior)):
        eori.append(((orior[oriorc]**publickey())%n))
    
    for eoric in range(0, len(eori)):
        etext += (chr(eori[eoric]))
    
    return etext

def decryption(eori):
    d = privatekey()
    
    eoris = list(eori)
    eroiso = []
    eroisor = []
    eroar = []
    text = ""
    
    for eorisc in range(0, len(eoris)):
        eroiso.append(ord(eoris[eorisc]))
    for eroisoc in range(0, len(eroiso)):
        eroisor.append((eroiso[eroisoc]**d)%n)
    for eroisorc in range(0, len(eroisor)):
        eroar.append(chr(eroisor[eroisorc]))
    for eroarc in range(0, len(eroar)):
        text += eroar[eroarc]

    return text