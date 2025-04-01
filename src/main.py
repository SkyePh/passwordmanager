from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QLabel, QPushButton, QInputDialog, QMessageBox, QLineEdit,
    QDialog, QHBoxLayout, QTableWidget, QTableWidgetItem
)
from PyQt6.QtCore import Qt
import sys
import csv
import os

from hashing import encrypt_password, decrypt_password

PASS = 'souvla'
CSV_FILE = 'mistika.csv'

def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

def load_key():
    key_path = resource_path("secret.key")
    with open(key_path, "rb") as key_file:
        return key_file.read()

def save_to_csv(service: str, encrypted_password: str):
    file_exists = os.path.isfile(CSV_FILE)
    with open(CSV_FILE, mode="a", newline="") as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(["Service", "EncryptedPassword"])
        writer.writerow([service, encrypted_password])

class PasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ksiannw")
        self.setFixedSize(400, 600)  # width x height

        if not self.verify_password():
            sys.exit()

        self.init_ui()

    def verify_password(self):
        text, ok = QInputDialog.getText(self, "Enter Password", "Enter Password:", echo=QLineEdit.EchoMode.Password)

        if ok and text == PASS:
            return True
        else:
            QMessageBox.critical(self, "Access Denied", "Incorrect password.")
            return False

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Title
        title = QLabel("Ksiannw")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 32px; font-weight: bold;")

        layout.addWidget(title)
        layout.addSpacing(30)

        # Buttons with icons
        view_button = self.create_icon_button("De tous kodikous", "🔑")
        view_button.clicked.connect(self.view_passwords)
        add_button = self.create_icon_button("Vale jenourko", "➕")
        add_button.clicked.connect(self.add_password)

        layout.addWidget(view_button, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(add_button, alignment=Qt.AlignmentFlag.AlignCenter)

        central_widget.setLayout(layout)

    def create_icon_button(self, text, emoji_icon):
        button = QPushButton(f"{emoji_icon}\n{text}")
        button.setFixedSize(150, 150)
        button.setStyleSheet("""
                    QPushButton {
                        font-size: 16px;
                        padding: 10px;
                        text-align: center;
                    }
                """)
        return button

    def add_password(self):
        dialog = AddPasswordDialog()
        if dialog.exec():
            service, password = dialog.get_data()

            if not service or not password:
                QMessageBox.warning(self, "Lathos", "Efien sou llio")
                return

            key = load_key()
            encrypted = encrypt_password(password, key)

            file_exists = os.path.isfile("mistika.csv")
            with open("mistika.csv", mode="a", newline="") as file:
                writer = csv.writer(file)
                if not file_exists:
                    writer.writerow(["Service", "EncryptedPassword"])
                writer.writerow([service, encrypted])

            QMessageBox.information(self, "OK", f"O kodikos gia '{service}' apothikeftike.")

    def view_passwords(self):
        dialog = ViewPasswordsDialog()
        dialog.exec()

class AddPasswordDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Jenourkos")
        self.setFixedSize(300, 200)

        layout = QVBoxLayout()

        # Service input
        self.service_input = QLineEdit()
        self.service_input.setPlaceholderText("Onoma")

        # Password input
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Kodikos")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)

        # Buttons
        buttons_layout = QHBoxLayout()
        save_button = QPushButton("Pompa")
        cancel_button = QPushButton("AKIROOO")
        buttons_layout.addWidget(save_button)
        buttons_layout.addWidget(cancel_button)

        layout.addWidget(QLabel("Vale jenourko"))
        layout.addWidget(self.service_input)
        layout.addWidget(self.password_input)
        layout.addLayout(buttons_layout)

        self.setLayout(layout)

        # Button actions
        save_button.clicked.connect(self.accept)
        cancel_button.clicked.connect(self.reject)

    def get_data(self):
        return self.service_input.text(), self.password_input.text()

class ViewPasswordsDialog(QDialog):
    def __init__(self, csv_file="mistika.csv"):
        super().__init__()
        self.setWindowTitle("Kodikoi pou eksiases")
        self.setFixedSize(500, 400)

        layout = QVBoxLayout()
        self.table = QTableWidget()
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["Service", "Hashed Password"])
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        layout.addWidget(self.table)
        self.setLayout(layout)

        self.load_passwords(csv_file)

    def load_passwords(self, csv_file):
        key = load_key()

        try:
            with open(csv_file, newline="") as file:
                reader = csv.reader(file)
                headers = next(reader, None)  # skip header
                for row in reader:
                    if len(row) < 2:
                        continue

                    service = row[0]
                    encrypted_password = row[1]

                    try:
                        password = decrypt_password(encrypted_password, key)
                    except Exception as e:
                        password = "[Error decrypting]"

                    row_position = self.table.rowCount()
                    self.table.insertRow(row_position)
                    self.table.setItem(row_position, 0, QTableWidgetItem(service))
                    self.table.setItem(row_position, 1, QTableWidgetItem(password))
        except FileNotFoundError:
            QMessageBox.warning(self, "File Not Found", "No saved passwords found yet.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordManager()
    window.show()
    sys.exit(app.exec())
