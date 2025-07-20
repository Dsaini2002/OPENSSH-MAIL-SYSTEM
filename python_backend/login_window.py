#!/usr/bin/env python3
# login_window.py

import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, pyqtSignal
from .user_manager import UserManager


class LoginWindow(QWidget):
    login_successful = pyqtSignal(str)
    goto_register = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle(" Quantum-Safe User Login")
        self.setGeometry(300, 300, 500, 320)

        self.user_manager = UserManager()

        # Fonts
        label_font = QFont("Segoe UI", 11)
        input_font = QFont("Segoe UI", 11)
        button_font = QFont("Segoe UI", 11, QFont.Bold)

        # Widgets
        self.username_label = QLabel(" Username:")
        self.username_label.setFont(label_font)

        self.username_input = QLineEdit()
        self.username_input.setFont(input_font)
        self.username_input.setPlaceholderText("Enter your username")

        self.password_label = QLabel(" Password:")
        self.password_label.setFont(label_font)

        self.password_input = QLineEdit()
        self.password_input.setFont(input_font)
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setEchoMode(QLineEdit.Password)

        self.login_button = QPushButton("Login")
        self.login_button.setFont(button_font)
        self.login_button.setCursor(Qt.PointingHandCursor)
        self.login_button.clicked.connect(self.login_user)

        self.register_button = QPushButton("Register New Account")
        self.register_button.setFont(button_font)
        self.register_button.setCursor(Qt.PointingHandCursor)
        self.register_button.clicked.connect(self.goto_register.emit)

        # Layout
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)
        layout.addWidget(self.register_button)

        self.setLayout(layout)

        # Stylesheet
        self.setStyleSheet("""
            QWidget {
                background-color: #16222A;
                color: #ECF0F1;
            }
            QLabel {
                color: #ECF0F1;
            }
            QLineEdit {
                background: #2C3E50;
                border: 1px solid #34495E;
                border-radius: 6px;
                padding: 10px;
            }
            QLineEdit:focus {
                border: 1px solid #3498DB;
                background: #3B4D61;
            }
            QPushButton {
                background-color: #3498DB;
                border: none;
                color: white;
                border-radius: 6px;
                padding: 12px;
            }
            QPushButton:hover {
                background-color: #5DADE2;
            }
            QPushButton:pressed {
                background-color: #2980B9;
            }
        """)

    def login_user(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()

        if not username or not password:
            QMessageBox.warning(self, "Input Required", "Please enter username and password")
            return

        success, user_data, message = self.user_manager.authenticate_user(username, password)

        if success:
            QMessageBox.information(
                self,
                "Login Successful",
                f"Welcome, {username}!\nLast login: {user_data.get('last_login')}"
            )
            self.login_successful.emit(username)
        else:
            QMessageBox.critical(self, "Login Failed", message)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LoginWindow()
    window.show()
    sys.exit(app.exec_())
