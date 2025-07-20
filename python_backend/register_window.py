#!/usr/bin/env python3
# register_window.py

import oqs
import os
import sys
import json
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
from .user_manager import UserManager

class RegisterWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(" Quantum-Safe User Registration")
        self.setGeometry(300, 300, 500, 300)  # बड़ा Window

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

        self.register_button = QPushButton("Create Account")
        self.register_button.setFont(button_font)
        self.register_button.setCursor(Qt.PointingHandCursor)
        self.register_button.clicked.connect(self.register_user)

        # Layout
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(40, 40, 40, 40)

        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.register_button)

        self.setLayout(layout)

        # Stylesheet
        self.setStyleSheet("""
            QWidget {
                background-color: #1f2c3e;
                color: #ecf0f1;
            }
            QLineEdit {
                background: #2c3e50;
                border: 1px solid #34495e;
                border-radius: 6px;
                padding: 10px;
            }
            QLineEdit:focus {
                border: 1px solid #3498db;
            }
            QPushButton {
                background-color: #3498db;
                border: none;
                color: white;
                border-radius: 6px;
                padding: 12px;
            }
            QPushButton:hover {
                background-color: #5dade2;
            }
            QPushButton:pressed {
                background-color: #2980b9;
            }
        """)


    def generate_user_certificates(self, username):
        import base64
    
        # Local user key directory
        user_local_dir = os.path.join(username+"_keys")
        os.makedirs(user_local_dir, exist_ok=True)
    
        # Server public key directory
        server_pub_base = os.path.join("server", "server_keys", "public_key", username)
        
        # --- All KEM Algorithms ---
        kem_algos = [ 
            "BIKE-L1", "BIKE-L3", "BIKE-L5",
            "Classic-McEliece-348864", "Classic-McEliece-348864f",
            "Classic-McEliece-460896", "Classic-McEliece-460896f",
            "Classic-McEliece-6688128", "Classic-McEliece-6688128f",
            "Classic-McEliece-6960119", "Classic-McEliece-6960119f",
            "Classic-McEliece-8192128", "Classic-McEliece-8192128f",
            "Kyber512", "Kyber768", "Kyber1024",
            "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
            "sntrup761",
            "FrodoKEM-640-AES", "FrodoKEM-640-SHAKE",
            "FrodoKEM-976-AES", "FrodoKEM-976-SHAKE",
            "FrodoKEM-1344-AES", "FrodoKEM-1344-SHAKE"]  # You can put full list again
    
        for kem_algo in kem_algos:
            algo_folder_local = os.path.join(user_local_dir, kem_algo)
            os.makedirs(algo_folder_local, exist_ok=True)
    
            kem = oqs.KeyEncapsulation(kem_algo)
            kem_public = kem.generate_keypair()
            kem_private = kem.export_secret_key()
    
            # File paths
            pub_key_path = os.path.join(algo_folder_local, f"{username}_{kem_algo}_public.key")
            priv_key_path = os.path.join(algo_folder_local, f"{username}_{kem_algo}_private.key")
            pub_pem_path = os.path.join(algo_folder_local, f"{username}_{kem_algo}_public.pem")
    
            # Write .key
            with open(pub_key_path, "wb") as f:
                f.write(kem_public)
            with open(priv_key_path, "wb") as f:
                f.write(kem_private)
    
            # Write .pem
            b64_pub = base64.encodebytes(kem_public).decode("ascii")
            pem_text = f"-----BEGIN {kem_algo} PUBLIC KEY-----\n"
            for i in range(0, len(b64_pub), 64):
                pem_text += b64_pub[i:i+64]
            pem_text += f"-----END {kem_algo} PUBLIC KEY-----\n"
            with open(pub_pem_path, "w") as f:
                f.write(pem_text)

    
            # Server side copy of public key
            server_algo_dir = os.path.join(server_pub_base, kem_algo)
            os.makedirs(server_algo_dir, exist_ok=True)
            server_pub_path = os.path.join(server_algo_dir, f"{username}_{kem_algo}_public.key")
            with open(server_pub_path, "wb") as f:
                f.write(kem_public)
            server_pem_path = os.path.join(server_algo_dir, f"{username}_{kem_algo}_public.pem")
            with open(server_pem_path, "w") as f:
                f.write(pem_text)
    
        # --- All Signature Algorithms ---
        sig_algos = [ 
            "Dilithium2", "Dilithium3", "Dilithium5",
            "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
            "Falcon-512", "Falcon-1024", "Falcon-padded-512", "Falcon-padded-1024",
            "SPHINCS+-SHA2-128f-simple", "SPHINCS+-SHA2-128s-simple",
            "SPHINCS+-SHA2-192f-simple", "SPHINCS+-SHA2-192s-simple",
            "SPHINCS+-SHA2-256f-simple", "SPHINCS+-SHA2-256s-simple",
            "SPHINCS+-SHAKE-128f-simple", "SPHINCS+-SHAKE-128s-simple",
            "SPHINCS+-SHAKE-192f-simple", "SPHINCS+-SHAKE-192s-simple",
            "SPHINCS+-SHAKE-256f-simple", "SPHINCS+-SHAKE-256s-simple",
            "MAYO-1", "MAYO-2", "MAYO-3", "MAYO-5",
            "cross-rsdp-128-balanced", "cross-rsdp-128-fast", "cross-rsdp-128-small",
            "cross-rsdp-192-balanced", "cross-rsdp-192-fast", "cross-rsdp-192-small",
            "cross-rsdp-256-balanced", "cross-rsdp-256-fast", "cross-rsdp-256-small",
            "cross-rsdpg-128-balanced", "cross-rsdpg-128-fast", "cross-rsdpg-128-small",
            "cross-rsdpg-192-balanced", "cross-rsdpg-192-fast", "cross-rsdpg-192-small",
            "cross-rsdpg-256-balanced", "cross-rsdpg-256-fast", "cross-rsdpg-256-small",
            "OV-Is", "OV-Ip", "OV-III", "OV-V",
            "OV-Is-pkc", "OV-Ip-pkc", "OV-III-pkc", "OV-V-pkc",
            "OV-Is-pkc-skc", "OV-Ip-pkc-skc", "OV-III-pkc-skc", "OV-V-pkc-skc",
            "SNOVA_24_5_4", "SNOVA_24_5_4_SHAKE", "SNOVA_24_5_4_esk", "SNOVA_24_5_4_SHAKE_esk",
            "SNOVA_37_17_2", "SNOVA_25_8_3", "SNOVA_56_25_2", "SNOVA_49_11_3",
            "SNOVA_37_8_4", "SNOVA_24_5_5", "SNOVA_60_10_4", "SNOVA_29_6_5"]  # You can put full list again
    
        for sig_algo in sig_algos:
            algo_folder_local = os.path.join(user_local_dir, sig_algo)
            os.makedirs(algo_folder_local, exist_ok=True)
    
            sig = oqs.Signature(sig_algo)
            sig_public = sig.generate_keypair()
            sig_private = sig.export_secret_key()
    
            # File paths
            pub_key_path = os.path.join(algo_folder_local, f"{username}_{sig_algo}_public.key")
            priv_key_path = os.path.join(algo_folder_local, f"{username}_{sig_algo}_private.key")
            pub_pem_path = os.path.join(algo_folder_local, f"{username}_{sig_algo}_public.pem")
    
            # Write .key
            with open(pub_key_path, "wb") as f:
                f.write(sig_public)
            with open(priv_key_path, "wb") as f:
                f.write(sig_private)
    
            # Write .pem
            b64_sig = base64.encodebytes(sig_public).decode("ascii")
            pem_text = f"-----BEGIN {sig_algo} PUBLIC KEY-----\n"
            for i in range(0, len(b64_sig), 64):
                pem_text += b64_sig[i:i+64]
            pem_text += f"-----END {sig_algo} PUBLIC KEY-----\n"
            with open(pub_pem_path, "w") as f:
                f.write(pem_text)


    
            # Server side copy of public key
            server_algo_dir = os.path.join(server_pub_base, sig_algo)
            os.makedirs(server_algo_dir, exist_ok=True)
            server_pub_path = os.path.join(server_algo_dir, f"{username}_{sig_algo}_public.key")
            with open(server_pub_path, "wb") as f:
                f.write(sig_public)
            # Server side copy of PEM file
            server_pem_path = os.path.join(server_algo_dir, f"{username}_{sig_algo}_public.pem")
            with open(server_pem_path, "w") as f:
                f.write(pem_text)
    
        print(f"✅ All keys generated and copied for {username}")

    def update_user_cert_map(self, username, kem_pub_path, sig_pub_path):
        """Update certs/user_cert_map.json mapping."""
        cert_map_path = "certs/user_cert_map.json"

        # Load existing map
        if os.path.exists(cert_map_path):
            with open(cert_map_path, "r") as f:
                cert_map = json.load(f)
        else:
            cert_map = {}

        # Update entry
        cert_map[username] = {
            "kem_public": kem_pub_path,
            "sig_public": sig_pub_path
        }

        # Save updated map
        with open(cert_map_path, "w") as f:
            json.dump(cert_map, f, indent=4)

    def register_user(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not username or not password:
            QMessageBox.warning(self, "Input Required", "Please fill all fields")
            return

        if len(username) < 3:
            QMessageBox.warning(self, "Invalid Username", "Username must be at least 3 characters long")
            return

        if len(password) < 6:
            QMessageBox.warning(self, "Weak Password", "Password must be at least 6 characters long")
            return

        success, message = self.user_manager.register_user(username, password)
        if success:
            try:
                self.generate_user_certificates(username)
                QMessageBox.information(
                    self,
                    "Success",
                    f"{message}\n\nQuantum certificates generated and mapped successfully."
                )
                self.username_input.clear()
                self.password_input.clear()
            except Exception as e:
                QMessageBox.critical(self, "Certificate Error", f"Error generating certificates:\n{str(e)}")
        else:
            QMessageBox.critical(self, "Error", message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RegisterWindow()
    window.show()
    sys.exit(app.exec_())
