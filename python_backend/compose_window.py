# python_backend/compose_window.py
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import json
import smtplib
import textwrap
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email_crypto import encrypt_and_sign_email, decrypt_and_verify_email, debug_encrypted_data, get_key_paths
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QTextEdit,
    QPushButton, QVBoxLayout, QMessageBox, QFileDialog, QComboBox, QHBoxLayout,
    QFrame, QScrollArea, QSizePolicy
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QPalette, QColor
import oqs
import logging
from datetime import datetime

# Add the parent directory to the path to import email_crypto
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from email_crypto import encrypt_and_sign_email
except ImportError:
    # Fallback if email_crypto is not available
    def encrypt_and_sign_email(email_data, crypto_config):
        return {
            "error": False,
            "encrypted_data": "dummy_encrypted_data",
            "signature": "dummy_signature",
            "message": "Email processed (crypto module not available)"
        }

logger = logging.getLogger(__name__)

class ComposeWindow(QWidget):
    def __init__(self, smtp_server=None, crypto_config=None):
        super().__init__()
        layout=QVBoxLayout()
        self.cert_path_input = QLineEdit()
        self.cert_path_input.setPlaceholderText("Optional: Certificate path")

        layout.addWidget(self.cert_path_input)
        self.smtp_server = smtp_server  # Reference to main SMTP server
        self.crypto_config = crypto_config  # Store crypto config if provided
        self.setWindowTitle("Compose Secure Email")
        self.setGeometry(200, 200, 600, 300)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        # Set application style
        self.setStyleSheet(self.get_main_stylesheet())
        
        # Initialize UI
        self.init_ui()
        self.populate_dropdowns()

    def browse_certificate(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Certificate File", "", "PEM Files (*.pem);;All Files (*)", options=options
        )
        if file_path:
            self.cert_path_input.setText(file_path)

    
    def get_main_stylesheet(self):
        """Return the main stylesheet for the application"""
        return """
        QWidget {
            background-color: #f8f9fa;
            color: #2c3e50;
            font-family: 'Segoe UI', Arial, sans-serif;
        }
        
        QLabel {
            color: #34495e;
            font-weight: 600;
            font-size: 13px;
            margin: 2px 0px 1px 0px;
        }
        
        QLineEdit {
            background-color: white;
            border: 2px solid #e1e8ed;
            border-radius: 8px;
            padding: 6px 8px;
            font-size: 13px;
            color: #2c3e50;
            selection-background-color: #3498db;
        }
        
        QLineEdit:focus {
            border-color: #3498db;
            outline: none;
        }
        
        QLineEdit:hover {
            border-color: #bdc3c7;
        }
        
        QTextEdit {
            background-color: white;
            border: 2px solid #e1e8ed;
            border-radius: 8px;
            padding: 10px;
            font-size: 13px;
            color: #2c3e50;
            selection-background-color: #3498db;
        }
        
        QTextEdit:focus {
            border-color: #3498db;
            outline: none;
        }
        
        QComboBox {
            background-color: white;
            border: 2px solid #e1e8ed;
            border-radius: 8px;
            padding: 4px 10px;
            font-size: 13px;
            color: #2c3e50;
            min-height: 20px;
        }
        
        QComboBox:focus {
            border-color: #3498db;
        }
        
        QComboBox:hover {
            border-color: #bdc3c7;
        }
        
        QComboBox::drop-down {
            border: none;
            width: 20px;
        }
        
        QComboBox::down-arrow {
            image: none;
            border-left: 5px solid transparent;
            border-right: 5px solid transparent;
            border-top: 5px solid #7f8c8d;
            margin-right: 5px;
        }
        
        QPushButton {
            background-color: #3498db;
            color: white;
            border: none;
            border-radius: 8px;
            padding: 6px 15px;
            font-size: 14px;
            font-weight: 600;
            min-height: 20px;
        }
        
        QPushButton:hover {
            background-color: #2980b9;
        }
        
        QPushButton:pressed {
            background-color: #21618c;
        }
        
        QPushButton:disabled {
            background-color: #bdc3c7;
            color: #7f8c8d;
        }
        
        QFrame {
            background-color: white;
            border: 1px solid #e1e8ed;
            border-radius: 10px;
            margin: 5px;
        }
        """
    
    def init_ui(self):
        layout = QVBoxLayout()
        layout.addWidget(self.cert_path_input)
        # Main layout
        main_layout = QVBoxLayout()
        main_layout.setSpacing(5)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        # Header
        header_label = QLabel("Compose Secure Email")
        header_label.setStyleSheet("""
            QLabel {
                font-size: 20px;
                font-weight: bold;
                color: #2c3e50;
                margin-bottom: 5px;
                padding: 10px;
            }
        """)
        header_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(header_label)
        
        # Create a frame for the form
        form_frame = QFrame()
        form_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border: 1px solid #e1e8ed;
                border-radius: 15px;
                padding: 10px;
                margin: 5px;
            }
        """)
        kem_label = QLabel(" Key Encapsulation (KEM) Algorithm:")
        self.kem_dropdown = QComboBox()
        layout.addWidget(kem_label)
        layout.addWidget(self.kem_dropdown)

        sig_label = QLabel(" Signature Algorithm:")
        self.sig_dropdown = QComboBox()
        layout.addWidget(sig_label)
        layout.addWidget(self.sig_dropdown)
        

                # Form layout
        form_layout = QVBoxLayout()
        form_layout.setSpacing(8)
        form_layout.setContentsMargins(15, 15, 15, 15)
        
        # Email details section
        email_section = self.create_section(" Email Details")
        
        # Labels and inputs
        self.to_label = QLabel(" To:")
        self.from_label = QLabel(" From:")
        self.subject_label = QLabel(" Subject:")
        self.body_label = QLabel(" Message:")
        
        # Input Fields
        self.to_input = QLineEdit()
        self.from_input = QLineEdit()
        self.subject_input = QLineEdit()
        self.body_input = QTextEdit()
        
        # Set placeholder text
        self.to_input.setPlaceholderText("recipient@example.com")
        self.from_input.setPlaceholderText("sender@example.com")
        self.subject_input.setPlaceholderText("Enter subject")
        self.body_input.setPlaceholderText("Enter your message here...")
        
        # Style the text edit
        self.body_input.setMinimumHeight(50)
        
        # Add to email section
        email_section.addWidget(self.to_label)
        email_section.addWidget(self.to_input)
        email_section.addWidget(self.from_label)
        email_section.addWidget(self.from_input)
        email_section.addWidget(self.subject_label)
        email_section.addWidget(self.subject_input)
        email_section.addWidget(self.body_label)
        email_section.addWidget(self.body_input)
        
        # Certificate section
        cert_section = self.create_section(" Recipient Certificate")   
        self.cert_path_input.setPlaceholderText("Select recipient .pem certificate")
        self.cert_label = QLabel(" Certificate Path:")
        self.browse_button = QPushButton(" Browse")
        self.browse_button.clicked.connect(self.browse_certificate)
        self.browse_button.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                padding: 10px 15px;
                font-size: 13px;
                max-width: 100px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        
        
        cert_section.addWidget(self.cert_label)
        self.cert_label = QLabel("Recipient Certificate:")

        
        # Crypto section
        crypto_section = self.create_section("🔒 Cryptographic Settings")
        
        self.kem_label = QLabel(" Key Exchange (KEM):")
        self.sig_label = QLabel(" Signature Algorithm:")
        
        # Dropdowns
        self.kem_combo = QComboBox()
        self.sig_combo = QComboBox()
        
        # Make dropdowns wider and searchable
        self.kem_combo.setMinimumWidth(200)
        self.sig_combo.setMinimumWidth(200)
        self.kem_combo.setEditable(True)  # Makes it searchable
        self.sig_combo.setEditable(True)  # Makes it searchable
        
        # KEM + Signature selection in horizontal layout
        crypto_layout = QVBoxLayout()
        
        # KEM Layout
        kem_layout = QVBoxLayout()
        kem_layout.addWidget(self.kem_label)
        kem_layout.addWidget(self.kem_combo)
        
        # Signature Layout
        sig_layout = QVBoxLayout()
        sig_layout.addWidget(self.sig_label)
        sig_layout.addWidget(self.sig_combo)
        
        crypto_layout.addLayout(kem_layout)
        crypto_layout.addLayout(sig_layout)
        
        crypto_section.addLayout(crypto_layout)
        
        # Send button
        self.encrypt_button = QPushButton("🔐 Encrypt, Sign & Send")
        self.encrypt_button.clicked.connect(self.encrypt_and_send_email)
        self.encrypt_button.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                padding: 10px 20px;
                font-size: 16px;
                font-weight: bold;
                border-radius: 8px;
                margin: 8px 0px;
            }
            QPushButton:hover {
                background-color: #229954;
            }
            QPushButton:pressed {
                background-color: #1e8449;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
                color: #7f8c8d;
            }
        """)
        
        # Add all sections to form
        form_layout.addLayout(email_section)
        form_layout.addLayout(cert_section)
        form_layout.addLayout(crypto_section)
        form_layout.addWidget(self.encrypt_button)
        
        form_frame.setLayout(form_layout)
        
        # Add to main layout
        main_layout.addWidget(form_frame)
        
        # Add some stretch at the bottom
        
        
        self.setLayout(main_layout)
        
        print(" ComposeWindow: Encrypt button connected")
    def populate_dropdowns(self):
        self.kem_dropdown.addItems(oqs.get_enabled_KEM_mechanisms())
        self.sig_dropdown.addItems(oqs.get_enabled_sig_mechanisms())

    def create_section(self, title):
        """Create a styled section with title"""
        section_layout = QVBoxLayout()
        section_layout.setSpacing(5)
        
        # Section title
        title_label = QLabel(title)
        title_label.setStyleSheet("""
            QLabel {
                font-size: 16px;
                font-weight: bold;
                color: #2c3e50;
                padding: 8px 0px;
                border-bottom: 2px solid #3498db;
                margin-bottom: 5px;
            }
        """)
        
        section_layout.addWidget(title_label)
        
        return section_layout
    

    def populate_dropdowns(self):
        """Populate KEM and Signature algorithm dropdowns"""
        try:
            # Get available KEM mechanisms
            kem_algorithms = oqs.get_enabled_kem_mechanisms()
            print(f"Available KEM algorithms: {len(kem_algorithms)}")
            
            # Clear and populate KEM dropdown
            self.kem_combo.clear()
            self.kem_combo.addItems(kem_algorithms)
            
            # Set default KEM (recommend a fast one)
            if "Kyber512" in kem_algorithms:
                self.kem_combo.setCurrentText("Kyber512")
            elif kem_algorithms:
                self.kem_combo.setCurrentIndex(0)
            
            # Get available Signature mechanisms
            sig_algorithms = oqs.get_enabled_sig_mechanisms()
            print(f"Available Signature algorithms: {len(sig_algorithms)}")
            
            # Clear and populate Signature dropdown
            self.sig_combo.clear()
            self.sig_combo.addItems(sig_algorithms)
            
            # Set default Signature (recommend a fast one)
            if "Dilithium2" in sig_algorithms:
                self.sig_combo.setCurrentText("Dilithium2")
            elif sig_algorithms:
                self.sig_combo.setCurrentIndex(0)
                
        except Exception as e:
            print(f"Error loading algorithms: {e}")
            QMessageBox.warning(self, "Warning", f"Could not load quantum algorithms: {e}")
            
            # Add some fallback options
            self.kem_combo.addItems(["Kyber512", "Kyber768", "Kyber1024"])
            self.sig_combo.addItems(["Dilithium2", "Dilithium3", "Dilithium5"])
    
    def get_project_root(self):
        """Get the project root directory"""
        # Get current file's directory
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Go up directories until we find main.py (project root)
        while current_dir != os.path.dirname(current_dir):  # Not at filesystem root
            if os.path.exists(os.path.join(current_dir, 'main.py')):
                return current_dir
            current_dir = os.path.dirname(current_dir)
        
        # Fallback: use current working directory
        return os.getcwd()
    
    def save_sent_email(self, email_data, encrypted_result):
        """Save sent email to sent.json file"""
        try:
            sent_email = {
                "timestamp": datetime.now().isoformat(),
                "from": email_data["from"],
                "to": email_data["to"],
                "subject": email_data["subject"],
                "body": email_data["body"],
                "is_quantum": True,
                "kem_algorithm": self.kem_combo.currentText(),
                "sig_algorithm": self.sig_combo.currentText(),
                "encrypted_data": encrypted_result,
                "status": "sent"
            }
            
            # Get the project root directory
            project_root = self.get_project_root()
            
            # Create emails directory if it doesn't exist
            emails_dir = os.path.join(project_root, "server","emails")
            if not os.path.exists(emails_dir):
                os.makedirs(emails_dir)
                logger.info(f" Created emails directory: {emails_dir}")
            
            # Path to sent.json file
            sent_file_path = os.path.join(emails_dir, "sent.json") 
            
            logger.info(f" Trying to save to: {sent_file_path}")
            print(f"Trying to save to: {sent_file_path}")
            
            # Try to load existing sent emails
            try:
                with open(sent_file_path, "r") as f:
                    sent_emails = json.load(f)
                    if not isinstance(sent_emails, list):
                        sent_emails = []
                logger.info(f"Loaded {len(sent_emails)} existing sent emails")
                print(f"Loaded {len(sent_emails)} existing sent emails")
            except (FileNotFoundError, json.JSONDecodeError):
                sent_emails = []
                logger.info("Creating new sent emails list")
                print("Creating new sent emails list")
            
            # Add new email
            sent_emails.append(sent_email)
            
            # Save back to file
            with open(sent_file_path, "w") as f:
                json.dump(sent_emails, f, indent=2)
            
            logger.info(f"Email saved to sent.json: {email_data['subject']} (Total: {len(sent_emails)} emails)")
            print(f"Email saved to sent.json: {email_data['subject']} (Total: {len(sent_emails)} emails)")
            
            # Verify file was written
            if os.path.exists(sent_file_path):
                file_size = os.path.getsize(sent_file_path)
                logger.info(f"File size: {file_size} bytes")
                print(f"File size: {file_size} bytes")
            else:
                logger.error("❌ File was not created!")
                print("❌ File was not created!")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to save sent email: {e}")
            print(f"❌ Failed to save sent email: {e}")
            import traceback
            traceback.print_exc()
            return False

    def save_inbox_email(self, email_data, encrypted_result):
        """Save encrypted email to inbox.json"""
        try:
            inbox_email = {
                "timestamp": datetime.now().isoformat(),
                "from": email_data["from"],
                "to": email_data["to"],
                "subject": email_data["subject"],
                "is_quantum": True,
                "kem_algorithm": self.kem_combo.currentText(),
                "sig_algorithm": self.sig_combo.currentText(),
                "encrypted_content": encrypted_result.get("encrypted_content"),
                "ciphertext": encrypted_result.get("ciphertext"),  
                "signature": encrypted_result.get("signature"),
                "shared_secret": encrypted_result.get("shared_secret"),
                "sig_public_key": encrypted_result["sig_public_key"],
                "status": "received"
            }

            # Get project root
            project_root = self.get_project_root()
            inbox_file_path = os.path.join(project_root, "emails", "inbox.json")

            # Create directory if missing
            if not os.path.exists(os.path.dirname(inbox_file_path)):
                os.makedirs(os.path.dirname(inbox_file_path))

            # Load existing inbox
            try:
                with open(inbox_file_path, "r") as f:
                    inbox_emails = json.load(f)
                    if not isinstance(inbox_emails, list):
                        inbox_emails = []
            except (FileNotFoundError, json.JSONDecodeError):
                inbox_emails = []

            # Append new email
            inbox_emails.append(inbox_email)

            # Save back
            with open(inbox_file_path, "w") as f:
                json.dump(inbox_emails, f, indent=2)

            print(f"✅ Email saved to inbox.json (Total: {len(inbox_emails)} emails)")

        except Exception as e:
            print(f"❌ Failed to save to inbox.json: {e}")
    
    def send_quantum_email_smtp_fixed(self, email_data, encrypted_result):
        """Send quantum encrypted email via SMTP with line length fix"""
        try:
            # Convert encrypted data to base64 for safe transmission
            json_str = json.dumps(encrypted_result, separators=(',', ':'))  # Compact JSON
            encoded_data = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
            
            # Wrap the base64 data to 76 characters per line (RFC compliant)
            wrapped_data = textwrap.fill(encoded_data, width=76)
            
            # Create RFC-compliant message
            message = f"""From: {email_data['from']}
To: {email_data['to']}
Subject: [QUANTUM-ENCRYPTED] {email_data['subject']}
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

This is a quantum-encrypted email.

Original Subject: {email_data['subject']}
Encryption: Post-Quantum Cryptography
KEM: {self.kem_combo.currentText()}
Signature: {self.sig_combo.currentText()}

=== ENCRYPTED PAYLOAD (Base64) ===
{wrapped_data}
=== END ENCRYPTED PAYLOAD ===

Use a compatible quantum email client to decrypt this message.
"""
            
            # Send via SMTP
            server = smtplib.SMTP("localhost", 1025)
            server.sendmail(email_data["from"], [email_data["to"]], message)
            server.quit()
            
            return True
            
        except Exception as e:
            print(f"SMTP Error: {e}")
            return False
    def encrypt_and_send_email(self):
        sender = self.from_input.text().strip()
        recipient = self.to_input.text().strip()
        subject = self.subject_input.text().strip()
        body = self.body_input.toPlainText().strip()
    
        if not sender or not recipient or not subject or not body:
            QMessageBox.warning(self, "Missing Fields", "All fields are required.")
            return
    
        # Fix: Use the correct dropdown widget names
        selected_kem = self.kem_combo.currentText()
        selected_sig = self.sig_combo.currentText()
        
        # Check if algorithms are selected
        if not selected_kem or not selected_sig:
            QMessageBox.warning(self, "Missing Algorithms", "Please select KEM and Signature algorithms.")
            return
        
        cert_path = self.cert_path_input.text().strip() or None
        if not cert_path:
            cert_path = f"server/server_keys/public_key/{recipient}/{selected_sig}/{recipient}_{selected_sig}_public.key"
    
        print(f"🔍 Debug: Looking for certificate at: {cert_path}")
        print(f"🔍 Debug: Selected KEM: {selected_kem}")
        print(f"🔍 Debug: Selected Signature: {selected_sig}")
        print(f"🔍 Debug: Recipient: {recipient}")
    
        if not os.path.exists(cert_path):
            QMessageBox.critical(self, "Error", f"❌ Public certificate not found:\n{cert_path}")
            return
        
        # Build email data
        email_data = {
            "from": sender,
            "to": recipient,
            "subject": subject,
            "body": body
        }
    
        # 🔐 Step 1: Resolve all key paths
        try:
            key_paths = get_key_paths(
                sender=sender,
                recipient=recipient,
                sig_algo=selected_sig,
                kem_algo=selected_kem
            )
        except FileNotFoundError as e:
            print(f"❌ Key path error: {e}")
            QMessageBox.critical(self, "Key Error", str(e))
            return
    
        # 🧪 Step 2: Encrypt and sign
        try:
            result = encrypt_and_sign_email(email_data, {
                "kem": selected_kem,
                "sig": selected_sig,
                "recipient_cert": key_paths["recipient_kem_pub"],  # Fix: Use key_paths instead of cert_path
                "sender_sig_priv": key_paths["sender_sig_priv"],
                "sender_kem_priv": key_paths["sender_kem_priv"]
            })
            
            if result and not result.get("error", False):
                # Save to sent emails
                self.save_sent_email(email_data, result)
                
                # Save to inbox (for testing)
                self.save_inbox_email(email_data, result)
                
                # Send via SMTP
                if self.send_quantum_email_smtp_fixed(email_data, result):
                    QMessageBox.information(self, "Success", "✅ Email encrypted, signed, and sent successfully!")
                    self.clear_form()
                else:
                    QMessageBox.warning(self, "SMTP Error", "Email was encrypted but failed to send via SMTP.")
            else:
                error_msg = result.get("message", "Unknown encryption error") if result else "Encryption failed"
                QMessageBox.critical(self, "Error", f"❌ Email encryption failed: {error_msg}")
                
        except Exception as e:
            print(f"❌ Encryption error: {e}")
            import traceback
            traceback.print_exc()
            QMessageBox.critical(self, "Encryption Failed", f"Could not encrypt email.\n\n{e}")
    def clear_form(self):
        """Clear the form fields after successful send"""
        self.to_input.clear()
        self.subject_input.clear()
        self.body_input.clear()
        self.cert_path_input.clear()
        print("🧹 Form cleared after successful send")
    
    def debug_encrypted_payload(self, result):
        """Debug helper to print encrypted payload structure"""
        try:
            print("🔍 Debug: Encrypted payload structure:")
            for key, value in result.items():
                if isinstance(value, (str, int, float, bool)):
                    print(f"  {key}: {type(value).__name__} (length: {len(str(value)) if isinstance(value, str) else 'N/A'})")
                elif isinstance(value, bytes):
                    print(f"  {key}: bytes (length: {len(value)})")
                elif isinstance(value, dict):
                    print(f"  {key}: dict with keys: {list(value.keys())}")
                elif isinstance(value, list):
                    print(f"  {key}: list (length: {len(value)})")
                else:
                    print(f"  {key}: {type(value).__name__}")
        except Exception as e:
            print(f"🔍 Debug error: {e}")
    
    def fix_encrypted_data_structure(self, result):
        """Fix encrypted data structure to ensure compatibility"""
        try:
            # Ensure all required fields are present
            required_fields = ['encrypted_content', 'ciphertext', 'signature', 'shared_secret', 'sig_public_key']
            
            for field in required_fields:
                if field not in result:
                    print(f"⚠️ Missing field '{field}' in encrypted result")
                    result[field] = None
            
            # Convert bytes to base64 strings for JSON serialization
            for key, value in result.items():
                if isinstance(value, bytes):
                    result[key] = base64.b64encode(value).decode('utf-8')
                    print(f"🔧 Converted {key} from bytes to base64 string")
            
            return result
            
        except Exception as e:
            print(f"❌ Error fixing encrypted data structure: {e}")
            return result