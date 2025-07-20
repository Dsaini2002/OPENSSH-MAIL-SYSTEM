import os
import json
import base64
from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFileDialog,
    QTextEdit,
    QMessageBox,
    QFrame,
    QScrollArea,
    QSplitter
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont

from email_crypto import decrypt_and_verify_email


class EmailItem(QWidget):
    clicked = pyqtSignal(object)

    def __init__(self, email_data, index):
        super().__init__()
        self.email_data = email_data
        self.index = index
        self.is_selected = False
        self.setup_ui()

    def setup_ui(self):
        self.setFixedHeight(70)
        self.setCursor(Qt.PointingHandCursor)
        self.update_style()

        layout = QVBoxLayout()
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(6)

        top_row = QHBoxLayout()
        from_label = QLabel(f"From: {self.email_data.get('from', 'Unknown')}")
        from_label.setFont(QFont("Arial", 14, QFont.Bold))
        time_label = QLabel(self.email_data.get('timestamp', self.email_data.get('sent_at', 'Unknown')))
        time_label.setFont(QFont("Arial", 12))
        time_label.setStyleSheet("color: #666;")

        top_row.addWidget(from_label)
        top_row.addStretch()
        top_row.addWidget(time_label)

        subject = self.email_data.get('subject', 'No Subject')
        if len(subject) > 50:
            subject = subject[:47] + "..."
        subject_label = QLabel(subject)
        subject_label.setFont(QFont("Arial", 13))
        subject_label.setStyleSheet("color: #333;")

        layout.addLayout(top_row)
        layout.addWidget(subject_label)

        self.setLayout(layout)

    def update_style(self):
        if self.is_selected:
            self.setStyleSheet("""
                QWidget {
                    background-color: #e3f2fd;
                    border: 1px solid #2196f3;
                    border-radius: 5px;
                    margin: 2px;
                }
            """)
        else:
            self.setStyleSheet("""
                QWidget {
                    background-color: #f5f5f5;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    margin: 2px;
                }
                QWidget:hover {
                    background-color: #e8e8e8;
                }
            """)

    def set_selected(self, selected):
        self.is_selected = selected
        self.update_style()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self)
        super().mousePressEvent(event)


class InboxWindow(QWidget):
    def __init__(self, username, kem_private_key_b64=None):
        super().__init__()
        self.username = username.strip()
        self.kem_private_key_b64 = kem_private_key_b64

        self.setWindowTitle("Email Inbox")
        self.setGeometry(200, 200, 1400, 900)
        self.setStyleSheet("""
            QWidget {
                background-color: white;
                font-family: Arial, sans-serif;
            }
        """)

        self.selected_email = None
        self.selected_item = None
        self.setup_ui()
        QTimer.singleShot(100, self.load_emails)

    def setup_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)
        self.setLayout(main_layout)

        title_label = QLabel("Email Inbox")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_label.setStyleSheet("color: #333; padding: 10px;")
        main_layout.addWidget(title_label)

        splitter = QSplitter(Qt.Horizontal)

        left_panel = QFrame()
        left_panel.setFrameStyle(QFrame.Box)
        left_panel.setStyleSheet("border: 1px solid #ddd;")
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(15, 15, 15, 15)

        list_header = QLabel("Messages")
        list_header.setFont(QFont("Arial", 16, QFont.Bold))
        list_header.setStyleSheet("color: #333; padding: 10px;")
        left_layout.addWidget(list_header)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.email_list_widget = QWidget()
        self.email_list_layout = QVBoxLayout()
        self.email_list_layout.setSpacing(4)
        self.email_list_layout.setContentsMargins(0, 0, 0, 0)
        self.email_list_widget.setLayout(self.email_list_layout)

        scroll_area.setWidget(self.email_list_widget)
        left_layout.addWidget(scroll_area)

        left_panel.setLayout(left_layout)
        left_panel.setMinimumWidth(500)

        right_panel = QFrame()
        right_panel.setFrameStyle(QFrame.Box)
        right_panel.setStyleSheet("border: 1px solid #ddd;")
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(15, 15, 15, 15)

        content_header_layout = QHBoxLayout()
        content_header = QLabel("Message Content")
        content_header.setFont(QFont("Arial", 16, QFont.Bold))
        content_header.setStyleSheet("color: #333; padding: 10px;")

        self.decrypt_button = QPushButton("Decrypt Message")
        self.decrypt_button.setEnabled(False)
        self.decrypt_button.clicked.connect(self.decrypt_selected_email)
        self.decrypt_button.setStyleSheet("""
            QPushButton {
                background-color: #2196f3;
                color: white;
                border: none;
                padding: 14px 24px;
                border-radius: 4px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976d2;
            }
            QPushButton:disabled {
                background-color: #ccc;
                color: #666;
            }
        """)

        content_header_layout.addWidget(content_header)
        content_header_layout.addStretch()
        content_header_layout.addWidget(self.decrypt_button)

        right_layout.addLayout(content_header_layout)

        self.email_content = QTextEdit()
        self.email_content.setPlaceholderText("Select an email to view its content...")
        self.email_content.setStyleSheet("""
            QTextEdit {
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 20px;
                font-size: 16px;
                color: #333;
                line-height: 1.6;
            }
        """)
        right_layout.addWidget(self.email_content)
        right_panel.setLayout(right_layout)

        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([500, 900])
        main_layout.addWidget(splitter)

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("""
            QLabel {
                background-color: #f0f0f0;
                color: #333;
                padding: 12px;
                border-top: 1px solid #ddd;
                font-size: 14px;
            }
        """)
        main_layout.addWidget(self.status_label)

    def get_project_root(self):
        """Get the project root directory (same as compose window)"""
        # Get current file's directory
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Go up directories until we find main.py (project root)
        while current_dir != os.path.dirname(current_dir):  # Not at filesystem root
            if os.path.exists(os.path.join(current_dir, 'main.py')):
                return current_dir
            current_dir = os.path.dirname(current_dir)
        
        # Fallback: use current working directory
        return os.getcwd()

    def load_emails_from_json_files(self, emails_folder):
        """Load emails from sent.json and inbox.json files"""
        emails = []
        
        # Check both sent.json and inbox.json
        json_files = ['sent.json']
    
        for json_file in json_files:
            filepath = os.path.join(emails_folder, json_file)
            if not os.path.exists(filepath):
                print(f"📁 {json_file} not found at {filepath}")
                continue
                
            try:
                with open(filepath, "r") as f:
                    data = json.load(f)
                    
                if isinstance(data, list):
                    print(f"📧 Loading {len(data)} emails from {json_file}")
                    for email_data in data:
                        # Filter emails for this user
                        if email_data.get("to") == self.username:
                            # Convert to expected format
                            email_entry = {
                                "from": email_data.get("from", "Unknown"),
                                "to": email_data.get("to", "Unknown"),
                                "subject": email_data.get("subject", "No Subject"),
                                "timestamp": email_data.get("timestamp", "Unknown"),
                                "encrypted_content": email_data.get("encrypted_data", {}),
                                "source_file": json_file
                            }
                            emails.append(email_entry)
                            print(f"✅ Added email: {email_entry['subject']} from {json_file}")
                else:
                    print(f"⚠️ {json_file} is not a list, skipping")
                    
            except Exception as e:
                print(f"❌ Failed to read {json_file}: {e}")
                continue
        
        return emails

    def load_emails_from_individual_files(self, emails_folder):
        """Load emails from individual JSON files (legacy format)"""
        emails = []
        
        files = [f for f in os.listdir(emails_folder) if f.endswith(".json") and f not in ['sent.json', 'inbox.json']]
        files.sort(reverse=True)

        for file_name in files:
            filepath = os.path.join(emails_folder, file_name)
            try:
                with open(filepath, "r") as f:
                    data = json.load(f)
                    
                if isinstance(data, list):
                    print(f"⚠️ Skipping {file_name} because it contains a list")
                    continue
                    
            except Exception as e:
                print(f"⚠️ Failed to read {file_name}: {e}")
                continue

            metadata = data.get("metadata", {})
            if metadata.get("to") != self.username:
                continue

            email_entry = {
                "from": metadata.get("from", "Unknown"),
                "to": metadata.get("to", "Unknown"),
                "subject": metadata.get("subject", "No Subject"),
                "timestamp": metadata.get("sent_at", "Unknown"),
                "encrypted_content": data.get("encrypted_data", {}),
                "source_file": file_name
            }
            emails.append(email_entry)
            print(f"✅ Added email from individual file: {email_entry['subject']}")

        return emails

    def load_emails(self):
        """Load emails from both JSON files and individual files"""
        # Use same project root detection as compose window
        project_root = self.get_project_root()
        emails_folder = os.path.join(project_root,"server", "emails")
        
        print(f"📁 Looking for emails in: {emails_folder}")
        
        if not os.path.exists(emails_folder):
            print(f"❌ Emails folder not found: {emails_folder}")
            self.status_label.setText("No emails folder found")
            return

        self.emails = []
        self.email_items = []

        # Clear existing items
        for i in reversed(range(self.email_list_layout.count())):
            item = self.email_list_layout.itemAt(i)
            if item.widget():
                item.widget().setParent(None)

        # Load emails from sent.json and inbox.json
        emails_from_json = self.load_emails_from_json_files(emails_folder)
        
        # Load emails from individual files (legacy)
        emails_from_individual = self.load_emails_from_individual_files(emails_folder)
        
        # Combine all emails
        all_emails = emails_from_json + emails_from_individual
        
        # Sort by timestamp (newest first)
        all_emails.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        # Create email items
        for email_entry in all_emails:
            email_item = EmailItem(email_entry, len(self.emails))
            email_item.clicked.connect(self.handle_email_selection)
            self.email_list_layout.addWidget(email_item)

            self.emails.append(email_entry)
            self.email_items.append(email_item)

        self.email_list_layout.addStretch()

        if not self.emails:
            no_emails_label = QLabel(f"No encrypted emails found for {self.username}")
            no_emails_label.setAlignment(Qt.AlignCenter)
            no_emails_label.setStyleSheet("color: #666; font-style: italic; padding: 20px; font-size: 14px;")
            self.email_list_layout.addWidget(no_emails_label)
            self.status_label.setText("No emails for your account.")
        else:
            self.status_label.setText(f"{len(self.emails)} emails loaded for {self.username}")
            print(f"✅ Total emails loaded: {len(self.emails)}")

    def handle_email_selection(self, email_item):
        self.selected_email = email_item.email_data

        if self.selected_item:
            self.selected_item.set_selected(False)

        email_item.set_selected(True)
        self.selected_item = email_item

        content = f"""From: {self.selected_email.get('from', 'Unknown')}
To: {self.selected_email.get('to', 'Unknown')}
Subject: {self.selected_email.get('subject', 'No Subject')}
Source: {self.selected_email.get('source_file', 'Unknown')}

Status: Encrypted - Click 'Decrypt Message' to view content"""
        self.email_content.setPlainText(content)
        self.decrypt_button.setEnabled(True)
        self.status_label.setText("Email selected")

    def decrypt_selected_email(self):
        if not self.selected_email:
            QMessageBox.warning(self, "No Selection", "Please select an email first.")
            return
    
        self.status_label.setText("Selecting private key...")
    
        recipient = self.selected_email.get("to") or self.username
        encrypted_content = self.selected_email.get("encrypted_content", {})
        kem_algo = encrypted_content.get("kem_algorithm", "Kyber512")
        print(f"📦 Encrypted email ka KEM algorithm: {kem_algo}")

    
        project_root = self.get_project_root()
        recipient_keys_path = os.path.join(project_root, f"{recipient}_keys")
    
        pem_path = None
        for root, dirs, files in os.walk(recipient_keys_path):
            for file in files:
                if file.endswith("_private.key") and kem_algo in file:
                    pem_path = os.path.join(root, file)
                    print(f"✅ Found matching private key: {pem_path}")
                    break
            if pem_path:
                break
            
        if not pem_path:
            self.status_label.setText("Private key not found")
            QMessageBox.critical(
                self, "Key Error", f"No matching private key file found in {recipient_keys_path}"
            )
            return
    
        self.status_label.setText("Decrypting...")
    
        try:
            with open(pem_path, "rb") as f:
                pem_bytes = f.read()
            try:
                pem_text = pem_bytes.decode('utf-8')
                lines = pem_text.split('\n')
                b64_data = "".join([line.strip() for line in lines if not line.startswith("-----")])
                kem_private_key_b64 = b64_data
            except UnicodeDecodeError:
                kem_private_key_b64 = base64.b64encode(pem_bytes).decode('ascii')
        except Exception as e:
            QMessageBox.critical(self, "Key Error", f"Could not load private key:\n{e}")
            self.status_label.setText("Failed to load private key")
            return
    
        try:
            decrypted = decrypt_and_verify_email(
                encrypted_data=self.selected_email["encrypted_content"],
                kem_private_key_b64=kem_private_key_b64
            )
        except Exception as e:
            QMessageBox.critical(self, "Decryption Error", f"Decryption failed:\n{e}")
            self.status_label.setText("Decryption failed")
            return
    
        if not decrypted.get("success"):
            content = f"DECRYPTION FAILED\n\nError: {decrypted.get('message', 'Unknown error')}"
            self.status_label.setText("Decryption failed")
        else:
            email_data = decrypted.get("email", {})
            signature_status = "Valid" if decrypted.get('signature_valid') else "Invalid"
    
            content = f"""DECRYPTED MESSAGE
    
    From: {email_data.get('from', 'Unknown')}
    To: {email_data.get('to', 'Unknown')}
    Subject: {email_data.get('subject', 'No Subject')}
    Signature: {signature_status}
    
    Message:
    {email_data.get('body', 'No content available')}"""
            self.status_label.setText("Message decrypted successfully")
    
            # 🟢 Yeh line sahi jagah (else ke andar) hona chahiye:
            self.email_content.setPlainText(content)
    