# main_window.py
from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QMessageBox,
    QFrame,
    QSpacerItem,
    QSizePolicy
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QPixmap, QPalette, QLinearGradient, QColor, QBrush
# Import your Compose and Inbox windows
from python_backend.compose_window import ComposeWindow
from python_backend.inbox_window import InboxWindow

def load_pem_key(filepath):
    """Load a PEM file and return its Base64 string (without headers)"""
    try:
        with open(filepath, "r") as f:
            lines = f.readlines()
            b64_lines = [line.strip() for line in lines if not line.startswith("-----")]
            return "".join(b64_lines)
    except Exception as e:
        print(f"❌ Error loading PEM key: {e}")
        return None

class QuantumEmailMainWindow(QWidget):
    def __init__(self, username):
        super().__init__()
        
        self.setWindowTitle("Quantum Email Client")
        self.username = username  # Store the username properly
        
        # Load KEM private key
        try:
            with open("kem_private_key.b64", "r") as f:
                self.kem_private_key_b64 = f.read().strip()
        except FileNotFoundError:
            self.kem_private_key_b64 = None
        
        self.setup_ui()
        self.apply_styles()
        
        # Initialize windows
        self.compose_window = None
        self.inbox_window = None
    
    def setup_ui(self):
        # Set window to full screen
        self.showMaximized()
        self.setMinimumSize(450, 350)
        
        # Main layout
        main_layout = QVBoxLayout()
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(30, 30, 30, 30)
        self.setLayout(main_layout)
        
        # Header section
        header_frame = QFrame()
        header_frame.setObjectName("headerFrame")
        header_layout = QVBoxLayout()
        header_frame.setLayout(header_layout)
        
        # Title
        title_label = QLabel("Quantum Email Client")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setObjectName("titleLabel")
        header_layout.addWidget(title_label)
        
        # Subtitle with username
        subtitle_label = QLabel(f"Secure Communication with Quantum Cryptography - Welcome {self.username}")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setObjectName("subtitleLabel")
        header_layout.addWidget(subtitle_label)
        
        main_layout.addWidget(header_frame)
        
        # Add spacer
        main_layout.addItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Fixed))
        
        # Buttons section
        buttons_frame = QFrame()
        buttons_frame.setObjectName("buttonsFrame")
        buttons_layout = QVBoxLayout()
        buttons_layout.setSpacing(15)
        buttons_frame.setLayout(buttons_layout)
        
        # Compose Mail Button
        compose_button = QPushButton("Compose New Message")
        compose_button.setObjectName("composeButton")
        compose_button.clicked.connect(self.open_compose_window)
        compose_button.setMinimumHeight(50)
        buttons_layout.addWidget(compose_button)
        
        # Inbox Button
        inbox_button = QPushButton("Open Inbox")
        inbox_button.setObjectName("inboxButton")
        inbox_button.clicked.connect(self.open_inbox_window)  # Fixed: removed username parameter
        inbox_button.setMinimumHeight(50)
        buttons_layout.addWidget(inbox_button)
        
        # Settings Button (placeholder)
        settings_button = QPushButton("Settings")
        settings_button.setObjectName("settingsButton")
        settings_button.clicked.connect(self.show_settings_placeholder)
        settings_button.setMinimumHeight(50)
        buttons_layout.addWidget(settings_button)
        
        main_layout.addWidget(buttons_frame)
        
        # Add expanding spacer
        main_layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))
        
        # Footer section
        footer_frame = QFrame()
        footer_frame.setObjectName("footerFrame")
        footer_layout = QHBoxLayout()
        footer_frame.setLayout(footer_layout)
        
        # Status label with username
        status_label = QLabel(f"Quantum encryption active - User: {self.username}")
        status_label.setObjectName("statusLabel")
        footer_layout.addWidget(status_label)
        
        # Add spacer
        footer_layout.addItem(QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        
        # Exit Button
        exit_button = QPushButton("❌ Exit")
        exit_button.setObjectName("exitButton")
        exit_button.clicked.connect(self.close)
        exit_button.setMaximumWidth(80)
        footer_layout.addWidget(exit_button)
        
        main_layout.addWidget(footer_frame)
    
    def apply_styles(self):
        """Apply modern styling to the window"""
        self.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2C3E50, stop:1 #34495E);
                color: #ECF0F1;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            
            #titleLabel {
                font-size: 28px;
                font-weight: bold;
                color: #3498DB;
                margin: 10px 0;
            }
            
            #subtitleLabel {
                font-size: 14px;
                color: #BDC3C7;
                margin-bottom: 10px;
                font-style: italic;
            }
            
            #headerFrame {
                background: rgba(52, 152, 219, 0.1);
                border: 2px solid #3498DB;
                border-radius: 15px;
                padding: 20px;
                margin-bottom: 10px;
            }
            
            #buttonsFrame {
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 15px;
                padding: 20px;
            }
            
            #footerFrame {
                background: rgba(0, 0, 0, 0.1);
                border-radius: 10px;
                padding: 10px;
            }
            
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #3498DB, stop:1 #2980B9);
                color: white;
                border: none;
                padding: 12px 20px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: bold;
                text-align: left;
                padding-left: 20px;
            }
            
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #5DADE2, stop:1 #3498DB);
            }
            
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2980B9, stop:1 #1F618D);
            }
            
            #composeButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #27AE60, stop:1 #229954);
            }
            
            #composeButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #58D68D, stop:1 #27AE60);
            }
            
            #inboxButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #E67E22, stop:1 #D35400);
            }
            
            #inboxButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #F39C12, stop:1 #E67E22);
            }
            
            #settingsButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #8E44AD, stop:1 #7D3C98);
            }
            
            #settingsButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #A569BD, stop:1 #8E44AD);
            }
            
            #exitButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #E74C3C, stop:1 #C0392B);
                padding: 8px 15px;
                font-size: 12px;
            }
            
            #exitButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #EC7063, stop:1 #E74C3C);
            }
            
            #statusLabel {
                color: #2ECC71;
                font-size: 12px;
                font-weight: bold;
            }
            
            QMessageBox {
                background-color: #34495E;
                color: #ECF0F1;
            }
            
            QMessageBox QPushButton {
                background: #3498DB;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                min-width: 80px;
            }
            
            QMessageBox QPushButton:hover {
                background: #5DADE2;
            }
        """)
    
    def open_compose_window(self):
        """Open compose window with visual feedback"""
        try:
            self.compose_window = ComposeWindow()
            self.compose_window.show()
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Could not open compose window:\n{str(e)}"
            )
    
    def open_inbox_window(self):  # Fixed: removed username parameter
        """Open inbox window with enhanced error handling"""
        # Crypto config
        crypto_config = {
            "kem": "Kyber512",
            "sig": "Dilithium2"
        }
        
        # Load KEM private key from PEM file
        kem_private_key_b64 = load_pem_key("keys/kem_private_key.pem")
        if not kem_private_key_b64:
            QMessageBox.critical(
                self,
                "🔑 Key Error",
                "Could not load kem_private_key.pem.\n\n"
                "Please ensure:\n"
                "• The file exists in the 'keys' directory\n"
                "• The file is readable\n"
                "• The file contains a valid PEM key"
            )
            return
        
        try:
            # Create Inbox Window with keys - Fixed: use self.username
            self.inbox_window = InboxWindow(username=self.username)
            self.inbox_window.show()
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Could not open inbox window:\n{str(e)}"
            )
    
    def show_settings_placeholder(self):
        """Show settings placeholder dialog"""
        QMessageBox.information(
            self,
            "⚙️ Settings",
            "Settings panel coming soon!\n\n"
            "Future features:\n"
            "• Key management\n"
            "• Encryption algorithms\n"
            "• UI themes\n"
            "• Server configuration"
        )
    
    def closeEvent(self, event):
        """Handle window close event"""
        reply = QMessageBox.question(
            self,
            "Exit Quantum Email",
            "Are you sure you want to exit?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Close any open windows
            if self.compose_window:
                self.compose_window.close()
            if self.inbox_window:
                self.inbox_window.close()
            event.accept()
        else:
            event.ignore()