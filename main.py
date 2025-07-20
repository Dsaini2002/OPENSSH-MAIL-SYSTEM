#!/usr/bin/env python3
"""
Fixed Quantum Email Application - Main Entry Point
Addresses login/register window display issues
"""
import sys
import os
import logging
import argparse
import signal
import atexit

from datetime import datetime

# Setup logging first
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler('quantum_email.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

# Suppress warnings but keep logging
os.environ["PYTHONWARNINGS"] = "ignore"
import warnings
warnings.filterwarnings("ignore")

logger = logging.getLogger(__name__)

# Global variables for cleanup
smtp_server = None
gui_app = None
running_threads = []

def signal_handler(signum, frame):
    """Handle signals gracefully"""
    logger.info(f"📡 Signal {signum} received, shutting down gracefully...")
    cleanup_resources()
    sys.exit(0)

def cleanup_resources():
    """Clean up all resources before exit"""
    global smtp_server, gui_app, running_threads
    
    logger.info("🧹 Cleaning up resources...")
    
    # Clean up SMTP server
    if smtp_server:
        try:
            smtp_server.stop_server()
            logger.info("✅ SMTP server stopped")
        except:
            pass
    
    # Clean up GUI app
    if gui_app:
        try:
            gui_app.quit()
            logger.info("✅ GUI application stopped")
        except:
            pass
    
    # Clean up threads
    for thread in running_threads:
        try:
            if thread.is_alive():
                thread.join(timeout=1.0)
        except:
            pass
    
    logger.info("✅ Cleanup completed")

def setup_qt_environment():
    """Set up Qt environment for better compatibility"""
    logger.info("🔧 Setting up Qt environment...")
    
    # Check if we're in a display environment
    has_display = bool(os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY'))
    
    if not has_display:
        logger.warning("⚠️ No display detected")
        return False
    
    # Set Qt platform if not already set
    if not os.environ.get('QT_QPA_PLATFORM'):
        if os.environ.get('WAYLAND_DISPLAY'):
            os.environ['QT_QPA_PLATFORM'] = 'wayland'
            logger.info("🔧 Set QT_QPA_PLATFORM to wayland")
        else:
            os.environ['QT_QPA_PLATFORM'] = 'xcb'
            logger.info("🔧 Set QT_QPA_PLATFORM to xcb")
    
    # Additional Qt settings for stability
    os.environ['QT_AUTO_SCREEN_SCALE_FACTOR'] = '0'
    os.environ['QT_SCALE_FACTOR'] = '1'
    
    return True

def check_dependencies():
    """Check if all required dependencies are available"""
    missing_deps = []
    
    # Check PyQt5
    try:
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtCore import QTimer
        
        # Test minimal Qt application
        test_app = QApplication([])
        timer = QTimer()
        timer.timeout.connect(test_app.quit)
        timer.start(10)
        test_app.processEvents()
        test_app.quit()
        
        logger.info("✅ PyQt5 available and tested")
    except ImportError:
        missing_deps.append("PyQt5")
        logger.error("❌ PyQt5 not found")
    except Exception as e:
        logger.error(f"❌ PyQt5 test failed: {e}")
        missing_deps.append("PyQt5")
    
    # Check OQS
    try:
        import oqs
        logger.info("✅ OQS (liboqs-python) available")
    except ImportError:
        missing_deps.append("oqs")
        logger.error("❌ OQS not found")
    
    if missing_deps:
        logger.error(f"❌ Missing dependencies: {', '.join(missing_deps)}")
        return False
    
    return True

def test_oqs_functionality():
    """Test OQS quantum cryptography functionality"""
    try:
        logger.info("🔍 Testing OQS quantum cryptography...")
        
        import oqs
        
        # Test KeyEncapsulation
        logger.info("Testing Key Encapsulation Mechanism (KEM)...")
        kem = oqs.KeyEncapsulation('Kyber512')
        public_key = kem.generate_keypair()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        logger.info("✅ KEM test passed")
        
        # Test Digital Signature
        logger.info("Testing Digital Signature...")
        sig = oqs.Signature('Dilithium2')
        sig_public_key = sig.generate_keypair()
        test_msg = b"quantum email test message"
        signature = sig.sign(test_msg)
        is_valid = sig.verify(test_msg, signature, sig_public_key)
        
        if is_valid:
            logger.info("✅ Digital signature test passed")
        else:
            logger.error("❌ Digital signature verification failed")
            return False
        
        logger.info("✅ All OQS quantum cryptography tests passed!")
        return True
        
    except Exception as e:
        logger.error(f"❌ OQS test failed: {e}")
        return False

def discover_quantum_algorithms():
    """Discover available quantum algorithms"""
    try:
        import oqs
        
        # Get available algorithms
        kem_algorithms = oqs.get_enabled_kem_mechanisms()
        sig_algorithms = oqs.get_enabled_sig_mechanisms()
        
        logger.info(f"🔐 Available KEM algorithms: {len(kem_algorithms)}")
        logger.info(f"🔐 Available Signature algorithms: {len(sig_algorithms)}")
        
        # Test a few key algorithms
        working_kem = []
        working_sig = []
        
        test_kems = ['Kyber512', 'Kyber768', 'Kyber1024']
        test_sigs = ['Dilithium2', 'Dilithium3', 'Dilithium5']
        
        for alg in test_kems:
            if alg in kem_algorithms:
                try:
                    test_kem = oqs.KeyEncapsulation(alg)
                    working_kem.append(alg)
                    logger.info(f"✅ {alg} KEM working")
                except Exception as e:
                    logger.warning(f"❌ {alg} KEM failed: {e}")
        
        for alg in test_sigs:
            if alg in sig_algorithms:
                try:
                    test_sig = oqs.Signature(alg)
                    working_sig.append(alg)
                    logger.info(f"✅ {alg} Signature working")
                except Exception as e:
                    logger.warning(f"❌ {alg} Signature failed: {e}")
        
        return {
            'kem': working_kem if working_kem else ['Kyber512'],
            'sig': working_sig if working_sig else ['Dilithium2'],
            'all_kem': kem_algorithms,
            'all_sig': sig_algorithms
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to discover algorithms: {e}")
        return {
            'kem': ['Kyber512'],
            'sig': ['Dilithium2'],
            'all_kem': ['Kyber512'],
            'all_sig': ['Dilithium2']
        }

def get_crypto_config():
    """Get default cryptographic configuration"""
    config = {
        "kem": "Kyber512",
        "sig": "Dilithium2",
        "recipient_cert": "certs/recipient_public.pem",
        "sender_email": "quantum.email@localhost",
        "smtp_server": "localhost",
        "smtp_port": 1025,
        "smtp_username": "quantum",
        "smtp_password": "secure123",
        "enable_tls": False,
        "enable_auth": False
    }
    
    # Check if cert file exists
    if os.path.exists(config["recipient_cert"]):
        logger.info(f"✅ Certificate file found: {config['recipient_cert']}")
    else:
        logger.warning(f"⚠️ Certificate file not found: {config['recipient_cert']}")
    
    return config

def ensure_directories():
    """Ensure required directories exist"""
    directories = [
        "emails",
        "certs",
        "logs"
    ]
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            logger.info(f"📁 Created directory: {directory}")

def start_smtp_server():
    """Start the SMTP server"""
    global smtp_server
    
    try:
        from mainserver.custom_smtp_server import QuantumEmailSMTPServer
        
        smtp_server = QuantumEmailSMTPServer()
        
        if smtp_server.start_server():
            logger.info("✅ SMTP server started successfully on localhost:1025")
            return smtp_server
        else:
            logger.error("❌ Failed to start SMTP server")
            return None
            
    except ImportError as e:
        logger.error(f"❌ Cannot import SMTP server: {e}")
        return None
    except Exception as e:
        logger.error(f"❌ SMTP server error: {e}")
        return None

def start_gui_application(algorithms, crypto_config, smtp_server_instance):
    """Start the GUI application with proper login/register flow"""
    global gui_app
    
    try:
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtCore import QTimer
        
        # Create application
        gui_app = QApplication(sys.argv)
        gui_app.setApplicationName("Quantum Email")
        gui_app.setApplicationVersion("1.0")
        gui_app.setOrganizationName("Quantum Communications")
        
        # Import windows
        from python_backend.login_window import LoginWindow
        from python_backend.register_window import RegisterWindow
        
        # Create application controller
        class QuantumEmailApp:
            def __init__(self):
                self.algorithms = algorithms
                self.crypto_config = crypto_config
                self.smtp_server = smtp_server_instance
                
                # Initialize windows
                self.login_window = None
                self.register_window = None
                self.main_window = None
                
                # Start with login window
                self.show_login()
            
            def show_login(self):
                """Show login window"""
                logger.info("🔐 Showing login window...")
                
                # Close existing windows
                if self.register_window:
                    self.register_window.close()
                if self.main_window:
                    self.main_window.close()
                
                # Create and show login window
                self.login_window = LoginWindow()
                
                # Connect signals if they exist
                if hasattr(self.login_window, 'login_successful'):
                    self.login_window.login_successful.connect(self.on_login_success)
                if hasattr(self.login_window, 'goto_register'):
                    self.login_window.goto_register.connect(self.show_register)
                
                self.login_window.show()
                self.login_window.raise_()
                self.login_window.activateWindow()
                
                logger.info("✅ Login window displayed")
            
            def show_register(self):
                """Show register window"""
                logger.info("📝 Showing register window...")
                
                # Close login window
                if self.login_window:
                    self.login_window.close()
                
                # Create and show register window
                self.register_window = RegisterWindow()
                
                # Connect signals if they exist
                if hasattr(self.register_window, 'register_successful'):
                    self.register_window.register_successful.connect(self.on_register_success)
                if hasattr(self.register_window, 'goto_login'):
                    self.register_window.goto_login.connect(self.show_login)
                
                self.register_window.show()
                self.register_window.raise_()
                self.register_window.activateWindow()
                
                logger.info("✅ Register window displayed")
            
            def on_register_success(self):
                """Handle successful registration"""
                logger.info("✅ Registration successful, returning to login")
                self.show_login()
            
            def on_login_success(self, username):
                """Handle successful login"""
                logger.info(f"✅ Login successful for user: {username}")
                
                # Close login window
                if self.login_window:
                    self.login_window.close()
                
                # Show main application
                self.show_main_app(username)
            
            def show_main_app(self, username):
                """Show main application window"""
                try:
                    logger.info("🚀 Launching main application...")
                    
                    # Import main window
                    from gui.main_window import QuantumEmailMainWindow
                    

                    
                    # Create main window with all required attributes
                    class ConfiguredMainWindow(QuantumEmailMainWindow):
                        def __init__(self, username):
                            self.username=username
                            # Set required attributes before calling super()
                            self.current_user = username
                            self.available_algorithms = algorithms
                            self.crypto_config = crypto_config
                            self.smtp_server = smtp_server_instance
                            
                            # Algorithm lists for compatibility
                            self.all_kem_algorithms = algorithms.get('all_kem', ['Kyber512'])
                            self.all_sig_algorithms = algorithms.get('all_sig', ['Dilithium2'])
                            self.working_kem_algorithms = algorithms.get('kem', ['Kyber512'])
                            self.working_sig_algorithms = algorithms.get('sig', ['Dilithium2'])
                            
                            # Call parent constructor
                            super().__init__(username)
                            
                            # Set window title with username
                            self.setWindowTitle(f"Quantum Email - {username}")
                        
                        def closeEvent(self, event):
                            """Handle window close"""
                            logger.info("🔄 Main application closing...")
                            cleanup_resources()
                            event.accept()
                    
                    # Create and show main window
                    self.main_window = ConfiguredMainWindow(username)
                    self.main_window.show()
                    self.main_window.raise_()
                    self.main_window.activateWindow()
                    
                    logger.info("✅ Main application window displayed")
                    
                except Exception as e:
                    logger.error(f"❌ Failed to show main application: {e}")
                    import traceback
                    traceback.print_exc()
                    # Return to login on error
                    self.show_login()
        
        # Create and start application
        app_controller = QuantumEmailApp()
        
        logger.info("🚀 GUI application started successfully!")
        logger.info("🔧 SMTP Server: localhost:1025")
        logger.info("🔐 Quantum algorithms loaded")
        logger.info("📧 Ready for quantum-encrypted emails")
        
        # Start the application event loop
        result = gui_app.exec_()
        
        # Cleanup after GUI closes
        cleanup_resources()
        
        return result
        
    except ImportError as e:
        logger.error(f"❌ Cannot import GUI components: {e}")
        logger.error("Make sure python_backend.login_window and python_backend.register_window exist")
        return 1
    except Exception as e:
        logger.error(f"❌ GUI application error: {e}")
        import traceback
        traceback.print_exc()
        return 1

def run_cli_mode():
    """Run in CLI mode for testing"""
    logger.info("🖥️ Running in CLI mode")
    
    # Test basic functionality
    if not test_oqs_functionality():
        logger.error("❌ OQS tests failed")
        return 1
    
    # Start SMTP server
    smtp_server_instance = start_smtp_server()
    if not smtp_server_instance:
        logger.error("❌ Cannot start SMTP server")
        return 1
    
    logger.info("✅ CLI mode test completed successfully")
    return 0

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(description="Quantum Email Application")
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode")
    parser.add_argument("--test", action="store_true", help="Run tests only")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    atexit.register(cleanup_resources)
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    logger.info("🚀 Starting Quantum Email Application...")
    logger.info(f"📅 Started at: {datetime.now()}")
    logger.info(f"🐍 Python version: {sys.version}")
    logger.info(f"📂 Working directory: {os.getcwd()}")
    
    # Set up Qt environment (if not CLI mode)
    if not args.cli and not args.test:
        if not setup_qt_environment():
            logger.warning("⚠️ Display environment not detected, switching to CLI mode")
            args.cli = True
    
    # Check dependencies
    if not check_dependencies():
        logger.error("❌ Cannot start application - missing dependencies")
        return 1
    
    # Ensure directories exist
    ensure_directories()
    
    # Test OQS functionality
    if not test_oqs_functionality():
        logger.error("❌ Cannot start application - OQS tests failed")
        return 1
    
    # Discover quantum algorithms
    algorithms = discover_quantum_algorithms()
    crypto_config = get_crypto_config()
    
    if args.test:
        logger.info("🧪 Running in test mode")
        return run_cli_mode()
    
    if args.cli:
        logger.info("🖥️ Running in CLI mode")
        return run_cli_mode()
    
    # Start SMTP server
    smtp_server_instance = start_smtp_server()
    if not smtp_server_instance:
        logger.error("❌ Cannot start application - SMTP server failed")
        return 1
    
    # Start GUI application
    try:
        return start_gui_application(algorithms, crypto_config, smtp_server_instance)
    except KeyboardInterrupt:
        logger.info("🛑 Application interrupted by user")
        return 0
    except Exception as e:
        logger.error(f"❌ Application error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        cleanup_resources()

if __name__ == "__main__":
    sys.exit(main())