import json
import os
import bcrypt
import datetime
import re
import base64
import oqs
from typing import Dict, Any, Optional, Tuple

USERS_FILE = "users.json"

class EmailCrypto:
    """Post-quantum cryptography for email encryption and signing"""
    
    @staticmethod
    def encrypt_and_sign_email(
        message: str,
        sender_username: str,
        recipient_username: str,
        kem_algo: str = "Kyber768",
        sig_algo: str = "Dilithium3"
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Encrypt and sign email message using post-quantum cryptography
        
        Args:
            message: Email message to encrypt
            sender_username: Username of sender
            recipient_username: Username of recipient
            kem_algo: KEM algorithm to use
            sig_algo: Signature algorithm to use
            
        Returns:
            Tuple of (success, message, encrypted_data)
        """
        try:
            # Load recipient's public KEM key
            recipient_kem_public_path = os.path.join(
                "certs", f"{recipient_username}_keys", kem_algo, 
                f"{recipient_username}_{kem_algo}_kem_public.bin"
            )
            
            if not os.path.exists(recipient_kem_public_path):
                return False, f"Recipient's KEM public key not found: {recipient_kem_public_path}", None
            
            with open(recipient_kem_public_path, "rb") as f:
                recipient_kem_public = f.read()
            
            # Load sender's private signature key
            sender_sig_private_path = os.path.join(
                "certs", f"{sender_username}_keys", sig_algo,
                f"{sender_username}_{sig_algo}_sig_private.bin"
            )
            
            if not os.path.exists(sender_sig_private_path):
                return False, f"Sender's signature private key not found: {sender_sig_private_path}", None
            
            with open(sender_sig_private_path, "rb") as f:
                sender_sig_private = f.read()
            
            # Initialize KEM and create shared secret
            kem = oqs.KeyEncapsulation(kem_algo)
            ciphertext, shared_secret = kem.encaps(recipient_kem_public)
            
            # Encrypt message using shared secret (simple XOR for demo - use proper AES in production)
            message_bytes = message.encode('utf-8')
            encrypted_message = bytes(a ^ b for a, b in zip(message_bytes, shared_secret[:len(message_bytes)]))
            
            # Sign the encrypted message
            sig = oqs.Signature(sig_algo)
            signature = sig.sign(encrypted_message, sender_sig_private)
            
            # Create encrypted email package
            encrypted_data = {
                "ciphertext": base64.b64encode(ciphertext).decode('ascii'),
                "encrypted_message": base64.b64encode(encrypted_message).decode('ascii'),
                "signature": base64.b64encode(signature).decode('ascii'),
                "kem_algo": kem_algo,
                "sig_algo": sig_algo,
                "sender": sender_username,
                "recipient": recipient_username,
                "timestamp": datetime.datetime.now().isoformat()
            }
            
            return True, "Email encrypted and signed successfully", encrypted_data
            
        except Exception as e:
            return False, f"Error encrypting email: {str(e)}", None
    
    @staticmethod
    def decrypt_and_verify_email(
        encrypted_data: Dict[str, Any],
        recipient_username: str
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Decrypt and verify email message
        
        Args:
            encrypted_data: Encrypted email data
            recipient_username: Username of recipient
            
        Returns:
            Tuple of (success, message, decrypted_message)
        """
        try:
            kem_algo = encrypted_data["kem_algo"]
            sig_algo = encrypted_data["sig_algo"]
            sender_username = encrypted_data["sender"]
            
            # Load recipient's private KEM key
            recipient_kem_private_path = os.path.join(
                "certs", f"{recipient_username}_keys", kem_algo,
                f"{recipient_username}_{kem_algo}_kem_private.bin"
            )
            
            if not os.path.exists(recipient_kem_private_path):
                return False, f"Recipient's KEM private key not found", None
            
            with open(recipient_kem_private_path, "rb") as f:
                recipient_kem_private = f.read()
            
            # Load sender's public signature key
            sender_sig_public_path = os.path.join(
                "certs", f"{sender_username}_keys", sig_algo,
                f"{sender_username}_{sig_algo}_sig_public.bin"
            )
            
            if not os.path.exists(sender_sig_public_path):
                return False, f"Sender's signature public key not found", None
            
            with open(sender_sig_public_path, "rb") as f:
                sender_sig_public = f.read()
            
            # Decode data
            ciphertext = base64.b64decode(encrypted_data["ciphertext"])
            encrypted_message = base64.b64decode(encrypted_data["encrypted_message"])
            signature = base64.b64decode(encrypted_data["signature"])
            
            # Verify signature
            sig = oqs.Signature(sig_algo)
            is_valid = sig.verify(encrypted_message, signature, sender_sig_public)
            
            if not is_valid:
                return False, "Signature verification failed", None
            
            # Decrypt message
            kem = oqs.KeyEncapsulation(kem_algo)
            shared_secret = kem.decaps(ciphertext, recipient_kem_private)
            
            # Decrypt message (reverse XOR)
            decrypted_bytes = bytes(a ^ b for a, b in zip(encrypted_message, shared_secret[:len(encrypted_message)]))
            decrypted_message = decrypted_bytes.decode('utf-8')
            
            return True, "Email decrypted and verified successfully", decrypted_message
            
        except Exception as e:
            return False, f"Error decrypting email: {str(e)}", None

class UserManager:
    def __init__(self, users_file: str = USERS_FILE):
        self.users_file = users_file
        self._initialize_users_file()
    
    def _initialize_users_file(self):
        """Initialize users file if it doesn't exist"""
        if not os.path.exists(self.users_file):
            with open(self.users_file, "w") as f:
                json.dump({}, f)
    
    def load_users(self) -> Dict[str, Any]:
        """Load users from JSON file with error handling"""
        try:
            with open(self.users_file, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading users: {e}")
            return {}
    
    def save_users(self, users: Dict[str, Any]) -> bool:
        """Save users to JSON file with error handling"""
        try:
            with open(self.users_file, "w") as f:
                json.dump(users, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving users: {e}")
            return False
    
    def _validate_username(self, username: str) -> bool:
        """Validate username format"""
        if not username or len(username) < 3 or len(username) > 20:
            return False
        return re.match(r'^[a-zA-Z0-9_]+$', username) is not None
    
    def _validate_password(self, password: str) -> Tuple[bool, str]:
        """Validate password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit"
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        return True, "Password is valid"
    
    def register_user(self, username: str, password: str, user_data: Dict[str, Any] = None) -> Tuple[bool, str]:
        """Register a new user with validation"""
        if user_data is None:
            user_data = {}
        
        # Validate username
        if not self._validate_username(username):
            return False, "Username must be 3-20 characters long and contain only letters, numbers, and underscores"
        
        # Validate password
        is_valid, message = self._validate_password(password)
        if not is_valid:
            return False, message
        
        users = self.load_users()
        
        # Check if user already exists
        if username in users:
            return False, "User already exists"
        
        # Hash password
        try:
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        except Exception as e:
            return False, f"Error hashing password: {e}"
        
        # Create user record
        users[username] = {
            "password_hash": password_hash,
            "created_at": datetime.datetime.now().isoformat(),
            "last_login": None,
            "is_active": True,
            "login_attempts": 0,
            "locked_until": None,
            **user_data
        }
        
        if self.save_users(users):
            # Generate crypto keys and register on server
            self.generate_user_certificates(username)
            return True, "User registered successfully"
        else:
            return False, "Failed to save user data"
    
    def authenticate_user(self, username: str, password: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """Authenticate user with account lockout protection"""
        users = self.load_users()
        
        if username not in users:
            return False, None, "Invalid username or password"
        
        user = users[username]
        
        # Check if account is active
        if not user.get("is_active", True):
            return False, None, "Account is deactivated"
        
        # Check if account is locked
        if user.get("locked_until"):
            locked_until = datetime.datetime.fromisoformat(user["locked_until"])
            if datetime.datetime.now() < locked_until:
                return False, None, f"Account is locked until {locked_until.strftime('%Y-%m-%d %H:%M:%S')}"
            else:
                # Unlock account
                user["locked_until"] = None
                user["login_attempts"] = 0
        
        # Check password
        try:
            stored_hash = user["password_hash"].encode()
            if bcrypt.checkpw(password.encode(), stored_hash):
                # Successful login
                user["last_login"] = datetime.datetime.now().isoformat()
                user["login_attempts"] = 0
                user["locked_until"] = None
                self.save_users(users)
                return True, user, "Login successful"
            else:
                # Failed login
                user["login_attempts"] = user.get("login_attempts", 0) + 1
                if user["login_attempts"] >= 5:
                    # Lock account for 30 minutes
                    lock_time = datetime.datetime.now() + datetime.timedelta(minutes=30)
                    user["locked_until"] = lock_time.isoformat()
                    self.save_users(users)
                    return False, None, "Account locked due to too many failed attempts"
                else:
                    self.save_users(users)
                    return False, None, f"Invalid username or password. {5 - user['login_attempts']} attempts remaining"
        except Exception as e:
            return False, None, f"Authentication error: {e}"
    
    def change_password(self, username: str, old_password: str, new_password: str) -> Tuple[bool, str]:
        """Change user password"""
        # Authenticate with old password
        auth_success, user_data, message = self.authenticate_user(username, old_password)
        if not auth_success:
            return False, "Current password is incorrect"
        
        # Validate new password
        is_valid, validation_message = self._validate_password(new_password)
        if not is_valid:
            return False, validation_message
        
        # Update password
        users = self.load_users()
        try:
            new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
            users[username]["password_hash"] = new_hash
            if self.save_users(users):
                return True, "Password changed successfully"
            else:
                return False, "Failed to save new password"
        except Exception as e:
            return False, f"Error changing password: {e}"
    
    def update_user_data(self, username: str, new_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Update user data"""
        users = self.load_users()
        if username not in users:
            return False, "User not found"
        
        # Don't allow updating sensitive fields
        protected_fields = ["password_hash", "created_at", "login_attempts", "locked_until"]
        for field in protected_fields:
            if field in new_data:
                del new_data[field]
        
        users[username].update(new_data)
        
        if self.save_users(users):
            return True, "User data updated successfully"
        else:
            return False, "Failed to update user data"
    
    def deactivate_user(self, username: str) -> Tuple[bool, str]:
        """Deactivate user account"""
        users = self.load_users()
        if username not in users:
            return False, "User not found"
        
        users[username]["is_active"] = False
        if self.save_users(users):
            return True, "User account deactivated"
        else:
            return False, "Failed to deactivate user account"
    
    def generate_user_certificates(self, username):
        """
        Generate KEM and Signature keys for the user.
        Store public keys on server; private keys only on user machine.
        """
        import json
    
        # Server registry file
        os.makedirs("server", exist_ok=True)
        registry_path = os.path.join("server", "public_keys.json")
    
        # Local key storage path (simulate user's local folder)
        user_dir = os.path.join("certs", f"{username}_keys")
        os.makedirs(user_dir, exist_ok=True)
    
        user_public_keys = {"KEM": {}, "Signature": {}}
    
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
            "FrodoKEM-1344-AES", "FrodoKEM-1344-SHAKE"
        ] 
        
        sig_algos = [
            "Dilithium2", "Dilithium3", "Dilithium5",
            "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
            "Falcon-512", "Falcon-1024",
            "Falcon-padded-512", "Falcon-padded-1024",
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
            "SNOVA_37_8_4", "SNOVA_24_5_5", "SNOVA_60_10_4", "SNOVA_29_6_5"
        ]
    
        for kem_algo in kem_algos:
            try:
                kem_folder = os.path.join(user_dir, kem_algo)
                os.makedirs(kem_folder, exist_ok=True)
        
                kem = oqs.KeyEncapsulation(kem_algo)
                kem_public = kem.generate_keypair()
                kem_private = kem.export_secret_key()
        
                # Save public/private key locally
                with open(os.path.join(kem_folder, f"{username}_{kem_algo}_kem_public.bin"), "wb") as f:
                    f.write(kem_public)
                with open(os.path.join(kem_folder, f"{username}_{kem_algo}_kem_private.bin"), "wb") as f:
                    f.write(kem_private)
        
                # Store public key to send to server
                b64_pub = base64.b64encode(kem_public).decode("ascii")
                user_public_keys["KEM"][kem_algo] = b64_pub
            except Exception as e:
                print(f"Warning: Failed to generate {kem_algo} key: {e}")
    
        for sig_algo in sig_algos:
            try:
                sig_folder = os.path.join(user_dir, sig_algo)
                os.makedirs(sig_folder, exist_ok=True)
        
                sig = oqs.Signature(sig_algo)
                sig_public = sig.generate_keypair()
                sig_private = sig.export_secret_key()
        
                with open(os.path.join(sig_folder, f"{username}_{sig_algo}_sig_public.bin"), "wb") as f:
                    f.write(sig_public)
                with open(os.path.join(sig_folder, f"{username}_{sig_algo}_sig_private.bin"), "wb") as f:
                    f.write(sig_private)
        
                b64_sig = base64.b64encode(sig_public).decode("ascii")
                user_public_keys["Signature"][sig_algo] = b64_sig
            except Exception as e:
                print(f"Warning: Failed to generate {sig_algo} key: {e}")
    
        # Store public keys on server
        if os.path.exists(registry_path):
            with open(registry_path, "r") as f:
                server_keys = json.load(f)
        else:
            server_keys = {}
    
        server_keys[username] = user_public_keys
    
        with open(registry_path, "w") as f:
            json.dump(server_keys, f, indent=2)
    
        print(f"✅ Keys generated for user '{username}' in {user_dir}")
        print(f"✅ Server registry updated at {registry_path}")
    
    def activate_user(self, username: str) -> Tuple[bool, str]:
        """Activate user account"""
        users = self.load_users()
        if username not in users:
            return False, "User not found"
        
        users[username]["is_active"] = True
        users[username]["login_attempts"] = 0
        users[username]["locked_until"] = None
        
        if self.save_users(users):
            return True, "User account activated"
        else:
            return False, "Failed to activate user account"
    
    def delete_user(self, username: str) -> Tuple[bool, str]:
        """Delete user account"""
        users = self.load_users()
        if username not in users:
            return False, "User not found"
        
        del users[username]
        if self.save_users(users):
            return True, "User deleted successfully"
        else:
            return False, "Failed to delete user"
    
    def get_user_info(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user information (without password hash)"""
        users = self.load_users()
        if username not in users:
            return None
        
        user_info = users[username].copy()
        user_info.pop("password_hash", None)  # Remove password hash for security
        return user_info
    
    def list_users(self) -> Dict[str, Dict[str, Any]]:
        """List all users (without password hashes)"""
        users = self.load_users()
        safe_users = {}
        
        for username, user_data in users.items():
            safe_user_data = user_data.copy()
            safe_user_data.pop("password_hash", None)
            safe_users[username] = safe_user_data
        
        return safe_users
    
    def unlock_user(self, username: str) -> Tuple[bool, str]:
        """Manually unlock a locked user account"""
        users = self.load_users()
        if username not in users:
            return False, "User not found"
        
        users[username]["locked_until"] = None
        users[username]["login_attempts"] = 0
        
        if self.save_users(users):
            return True, "User account unlocked"
        else:
            return False, "Failed to unlock user account"

# Example usage
if __name__ == "__main__":
    # Initialize user manager
    user_manager = UserManager()
    
    # Register users
    print("=== User Registration ===")
    success, message = user_manager.register_user("alice", "SecurePass123!")
    print(f"Alice registration: {message}")
    
    success, message = user_manager.register_user("bob", "StrongPass456@")
    print(f"Bob registration: {message}")
    
    # Send encrypted email
    print("\n=== Email Encryption ===")
    email_message = "Hello Bob! This is a confidential message from Alice."
    
    success, message, encrypted_data = EmailCrypto.encrypt_and_sign_email(
        message=email_message,
        sender_username="alice",
        recipient_username="bob",
        kem_algo="Kyber768",
        sig_algo="Dilithium3"
    )
    
    if success:
        print(f"✅ {message}")
        print(f"Encrypted data keys: {list(encrypted_data.keys())}")
        
        # Decrypt email
        print("\n=== Email Decryption ===")
        success, message, decrypted_message = EmailCrypto.decrypt_and_verify_email(
            encrypted_data=encrypted_data,
            recipient_username="bob"
        )
        
        if success:
            print(f"✅ {message}")
            print(f"Decrypted message: {decrypted_message}")
        else:
            print(f"❌ {message}")
    else:
        print(f"❌ {message}")