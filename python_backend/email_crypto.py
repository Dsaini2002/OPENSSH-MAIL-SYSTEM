import base64
import json
import oqs
import traceback
import os  # Add missing import
print("✅✅ Loaded email_crypto.py")

class CryptoError(Exception):
    pass

def load_kyber_public_key(path):
    """Load Kyber public key as binary"""
    with open(path, "rb") as f:
        return f.read()

def load_kyber_private_key(path):
    """Load Kyber private key as binary"""
    with open(path, "rb") as f:
        return f.read()

def aes_encrypt(plaintext, key):
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return iv + ciphertext

def aes_decrypt(ciphertext_with_iv, key):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    iv = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

class EmailCrypto:
    @staticmethod
    def encrypt_and_sign_email(email_data, crypto_config):
        """
        Encrypt and sign email data.
        crypto_config: dict with 'kem', 'sig', 'recipient_cert'
        """
        print("✅✅ Running encrypt_and_sign_email function")
        traceback.print_stack()
        try:
            kem = oqs.KeyEncapsulation(crypto_config["kem"])
            sig = oqs.Signature(crypto_config["sig"])
            
            # Generate signature keypair
            sig_public_key = sig.generate_keypair()
            print("🟢 Signature keypair generated")
            
            # Load recipient KEM public key
            kem_public_key = load_kyber_public_key(crypto_config["recipient_cert"])
            print("🟢 Recipient Kyber public key loaded")
            
            # KEM encapsulation
            ciphertext, shared_secret = kem.encap_secret(kem_public_key)
            encryption_key = shared_secret[:32]
            print("🟢 KEM encapsulation done")
            
            # AES encrypt
            plaintext_json = json.dumps(email_data)
            encrypted_bytes = aes_encrypt(plaintext_json, encryption_key)
            encrypted_b64 = base64.b64encode(encrypted_bytes).decode()
            print("🟢 AES encryption done")
            
            # Sign the encrypted content
            signature_bytes = sig.sign(encrypted_b64.encode("utf-8"))
            signature_b64 = base64.b64encode(signature_bytes).decode()
            print("🟢 Signature generated")
            
            return {
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "encrypted_content": encrypted_b64,
                "signature": signature_b64,
                "sig_public_key": base64.b64encode(sig_public_key).decode(),
                "kem_algorithm": crypto_config["kem"],
                "sig_algorithm": crypto_config["sig"]
            }
        except Exception as e:
            print(f"❌ Encryption/signing error: {e}")
            raise CryptoError(f"Encryption/signing error: {e}")

    @staticmethod
    def decrypt_and_verify_email(encrypted_data, crypto_config=None, kem_private_key_b64=None):
     """
     Decrypt and verify email data.
     encrypted_data: dict with encrypted content and signature
     crypto_config: dict with 'kem', 'sig', 'private_key_path'
     kem_private_key_b64: base64 encoded private key
     """
     print("✅✅ Running decrypt_and_verify_email function")
     try:
         # Algorithm selection
         kem_algo = encrypted_data.get("kem_algorithm", "Kyber512")
         sig_algo = encrypted_data.get("sig_algorithm", "Dilithium2")
 
         if crypto_config:
             kem_algo = crypto_config.get("kem", kem_algo)
             sig_algo = crypto_config.get("sig", sig_algo)
 
         kem = oqs.KeyEncapsulation(kem_algo)
         sig = oqs.Signature(sig_algo)
         print(f"🟢 OQS initialized: KEM={kem_algo}, SIG={sig_algo}")
 
         # Validate essential fields
         for k in ["encrypted_content", "signature", "sig_public_key"]:
             if k not in encrypted_data:
                 raise CryptoError(f"Missing required key: {k}")
 
         if "ciphertext" not in encrypted_data and "shared_secret" not in encrypted_data:
             raise CryptoError("Missing both 'ciphertext' and 'shared_secret'")
 
         # Determine shared secret
         if "shared_secret" in encrypted_data and encrypted_data["shared_secret"]:
             shared_secret = base64.b64decode(encrypted_data["shared_secret"])
             encryption_key = shared_secret[:32]
             print("🟢 Using provided shared_secret")
         else:
             # Load KEM private key
             if kem_private_key_b64:
                 kem_private_key = base64.b64decode(kem_private_key_b64)
                 print("🟢 Loaded KEM private key from base64")
             elif crypto_config and "private_key_path" in crypto_config:
                 kem_private_key = load_kyber_private_key(crypto_config["private_key_path"])
                 print("🟢 Loaded KEM private key from file")
             else:
                 # 🔁 Try loading from all possible local key paths
                 username = encrypted_data.get("recipient", "unknown")
                 found = False
                 for algo in oqs.get_enabled_KEM_mechanisms():
                     folder_name = algo.replace("-", "")
                     key_path = f"{username}_keys/{folder_name}/{username}_{folder_name}_private.key"
                     if os.path.exists(key_path):
                         try:
                             kem_private_key = load_kyber_private_key(key_path)
                             kem_algo = algo  # update algo
                             print(f"🟢 Auto-loaded private key: {key_path}")
                             found = True
                             break
                         except Exception as e:
                             print(f"⚠️ Failed to load {key_path}: {e}")
                 if not found:
                     raise CryptoError("No private key provided or found automatically.")
 
             # KEM decapsulation
             kem_ciphertext = base64.b64decode(encrypted_data["ciphertext"])
             kem_for_decap = oqs.KeyEncapsulation(kem_algo, kem_private_key)
             shared_secret = kem_for_decap.decap_secret(kem_ciphertext)
             encryption_key = shared_secret[:32]
             print("🟢 KEM decapsulation done")
 
         # Signature verification
         sig_public_key = base64.b64decode(encrypted_data["sig_public_key"])
         signature_bytes = base64.b64decode(encrypted_data["signature"])
         encrypted_content = encrypted_data["encrypted_content"]
 
         if not sig.verify(encrypted_content.encode("utf-8"), signature_bytes, sig_public_key):
             raise CryptoError("Signature verification failed")
         print("🟢 Signature verification passed")
 
         # AES decryption
         encrypted_bytes = base64.b64decode(encrypted_content)
         decrypted_json = aes_decrypt(encrypted_bytes, encryption_key)
         email_data = json.loads(decrypted_json)
         print("🟢 AES decryption successful")
 
         return {
             "success": True,
             "email": email_data,
             "signature_valid": True,
             "kem_algorithm": kem_algo,
             "sig_algorithm": sig_algo
         }
     except Exception as e:
         print(f"❌ Decryption error: {e}")
         return {
             "success": False,
             "message": str(e)
         }
 
    @staticmethod
    def debug_encrypted_data(encrypted_data):
        print("🔍 DEBUGGING ENCRYPTED DATA:")
        print("=" * 50)
        for key, value in encrypted_data.items():
            if key in ['encrypted_content', 'signature', 'sig_public_key', 'ciphertext', 'shared_secret']:
                size = len(value) if value else 0
                print(f"✅ {key}: {size} chars")
            else:
                print(f"ℹ️ {key}: {value}")
        print("=" * 50)
        
        if encrypted_data.get('ciphertext'):
            print("✅ Ciphertext present")
        else:
            print("❌ Ciphertext missing")
        
        if encrypted_data.get('shared_secret'):
            print("✅ Shared secret present")
        else:
            print("❌ Shared secret missing")

# Support both import styles - create function aliases
encrypt_and_sign_email = EmailCrypto.encrypt_and_sign_email
decrypt_and_verify_email = EmailCrypto.decrypt_and_verify_email
debug_encrypted_data = EmailCrypto.debug_encrypted_data

# 🔽🔽🔽 FIXED FUNCTION FOR KEY PATH MANAGEMENT 🔽🔽🔽

def get_key_paths(sender, recipient, sig_algo, kem_algo):
    """
    Construct and validate sender's private keys (local) and recipient's public keys (server).
    """
    print("Sender:", sender)
    print("Recipient:", recipient)
    print("Selected KEM:", kem_algo)
    print("Selected SIG:", sig_algo)  # FIXED: Changed 'si' to 'sig_algo'
    
    sender_sig_priv = f"{sender}_keys/{sig_algo}/{sender}_{sig_algo}_private.key"
    sender_kem_priv = f"{sender}_keys/{kem_algo}/{sender}_{kem_algo}_private.key"
    
    recipient_sig_pub = f"server/server_keys/public_key/{recipient}/{sig_algo}/{recipient}_{sig_algo}_public.key"
    recipient_kem_pub = f"server/server_keys/public_key/{recipient}/{kem_algo}/{recipient}_{kem_algo}_public.key"

    print("🔍 Checking key paths:")
    print(f"  Sender sig private: {sender_sig_priv}")
    print(f"  Sender kem private: {sender_kem_priv}")
    print(f"  Recipient sig public: {recipient_sig_pub}")
    print(f"  Recipient kem public: {recipient_kem_pub}")

    for path in [sender_sig_priv, sender_kem_priv, recipient_sig_pub, recipient_kem_pub]:
        if not os.path.exists(path):
            print(f"❌ Key not found: {path}")
            raise FileNotFoundError(f"❌ Key not found: {path}")
        else:
            print(f"✅ Key found: {path}")
    
    return {
        "sender_sig_priv": sender_sig_priv,
        "sender_kem_priv": sender_kem_priv,
        "recipient_sig_pub": recipient_sig_pub,
        "recipient_kem_pub": recipient_kem_pub,
    }