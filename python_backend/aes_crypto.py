from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64


def pad(data: bytes) -> bytes:
    padding_len = 16 - len(data) % 16
    return data + bytes([padding_len] * padding_len)


def unpad(data: bytes) -> bytes:
    padding_len = data[-1]
    return data[:-padding_len]


def encrypt_email(plaintext: str, key: bytes) -> str:
    """
    Encrypts plaintext string using AES-CBC and returns base64.
    """
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode()))
    return base64.b64encode(iv + ciphertext).decode()


def decrypt_email(ciphertext_b64: str, key: bytes) -> str:
    """
    Decrypts base64 ciphertext string using AES-CBC.
    """
    raw = base64.b64decode(ciphertext_b64)
    iv = raw[:16]
    ciphertext = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext))
    return decrypted.decode()
