 🛡️ OpenSSH Quantum-Safe Mail System

A **Quantum-Safe Email System** built using **OpenSSH + Post-Quantum Cryptography** and a custom SMTP server, with a full **PyQt5 GUI**, secure email encryption, and robust key management.

---

## 🚀 Features

- ✅ **Post-Quantum Encryption** using [Open Quantum Safe (liboqs)](https://openquantumsafe.org/)
- ✅ **Custom SMTP Server** written in Python
- ✅ **AES + KEM Hybrid Encryption**
- ✅ **Digital Signatures using Dilithium, Falcon, etc.**
- ✅ **Key Management with auto key selection**
- ✅ **End-to-End Encrypted Email Transfer**
- ✅ **GUI Interface** for login, inbox, compose, and more

---

## 📁 Project Structure

OPENSSH-MAIL-SYSTEM/
├── gui/ # PyQt5 GUI components
│ ├── algorithm_selector.py
│ ├── email_composer.py
│ ├── inbox_window.py
│ ├── main_window.py
│ └── init.py
│
├── python_backend/ # Crypto logic and application logic
│ ├── aes_crypto.py
│ ├── compose_window.py
│ ├── decrypt_utils.py
│ ├── email_crypto.py
│ ├── inbox_window.py
│ ├── login_window.py
│ ├── register_window.py
│ ├── sshd_launcher.py
│ ├── user_manager.py
│ └── init.py
│
├── mainserver/ # ✅ Custom SMTP Server modules
│ ├── custom_smtp_server.py
│ ├── send_via_smtp.py
│ ├── smtp_handler.py
│ └── init.py
│
├── server/ # Server-side public keys and stored emails
│ ├── emails/
│ └── server_keys/
│ └── public_key/
│ └── {username}/{algorithm}/username_algorithm_public.key
│
├── main.py # 🔷 Main application entry point
├── LICENSE
└── README.md # 📄 You're here!


---

## 🔐 Key Storage

- 🧑‍💻 **Local (Client) Keys:**

username_keys/
└── {algorithm}/
├── {username}_{algorithm}public.key
└── {username}{algorithm}_private.key


- 🌐 **Server Public Keys:**

server/server_keys/public_key/{username}/{algorithm}/{username}_{algorithm}_public.key


---

## ⚙️ How It Works

1. 🔐 Users register → PQ KEM + Signature key pairs are generated.
2. 📥 Incoming & outgoing mail is encrypted using hybrid AES + PQ KEM.
3. 📨 Custom SMTP server transmits emails securely.
4. 📬 Inbox displays encrypted messages, decrypted with private key.

---

🧪 Algorithms Supported
Algorithm Type	Algorithms
🔐 KEM (Key Exchange)	Kyber512, Kyber768, Kyber1024, BIKE-L1, BIKE-L3, FrodoKEM-640-AES, FrodoKEM-640-SHAKE, FrodoKEM-976-AES, FrodoKEM-976-SHAKE, NTRU-HPS-2048-509, NTRU-HPS-2048-677, NTRU-HRSS-701, SABER, LightSaber, FireSaber, Classic-McEliece-348864, Classic-McEliece-460896, Classic-McEliece-6688128
✍️ Signatures	Dilithium2, Dilithium3, Dilithium5, Falcon-512, Falcon-1024, SPHINCS+-SHA2-128s, SPHINCS+-SHA2-192s, SPHINCS+-SHA2-256s, SPHINCS+-SHAKE-128s, SPHINCS+-SHAKE-192s, SPHINCS+-SHAKE-256s, Rainbow-I-Classic, Rainbow-III-Classic, Rainbow-V-Classic

## 💡 Tech Stack

- 🐍 Python 3
- 💻 PyQt5 (GUI)
- 🔐 [liboqs-python](https://github.com/open-quantum-safe/liboqs-python)
- 📡 Custom SMTP via `smtplib` and sockets
- 🧵 Threads and subprocess for SSHD integration

---

## ▶️ Run the Application

```bash
python main.py

    Make sure all required keys are generated, and liboqs is properly installed.

🛠️ Installation Notes

    Install dependencies:

pip install -r requirements.txt

Clone and build liboqs:

git clone --recursive https://github.com/open-quantum-safe/liboqs
cd liboqs
cmake -DCMAKE_INSTALL_PREFIX=../liboqs-install .
make && make install

Install liboqs-python:

    git clone https://github.com/open-quantum-safe/liboqs-python
    cd liboqs-python
    python3 setup.py build
    python3 setup.py install

🧠 Author Info

👨‍💻 Dinesh Saini
MCA Student, NIT Trichy
Built this as a secure communication project under the post-quantum cryptography domain.
📜 License

This project is licensed under the MIT License. See LICENSE file for details.
🌐 GitHub

🔗 GitHub Repo: https://github.com/Dsaini2002/OPENSSH-MAIL-SYSTEM

