#!/usr/bin/env python3
"""
inbox_window.py - Quantum Crypto Integrated Email Client
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import json
import base64
from datetime import datetime
import threading
import time

# Import your email_crypto module
try:
    from python_backend.email_crypto import encrypt_and_sign_email, decrypt_and_verify_email, OQS_AVAILABLE
    CRYPTO_AVAILABLE = True
    print("INFO: email_crypto module loaded successfully")
except ImportError:
    CRYPTO_AVAILABLE = False
    OQS_AVAILABLE = False
    print("WARNING: email_crypto module not available - using simulation mode")

class QuantumCrypto:
    """Quantum cryptography implementation using email_crypto module"""
    
    def __init__(self, kem_algorithm="Kyber512", sig_algorithm="Dilithium2"):
        self.kem_algorithm = kem_algorithm
        self.sig_algorithm = sig_algorithm
        self.crypto_config = {
            "kem": kem_algorithm,
            "sig": sig_algorithm
        }
        self.last_private_key = None  # Store private key for decryption
        
        if CRYPTO_AVAILABLE:
            print(f"INFO: Using real quantum crypto - KEM: {self.kem_algorithm}, Sig: {self.sig_algorithm}")
        else:
            print("INFO: Using simulation mode for crypto operations")
    
    def encrypt_email(self, subject, body, sender_email):
        """Encrypt email with quantum cryptography using email_crypto module"""
        
        if not CRYPTO_AVAILABLE:
            # Simulation mode
            return self._simulate_encryption(subject, body, sender_email)
        
        try:
            # Create email data in the format expected by email_crypto
            email_data = {
                'to': 'recipient@example.com',  # Default recipient
                'from': sender_email,
                'subject': subject,
                'body': body
            }
            
            # Use email_crypto module for encryption
            encrypted_result = encrypt_and_sign_email(email_data, self.crypto_config)
            
            # Store private key for later decryption
            self.last_private_key = encrypted_result.get('kem_private_key')
            
            # Check if encryption was successful
            if encrypted_result["metadata"]["encrypted"]:
                print(f"INFO: Email encrypted and signed successfully")
                return encrypted_result
            else:
                raise ValueError(f"Encryption failed: {encrypted_result['metadata'].get('error_message', 'Unknown error')}")
            
        except Exception as e:
            print(f"ERROR: Encryption failed: {e}")
            raise
    
    def decrypt_email(self, encrypted_data, private_key=None):
        """Decrypt email with quantum cryptography using email_crypto module"""
        
        if not CRYPTO_AVAILABLE:
            # Simulation mode
            return self._simulate_decryption(encrypted_data)
        
        try:
            # Use provided private key or last stored private key
            kem_private_key = private_key or self.last_private_key
            
            if not kem_private_key:
                raise ValueError("No private key available for decryption")
            
            # Use email_crypto module for decryption
            decrypted_result = decrypt_and_verify_email(
                encrypted_data, 
                self.crypto_config, 
                kem_private_key
            )
            
            # Check if decryption was successful
            if decrypted_result.get("error"):
                raise ValueError(f"Decryption failed: {decrypted_result['error_message']}")
            
            # Convert back to our expected format
            email_content = {
                'subject': decrypted_result['subject'],
                'body': decrypted_result['body'],
                'sender': decrypted_result['from'],
                'timestamp': decrypted_result.get('timestamp', datetime.now().isoformat()),
                'signature_valid': decrypted_result.get('signature_valid', False)
            }
            
            print(f"INFO: Email decrypted successfully")
            print(f"INFO: Signature verification: {'VALID' if email_content['signature_valid'] else 'INVALID'}")
            
            return email_content
            
        except Exception as e:
            print(f"ERROR: Decryption failed: {e}")
            raise
    
    def _simulate_encryption(self, subject, body, sender_email):
        """Simulate encryption for demo purposes"""
        email_content = {
            'subject': subject,
            'body': body,
            'sender': sender_email,
            'timestamp': datetime.now().isoformat()
        }
        
        # Simulate encrypted payload in email_crypto format
        simulated_data = {
            'payload': {
                'encrypted_content': base64.b64encode(json.dumps(email_content).encode()).decode(),
                'ciphertext': base64.b64encode(b"simulated_ciphertext").decode(),
                'signature': base64.b64encode(b"simulated_signature").decode(),
                'sig_public_key': base64.b64encode(b"simulated_public_key").decode()
            },
            'metadata': {
                'kem': 'Kyber512-SIM',
                'signature': 'Dilithium2-SIM',
                'timestamp': datetime.now().isoformat(),
                'encrypted': True,
                'signed': True,
                'quantum_safe': False
            },
            'kem_private_key': base64.b64encode(b"simulated_private_key").decode()
        }
        
        self.last_private_key = simulated_data['kem_private_key']
        
        print("INFO: Email encrypted (simulation mode)")
        return simulated_data
    
    def _simulate_decryption(self, encrypted_data):
        """Simulate decryption for demo purposes"""
        try:
            # Extract from simulation
            payload = encrypted_data['payload']
            encrypted_content = base64.b64decode(payload['encrypted_content'])
            email_content = json.loads(encrypted_content.decode('utf-8'))
            
            email_content['signature_valid'] = True  # Simulate valid signature
            
            print("INFO: Email decrypted (simulation mode)")
            print("INFO: Signature verification: VALID (simulated)")
            
            return email_content
            
        except Exception as e:
            print(f"ERROR: Simulation decryption failed: {e}")
            raise


class InboxWindow:
    """Main inbox window with quantum crypto integration"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Quantum Email Client - Inbox")
        self.root.geometry("1000x700")
        
        # Initialize quantum crypto
        self.quantum_crypto = QuantumCrypto()
        
        # Email storage
        self.emails = []
        self.encrypted_emails = []
        
        self.create_widgets()
        self.load_sample_emails()
    
    def create_widgets(self):
        """Create GUI widgets"""
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="🔐 Quantum Email Client", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))
        
        # Status
        if CRYPTO_AVAILABLE:
            if OQS_AVAILABLE:
                status_text = "🟢 Real Quantum Crypto Available"
            else:
                status_text = "🟡 Mock Quantum Crypto (email_crypto module)"
        else:
            status_text = "🔴 Simulation Mode Only"
        status_label = ttk.Label(main_frame, text=status_text, 
                                font=('Arial', 10))
        status_label.grid(row=1, column=0, columnspan=2, pady=(0, 10))
        
        # Email list frame
        list_frame = ttk.LabelFrame(main_frame, text="📧 Email List", padding="5")
        list_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), 
                       padx=(0, 5), pady=(0, 10))
        
        # Email listbox
        self.email_listbox = tk.Listbox(list_frame, height=15, width=50)
        self.email_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.email_listbox.bind('<<ListboxSelect>>', self.on_email_select)
        
        # Email content frame
        content_frame = ttk.LabelFrame(main_frame, text="📄 Email Content", padding="5")
        content_frame.grid(row=2, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), 
                          padx=(5, 0), pady=(0, 10))
        
        # Email content display
        self.content_text = scrolledtext.ScrolledText(content_frame, 
                                                     width=60, height=20,
                                                     wrap=tk.WORD)
        self.content_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        # Buttons
        ttk.Button(button_frame, text="📝 Compose Email", 
                  command=self.compose_email).grid(row=0, column=0, padx=5)
        
        ttk.Button(button_frame, text="🔒 Encrypt Selected", 
                  command=self.encrypt_selected_email).grid(row=0, column=1, padx=5)
        
        ttk.Button(button_frame, text="🔓 Decrypt Selected", 
                  command=self.decrypt_selected_email).grid(row=0, column=2, padx=5)
        
        ttk.Button(button_frame, text="💾 Save Encrypted", 
                  command=self.save_encrypted_email).grid(row=0, column=3, padx=5)
        
        ttk.Button(button_frame, text="📂 Load Encrypted", 
                  command=self.load_encrypted_email).grid(row=0, column=4, padx=5)
        
        # Configure grid weights
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=2)
        main_frame.rowconfigure(2, weight=1)
        
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        content_frame.columnconfigure(0, weight=1)
        content_frame.rowconfigure(0, weight=1)
    
    def load_sample_emails(self):
        """Load sample emails"""
        sample_emails = [
            {
                'subject': 'Welcome to Quantum Email!',
                'body': 'This is a test email to demonstrate quantum cryptography integration.',
                'sender': 'admin@quantumail.com',
                'timestamp': datetime.now().isoformat()
            },
            {
                'subject': 'Test Message',
                'body': 'Another test email for encryption/decryption testing.',
                'sender': 'test@example.com',
                'timestamp': datetime.now().isoformat()
            }
        ]
        
        self.emails = sample_emails
        self.refresh_email_list()
    
    def refresh_email_list(self):
        """Refresh email list display"""
        self.email_listbox.delete(0, tk.END)
        
        for i, email in enumerate(self.emails):
            display_text = f"📧 {email['subject']} - {email['sender']}"
            self.email_listbox.insert(tk.END, display_text)
        
        for i, enc_email in enumerate(self.encrypted_emails):
            timestamp = enc_email['metadata'].get('timestamp', 'Unknown')
            display_text = f"🔒 [ENCRYPTED] {timestamp}"
            self.email_listbox.insert(tk.END, display_text)
    
    def on_email_select(self, event):
        """Handle email selection"""
        selection = self.email_listbox.curselection()
        if not selection:
            return
        
        index = selection[0]
        
        if index < len(self.emails):
            # Regular email
            email = self.emails[index]
            content = f"From: {email['sender']}\n"
            content += f"Subject: {email['subject']}\n"
            content += f"Date: {email['timestamp']}\n"
            content += f"\n{email['body']}"
            
        else:
            # Encrypted email
            enc_index = index - len(self.emails)
            enc_email = self.encrypted_emails[enc_index]
            content = f"🔒 ENCRYPTED EMAIL\n"
            content += f"KEM Algorithm: {enc_email['metadata'].get('kem', 'Unknown')}\n"
            content += f"Signature Algorithm: {enc_email['metadata'].get('signature', 'Unknown')}\n"
            content += f"Encrypted: {enc_email['metadata'].get('timestamp', 'Unknown')}\n"
            content += f"Quantum Safe: {enc_email['metadata'].get('quantum_safe', False)}\n"
            content += f"\nClick 'Decrypt Selected' to view content"
        
        self.content_text.delete(1.0, tk.END)
        self.content_text.insert(1.0, content)
    
    def compose_email(self):
        """Open compose email dialog"""
        ComposeDialog(self.root, self.add_email)
    
    def add_email(self, subject, body, sender):
        """Add new email to list"""
        new_email = {
            'subject': subject,
            'body': body,
            'sender': sender,
            'timestamp': datetime.now().isoformat()
        }
        
        self.emails.append(new_email)
        self.refresh_email_list()
    
    def encrypt_selected_email(self):
        """Encrypt selected email"""
        selection = self.email_listbox.curselection()
        if not selection or selection[0] >= len(self.emails):
            messagebox.showwarning("Warning", "Please select a regular email to encrypt")
            return
        
        email = self.emails[selection[0]]
        
        try:
            # Show progress
            progress = ProgressDialog(self.root, "Encrypting email...")
            
            def encrypt_task():
                encrypted_data = self.quantum_crypto.encrypt_email(
                    email['subject'], email['body'], email['sender']
                )
                self.encrypted_emails.append(encrypted_data)
                progress.close()
                
                # Update UI in main thread
                self.root.after(0, lambda: [
                    self.refresh_email_list(),
                    messagebox.showinfo("Success", "Email encrypted successfully!")
                ])
            
            # Run encryption in background
            threading.Thread(target=encrypt_task, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_selected_email(self):
        """Decrypt selected email"""
        selection = self.email_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an email")
            return
        
        index = selection[0]
        
        if index < len(self.emails):
            messagebox.showinfo("Info", "Selected email is already decrypted")
            return
        
        enc_index = index - len(self.emails)
        enc_email = self.encrypted_emails[enc_index]
        
        try:
            # Show progress
            progress = ProgressDialog(self.root, "Decrypting email...")
            
            def decrypt_task():
                decrypted_email = self.quantum_crypto.decrypt_email(enc_email)
                progress.close()
                
                # Update UI in main thread
                def update_ui():
                    content = f"🔓 DECRYPTED EMAIL\n"
                    content += f"From: {decrypted_email['sender']}\n"
                    content += f"Subject: {decrypted_email['subject']}\n"
                    content += f"Date: {decrypted_email['timestamp']}\n"
                    content += f"Signature Valid: {decrypted_email.get('signature_valid', False)}\n"
                    content += f"\n{decrypted_email['body']}"
                    
                    self.content_text.delete(1.0, tk.END)
                    self.content_text.insert(1.0, content)
                    
                    sig_status = "✅ VALID" if decrypted_email.get('signature_valid', False) else "❌ INVALID"
                    messagebox.showinfo("Success", f"Email decrypted successfully!\nSignature: {sig_status}")
                
                self.root.after(0, update_ui)
            
            # Run decryption in background
            threading.Thread(target=decrypt_task, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    def save_encrypted_email(self):
        """Save encrypted email to file"""
        selection = self.email_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an encrypted email")
            return
        
        index = selection[0]
        
        if index < len(self.emails):
            messagebox.showwarning("Warning", "Please select an encrypted email")
            return
        
        enc_index = index - len(self.emails)
        enc_email = self.encrypted_emails[enc_index]
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(enc_email, f, indent=2)
                messagebox.showinfo("Success", f"Encrypted email saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")
    
    def load_encrypted_email(self):
        """Load encrypted email from file"""
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    enc_email = json.load(f)
                
                # Validate structure
                if 'payload' not in enc_email or 'metadata' not in enc_email:
                    raise ValueError("Invalid encrypted email format")
                
                self.encrypted_emails.append(enc_email)
                self.refresh_email_list()
                messagebox.showinfo("Success", f"Encrypted email loaded from {filename}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")


class ComposeDialog:
    """Dialog for composing new emails"""
    
    def __init__(self, parent, callback):
        self.callback = callback
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Compose Email")
        self.dialog.geometry("500x400")
        self.dialog.grab_set()
        
        self.create_widgets()
    
    def create_widgets(self):
        """Create dialog widgets"""
        frame = ttk.Frame(self.dialog, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Sender
        ttk.Label(frame, text="From:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.sender_entry = ttk.Entry(frame, width=50)
        self.sender_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        self.sender_entry.insert(0, "user@example.com")
        
        # Subject
        ttk.Label(frame, text="Subject:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.subject_entry = ttk.Entry(frame, width=50)
        self.subject_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # Body
        ttk.Label(frame, text="Body:").grid(row=2, column=0, sticky=(tk.W, tk.N), pady=5)
        self.body_text = scrolledtext.ScrolledText(frame, width=50, height=15)
        self.body_text.grid(row=2, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Send", command=self.send_email).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.dialog.destroy).grid(row=0, column=1, padx=5)
        
        # Configure grid
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(2, weight=1)
        
        self.dialog.columnconfigure(0, weight=1)
        self.dialog.rowconfigure(0, weight=1)
    
    def send_email(self):
        """Send email"""
        sender = self.sender_entry.get().strip()
        subject = self.subject_entry.get().strip()
        body = self.body_text.get(1.0, tk.END).strip()
        
        if not sender or not subject or not body:
            messagebox.showwarning("Warning", "Please fill all fields")
            return
        
        self.callback(subject, body, sender)
        self.dialog.destroy()


class ProgressDialog:
    """Progress dialog for long operations"""
    
    def __init__(self, parent, message):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Processing")
        self.dialog.geometry("300x100")
        self.dialog.grab_set()
        
        frame = ttk.Frame(self.dialog, padding="20")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text=message).grid(row=0, column=0, pady=10)
        
        self.progress = ttk.Progressbar(frame, mode='indeterminate')
        self.progress.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=10)
        self.progress.start()
        
        frame.columnconfigure(0, weight=1)
        
        self.dialog.columnconfigure(0, weight=1)
        self.dialog.rowconfigure(0, weight=1)
    
    def close(self):
        """Close dialog"""
        self.dialog.destroy()


def main():
    """Main function"""
    root = tk.Tk()
    app = InboxWindow(root)
    root.mainloop()


if __name__ == "__main__":
    main()