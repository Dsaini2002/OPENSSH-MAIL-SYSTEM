import os
import json
from datetime import datetime

def save_email_to_json(json_path, email_record):
    """Utility to save email to JSON file"""
    if not os.path.exists(json_path):
        with open(json_path, "w") as f:
            json.dump([], f)

    with open(json_path, "r+") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            data = []
        data.append(email_record)
        f.seek(0)
        json.dump(data, f, indent=2)
        f.truncate()

def send_email(self):
    recipient = self.to_input.text().strip()
    subject = self.subject_input.text().strip()
    message = self.body_input.toPlainText().strip()

    if not recipient or not message:
        QMessageBox.warning(self, "Missing Info", "Recipient and message are required.")
        return

    config = self.get_crypto_config()
    self.status_bar.showMessage("Encrypting and sending...")

    try:
        encrypted_output = encrypt_and_sign_email(
            to=recipient,
            subject=subject,
            body=message,
            kem_algo=config['kem'],
            sig_algo=config['sig'],
            recipient_cert=config['recipient_cert']
        )

        if isinstance(encrypted_output, dict) and 'ciphertext' in encrypted_output:
            encrypted_message = encrypted_output['ciphertext']
        elif isinstance(encrypted_output, str):
            encrypted_message = encrypted_output
        else:
            raise ValueError("Invalid encrypted output format")

        sent = send_email_smtp(
            sender_email=config['sender_email'],
            recipient_email=recipient,
            subject=subject,
            encrypted_message=encrypted_message,
            smtp_server=config['smtp_server'],
            smtp_port=config['smtp_port'],
            smtp_username=config['smtp_username'],
            smtp_password=config['smtp_password']
        )

        email_record = {
            "from": config['sender_email'],
            "to": recipient,
            "subject": subject,
            "message": encrypted_message,
            "timestamp": datetime.now().isoformat()
        }

        if sent:
            # ✅ Save to sent.json
            save_email_to_json(
                "/home/dinesh/openssh/openssh/emails/sent.json",
                email_record
            )
            # ✅ Also save to inbox.json (self-test)
            save_email_to_json(
                "/home/dinesh/openssh/openssh/emails/inbox.json",
                email_record
            )

            QMessageBox.information(self, "✅ Success", "Encrypted email sent and saved.")
            self.status_bar.showMessage("✅ Email sent and saved", 5000)
            self.show_banner("✅ Email sent successfully!", color="green")
        else:
            QMessageBox.critical(self, "❌ SMTP Failed", "Encryption succeeded, but sending failed.")
            self.status_bar.showMessage("❌ SMTP failed", 5000)
            self.show_banner("❌ Failed to send email", color="red")

    except Exception as e:
        QMessageBox.critical(self, "❌ Error", f"Send failed: {str(e)}")
        self.status_bar.showMessage("❌ Error occurred", 5000)
        self.show_banner(f"❌ {str(e)}", color="red")
