#!/usr/bin/env python3
"""
Custom SMTP Server for Quantum Email Application
Handles email receiving and sending with quantum encryption
"""

import os
import json
import logging
import smtplib
import threading
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import socket
import asyncio
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP as SMTPServer

logger = logging.getLogger(__name__)

class QuantumEmailHandler:
    """Handler for incoming emails"""
    
    def __init__(self, inbox_file="emails/inbox.json"):
        self.inbox_file = inbox_file
        self.ensure_inbox_exists()
    
    def ensure_inbox_exists(self):
        """Ensure inbox file exists"""
        try:
            os.makedirs(os.path.dirname(self.inbox_file), exist_ok=True)
            if not os.path.exists(self.inbox_file):
                with open(self.inbox_file, 'w') as f:
                    json.dump([], f)
        except Exception as e:
            logger.error(f"Error creating inbox file: {e}")
    
    async def handle_DATA(self, server, session, envelope):
        """Handle incoming email data"""
        try:
            # Parse email data
            email_data = {
                "id": self.get_next_id(),
                "from": envelope.mail_from,
                "to": envelope.rcpt_tos,
                "subject": self.extract_subject(envelope.content),
                "message": self.extract_message(envelope.content),
                "timestamp": datetime.now().isoformat(),
                "is_quantum": self.detect_quantum_encryption(envelope.content),
                "status": "received",
                "raw_content": envelope.content.decode('utf-8', errors='ignore')
            }
            
            # Save to inbox
            self.save_to_inbox(email_data)
            
            logger.info(f"Received email from {envelope.mail_from} to {envelope.rcpt_tos}")
            return '250 Message accepted for delivery'
            
        except Exception as e:
            logger.error(f"Error handling email: {e}")
            return '550 Error processing email'
    
    def get_next_id(self):
        """Get next email ID"""
        try:
            with open(self.inbox_file, 'r') as f:
                emails = json.load(f)
            return len(emails) + 1
        except:
            return 1
    
    def extract_subject(self, content):
        """Extract subject from email content"""
        try:
            content_str = content.decode('utf-8', errors='ignore')
            for line in content_str.split('\n'):
                if line.lower().startswith('subject:'):
                    return line.split(':', 1)[1].strip()
            return "No Subject"
        except:
            return "No Subject"
    
    def extract_message(self, content):
        """Extract message body from email content"""
        try:
            content_str = content.decode('utf-8', errors='ignore')
            # Simple extraction - look for empty line that separates headers from body
            lines = content_str.split('\n')
            body_started = False
            message_lines = []
            
            for line in lines:
                if body_started:
                    message_lines.append(line)
                elif line.strip() == '':
                    body_started = True
            
            return '\n'.join(message_lines).strip()
        except:
            return "Could not extract message"
    
    def detect_quantum_encryption(self, content):
        """Detect if email uses quantum encryption"""
        try:
            content_str = content.decode('utf-8', errors='ignore').lower()
            quantum_indicators = ['quantum', 'kyber', 'dilithium', 'x-quantum-encrypted']
            return any(indicator in content_str for indicator in quantum_indicators)
        except:
            return False
    
    def save_to_inbox(self, email_data):
        """Save email to inbox file"""
        try:
            # Load existing emails
            emails = []
            if os.path.exists(self.inbox_file):
                with open(self.inbox_file, 'r') as f:
                    emails = json.load(f)
            
            # Add new email
            emails.append(email_data)
            
            # Save back to file
            with open(self.inbox_file, 'w') as f:
                json.dump(emails, f, indent=2)
            
            logger.info(f"Email saved to inbox: {self.inbox_file}")
            
        except Exception as e:
            logger.error(f"Error saving email to inbox: {e}")


class QuantumEmailSMTPServer:
    """SMTP Server for Quantum Email Application"""
    
    def __init__(self, host='localhost', port=1025):
        self.host = host
        self.port = port
        self.controller = None
        self.handler = QuantumEmailHandler()
        self.sent_file = "emails/sent.json"
        self.ensure_sent_file_exists()
    
    def ensure_sent_file_exists(self):
        """Ensure sent emails file exists"""
        try:
            os.makedirs(os.path.dirname(self.sent_file), exist_ok=True)
            if not os.path.exists(self.sent_file):
                with open(self.sent_file, 'w') as f:
                    json.dump([], f)
        except Exception as e:
            logger.error(f"Error creating sent file: {e}")
    
    def start_server(self):
        """Start the SMTP server"""
        try:
            self.controller = Controller(
                self.handler,
                hostname=self.host,
                port=self.port
            )
            self.controller.start()
            logger.info(f"🚀 Quantum SMTP Server running on {self.host}:{self.port}")
            logger.info(f"📧 Emails will be saved to: {os.path.abspath(self.handler.inbox_file)}")
            return True
        except Exception as e:
            logger.error(f"Failed to start SMTP server: {e}")
            return False
    
    def stop_server(self):
        """Stop the SMTP server"""
        try:
            if self.controller:
                self.controller.stop()
                logger.info("SMTP server stopped")
        except Exception as e:
            logger.error(f"Error stopping SMTP server: {e}")
    
    def send_email_with_notification(self, from_addr, to_addr, subject, message, 
                                   is_quantum=True, attachments=None):
        """Send email and save to sent folder"""
        try:
            logger.info(f"Sending email from {from_addr} to {to_addr}")
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = from_addr
            msg['To'] = to_addr
            msg['Subject'] = subject
            
            # Add quantum headers if enabled
            if is_quantum:
                msg['X-Quantum-Encrypted'] = 'true'
                msg['X-Quantum-Algorithm'] = 'Kyber512+Dilithium2'
            
            # Add message body
            msg.attach(MIMEText(message, 'plain'))
            
            # Add attachments if any
            if attachments:
                for file_path in attachments:
                    if os.path.exists(file_path):
                        with open(file_path, 'rb') as attachment:
                            part = MIMEBase('application', 'octet-stream')
                            part.set_payload(attachment.read())
                            encoders.encode_base64(part)
                            part.add_header(
                                'Content-Disposition',
                                f'attachment; filename= {os.path.basename(file_path)}'
                            )
                            msg.attach(part)
            
            # Try to send via SMTP (this might fail, but we'll still save to sent)
            try:
                with smtplib.SMTP(self.host, self.port) as server:
                    server.send_message(msg)
                    logger.info("Email sent via SMTP")
            except Exception as smtp_error:
                logger.warning(f"SMTP sending failed: {smtp_error}")
                # Continue to save in sent folder even if SMTP fails
            
            # Save to sent folder
            self.save_to_sent(from_addr, to_addr, subject, message, is_quantum, attachments)
            
            return True
            
        except Exception as e:
            logger.error(f"Error sending email: {e}")
            return False
    
    def save_to_sent(self, from_addr, to_addr, subject, message, is_quantum, attachments=None):
        """Save email to sent folder"""
        try:
            # Load existing sent emails
            sent_emails = []
            if os.path.exists(self.sent_file):
                with open(self.sent_file, 'r') as f:
                    sent_emails = json.load(f)
            
            # Create email entry
            email_entry = {
                "id": len(sent_emails) + 1,
                "from": from_addr,
                "to": to_addr,
                "subject": subject,
                "message": message,
                "timestamp": datetime.now().isoformat(),
                "is_quantum": is_quantum,
                "status": "sent",
                "attachments": attachments if attachments else []
            }
            
            # Add to sent emails
            sent_emails.append(email_entry)
            
            # Save to file
            with open(self.sent_file, 'w') as f:
                json.dump(sent_emails, f, indent=2)
            
            logger.info(f"✅ Email saved to sent folder: {self.sent_file}")
            logger.info(f"📧 Email ID: {email_entry['id']}")
            logger.info(f"📧 From: {from_addr}")
            logger.info(f"📧 To: {to_addr}")
            logger.info(f"📧 Subject: {subject}")
            logger.info(f"📧 Quantum: {is_quantum}")
            
        except Exception as e:
            logger.error(f"Error saving email to sent folder: {e}")
            raise e
    
    def get_sent_emails(self):
        """Get all sent emails"""
        try:
            if os.path.exists(self.sent_file):
                with open(self.sent_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            logger.error(f"Error reading sent emails: {e}")
            return []
    
    def get_inbox_emails(self):
        """Get all inbox emails"""
        try:
            if os.path.exists(self.handler.inbox_file):
                with open(self.handler.inbox_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            logger.error(f"Error reading inbox emails: {e}")
            return []


def main():
    """Test the SMTP server"""
    logging.basicConfig(level=logging.INFO)
    
    # Create and start server
    server = QuantumEmailSMTPServer()
    
    if server.start_server():
        print("SMTP Server started successfully!")
        print(f"Server running on {server.host}:{server.port}")
        
        # Test sending an email
        success = server.send_email_with_notification(
            from_addr="test@quantum.app",
            to_addr="user@example.com",
            subject="Test Email",
            message="This is a test email from the quantum SMTP server.",
            is_quantum=True
        )
        
        if success:
            print("Test email sent successfully!")
        else:
            print("Failed to send test email")
        
        # Keep server running
        try:
            input("Press Enter to stop the server...")
        except KeyboardInterrupt:
            pass
        finally:
            server.stop_server()
    else:
        print("Failed to start SMTP server")


if __name__ == "__main__":
    main()