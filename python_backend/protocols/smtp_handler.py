#!/usr/bin/env python3
"""
Modern Quantum SMTP Server
Uses aiosmtpd with better connection handling
Fixes IPv6/IPv4 and connection issues
"""
import asyncio
import json
import base64
from datetime import datetime
import os
import email
from email.parser import BytesParser
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP as SMTPProtocol
import logging
import socket

# Set up logging with more detail
logging.basicConfig(
    level=logging.DEBUG, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

INBOX_FILE = "/home/dinesh/openssh/openssh/emails/inbox.json"

class QuantumSMTPHandler:
    """Handler for incoming SMTP messages"""
    
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        """Handle RCPT TO command"""
        print(f"📨 RCPT TO: {address}")
        if not hasattr(envelope, 'rcpt_tos'):
            envelope.rcpt_tos = []
        envelope.rcpt_tos.append(address)
        return '250 OK'
    
    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        """Handle MAIL FROM command"""
        print(f"📤 MAIL FROM: {address}")
        envelope.mail_from = address
        return '250 OK'
    
    async def handle_DATA(self, server, session, envelope):
        """Handle DATA command - this is where the email content is processed"""
        print("\n" + "="*50)
        print("🚨 DEBUG: handle_DATA() called")
        print(f"🚨 DEBUG: Mail from: {getattr(envelope, 'mail_from', 'Unknown')}")
        print(f"🚨 DEBUG: Recipients: {getattr(envelope, 'rcpt_tos', [])}")
        print(f"🚨 DEBUG: Content type: {type(envelope.content)}")
        print(f"🚨 DEBUG: Content length: {len(envelope.content) if envelope.content else 'None'}")
        print(f"🚨 DEBUG: Session peer: {session.peer}")
        
        try:
            # Get email data
            email_data = envelope.content
            
            if not email_data:
                print("❌ No email data received")
                return '250 Message accepted for delivery'
            
            # Parse email using email library
            if isinstance(email_data, str):
                email_data = email_data.encode('utf-8')
            
            print(f"📄 Raw email data preview: {email_data[:300]}...")
            
            # Parse the email
            parser = BytesParser()
            parsed_email = parser.parsebytes(email_data)
            
            # Extract basic info
            subject = parsed_email.get('Subject', 'No Subject')
            from_addr = getattr(envelope, 'mail_from', None) or parsed_email.get('From', 'Unknown')
            to_addrs = getattr(envelope, 'rcpt_tos', []) or [parsed_email.get('To', 'Unknown')]
            
            print(f"📧 Subject: {subject}")
            print(f"📧 From: {from_addr}")
            print(f"📧 To: {to_addrs}")
            
            # Extract message body
            message_text = self.extract_message_body(parsed_email)
            print(f"📝 Message extracted: {message_text[:100]}...")
            
            # Base64 encode the raw bytes for storage
            raw_encoded = base64.b64encode(email_data).decode('ascii')
            
            # Prepare email entry
            email_entry = {
                "id": self.generate_email_id(),
                "from": from_addr,
                "to": to_addrs,
                "subject": subject,
                "message": message_text,
                "timestamp": datetime.utcnow().isoformat(),
                "received_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "raw_data": raw_encoded,
                "peer": str(session.peer),
                "processed": True,
                "headers": dict(parsed_email.items())
            }
            
            # Save to inbox
            await self.save_to_inbox(email_entry)
            
            # Save individual email file
            await self.save_individual_email(email_entry)
            
            print("✅ Email processed and saved successfully")
            print(f"🆔 Email ID: {email_entry['id']}")
            print("="*50 + "\n")
            
        except Exception as e:
            print(f"❌ Error processing message: {e}")
            import traceback
            traceback.print_exc()
        
        return '250 Message accepted for delivery'
    
    def extract_message_body(self, parsed_email):
        """Extract message body from parsed email"""
        message_text = "(No content)"
        
        try:
            if parsed_email.is_multipart():
                # Handle multipart messages
                for part in parsed_email.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            message_text = payload.decode('utf-8', errors='ignore').strip()
                            break
                    elif content_type == "text/html" and message_text == "(No content)":
                        # Fallback to HTML if no plain text found
                        payload = part.get_payload(decode=True)
                        if payload:
                            message_text = f"[HTML] {payload.decode('utf-8', errors='ignore').strip()[:200]}..."
            else:
                # Handle single part messages
                payload = parsed_email.get_payload(decode=True)
                if payload:
                    message_text = payload.decode('utf-8', errors='ignore').strip()
                else:
                    # If decode=True fails, try raw payload
                    payload = parsed_email.get_payload()
                    if payload:
                        message_text = str(payload).strip()
        except Exception as e:
            print(f"⚠️ Could not extract message body: {e}")
            # Fallback: try to get raw payload as string
            try:
                payload = parsed_email.get_payload()
                message_text = str(payload)[:500] if payload else "(No content)"
            except:
                message_text = "(Could not extract content)"
        
        return message_text
    
    def generate_email_id(self):
        """Generate unique email ID"""
        return f"email_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
    
    async def save_to_inbox(self, email_entry):
        """Save email to inbox.json"""
        try:
            # Load existing emails
            inbox = []
            if os.path.exists(INBOX_FILE):
                try:
                    with open(INBOX_FILE, "r", encoding='utf-8') as f:
                        inbox = json.load(f)
                except json.JSONDecodeError:
                    print("⚠️ Corrupted inbox.json, creating new one")
                    inbox = []
            
            # Add new email
            inbox.append(email_entry)
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(INBOX_FILE), exist_ok=True)
            
            # Save inbox
            with open(INBOX_FILE, "w", encoding='utf-8') as f:
                json.dump(inbox, f, indent=2, ensure_ascii=False)
            
            print(f"✅ Email saved to {INBOX_FILE}")
            print(f"📬 Total emails in inbox: {len(inbox)}")
            
        except Exception as e:
            print(f"❌ Error saving to inbox: {e}")
    
    async def save_individual_email(self, email_entry):
        """Save individual email file"""
        try:
            # Create individual email directory
            email_dir = "emails/individual"
            os.makedirs(email_dir, exist_ok=True)
            
            # Save as JSON
            json_filename = f"{email_dir}/{email_entry['id']}.json"
            with open(json_filename, "w", encoding='utf-8') as f:
                json.dump(email_entry, f, indent=2, ensure_ascii=False)
            
            # Save raw email as .eml
            eml_filename = f"{email_dir}/{email_entry['id']}.eml"
            raw_data = base64.b64decode(email_entry['raw_data'])
            with open(eml_filename, "wb") as f:
                f.write(raw_data)
            
            print(f"✅ Individual email saved: {json_filename} and {eml_filename}")
            
        except Exception as e:
            print(f"❌ Error saving individual email: {e}")

class QuantumSMTPServer:
    """Main SMTP Server class"""
    
    def __init__(self, host='127.0.0.1', port=1025):
        self.host = host
        self.port = port
        self.handler = QuantumSMTPHandler()
        self.controller = None
    
    def start(self):
        """Start the SMTP server"""
        try:
            # Ensure emails directory exists
            os.makedirs("emails", exist_ok=True)
            os.makedirs("emails/individual", exist_ok=True)
            
            # Create controller with specific settings
            
            print("🚀 Quantum SMTP Server starting...")
            print(f"🌐 Server address: {self.host}:{self.port}")
            print("📧 Emails will be saved to:", INBOX_FILE)
            print("📁 Individual emails saved to: emails/individual/")
            print("🔧 Server configured with:")
            print(f"   - Hostname: {self.host}")
            print(f"   - Port: {self.port}")
            print(f"   - UTF8 Support: Enabled")
            print(f"   - Timeout: 300 seconds")
            print("🔄 Server is running... Press Ctrl+C to stop")
            print("=" * 50)
            
            
            # Keep server running
            try:
                asyncio.get_event_loop().run_forever()
            except KeyboardInterrupt:
                print("\n🛑 Server stopped by user")
            finally:
                if self.controller:
                    self.controller.stop()            
                
        except OSError as e:
            if "Address already in use" in str(e):
                print("❌ Error: Port 1025 is already in use!")
                print("💡 Try stopping other SMTP servers or use a different port")
                print("🔍 Check running processes: lsof -i :1025")
            else:
                print(f"❌ OS Error: {e}")
        except Exception as e:
            print(f"❌ Error starting server: {e}")
            import traceback
            traceback.print_exc()

def test_email_send():
    """Test function to send email to the server"""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    
    try:
        # Create message
        msg = MIMEMultipart()
        msg['Subject'] = 'Test Email from Quantum SMTP'
        msg['From'] = 'test@example.com'
        msg['To'] = 'recipient@example.com'
        
        # Add body
        body = "This is a test message from the Quantum SMTP Server test function!"
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        print("📤 Sending test email...")
        with smtplib.SMTP('127.0.0.1', 1025) as server:
            server.send_message(msg)
            print("✅ Test email sent successfully!")
            
    except Exception as e:
        print(f"❌ Error sending test email: {e}")

def check_inbox():
    """Check current inbox contents"""
    try:
        if os.path.exists(INBOX_FILE):
            with open(INBOX_FILE, "r", encoding='utf-8') as f:
                inbox = json.load(f)
            
            print(f"📬 Inbox contains {len(inbox)} emails:")
            print("-" * 50)
            for i, email in enumerate(inbox[-10:], 1):  # Show last 10
                print(f"📧 Email {i}:")
                print(f"   ID: {email.get('id', 'Unknown')}")
                print(f"   From: {email.get('from', 'Unknown')}")
                print(f"   To: {email.get('to', 'Unknown')}")
                print(f"   Subject: {email.get('subject', 'No Subject')}")
                print(f"   Time: {email.get('received_time', 'Unknown')}")
                print(f"   Message: {email.get('message', 'No message')[:100]}...")
                print("-" * 30)
        else:
            print("📭 Inbox is empty - no emails received yet")
            print(f"💡 Expected inbox file: {INBOX_FILE}")
    except Exception as e:
        print(f"❌ Error checking inbox: {e}")

def main():
    """Main function"""
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "check":
            check_inbox()
        elif sys.argv[1] == "test":
            test_email_send()
        else:
            print("Usage:")
            print("  python script.py        - Start SMTP server")
            print("  python script.py check  - Check inbox")
            print("  python script.py test   - Send test email")
    else:
        server = QuantumSMTPServer(host='127.0.0.1', port=1025)
        server.start()

if __name__ == "__main__":
    main()