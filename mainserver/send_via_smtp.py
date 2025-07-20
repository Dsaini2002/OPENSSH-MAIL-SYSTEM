import smtplib
import json
import base64

def send_email_via_smtp(email_data, smtp_host="localhost", smtp_port=1025):
    """
    Connects to the custom SMTP server and sends the email_data as base64-encoded JSON.
    """
    # Serialize and encode
    raw_json = json.dumps(email_data)
    encoded = base64.b64encode(raw_json.encode()).decode()

    # Compose minimal SMTP message
    message = f"""From: {email_data.get('from')}
To: {email_data.get('to')}
Subject: {email_data.get('subject', 'No Subject')}

{encoded}
"""

    # Send
    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.sendmail(email_data.get("from"), [email_data.get("to")], message)
