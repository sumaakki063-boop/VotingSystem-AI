import os
from dotenv import load_dotenv
import smtplib
from email.message import EmailMessage

load_dotenv()

MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 465
MAIL_USERNAME = os.getenv('MAIL_USERNAME')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')

def send_otp_email(target_email, otp_code):
    try:
        msg = EmailMessage()
        msg.set_content(f"Hello,\n\nYour secure verification code for SecureVote AI is: {otp_code}")
        msg['Subject'] = "SecureVote AI: Your Verification Code"
        msg['From'] = MAIL_USERNAME
        msg['To'] = target_email

        print(f"SMTP Attempt: From={MAIL_USERNAME} To={target_email}")
        with smtplib.SMTP_SSL(MAIL_SERVER, MAIL_PORT) as server:
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.send_message(msg)
            
        print("Email sent successfully.")
        return True
    except Exception as e:
        print(f"SMTP Error: {e}")
        return False

send_otp_email("test@example.com", "123456")
