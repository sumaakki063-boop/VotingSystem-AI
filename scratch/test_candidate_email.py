
from app import send_otp_email
import os
from dotenv import load_dotenv

load_dotenv()

# Test with a candidate's email
email = "vinayakkulkarni457@gmail.com"
print(f"Testing with {email}...")
success = send_otp_email(email, "123456")
if success:
    print("Success!")
else:
    print("Failed!")
