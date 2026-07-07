
import os
from dotenv import load_dotenv

load_dotenv()
print(f"MAIL_USERNAME: {os.getenv('MAIL_USERNAME')}")
print(f"MAIL_PASSWORD set: {os.getenv('MAIL_PASSWORD') is not None}")
print(f"MAIL_SERVER: {os.getenv('MAIL_SERVER', 'smtp.gmail.com')}")
