
from cryptography.fernet import Fernet
import os

key = "AHl-9BaiZwIkLQUzrLVPkdMAmt_9a4W4sjZ3xUbG4y0="
f = Fernet(key.encode())

data = "gAAAAABp-aEhf0iGWPDEJRYWtpqL31F6zCfX9qOL5tFB0dHurNSl6siBaLW6DXnuGaN-QZ4bShbRlY7vJ1gcmNB_VN0pYEmVWehqaOaliSQcZhK_pIE6uZs="
try:
    print(f"Decrypted: {f.decrypt(data.encode()).decode()}")
except Exception as e:
    print(f"Decryption failed: {e}")
