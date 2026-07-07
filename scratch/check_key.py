
import os
from dotenv import load_dotenv

load_dotenv()
print(f"USER_DATA_ENCRYPTION_KEY set: {os.getenv('USER_DATA_ENCRYPTION_KEY') is not None}")
if os.getenv('USER_DATA_ENCRYPTION_KEY'):
    print(f"USER_DATA_ENCRYPTION_KEY length: {len(os.getenv('USER_DATA_ENCRYPTION_KEY'))}")
