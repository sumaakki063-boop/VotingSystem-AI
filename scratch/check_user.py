
import sqlite3
import os

db_path = 'databases/voting_system.db'
if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("Checking for ORG014 in users table...")
    cursor.execute("SELECT org_id, email_enc FROM users WHERE org_id='ORG014'")
    rows = cursor.fetchall()
    for row in rows:
        print(f"Found ORG014: {row}")
        
    print("\nChecking for email@org.com (hash: 3d684ce5ddb187383dc8b571da3721c1b5e2e1ab6559dcabff0a64c4596dd4e0)...")
    cursor.execute("SELECT org_id, email_hash FROM users WHERE email_hash='3d684ce5ddb187383dc8b571da3721c1b5e2e1ab6559dcabff0a64c4596dd4e0'")
    rows = cursor.fetchall()
    for row in rows:
        print(f"Found Email Hash: {row}")

    conn.close()
else:
    print(f"{db_path} not found")
