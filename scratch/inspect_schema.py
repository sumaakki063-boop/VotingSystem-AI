import sqlite3
import os

databases = [
    r'd:\VOtingSyStem\databases\voting_system.db',
    r'd:\VOtingSyStem\databases\organization_database.db',
    r'd:\VOtingSyStem\databases\audit_ledger.db'
]

for db_path in databases:
    if os.path.exists(db_path):
        print(f"\n--- Schema for {os.path.basename(db_path)} ---")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        for table in tables:
            table_name = table[0]
            print(f"\nTable: {table_name}")
            cursor.execute(f"PRAGMA table_info({table_name});")
            columns = cursor.fetchall()
            for col in columns:
                print(f"  {col[1]} ({col[2]})")
        conn.close()
    else:
        print(f"\nDatabase file not found at {db_path}")
