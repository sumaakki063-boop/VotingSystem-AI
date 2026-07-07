
import sqlite3
import os

db_path = 'databases/organization_database.db'
if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(organization_users)")
    columns = cursor.fetchall()
    print("Columns in organization_users:")
    for col in columns:
        print(col)
    
    cursor.execute("SELECT * FROM organization_users LIMIT 5")
    rows = cursor.fetchall()
    print("\nFirst 5 rows:")
    for row in rows:
        print(row)
    conn.close()
else:
    print(f"{db_path} not found")
