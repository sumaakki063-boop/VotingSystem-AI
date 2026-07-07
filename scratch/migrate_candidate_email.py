import sqlite3
import os

db_path = os.path.join('databases', 'voting_system.db')

if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER TABLE candidates ADD COLUMN email VARCHAR(100)")
        conn.commit()
        print("Successfully added email column to candidates table.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            print("Column 'email' already exists.")
        else:
            print(f"Error: {e}")
    conn.close()
else:
    print(f"Database {db_path} not found.")
