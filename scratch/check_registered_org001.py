
import sqlite3
import os

main_db_path = os.path.join('databases', 'voting_system.db')
if os.path.exists(main_db_path):
    conn = sqlite3.connect(main_db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM users WHERE org_id='ORG001'")
        rows = cursor.fetchall()
        if rows:
            print(f"Registered User Data for ORG001: {rows}")
        else:
            print(f"No registered user with ORG001 in voting_system.db.")
    except Exception as e:
        print(f"Query error in main db: {e}")
    conn.close()
else:
    print("Main DB does not exist.")
