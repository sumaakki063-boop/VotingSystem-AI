
import sqlite3
import os

db_path = os.path.join('databases', 'org_master.db')
if not os.path.exists(db_path):
    print(f"Error: {db_path} does not exist.")
else:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"Tables in org_master.db: {tables}")
        
        for table in tables:
            table_name = table[0]
            cursor.execute(f"SELECT * FROM {table_name} WHERE org_id='ORG001'")
            rows = cursor.fetchall()
            if rows:
                print(f"Data for ORG001 in table {table_name}: {rows}")
            else:
                print(f"No data for ORG001 in table {table_name}.")
    except Exception as e:
        print(f"Query error: {e}")
    conn.close()

# Also check voting_system.db for any registered users with ORG001
main_db_path = os.path.join('databases', 'voting_system.db')
if os.path.exists(main_db_path):
    conn = sqlite3.connect(main_db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM user WHERE org_id='ORG001'")
        rows = cursor.fetchall()
        if rows:
            print(f"Data for ORG001 in voting_system.db (User table): {rows}")
        else:
            print(f"No registered user with ORG001 in voting_system.db.")
    except Exception as e:
        print(f"Query error in main db: {e}")
    conn.close()
