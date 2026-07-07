import sqlite3
import os

def add_column_if_missing(db_path, table, column, definition):
    if not os.path.exists(db_path):
        print(f"Database not found: {db_path}")
        return
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        # Check if column exists
        cursor.execute(f"PRAGMA table_info({table});")
        columns = [col[1] for col in cursor.fetchall()]
        if column not in columns:
            print(f"Adding {column} to {table} in {os.path.basename(db_path)}...")
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
            conn.commit()
            print(f"Successfully added {column}.")
        else:
            print(f"Column {column} already exists in {table} in {os.path.basename(db_path)}.")
    except Exception as e:
        print(f"Error updating {table} in {os.path.basename(db_path)}: {e}")
    finally:
        conn.close()

# Databases
main_db = r'd:\VOtingSyStem\databases\voting_system.db'
audit_db = r'd:\VOtingSyStem\databases\audit_ledger.db'

# Candidate table in main_db
add_column_if_missing(main_db, 'candidates', 'm_education', 'INTEGER DEFAULT 0')
add_column_if_missing(main_db, 'candidates', 'm_jobs', 'INTEGER DEFAULT 0')
add_column_if_missing(main_db, 'candidates', 'm_infrastructure', 'INTEGER DEFAULT 0')
add_column_if_missing(main_db, 'candidates', 'm_healthcare', 'INTEGER DEFAULT 0')
add_column_if_missing(main_db, 'candidates', 'm_economy', 'INTEGER DEFAULT 0')

# Vote table in main_db
add_column_if_missing(main_db, 'votes', 'voting_speed_seconds', 'INTEGER')
add_column_if_missing(main_db, 'votes', 'user_agent', 'VARCHAR(255)')

# FraudLog table in audit_db
add_column_if_missing(audit_db, 'fraud_logs', 'user_agent', 'VARCHAR(255)')
add_column_if_missing(audit_db, 'fraud_logs', 'risk_score', 'FLOAT DEFAULT 0.0')

print("\nMigration complete.")
