
import sqlite3
import os

def add_column(db_path, table, column, definition):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        conn.commit()
        print(f"  Added {column} to {table} in {db_path}.")
    except Exception as e:
        if "duplicate column name" in str(e).lower():
            print(f"  Column {column} already exists in {table} in {db_path}.")
        else:
            print(f"  Error adding {column} to {table}: {e}")
    conn.close()

def update_db():
    main_db = 'databases/voting_system.db'
    org_db = 'databases/organization_database.db'
    
    if os.path.exists(main_db):
        print(f"Updating {main_db}...")
        add_column(main_db, 'elections', 'phase1_end', 'DATETIME')
        add_column(main_db, 'candidates', 'party_name', 'VARCHAR(100)')
        add_column(main_db, 'candidates', 'party_logo', 'VARCHAR(255)')
        add_column(main_db, 'users', 'name_enc', 'TEXT')
        add_column(main_db, 'users', 'name_hash', 'VARCHAR(64)')
        add_column(main_db, 'users', 'email_enc', 'TEXT')
        add_column(main_db, 'users', 'email_hash', 'VARCHAR(64)')
        add_column(main_db, 'users', 'phone_enc', 'TEXT')
        add_column(main_db, 'users', 'org_id_hash', 'VARCHAR(64)')
    
    if os.path.exists(org_db):
        print(f"Updating {org_db}...")
        add_column(org_db, 'organization_users', 'full_name_enc', 'TEXT')
        add_column(org_db, 'organization_users', 'full_name_hash', 'VARCHAR(64)')
        add_column(org_db, 'organization_users', 'email_enc', 'TEXT')
        add_column(org_db, 'organization_users', 'email_hash', 'VARCHAR(64)')
        add_column(org_db, 'organization_users', 'phone_enc', 'TEXT')
        add_column(org_db, 'organization_users', 'org_id_hash', 'VARCHAR(64)')

if __name__ == "__main__":
    update_db()
