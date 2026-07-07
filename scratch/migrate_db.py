
import sqlite3
import os

def fix_table(db_path, table_name):
    print(f"Fixing {table_name} in {db_path}...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get current schema
    cursor.execute(f"SELECT sql FROM sqlite_master WHERE type='table' AND name='{table_name}'")
    create_sql = cursor.fetchone()[0]
    print(f"Old schema: {create_sql}")
    
    # Check if name/email are NOT NULL
    if "NOT NULL" in create_sql:
        # We need to recreate the table
        # 1. Rename old table
        cursor.execute(f"ALTER TABLE {table_name} RENAME TO {table_name}_old")
        
        # 2. Create new table with nullable old columns
        # We'll just define the new schema based on what models.py expects
        if table_name == 'users':
            new_schema = """
            CREATE TABLE users (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                org_id VARCHAR(50) NOT NULL UNIQUE,
                org_id_hash VARCHAR(64),
                name_enc TEXT NOT NULL,
                email_enc TEXT NOT NULL UNIQUE,
                email_hash VARCHAR(64),
                phone_enc TEXT,
                gender VARCHAR(10),
                age INTEGER,
                password_hash VARCHAR(255) NOT NULL,
                photo VARCHAR(255),
                is_verified BOOLEAN DEFAULT 0,
                is_approved BOOLEAN DEFAULT 0,
                has_voted_phase1 BOOLEAN DEFAULT 0,
                has_voted_phase2 BOOLEAN DEFAULT 0,
                role VARCHAR(20) DEFAULT 'voter',
                name VARCHAR(100), -- Nullable old column
                email VARCHAR(100), -- Nullable old column
                phone VARCHAR(20)   -- Nullable old column
            )
            """
        elif table_name == 'organization_users':
            new_schema = """
            CREATE TABLE organization_users (
                org_id VARCHAR(50) NOT NULL PRIMARY KEY,
                org_id_hash VARCHAR(64),
                full_name_enc TEXT NOT NULL,
                email_enc TEXT,
                email_hash VARCHAR(64),
                phone_enc TEXT NOT NULL,
                date_of_birth DATE NOT NULL,
                department VARCHAR(50) NOT NULL,
                status VARCHAR(20) DEFAULT 'Active',
                full_name VARCHAR(100), -- Nullable old column
                email VARCHAR(100),     -- Nullable old column
                phone VARCHAR(20)       -- Nullable old column
            )
            """
        else:
            print(f"Unknown table {table_name}")
            return

        cursor.execute(new_schema)
        
        # 3. Copy data back
        # We need to map columns carefully. 
        # For simplicity, we'll try to find overlapping columns
        cursor.execute(f"PRAGMA table_info({table_name}_old)")
        old_cols = [c[1] for c in cursor.fetchall()]
        
        cursor.execute(f"PRAGMA table_info({table_name})")
        new_cols = [c[1] for c in cursor.fetchall()]
        
        common_cols = list(set(old_cols) & set(new_cols))
        cols_str = ", ".join(common_cols)
        
        cursor.execute(f"INSERT INTO {table_name} ({cols_str}) SELECT {cols_str} FROM {table_name}_old")
        
        # 4. Drop old table
        cursor.execute(f"DROP TABLE {table_name}_old")
        print(f"Table {table_name} fixed.")
    else:
        print(f"Table {table_name} already seems fine or no NOT NULL found.")
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    fix_table('databases/voting_system.db', 'users')
    fix_table('databases/organization_database.db', 'organization_users')
