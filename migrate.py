# migrate.py
import sqlite3

DATABASE = 'database.db'

def migrate():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Get existing columns first
    cursor.execute("PRAGMA table_info(transcript_requests)")
    columns = [column[1] for column in cursor.fetchall()]
    
    # Check and add signed_timestamp column
    if 'signed_timestamp' not in columns:
        print("Adding 'signed_timestamp' column to transcript_requests table...")
        cursor.execute("ALTER TABLE transcript_requests ADD COLUMN signed_timestamp TEXT")
        conn.commit()
        print("Migration for signed_timestamp completed!")
    else:
        print("Column 'signed_timestamp' already exists.")
    
    # Check and add signature_path column
    if 'signature_path' not in columns:
        print("Adding 'signature_path' column to transcript_requests table...")
        cursor.execute("ALTER TABLE transcript_requests ADD COLUMN signature_path TEXT")
        conn.commit()
        print("Migration for signature_path completed!")
    else:
        print("Column 'signature_path' already exists.")
    
    # Check and add signed_data column
    if 'signed_data' not in columns:
        print("Adding 'signed_data' column to transcript_requests table...")
        cursor.execute("ALTER TABLE transcript_requests ADD COLUMN signed_data TEXT")
        conn.commit()
        print("Migration for signed_data completed!")
    else:
        print("Column 'signed_data' already exists.")
    
    conn.close()
    print("All migrations completed successfully!")

if __name__ == '__main__':
    migrate()