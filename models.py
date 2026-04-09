from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import json

DATABASE = 'database.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with required tables"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('student', 'admin')),
            mfa_secret TEXT,
            mfa_enabled INTEGER DEFAULT 0,
            public_key TEXT,
            private_key_encrypted TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP
        )
    ''')
    
    # Documents table (optional - for future use)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL,
            document_name TEXT NOT NULL,
            document_path TEXT NOT NULL,
            document_hash TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'active' CHECK(status IN ('active', 'archived')),
            FOREIGN KEY (admin_id) REFERENCES users(id)
        )
    ''')
    
    # Signature requests table (optional - for future use)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS signature_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            admin_id INTEGER NOT NULL,
            status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'signed', 'rejected', 'expired')),
            signature_data TEXT,
            signed_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (document_id) REFERENCES documents(id),
            FOREIGN KEY (student_id) REFERENCES users(id),
            FOREIGN KEY (admin_id) REFERENCES users(id)
        )
    ''')
    
    # Transcript requests table - CLEAN VERSION
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transcript_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            student_username TEXT NOT NULL,
            student_email TEXT NOT NULL,
            reason TEXT NOT NULL,
            signature TEXT NOT NULL,
            signature_path TEXT,
            status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected', 'ready')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            processed_at TIMESTAMP,
            processed_by INTEGER,
            admin_notes TEXT,
            transcript_path TEXT,
            signed_timestamp TEXT,
            signed_data TEXT,
            password_hash TEXT,
            FOREIGN KEY (student_id) REFERENCES users(id),
            FOREIGN KEY (processed_by) REFERENCES users(id)
        )
    ''')
    
    # Audit logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            hash TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    conn.commit()
    conn.close()

class User:
    @staticmethod
    def create_user(username, email, password, role):
        conn = get_db_connection()
        cursor = conn.cursor()
        
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        
        try:
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, role)
                VALUES (?, ?, ?, ?)
            ''', (username, email, password_hash, role))
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            return user_id
        except sqlite3.IntegrityError:
            conn.close()
            return None
    
    @staticmethod
    def get_by_username(username):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        return user
    
    @staticmethod
    def get_by_id(user_id):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        return user
    
    @staticmethod
    def verify_password(user, password):
        return check_password_hash(user['password_hash'], password)
    
    @staticmethod
    def update_mfa_secret(user_id, secret):
        conn = get_db_connection()
        conn.execute('UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE id = ?', 
                     (secret, user_id))
        conn.commit()
        conn.close()
    
    @staticmethod
    def update_keys(user_id, public_key, private_key_encrypted):
        conn = get_db_connection()
        conn.execute('UPDATE users SET public_key = ?, private_key_encrypted = ? WHERE id = ?',
                     (public_key, private_key_encrypted, user_id))
        conn.commit()
        conn.close()

    @staticmethod
    def increment_login_attempts(user_id):
        conn = get_db_connection()
        conn.execute('''
            UPDATE users 
            SET login_attempts = login_attempts + 1 
            WHERE id = ?
        ''', (user_id,))
        conn.commit()
        conn.close()
    
    @staticmethod
    def reset_login_attempts(user_id):
        """Reset counter on successful login"""
        conn = get_db_connection()
        conn.execute('''
            UPDATE users 
            SET login_attempts = 0, locked_until = NULL
            WHERE id = ?
        ''', (user_id,))
        conn.commit()
        conn.close()
    
    @staticmethod
    def lock_account(user_id):
        from config import Config  # Import here to avoid circular import
        conn = get_db_connection()
        locked_until = (datetime.now() + Config.LOCKOUT_DURATION).isoformat()
        conn.execute('''
            UPDATE users 
            SET locked_until = ? 
            WHERE id = ?
        ''', (locked_until, user_id))
        conn.commit()
        conn.close()
    
    @staticmethod
    def is_account_locked(user):
        if user['locked_until']:
            return datetime.fromisoformat(user['locked_until']) > datetime.now()
        return False

class Document:
    @staticmethod
    def create_document(admin_id, document_name, document_path, document_hash, description=None):
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO documents (admin_id, document_name, document_path, document_hash, description)
            VALUES (?, ?, ?, ?, ?)
        ''', (admin_id, document_name, document_path, document_hash, description))
        conn.commit()
        doc_id = cursor.lastrowid
        conn.close()
        return doc_id
    
    @staticmethod
    def get_by_id(doc_id):
        conn = get_db_connection()
        doc = conn.execute('SELECT * FROM documents WHERE id = ?', (doc_id,)).fetchone()
        conn.close()
        return doc
    
    @staticmethod
    def get_all_active():
        conn = get_db_connection()
        docs = conn.execute('''
            SELECT d.*, u.username as admin_username 
            FROM documents d 
            JOIN users u ON d.admin_id = u.id 
            WHERE d.status = 'active'
            ORDER BY d.created_at DESC
        ''').fetchall()
        conn.close()
        return docs
    
    @staticmethod
    def get_by_admin(admin_id):
        conn = get_db_connection()
        docs = conn.execute('''
            SELECT * FROM documents WHERE admin_id = ? ORDER BY created_at DESC
        ''', (admin_id,)).fetchall()
        conn.close()
        return docs

class SignatureRequest:
    @staticmethod
    def create_request(document_id, student_id, admin_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO signature_requests (document_id, student_id, admin_id)
                VALUES (?, ?, ?)
            ''', (document_id, student_id, admin_id))
            conn.commit()
            req_id = cursor.lastrowid
            conn.close()
            return req_id
        except sqlite3.IntegrityError:
            conn.close()
            return None
    
    @staticmethod
    def get_pending_for_student(student_id):
        conn = get_db_connection()
        requests = conn.execute('''
            SELECT sr.*, d.document_name, d.description, u.username as admin_username
            FROM signature_requests sr
            JOIN documents d ON sr.document_id = d.id
            JOIN users u ON sr.admin_id = u.id
            WHERE sr.student_id = ? AND sr.status = 'pending'
            ORDER BY sr.created_at DESC
        ''', (student_id,)).fetchall()
        conn.close()
        return requests
    
    @staticmethod
    def get_pending_for_admin(admin_id):
        conn = get_db_connection()
        requests = conn.execute('''
            SELECT sr.*, d.document_name, u.username as student_username, u.email as student_email
            FROM signature_requests sr
            JOIN documents d ON sr.document_id = d.id
            JOIN users u ON sr.student_id = u.id
            WHERE sr.admin_id = ? AND sr.status = 'pending'
            ORDER BY sr.created_at DESC
        ''', (admin_id,)).fetchall()
        conn.close()
        return requests
    
    @staticmethod
    def get_by_id(req_id):
        conn = get_db_connection()
        req = conn.execute('SELECT * FROM signature_requests WHERE id = ?', (req_id,)).fetchone()
        conn.close()
        return req
    
    @staticmethod
    def sign_request(req_id, signature_data):
        conn = get_db_connection()
        conn.execute('''
            UPDATE signature_requests 
            SET status = 'signed', signature_data = ?, signed_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (signature_data, req_id))
        conn.commit()
        conn.close()
    
    @staticmethod
    def reject_request(req_id):
        conn = get_db_connection()
        conn.execute("UPDATE signature_requests SET status = 'rejected' WHERE id = ?", (req_id,))
        conn.commit()
        conn.close()

class TranscriptRequest:
    @staticmethod
    def create_request(student_id, student_username, student_email, reason, signature, signature_path=None, signed_timestamp=None, signed_data=None, password_hash=None):
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO transcript_requests 
            (student_id, student_username, student_email, reason, signature, signature_path, signed_timestamp, signed_data, password_hash)
            VALUES (?, ?, ?, ?, ?, ?,?,?,?)
        ''', (student_id, student_username, student_email, reason, signature, signature_path, signed_timestamp, signed_data, password_hash))
        conn.commit()
        request_id = cursor.lastrowid
        conn.close()
        return request_id
    
    @staticmethod
    def get_all_requests():
        conn = get_db_connection()
        requests = conn.execute('''
            SELECT tr.*, u.username as processor_username
            FROM transcript_requests tr
            LEFT JOIN users u ON tr.processed_by = u.id
            ORDER BY tr.created_at DESC
        ''').fetchall()
        conn.close()
        return requests
    
    @staticmethod
    def get_by_student(student_id):
        conn = get_db_connection()
        requests = conn.execute('''
            SELECT * FROM transcript_requests 
            WHERE student_id = ?
            ORDER BY created_at DESC
        ''', (student_id,)).fetchall()
        conn.close()
        return requests
    
    @staticmethod
    def get_by_id(request_id):
        conn = get_db_connection()
        request = conn.execute('SELECT * FROM transcript_requests WHERE id = ?', 
                          (request_id,)).fetchone()
        conn.close()
    # Convert sqlite3.Row to dict to support .get() method
        if request:
            return dict(request)
        return None
    
    @staticmethod
    def update_status(request_id, status, admin_id, notes=None, transcript_path=None):
        conn = get_db_connection()
        conn.execute('''
            UPDATE transcript_requests 
            SET status = ?, processed_at = CURRENT_TIMESTAMP, 
                processed_by = ?, admin_notes = ?, transcript_path = ?
            WHERE id = ?
        ''', (status, admin_id, notes, transcript_path, request_id))
        conn.commit()
        conn.close()
    
    @staticmethod
    def get_ready_for_student(student_id):
        conn = get_db_connection()
        req = conn.execute('''
            SELECT * FROM transcript_requests 
            WHERE student_id = ? AND status = 'ready'
            ORDER BY processed_at DESC LIMIT 1
        ''', (student_id,)).fetchone()
        conn.close()
        return req

class AuditLog:
    @staticmethod
    def log_action(user_id, username, action, details=None, ip_address=None, hash_value=None):
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO audit_logs (user_id, username, action, details, ip_address, hash)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, username, action, details, ip_address, hash_value))
        conn.commit()
        conn.close()
    
    @staticmethod
    def get_all_logs(limit=100, offset=0):
        conn = get_db_connection()
        logs = conn.execute('''
            SELECT * FROM audit_logs 
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        ''', (limit, offset)).fetchall()
        conn.close()
        return logs
    
    @staticmethod
    def get_logs_count():
        conn = get_db_connection()
        count = conn.execute('SELECT COUNT(*) as count FROM audit_logs').fetchone()['count']
        conn.close()
        return count