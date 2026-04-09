from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response, send_file
from functools import wraps
import pyotp
import qrcode
import io
import base64
import os
import hashlib
from datetime import datetime, timedelta
from config import Config
from models import init_db, User, Document, SignatureRequest, TranscriptRequest, AuditLog, get_db_connection
from crypto_utils import CryptoManager
from fpdf import FPDF

app = Flask(__name__)
app.config.from_object(Config)

# Initialize database
init_db()

UPLOAD_FOLDER = 'uploads'
SIGNATURE_FOLDER = 'signatures'
TRANSCRIPT_FOLDER = 'transcripts'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNATURE_FOLDER, exist_ok=True)
os.makedirs(TRANSCRIPT_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Session management decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            remember_token = request.cookies.get('remember_token')
            if remember_token:
                user = verify_remember_token(remember_token)
                if user:
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    return f(*args, **kwargs)
            
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') != role:
                flash('Unauthorized access.', 'danger')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def verify_remember_token(token):
    try:
        data = base64.b64decode(token).decode().split('|')
        if len(data) == 3:
            user_id, username, expiry = data
            if datetime.fromisoformat(expiry) > datetime.now():
                return User.get_by_id(int(user_id))
    except:
        pass
    return None

def generate_remember_token(user_id, username):
    expiry = (datetime.now() + timedelta(days=7)).isoformat()
    token = base64.b64encode(f"{user_id}|{username}|{expiry}".encode()).decode()
    return token

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# ==================== AUTHENTICATION ROUTES ====================

@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('role') == 'student':
            return redirect(url_for('student_dashboard'))
        elif session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role', 'student')
        
        if not all([username, email, password, confirm_password]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('register'))
        
        user_id = User.create_user(username, email, password, role)
        
        if user_id:
            private_key, public_key = CryptoManager.generate_key_pair()
            encrypted_private_key = CryptoManager.encrypt_private_key(private_key, password)
            User.update_keys(user_id, public_key.decode('utf-8'), encrypted_private_key)
            
            AuditLog.log_action(user_id, username, 'USER_REGISTERED', 
                              f'New {role} account created', request.remote_addr)
            
            flash('Registration successful! Please set up MFA.', 'success')
            session['temp_user_id'] = user_id
            return redirect(url_for('setup_mfa'))
        else:
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/setup_mfa')
def setup_mfa():
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['temp_user_id']
    user = User.get_by_id(user_id)
    
    secret = pyotp.random_base32()
    User.update_mfa_secret(user_id, secret)
    
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user['email'],
        issuer_name='EduCryptSign'
    )
    
    from qrcode.image.pil import PilImage
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)

    img = qr.make_image(image_factory=PilImage)
    
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    qr_code = base64.b64encode(buffer.getvalue()).decode()
    
    return render_template('verify_mfa.html', qr_code=qr_code, secret=secret, setup=True)

@app.route('/verify_mfa_setup', methods=['POST'])
def verify_mfa_setup():
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['temp_user_id']
    user = User.get_by_id(user_id)
    token = request.form.get('token')
    
    totp = pyotp.TOTP(user['mfa_secret'])
    
    if totp.verify(token, valid_window=1):
        session.pop('temp_user_id', None)
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session.permanent = True
        
        AuditLog.log_action(user['id'], user['username'], 
                          'REGISTRATION_COMPLETE', 
                          'MFA setup and auto-login successful', 
                          request.remote_addr)
        
        flash(f'Welcome, {user["username"]}! Your account is ready.', 'success')
        
        if user['role'] == 'student':
            return redirect(url_for('student_dashboard'))
        else:
            return redirect(url_for('admin_dashboard'))
    else:
        flash('Invalid MFA code. Please try again.', 'danger')
        return redirect(url_for('setup_mfa'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'true'
        
        user = User.get_by_username(username)

        if not user:
            flash('Invalid username or password.', 'danger')
            AuditLog.log_action(None, username, 'FAILED_LOGIN', 
                              'Invalid credentials - user not found', request.remote_addr)
            return render_template('login.html')
        
        if User.is_account_locked(user):
            locked_until = datetime.fromisoformat(user['locked_until'])
            remaining = locked_until - datetime.now()
            minutes_remaining = int(remaining.total_seconds() / 60)
            flash(f'Account is locked. Try again in {minutes_remaining} minutes.', 'danger')
            AuditLog.log_action(user['id'], username, 'FAILED_LOGIN', 
                              'Login attempt on locked account', request.remote_addr)
            return render_template('login.html')
        
        if user and User.verify_password(user, password):
            if not user['mfa_enabled']:
                flash('MFA not set up. Please contact administrator.', 'danger')
                return redirect(url_for('login'))
            
            remember_token = request.cookies.get('remember_token')
            if remember_token and verify_remember_token(remember_token):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                session.permanent = True
                
                AuditLog.log_action(user['id'], user['username'], 
                                  'AUTO_LOGIN', 'Remember-me cookie valid', 
                                  request.remote_addr)
                
                flash(f'Welcome back, {user["username"]}!', 'success')
                if user['role'] == 'student':
                    return redirect(url_for('student_dashboard'))
                else:
                    return redirect(url_for('admin_dashboard'))
            
            session['temp_user'] = {
                'id': user['id'],
                'username': user['username'],
                'role': user['role'],
                'mfa_secret': user['mfa_secret'],
                'remember': remember
            }
            
            return redirect(url_for('inline_mfa'))
            
        else:
            # FAILED LOGIN - Increment counter
            User.increment_login_attempts(user['id'])
            new_attempts = user['login_attempts'] + 1  # Get updated count
            remaining_attempts = Config.MAX_LOGIN_ATTEMPTS - new_attempts
            
            # Check if we should lock the account
            if new_attempts >= Config.MAX_LOGIN_ATTEMPTS:
                User.lock_account(user['id'])
                flash(f'Too many failed attempts. Account locked for {Config.LOCKOUT_DURATION.seconds // 60} minutes.', 'danger')
                AuditLog.log_action(user['id'], username, 'ACCOUNT_LOCKED', 
                                  f'Account locked after {new_attempts} failed attempts', request.remote_addr)
    
    return render_template('login.html')

@app.route('/inline_mfa', methods=['GET', 'POST'])
def inline_mfa():
    if 'temp_user' not in session:
        return redirect(url_for('login'))
    
    temp_user = session['temp_user']
    
    if request.method == 'POST':
        token = request.form.get('token')
        
        totp = pyotp.TOTP(temp_user['mfa_secret'])
        
        if totp.verify(token, valid_window=1):
            session.clear()
            session['user_id'] = temp_user['id']
            session['username'] = temp_user['username']
            session['role'] = temp_user['role']
            session.permanent = True
            
            AuditLog.log_action(temp_user['id'], temp_user['username'], 
                              'LOGIN_SUCCESS', 'MFA verified', request.remote_addr)
            
            flash(f'Welcome back, {temp_user["username"]}!', 'success')
            
            response = make_response(redirect(url_for(
                'student_dashboard' if temp_user['role'] == 'student' else 'admin_dashboard'
            )))
            
            if temp_user.get('remember'):
                remember_token = generate_remember_token(temp_user['id'], temp_user['username'])
                response.set_cookie(
                    'remember_token', 
                    remember_token, 
                    max_age=604800,
                    httponly=True, 
                    samesite='Lax',
                    secure=False
                )
                flash('You will be remembered on this device for 7 days.', 'info')
            
            return response
            
        else:
            flash('Invalid MFA code. Please try again.', 'danger')
            AuditLog.log_action(temp_user['id'], temp_user['username'], 
                              'FAILED_MFA', 'Invalid MFA token', request.remote_addr)
            return redirect(url_for('inline_mfa'))
    
    return render_template('inline_mfa.html', username=temp_user['username'])

@app.route('/logout')
@login_required
def logout():
    AuditLog.log_action(session.get('user_id'), session.get('username'), 
                       'LOGOUT', 'User logged out', request.remote_addr)
    
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('remember_token')
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return response

@app.route('/session_expired')
def session_expired():
    return render_template('session_expired.html')

# ==================== STUDENT ROUTES (SIMPLIFIED) ====================

@app.route('/student/dashboard')
@login_required
@role_required('student')
def student_dashboard():
    user = User.get_by_id(session['user_id'])
    
    # Get transcript requests
    transcript_requests = TranscriptRequest.get_by_student(session['user_id'])
    
    # Check if there's a ready transcript for download
    ready_transcript = TranscriptRequest.get_ready_for_student(session['user_id'])
    
    return render_template('student_dashboard.html', 
                         user=user, 
                         transcript_requests=transcript_requests,
                         ready_transcript=ready_transcript)

@app.route('/student/request_transcript', methods=['GET', 'POST'])
@login_required
@role_required('student')
def request_transcript():
    if request.method == 'POST':
        reason = request.form.get('reason')
        password = request.form.get('password')
        
        # Handle signature file upload
        if 'signature_file' not in request.files:
            flash('Digital signature file is required.', 'danger')
            return redirect(url_for('request_transcript'))
        
        signature_file = request.files['signature_file']
        
        if signature_file.filename == '':
            flash('No signature file selected.', 'danger')
            return redirect(url_for('request_transcript'))
        
        if not reason or not password:
            flash('Reason and password are required.', 'danger')
            return redirect(url_for('request_transcript'))
        
        user = User.get_by_id(session['user_id'])
        
        # Verify password is correct (using the password hash in database)
        if not User.verify_password(user, password):
            flash('Invalid password. Cannot sign request.', 'danger')
            return redirect(url_for('request_transcript'))
        
        # Save signature file
        filename = f"student_sig_{session['user_id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}.png"
        signature_path = os.path.join(app.config['UPLOAD_FOLDER'], SIGNATURE_FOLDER, filename)
        os.makedirs(os.path.dirname(signature_path), exist_ok=True)
        signature_file.save(signature_path)
        
        # Create HMAC signature using password
        signed_timestamp = datetime.now().isoformat()
        data_to_sign = f"{user['username']}|{user['email']}|{reason}|{signed_timestamp}"
        signature = CryptoManager.sign_document(password, data_to_sign)
        
        if signature:
            # Create password hash for verification (first 16 chars of SHA256)
            password_hash = hashlib.sha256(password.encode()).hexdigest()[:16]
            
            request_id = TranscriptRequest.create_request(
                user['id'],           # 1. student_id
                user['username'],     # 2. student_username  
                user['email'],        # 3. student_email
                reason,               # 4. reason
                signature,            # 5. signature
                signature_path,       # 6. signature_path
                signed_timestamp,     # 7. signed_timestamp
                data_to_sign,         # 8. signed_data
                password_hash         # 9. password_hash
            )
            
            AuditLog.log_action(user['id'], user['username'], 'TRANSCRIPT_REQUESTED',
                              f'Request ID: {request_id}', request.remote_addr)
            
            flash('Transcript request submitted successfully!', 'success')
            return redirect(url_for('student_dashboard'))
        else:
            flash('Failed to create signature.', 'danger')
            return redirect(url_for('request_transcript'))
    
    return render_template('student_request_transcript.html')

@app.route('/student/download_transcript/<int:request_id>')
@login_required
@role_required('student')
def download_transcript(request_id):
    transcript_request = TranscriptRequest.get_by_id(request_id)
    
    if not transcript_request or transcript_request['student_id'] != session['user_id']:
        flash('Transcript not found.', 'danger')
        return redirect(url_for('student_dashboard'))
    
    if transcript_request['status'] != 'ready':
        flash('Transcript is not ready for download yet.', 'warning')
        return redirect(url_for('student_dashboard'))
    
    if not transcript_request['transcript_path'] or not os.path.exists(transcript_request['transcript_path']):
        flash('Transcript file not found. Please contact administrator.', 'danger')
        return redirect(url_for('student_dashboard'))
    
    # Log download
    AuditLog.log_action(session['user_id'], session['username'], 
                       'TRANSCRIPT_DOWNLOADED',
                       f'Downloaded transcript Request ID: {request_id}', 
                       request.remote_addr)
    
    return send_file(transcript_request['transcript_path'], as_attachment=True)

# ==================== ADMIN ROUTES ====================

@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    # Get counts for dashboard
    pending_transcripts = [r for r in TranscriptRequest.get_all_requests() if r['status'] == 'pending']
    pending_transcripts_count = len(pending_transcripts)
    
    # Get recent audit logs
    recent_logs = AuditLog.get_all_logs(limit=5)
    
    return render_template('admin_dashboard.html',
                         pending_transcripts_count=pending_transcripts_count,
                         recent_logs=recent_logs)

@app.route('/admin/transcript_requests')
@login_required
@role_required('admin')
def transcript_requests():
    requests = TranscriptRequest.get_all_requests()
    return render_template('admin_transcript_requests.html', requests=requests)

@app.route('/admin/verify_transcript/<int:request_id>')
@login_required
@role_required('admin')
def verify_transcript(request_id):
    transcript_request = TranscriptRequest.get_by_id(request_id)
    
    if not transcript_request:
        flash('Request not found.', 'danger')
        return redirect(url_for('transcript_requests'))
    
    has_signature = (
        transcript_request.get('signature') and 
        transcript_request.get('signed_data') and
        transcript_request.get('signed_timestamp')
    )
    
    is_valid = bool(has_signature)
    
    return render_template('admin_verify_transcript.html', 
                         request=transcript_request, 
                         student={'username': transcript_request['student_username']},
                         is_valid=is_valid)

@app.route('/admin/process_transcript/<int:request_id>', methods=['POST'])
@login_required
@role_required('admin')
def process_transcript(request_id):
    """Handle approve/reject for transcript requests"""
    action = request.form.get('action')
    notes = request.form.get('notes', '')
    
    if action not in ['approved', 'rejected']:
        flash('Invalid action.', 'danger')
        return redirect(url_for('transcript_requests'))
    
    transcript_request = TranscriptRequest.get_by_id(request_id)
    if not transcript_request:
        flash('Request not found.', 'danger')
        return redirect(url_for('transcript_requests'))
    
    student = User.get_by_id(transcript_request['student_id'])
    
    if action == 'approved':
        # Generate transcript PDF file
        transcript_filename = f"transcript_{request_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.pdf"
        transcript_path = os.path.join(TRANSCRIPT_FOLDER, transcript_filename)
        os.makedirs(os.path.dirname(transcript_path), exist_ok=True)
        
        # Create actual PDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'OFFICIAL TRANSCRIPT', ln=True, align='C')
        pdf.ln(10)
        
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 10, f"Student: {transcript_request['student_username']}", ln=True)
        pdf.cell(0, 10, f"Email: {transcript_request['student_email']}", ln=True)
        pdf.cell(0, 10, f"Reason: {transcript_request['reason']}", ln=True)
        pdf.cell(0, 10, f"Approved by: {session['username']}", ln=True)
        pdf.cell(0, 10, f"Date: {datetime.now().isoformat()}", ln=True)
        pdf.ln(10)
        
        pdf.set_font('Arial', 'I', 10)
        pdf.cell(0, 10, f"Digital Signature: {transcript_request['signature'][:50]}...", ln=True)
        
        pdf.output(transcript_path)
        
        # Update status to 'ready'
        TranscriptRequest.update_status(request_id, 'ready', session['user_id'], notes, transcript_path)
        
        flash(f'Transcript request approved. Student can now download.', 'success')
        AuditLog.log_action(session['user_id'], session['username'], 
                           'TRANSCRIPT_APPROVED',
                           f'Approved transcript request {request_id} for {student["username"]}', 
                           request.remote_addr)
    else:
        # Reject the request
        TranscriptRequest.update_status(request_id, 'rejected', session['user_id'], notes)
        
        flash('Transcript request rejected.', 'info')
        AuditLog.log_action(session['user_id'], session['username'], 
                           'TRANSCRIPT_REJECTED',
                           f'Rejected transcript request {request_id} for {student["username"]}. Notes: {notes}', 
                           request.remote_addr)
    
    return redirect(url_for('transcript_requests'))

@app.route('/admin/audit_log')
@login_required
@role_required('admin')
def audit_log():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    logs = AuditLog.get_all_logs(limit=per_page, offset=(page-1)*per_page)
    total_logs = AuditLog.get_logs_count()
    total_pages = (total_logs + per_page - 1) // per_page
    
    return render_template('admin_audit_log.html', 
                         logs=logs, 
                         page=page, 
                         total_pages=total_pages,
                         total_logs=total_logs)

@app.route('/debug')
def debug_redirect():
    """Debug route to check what's causing redirects"""
    output = []
    output.append(f"<h1>Debug Info</h1>")
    output.append(f"<p><strong>Session contents:</strong> {dict(session)}</p>")
    output.append(f"<p><strong>Request path:</strong> {request.path}</p>")
    output.append(f"<p><strong>User ID in session:</strong> {'user_id' in session}</p>")
    
    if 'user_id' in session:
        output.append(f"<p><strong>User ID:</strong> {session.get('user_id')}</p>")
        output.append(f"<p><strong>Role:</strong> {session.get('role')}</p>")
        output.append(f"<p><a href='/student/dashboard'>Go to Student Dashboard</a></p>")
        output.append(f"<p><a href='/admin/dashboard'>Go to Admin Dashboard</a></p>")
        output.append(f"<p><a href='/logout'>Logout</a></p>")
    else:
        output.append(f"<p><strong>Not logged in</strong></p>")
        output.append(f"<p><a href='/login'>Go to Login</a></p>")
        output.append(f"<p><a href='/register'>Go to Register</a></p>")
    
    return "<br>".join(output)

@app.route('/clear_session')
def clear_session():
    session.clear()
    return "Session cleared! <a href='/login'>Go to login</a>"

@app.route('/check_db')
def check_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [t[0] for t in cursor.fetchall()]
        
        output = f"<h1>Database Tables</h1><ul>"
        for table in tables:
            output += f"<li>{table}</li>"
            
            # Check columns
            cursor.execute(f"PRAGMA table_info({table})")
            columns = [c[1] for c in cursor.fetchall()]
            output += f"<ul><li>Columns: {', '.join(columns)}</li></ul>"
        
        output += "</ul>"
        conn.close()
        return output
        
    except Exception as e:
        return f"<h1>Error</h1><p>{str(e)}</p>"
    
@app.route('/debug_login/<username>')
def debug_login(username):
    user = User.get_by_username(username)
    if not user:
        return f"User '{username}' not found in database"
    
    output = f"<h1>User: {username}</h1>"
    output += f"<p>ID: {user['id']}</p>"
    output += f"<p>Email: {user['email']}</p>"
    output += f"<p>Role: {user['role']}</p>"
    output += f"<p>MFA Enabled: {user['mfa_enabled']}</p>"
    output += f"<p>Login Attempts: {user['login_attempts']}</p>"
    output += f"<p>Locked Until: {user['locked_until']}</p>"
    output += f"<p>Password Hash: {user['password_hash'][:30]}...</p>"
    
    # Test a password
    test_password = "your_password_here"
    is_valid = User.verify_password(user, test_password)
    output += f"<p>Password '{test_password}' valid: {is_valid}</p>"
    
    return output

@app.route('/fix_user/<username>')
def fix_user(username):
    conn = get_db_connection()
    conn.execute("UPDATE users SET mfa_enabled = 1, login_attempts = 0, locked_until = NULL WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    return f"Fixed user {username}"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)