from flask import Flask, send_from_directory, request, redirect, url_for, session, jsonify
import sqlite3
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import difflib
from datetime import datetime, timedelta
from difflib import SequenceMatcher
import re
from collections import Counter
import csv
from io import StringIO
from flask_session import Session
import uuid
from werkzeug.datastructures import CallbackDict
from contextlib import contextmanager
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from logging.handlers import RotatingFileHandler
from session_manager import SessionManager

# Update DATABASE path to ensure the directory exists
DATABASE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database')
DATABASE = os.path.join(DATABASE_DIR, 'database.db')
UPLOAD_FOLDER = os.path.join(DATABASE_DIR, 'uploads')

# Create necessary directories
os.makedirs(DATABASE_DIR, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_next_reset_time():
    now = datetime.now()
    next_reset = now + timedelta(minutes=5)
    return next_reset.strftime("%Y-%m-%d %H:%M:%S")

app = Flask(__name__, static_folder="../frontend", static_url_path="")

# Update initialize_db function
def initialize_db():
    try:
        # First check if database exists
        db_exists = os.path.exists(DATABASE)
        
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if not db_exists:  # Only drop tables if this is a new database
            print("Creating new database...")
            # Drop existing tables if they exist
            cursor.execute("DROP TABLE IF EXISTS scan_history")
            cursor.execute("DROP TABLE IF EXISTS scans")
            cursor.execute("DROP TABLE IF EXISTS documents")
            cursor.execute("DROP TABLE IF EXISTS users")
        
        # Create tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                credits INTEGER DEFAULT 20,
                is_admin INTEGER DEFAULT 0,
                last_reset DATETIME DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now', 'localtime'))
            )
        """)
        
        # Check if last_reset column exists, if not add it
        columns = cursor.execute("PRAGMA table_info(users)").fetchall()
        column_names = [column[1] for column in columns]
        
        if 'last_reset' not in column_names:
            print("Adding last_reset column to users table...")
            cursor.execute("ALTER TABLE users ADD COLUMN last_reset DATETIME")
            cursor.execute("""
                UPDATE users 
                SET last_reset = strftime('%Y-%m-%d %H:%M:%S', 'now', 'localtime')
                WHERE last_reset IS NULL
            """)
            conn.commit()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                filename TEXT,
                content TEXT,
                topic TEXT,
                upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                filename TEXT,
                scan_result TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                action TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS credit_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                requested_amount INTEGER,
                request_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending',
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Create admin user if it doesn't exist
        admin_exists = cursor.execute("SELECT 1 FROM users WHERE username = 'admin'").fetchone()
        if not admin_exists:
            admin_password = generate_password_hash('admin123')
            cursor.execute("""
                INSERT INTO users (username, password, credits, is_admin)
                VALUES (?, ?, ?, ?)
            """, ('admin', admin_password, 999999, 1))
            print("Admin user created")
        
        conn.commit()
        print("Database initialized successfully")
        
    except Exception as e:
        print(f"Database initialization error: {str(e)}")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()

@contextmanager
def get_db_connection():
    conn = None
    try:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        yield conn
    finally:
        if conn:
            conn.close()

initialize_db()

# Serve static HTML files
@app.route('/')
def home():
    return send_from_directory(app.static_folder, "index.html")

@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory(app.static_folder, filename)

# Add this error handler function at the top
def handle_error(error_msg, status_code=400):
    return jsonify({
        "error": error_msg,
        "status": "error",
        "timestamp": datetime.now().isoformat()
    }), status_code

def validate_input(**validators):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            data = request.get_json() or request.form
            for field, validator in validators.items():
                if not validator(data.get(field, '')):
                    return handle_error(f"Invalid {field}")
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Update the registration route
@app.route('/auth/register', methods=['POST'])
@validate_input(
    username=lambda x: x and len(x) >= 3 and re.match(r'^[a-zA-Z0-9_]+$', x),
    password=lambda x: x and len(x) >= 8
)
def register():
    try:
        username = request.form.get('username')
        password = request.form.get('password')

        # Enhanced validation
        if not username or not password:
            return handle_error("Username and password are required")
            
        if len(username) < 3:
            return handle_error("Username must be at least 3 characters long")
            
        if len(password) < 8:
            return handle_error("Password must be at least 8 characters long")
            
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return handle_error("Username can only contain letters, numbers, and underscores")

        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if username already exists
            if conn.execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone():
                return handle_error("Username already exists")

            # Hash password and create user
            hashed_password = generate_password_hash(password)
            cursor.execute(
                'INSERT INTO users (username, password, credits) VALUES (?, ?, 20)',
                (username, hashed_password)
            )
            conn.commit()

        return jsonify({
            "status": "success",
            "message": "Registration successful"
        })

    except Exception as e:
        print(f"Registration error: {str(e)}")
        return handle_error("An unexpected error occurred", 500)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'user')

        if not username or not password:
            return jsonify({'success': False, 'error': 'Missing username or password'}), 400

        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            user = cursor.execute('''
                SELECT id, username, password, is_admin, credits,
                       strftime('%Y-%m-%d %H:%M:%S', last_reset) as last_reset
                FROM users 
                WHERE username = ?
            ''', (username,)).fetchone()
            
            if not user:
                return jsonify({'success': False, 'error': 'User not found'}), 401

            if not check_password_hash(user['password'], password):
                return jsonify({'success': False, 'error': 'Invalid password'}), 401

            user = dict(user)
            is_admin = bool(user['is_admin'])

            # Validate role
            if (role == 'admin' and not is_admin) or (role == 'user' and is_admin):
                return jsonify({'success': False, 'error': 'Invalid role for this user'}), 403

            # Clear any existing sessions
            SessionManager.clear_user_session()
            SessionManager.clear_admin_session()

            # Create appropriate session
            if is_admin:
                SessionManager.create_admin_session(user['id'], user['username'])
                app.logger.info(f"Admin login successful: {username}")
            else:
                SessionManager.create_user_session(user['id'], user['username'])
                try:
                    handle_credit_reset(cursor, user)
                    conn.commit()
                except Exception as e:
                    app.logger.error(f"Error processing credit reset: {str(e)}")

            return jsonify({
                'success': True,
                'username': user['username'],
                'is_admin': is_admin,
                'credits': user['credits']
            })

    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('home'))

    return send_from_directory(app.static_folder, "profile.html")  # Serve profile page

@app.route('/user/profile')
@SessionManager.user_required
def get_user_profile():
    user_session = SessionManager.get_current_user()
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            user = cursor.execute(
                "SELECT username, credits FROM users WHERE id = ?", 
                (user_session['user_id'],)
            ).fetchone()
            
            # Get scan history with similarity scores
            scans = cursor.execute("""
                SELECT 
                    sh.id,
                    sh.filename,
                    sh.scan_result,
                    sh.timestamp,
                    CASE 
                        WHEN sh.scan_result LIKE '%Found%' 
                        THEN CAST(
                            REPLACE(
                                REPLACE(
                                    SUBSTR(sh.scan_result, 
                                        INSTR(sh.scan_result, 'similarity: ') + 11,
                                        INSTR(sh.scan_result, '%') - (INSTR(sh.scan_result, 'similarity: ') + 11) + 3
                                    ),
                                ' ', ''
                                ),
                            '%', ''
                            ) AS FLOAT
                        )
                        ELSE 0 
                    END as similarity
                FROM scan_history sh
                WHERE sh.user_id = ?
                ORDER BY sh.timestamp DESC
            """, (user_session['user_id'],)).fetchall()
            
            scan_history = [{
                'id': scan['id'],
                'filename': scan['filename'],
                'timestamp': scan['timestamp'],
                'similarity': scan['similarity']
            } for scan in scans]

            return jsonify({
                "username": user['username'],
                "credits": user['credits'],
                "next_reset": get_next_reset_time(),
                "scans": scan_history
            })

    except Exception as e:
        print(f"Error getting profile: {str(e)}")
        return jsonify({"error": "Failed to get profile"}), 500

def preprocess_text(text):
    """Clean and preprocess text for better comparison"""
    # Convert to lowercase
    text = text.lower()
    # Remove special characters and extra whitespace
    text = re.sub(r'[^\w\s]', '', text)
    # Split into words
    return text.split()

def get_similarity_score(text1, text2):
    """Calculate similarity between two texts using multiple metrics"""
    # Preprocess texts
    words1 = preprocess_text(text1)
    words2 = preprocess_text(text2)
    
    # Get word frequency distributions
    freq1 = Counter(words1)
    freq2 = Counter(words2)
    
    # Calculate Jaccard similarity
    common_words = set(words1) & set(words2)
    all_words = set(words1) | set(words2)
    jaccard = len(common_words) / len(all_words) if all_words else 0
    
    # Calculate sequence similarity
    sequence_sim = SequenceMatcher(None, text1, text2).ratio()
    
    # Calculate cosine similarity based on word frequencies
    common_words = set(freq1.keys()) & set(freq2.keys())
    dot_product = sum(freq1[word] * freq2[word] for word in common_words)
    norm1 = sum(freq1[word] ** 2 for word in freq1)
    norm2 = sum(freq2[word] ** 2 for word in freq2)
    cosine = dot_product / ((norm1 * norm2) ** 0.5) if norm1 and norm2 else 0
    
    # Calculate combined similarity with adjusted weights
    combined_similarity = (0.5 * sequence_sim + 0.3 * jaccard + 0.2 * cosine)
    
    # Adjust the similarity scale to be more sensitive
    adjusted_similarity = combined_similarity * 100
    
    # Round to 2 decimal places
    return round(adjusted_similarity, 2)

@app.route('/scan', methods=['POST'])
@SessionManager.user_required
def scan_document():
    user_session = SessionManager.get_current_user()
    try:
        if 'file' not in request.files:
            return handle_error("No file was uploaded")

        file = request.files['file']
        if file.filename == '':
            return handle_error("No file was selected")

        # Validate file type
        if not file.filename.endswith('.txt'):
            return handle_error("Only .txt files are supported")

        # Validate file size (e.g., 5MB limit)
        if len(file.read()) > 5 * 1024 * 1024:
            return handle_error("File size exceeds 5MB limit")
        file.seek(0)  # Reset file pointer

        # Check credits
        with get_db_connection() as conn:
            cursor = conn.cursor()
            user = cursor.execute(
                "SELECT credits FROM users WHERE id = ?", 
                (user_session['user_id'],)
            ).fetchone()

            if not user:
                return handle_error("User not found", 404)

            if user['credits'] <= 0:
                return handle_error("Insufficient credits. Please request more credits.")

            # Read and validate file content
            try:
                content = file.read().decode('utf-8')
                if not content.strip():
                    return handle_error("File is empty")
            except UnicodeDecodeError:
                return handle_error("Invalid file format. Please upload a valid text file.")

            # Save document to database
            cursor.execute("""
                INSERT INTO documents (user_id, filename, content)
                VALUES (?, ?, ?)
            """, (user_session['user_id'], file.filename, content))
            
            doc_id = cursor.lastrowid

            # Deduct credits
            cursor.execute("""
                UPDATE users 
                SET credits = credits - 1 
                WHERE id = ?
            """, (user_session['user_id'],))

            # Find similar documents
            similar_docs = cursor.execute("""
                SELECT id, filename, content 
                FROM documents 
                WHERE user_id = ? AND id != ?
            """, (user_session['user_id'], doc_id)).fetchall()

            matches = []
            for doc in similar_docs:
                similarity = get_similarity_score(content, doc['content'])
                # Include all matches with their actual similarity score
                matches.append({
                    "filename": doc['filename'],
                    "similarity": similarity,
                    "details": {
                        "word_count": len(preprocess_text(doc['content'])),
                        "common_phrases": find_common_phrases(content, doc['content'])
                    }
                })

            # Sort matches by similarity score
            matches.sort(key=lambda x: x['similarity'], reverse=True)

            # Log the scan in scan_history
            cursor.execute("""
                INSERT INTO scan_history (user_id, filename, scan_result)
                VALUES (?, ?, ?)
            """, (
                user_session['user_id'],
                file.filename,
                f"Found {len(matches)} similar documents with similarity: {matches[0]['similarity']:.2f}%" if matches else "No matches found"
            ))

            conn.commit()
            
            # Get remaining credits
            remaining_credits = cursor.execute(
                "SELECT credits FROM users WHERE id = ?", 
                (user_session['user_id'],)
            ).fetchone()['credits']

            return jsonify({
                "success": True,
                "message": "File scanned successfully",
                "remaining_credits": remaining_credits,
                "similar_documents": matches,
                "total_matches": len(matches)
            })

    except Exception as e:
        print(f"Scan error: {str(e)}")
        return handle_error("An unexpected error occurred while processing the file", 500)

def find_common_phrases(text1, text2, min_length=3):
    """Find common phrases between two texts"""
    words1 = preprocess_text(text1)
    words2 = preprocess_text(text2)
    
    common_phrases = []
    
    # Look for common phrases of different lengths
    for phrase_length in range(min_length, 6):
        phrases1 = set(
            ' '.join(words1[i:i+phrase_length]) 
            for i in range(len(words1)-phrase_length+1)
        )
        phrases2 = set(
            ' '.join(words2[i:i+phrase_length]) 
            for i in range(len(words2)-phrase_length+1)
        )
        
        # Get common phrases
        common = phrases1 & phrases2
        if common:
            common_phrases.extend(list(common)[:3])  # Limit to top 3 phrases per length
    
    return common_phrases[:5]  # Return top 5 common phrases overall

@app.route('/matches/<int:doc_id>', methods=['GET'])
def find_similar_documents(doc_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        current_doc = cursor.execute("SELECT content FROM documents WHERE id = ?", (doc_id,)).fetchone()

        if not current_doc:
            return jsonify({"error": "Document not found"}), 404

        current_text = current_doc["content"]
        all_docs = cursor.execute("SELECT id, filename, content FROM documents WHERE id != ?", (doc_id,)).fetchall()

        matches = []
        for doc in all_docs:
            similarity = difflib.SequenceMatcher(None, current_text, doc["content"]).ratio()
            if similarity > 0.5:  # Only consider matches above 50%
                matches.append({
                    "doc_id": doc["id"],
                    "filename": doc["filename"],
                    "similarity": round(similarity, 2)
                })

        return jsonify(matches)

@app.route('/auth/logout', methods=['POST'])
def logout():
    data = request.get_json()
    role = data.get('role', 'user')
    
    if role == 'admin':
        SessionManager.clear_admin_session()
    else:
        SessionManager.clear_user_session()
    
    return jsonify({'success': True})

# Replace the old is_admin() function with this
def is_admin():
    admin_session = SessionManager.get_current_admin()
    return admin_session is not None

# Update the admin_required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_admin():
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated_function

# Update the admin dashboard route
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    return send_from_directory(app.static_folder, "admin.html")

# Update the get_all_users route
@app.route('/admin/users')
@admin_required
def get_all_users():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            users = cursor.execute("""
                SELECT 
                    u.id,
                    u.username, 
                    u.credits,
                    COUNT(DISTINCT d.id) as total_documents,
                    MAX(d.upload_time) as last_activity
                FROM users u
                LEFT JOIN documents d ON u.id = d.user_id
                WHERE u.is_admin = 0
                GROUP BY u.id, u.username
            """).fetchall()
            
            # Convert rows to list of dictionaries
            return jsonify([{
                'id': user['id'],
                'username': user['username'],
                'credits': user['credits'],
                'total_documents': user['total_documents'] or 0,
                'last_activity': user['last_activity'] or 'Never'
            } for user in users])
    except Exception as e:
        app.logger.error(f"Error getting users: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/admin/delete/<username>', methods=['DELETE'])
def delete_user(username):
    if admin_required():
        return admin_required()

    if username == "admin":
        return jsonify({"error": "Cannot delete admin account"}), 400

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()

    return jsonify({"success": True})

@app.route('/admin/analytics')
@SessionManager.admin_required
def get_analytics_data():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Parse query parameters
            date_range = request.args.get('dateRange', '')
            user_filter = request.args.get('user', '')
            activity_filter = request.args.get('activity', '')
            sort_by = request.args.get('sort', 'date')
            
            # Get basic stats
            total_users = cursor.execute(
                "SELECT COUNT(*) as count FROM users WHERE is_admin = 0"
            ).fetchone()['count']
            
            total_credits = cursor.execute(
                "SELECT SUM(credits) as sum FROM users WHERE is_admin = 0"
            ).fetchone()['sum'] or 0
            
            # Get daily scan usage for the past week
            usage_data = cursor.execute("""
                SELECT DATE(upload_time) as date, COUNT(*) as count
                FROM documents
                WHERE upload_time >= date('now', '-7 days')
                GROUP BY DATE(upload_time)
                ORDER BY date
            """).fetchall()

            if not usage_data:
                today = datetime.now()
                usage_data = [
                    {'date': (today - timedelta(days=i)).strftime('%Y-%m-%d'), 'count': 0}
                    for i in range(7, -1, -1)
                ]
            
            # Get top users with enhanced details
            top_users = cursor.execute("""
                SELECT 
                    u.username,
                    COUNT(d.id) as total_scans,
                    COUNT(d.id) as credits_used,
                    'General' as common_topic,
                    MAX(d.upload_time) as last_activity,
                    CAST(
                        (CAST(COUNT(CASE WHEN sh.scan_result LIKE '%Found%' THEN 1 END) AS FLOAT) * 100 / 
                        CAST(CASE WHEN COUNT(sh.id) > 0 THEN COUNT(sh.id) ELSE 1 END AS FLOAT)) 
                        AS INTEGER
                    ) as success_rate
                FROM users u
                LEFT JOIN documents d ON u.id = d.user_id
                LEFT JOIN scan_history sh ON u.id = sh.user_id
                WHERE u.is_admin = 0
                GROUP BY u.id, u.username
                ORDER BY total_scans DESC
                LIMIT 5
            """).fetchall()

            # Format top users data
            formatted_top_users = [{
                'username': user['username'],
                'total_scans': user['total_scans'],
                'credits_used': user['credits_used'],
                'common_topic': user['common_topic'],
                'last_activity': user['last_activity'].split('.')[0] if user['last_activity'] else 'Never',
                'success_rate': user['success_rate']
            } for user in top_users] if top_users else []

            # Get document analysis with enhanced metrics
            docs_analysis = cursor.execute("""
                SELECT 
                    'All Documents' as topic,
                    COUNT(*) as doc_count,
                    (SELECT COUNT(*) FROM scan_history WHERE scan_result LIKE '%Found%') * 100.0 / 
                    (SELECT CASE WHEN COUNT(*) > 0 THEN COUNT(*) ELSE 1 END FROM scan_history) as similarity_rate
                FROM documents
            """).fetchall()

            # Format topics analysis
            topics_analysis = [{
                'name': doc['topic'],
                'count': doc['doc_count'],
                'percentage': 100.0,
                'average_similarity': round(doc['similarity_rate'], 1) if doc['similarity_rate'] else 0,
                'trend': '↑' if doc['doc_count'] > 0 else '↓'
            } for doc in docs_analysis] if docs_analysis else []

            return jsonify({
                'total_users': total_users,
                'total_credits': total_credits,
                'usage_data': {
                    'labels': [row['date'] for row in usage_data],
                    'values': [row['count'] for row in usage_data]
                },
                'topics_data': {
                    'labels': ['All Documents'],
                    'values': [sum(row['count'] for row in usage_data)]
                },
                'credits_data': {
                    'labels': [user['username'] for user in formatted_top_users],
                    'values': [user['credits_used'] for user in formatted_top_users]
                },
                'activity_data': {
                    'labels': [row['date'] for row in usage_data],
                    'values': [row['count'] for row in usage_data]
                },
                'top_users': formatted_top_users,
                'topics_analysis': topics_analysis
            })

    except Exception as e:
        print(f"Error getting analytics: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/admin/approve_credits', methods=['POST'])
def approve_credits():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403

    user_id = request.json.get("user_id")
    credits = request.json.get("credits")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET credits = credits + ? WHERE id = ?", (credits, user_id))
        conn.commit()

    return jsonify({"success": True})

@app.route('/admin/scan_history')
def scan_history():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        history = cursor.execute("SELECT * FROM scan_history ORDER BY timestamp DESC").fetchall()

    return jsonify([dict(entry) for entry in history])

# Current configuration
app.config.update(
    SESSION_TYPE='filesystem',
    SESSION_PERMANENT=True,
    PERMANENT_SESSION_LIFETIME=timedelta(days=1),
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_FILE_DIR='./flask_session',  # Directory to store session files
    SESSION_KEY_PREFIX='docscanner_'
)

# Secret key handling
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# Initialize Flask-Session
Session(app)

# Create session directory if it doesn't exist
os.makedirs('./flask_session', exist_ok=True)

@app.before_request
def check_session():
    # List of endpoints that don't require authentication
    public_endpoints = ['static', 'login', 'register', 'home']
    
    if request.endpoint and request.endpoint not in public_endpoints:
        # Check if it's an admin route
        if request.path.startswith('/admin'):
            if not SessionManager.get_current_admin():
                return jsonify({"error": "Admin login required"}), 403
        # Check if it's a user route
        elif not (SessionManager.get_current_user() or SessionManager.get_current_admin()):
            return jsonify({"error": "Login required"}), 403

@app.route('/admin/stats')
def get_admin_stats():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
        
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get total users (excluding admin)
            total_users = cursor.execute(
                "SELECT COUNT(*) as count FROM users WHERE is_admin = 0"
            ).fetchone()['count']
            
            # Get total credits in system
            total_credits = cursor.execute(
                "SELECT SUM(credits) as sum FROM users WHERE is_admin = 0"
            ).fetchone()['sum'] or 0
            
            # Get total documents scanned
            total_documents = cursor.execute("""
                SELECT COUNT(*) as count 
                FROM documents d
                JOIN users u ON d.user_id = u.id
                WHERE u.is_admin = 0
            """).fetchone()['count']
            
            return jsonify({
                "total_users": total_users,
                "total_credits": total_credits,
                "total_documents": total_documents
            })
    except Exception as e:
        print(f"Error getting admin stats: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/admin/credit_requests')
def get_credit_requests():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
        
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            requests = cursor.execute("""
                SELECT cr.id, u.username, u.credits as current_credits,
                       cr.requested_amount, cr.request_date
                FROM credit_requests cr
                JOIN users u ON cr.user_id = u.id
                WHERE cr.status = 'pending'
                ORDER BY cr.request_date DESC
            """).fetchall()
            
            return jsonify([dict(req) for req in requests])
    except Exception as e:
        print(f"Error getting credit requests: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/admin/credit_requests/<int:request_id>', methods=['POST'])
def handle_credit_request(request_id):
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
        
    try:
        approve = request.json.get('approve', False)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get request details
            credit_request = cursor.execute(
                "SELECT user_id, requested_amount FROM credit_requests WHERE id = ?",
                (request_id,)
            ).fetchone()
            
            if not credit_request:
                return jsonify({"error": "Request not found"}), 404
            
            if approve:
                # Add credits to user
                cursor.execute("""
                    UPDATE users 
                    SET credits = credits + ? 
                    WHERE id = ?
                """, (credit_request['requested_amount'], credit_request['user_id']))
            
            # Update request status
            cursor.execute("""
                UPDATE credit_requests 
                SET status = ? 
                WHERE id = ?
            """, ('approved' if approve else 'denied', request_id))
            
            conn.commit()

        return jsonify({"success": True})
    except Exception as e:
        print(f"Error handling credit request: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/admin/add_credits', methods=['POST'])
def add_user_credits():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
        
    try:
        username = request.json.get('username')
        amount = request.json.get('amount')
        
        if not username or not amount:
            return jsonify({"error": "Missing username or amount"}), 400
            
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users 
                SET credits = credits + ? 
                WHERE username = ?
            """, (amount, username))
            
            conn.commit()

        return jsonify({"success": True})
    except Exception as e:
        print(f"Error adding credits: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# Add this new route for credit requests
@app.route('/credits/request', methods=['POST'])
def request_credits():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 403
        
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if user already has a pending request
            existing_request = cursor.execute("""
                SELECT 1 FROM credit_requests 
                WHERE user_id = ? AND status = 'pending'
            """, (session['user_id'],)).fetchone()
            
            if existing_request:
                return "You already have a pending credit request", 400
            
            # Get user's current credits
            user = cursor.execute("""
                SELECT credits FROM users WHERE id = ?
            """, (session['user_id'],)).fetchone()
            
            # Default request amount (you can modify this logic)
            requested_amount = 20
            
            # Create new credit request
            cursor.execute("""
                INSERT INTO credit_requests (user_id, requested_amount)
                VALUES (?, ?)
            """, (session['user_id'], requested_amount))
            
            # Log the request
            cursor.execute("""
                INSERT INTO activity_log (username, action)
                VALUES (?, ?)
            """, (session['username'], f"Requested {requested_amount} credits"))
            
            conn.commit()

        return "Credit request submitted successfully. An admin will review your request.", 200
        
    except Exception as e:
        print(f"Error requesting credits: {str(e)}")
        return "Failed to submit credit request", 500

@app.route('/admin/export-data')
def export_analytics_data():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
        
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Create a string buffer to write CSV data
            si = StringIO()
            writer = csv.writer(si)
            
            # System Overview
            writer.writerow(['System Analytics Overview'])
            writer.writerow(['Generated on:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
            
            # Get system stats
            total_users = cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = 0").fetchone()[0]
            total_docs = cursor.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
            total_scans = cursor.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
            
            writer.writerow(['Total Users:', total_users])
            writer.writerow(['Total Documents:', total_docs])
            writer.writerow(['Total Scans:', total_scans])
            writer.writerow([])

            # User Activity Summary
            writer.writerow(['User Activity Summary'])
            writer.writerow(['Username', 'Total Documents', 'Total Scans', 'Credits Balance', 
                            'Success Rate', 'Last Activity', 'Avg. Similarity Score', 'Status'])
            
            users_data = cursor.execute("""
                SELECT 
                    u.username,
                    COUNT(DISTINCT d.id) as doc_count,
                    COUNT(DISTINCT sh.id) as scan_count,
                    u.credits,
                    MAX(d.upload_time) as last_activity,
                    CAST(
                        (CAST(COUNT(CASE WHEN sh.scan_result LIKE '%Found%' THEN 1 END) AS FLOAT) * 100 / 
                        NULLIF(COUNT(sh.id), 0)
                    ) AS INTEGER) as success_rate,
                    CAST(AVG(
                        CASE 
                            WHEN sh.scan_result LIKE '%Found%' THEN 100
                            ELSE 0 
                        END
                    ) AS INTEGER) as avg_similarity,
                    CASE 
                        WHEN u.credits > 50 THEN 'High Credits'
                        WHEN u.credits > 20 THEN 'Moderate Credits'
                        ELSE 'Low Credits'
                    END as status
                FROM users u
                LEFT JOIN documents d ON u.id = d.user_id
                LEFT JOIN scan_history sh ON u.id = sh.user_id
                WHERE u.is_admin = 0
                GROUP BY u.id, u.username
                ORDER BY doc_count DESC
            """).fetchall()
            
            for user in users_data:
                writer.writerow([
                    user['username'],
                    user['doc_count'],
                    user['scan_count'],
                    user['credits'],
                    f"{user['success_rate'] or 0}%",
                    user['last_activity'] or 'Never',
                    f"{user['avg_similarity'] or 0}%",
                    user['status']
                ])
            
            writer.writerow([])

            # Daily Activity Analysis
            writer.writerow(['Daily Activity Analysis'])
            writer.writerow(['Date', 'Documents Uploaded', 'Scans Performed', 
                            'Unique Users', 'Avg. Similarity', 'Success Rate'])
            
            daily_stats = cursor.execute("""
                WITH daily_data AS (
                    SELECT 
                        DATE(d.upload_time) as date,
                        COUNT(DISTINCT d.id) as doc_count,
                        COUNT(DISTINCT sh.id) as scan_count,
                        COUNT(DISTINCT d.user_id) as unique_users,
                        CAST(AVG(
                            CASE 
                                WHEN sh.scan_result LIKE '%Found%' THEN 100
                                ELSE 0 
                            END
                        ) AS INTEGER) as avg_similarity,
                        CAST(
                            (CAST(COUNT(CASE WHEN sh.scan_result LIKE '%Found%' THEN 1 END) AS FLOAT) * 100 / 
                            NULLIF(COUNT(sh.id), 0)
                        ) AS INTEGER) as success_rate
                    FROM documents d
                    LEFT JOIN scan_history sh ON DATE(d.upload_time) = DATE(sh.timestamp)
                    GROUP BY DATE(d.upload_time)
                    ORDER BY date DESC
                    LIMIT 30
                )
                SELECT *
                FROM daily_data
            """).fetchall()
            
            prev_count = None
            for stat in daily_stats:
                current_count = stat['doc_count']
                trend = ''
                if prev_count is not None:
                    trend = '↑' if current_count > prev_count else '↓'
                prev_count = current_count
                
                writer.writerow([
                    stat['date'],
                    f"{stat['doc_count']}{trend}",
                    stat['scan_count'],
                    stat['unique_users'],
                    f"{stat['avg_similarity']}%",
                    f"{stat['success_rate']}%"
                ])
            
            writer.writerow([])

            # Credit Request Analysis
            writer.writerow(['Credit Request Analysis'])
            writer.writerow(['Username', 'Request Date', 'Amount', 'Status', 
                            'Processing Time', 'Credits Before', 'Credits After'])
            
            credit_requests = cursor.execute("""
                SELECT 
                    u.username,
                    cr.request_date,
                    cr.requested_amount,
                    cr.status,
                    u.credits as current_credits,
                    CASE 
                        WHEN cr.status = 'approved' 
                        THEN (u.credits - cr.requested_amount) 
                        ELSE u.credits 
                    END as credits_before
                FROM credit_requests cr
                JOIN users u ON cr.user_id = u.id
                ORDER BY cr.request_date DESC
            """).fetchall()
            
            for req in credit_requests:
                writer.writerow([
                    req['username'],
                    req['request_date'],
                    req['requested_amount'],
                    req['status'].capitalize(),
                    'Within 24h' if req['status'] != 'pending' else 'Pending',
                    req['credits_before'],
                    req['current_credits']
                ])
            
            # Create response
            output = si.getvalue()
            si.close()
            
            # Create response with CSV file
            response = app.response_class(
                output,
                mimetype='text/csv',
                headers={
                    "Content-Disposition": f"attachment;filename=detailed_analytics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                }
            )
            
            return response
        
    except Exception as e:
        print(f"Error exporting data: {str(e)}")
        return jsonify({"error": "Failed to export data"}), 500

@app.route('/scan/history/<scan_id>', methods=['DELETE'])
def delete_scan_history(scan_id):
    if 'user_id' not in session:
        return handle_error("Please login to continue", 403)
        
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Verify the scan belongs to the user
            scan = cursor.execute("""
                SELECT id FROM scan_history 
                WHERE id = ? AND user_id = ?
            """, (int(scan_id), session['user_id'])).fetchone()
            
            if not scan:
                return handle_error("Scan history not found or unauthorized", 404)
            
            # Delete the scan history
            cursor.execute("DELETE FROM scan_history WHERE id = ?", (int(scan_id),))
            conn.commit()

        return jsonify({
            "status": "success",
            "message": "Scan history deleted successfully"
        })
        
    except Exception as e:
        print(f"Error deleting scan history: {str(e)}")
        return handle_error("Failed to delete scan history", 500)

@app.route('/user/change-password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 403
        
    try:
        data = request.get_json()
        current_password = data.get('currentPassword')
        new_password = data.get('newPassword')
        
        if not current_password or not new_password:
            return jsonify({"error": "Missing current or new password"}), 400
            
        if len(new_password) < 8:
            return jsonify({"error": "New password must be at least 8 characters long"}), 400
            
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get user's current password
            user = cursor.execute(
                "SELECT password FROM users WHERE id = ?", 
                (session['user_id'],)
            ).fetchone()
            
            if not user:
                return jsonify({"error": "User not found"}), 404
            
            # Verify current password
            if not check_password_hash(user['password'], current_password):
                return jsonify({"error": "Current password is incorrect"}), 401
            
            # Update password
            hashed_password = generate_password_hash(new_password)
            cursor.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (hashed_password, session['user_id'])
            )
            
            conn.commit()

        return jsonify({
            "success": True,
            "message": "Password updated successfully"
        })
        
    except Exception as e:
        print(f"Error changing password: {str(e)}")
        return jsonify({"error": "Failed to change password"}), 500

@app.errorhandler(Exception)
def handle_exception(e):
    print(f"Unhandled error: {str(e)}")
    return jsonify({
        "error": "An unexpected error occurred",
        "status": "error",
        "timestamp": datetime.now().isoformat()
    }), 500

def setup_logging():
    if not os.path.exists('logs'):
        os.mkdir('logs')
    
    file_handler = RotatingFileHandler(
        'logs/app.log', 
        maxBytes=10240, 
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s'
    ))
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)

setup_logging()

def handle_credit_reset(cursor, user):
    """Handle credit reset logic for users"""
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    last_reset = datetime.strptime(user['last_reset'], '%Y-%m-%d %H:%M:%S')
    current_time = datetime.strptime(now, '%Y-%m-%d %H:%M:%S')
    
    time_diff = (current_time - last_reset).total_seconds() / 60
    
    if time_diff >= 5:  # Check if 5 minutes have passed
        cursor.execute('''
            UPDATE users 
            SET credits = 20, 
                last_reset = strftime('%Y-%m-%d %H:%M:%S', 'now', 'localtime')
            WHERE id = ?
        ''', (user['id'],))
        user['credits'] = 20

@app.after_request
def after_request(response):
    # Log failed requests
    if response.status_code >= 400:
        app.logger.warning(
            f"Request failed: {request.method} {request.path} - {response.status_code}"
        )
    return response

@app.route('/admin/refresh-data')
@admin_required
def refresh_admin_data():
    """Endpoint to refresh all admin dashboard data"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get latest stats
            stats = {
                'total_users': cursor.execute(
                    "SELECT COUNT(*) as count FROM users WHERE is_admin = 0"
                ).fetchone()['count'],
                
                'total_credits': cursor.execute(
                    "SELECT SUM(credits) as sum FROM users WHERE is_admin = 0"
                ).fetchone()['sum'] or 0,
                
                'total_documents': cursor.execute(
                    "SELECT COUNT(*) as count FROM documents"
                ).fetchone()['count'],
                
                'pending_requests': cursor.execute(
                    "SELECT COUNT(*) as count FROM credit_requests WHERE status = 'pending'"
                ).fetchone()['count']
            }
            
            # Get latest user list
            users = cursor.execute("""
                SELECT 
                    u.id,
                    u.username, 
                    u.credits,
                    COUNT(DISTINCT d.id) as total_documents,
                    MAX(d.upload_time) as last_activity
                FROM users u
                LEFT JOIN documents d ON u.id = d.user_id
                WHERE u.is_admin = 0
                GROUP BY u.id, u.username
                ORDER BY u.username
            """).fetchall()
            
            users_list = [{
                'id': user['id'],
                'username': user['username'],
                'credits': user['credits'],
                'total_documents': user['total_documents'] or 0,
                'last_activity': user['last_activity'] or 'Never'
            } for user in users]

            return jsonify({
                'success': True,
                'stats': stats,
                'users': users_list
            })

    except Exception as e:
        app.logger.error(f"Error refreshing admin data: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to refresh data'
        }), 500

if __name__ == '__main__':
    app.run(debug=True)
