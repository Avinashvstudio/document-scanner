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

# Update DATABASE path to ensure the directory exists
DATABASE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database')
DATABASE = os.path.join(DATABASE_DIR, 'database.db')
UPLOAD_FOLDER = os.path.join(DATABASE_DIR, 'uploads')

# Create necessary directories
os.makedirs(DATABASE_DIR, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_next_reset_time():
    now = datetime.now()
    next_reset = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
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
                is_admin INTEGER DEFAULT 0
            )
        """)
        
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

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

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

# Update the registration route
@app.route('/auth/register', methods=['POST'])
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

        conn = get_db_connection()
        
        # Check if username already exists
        if conn.execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone():
            return handle_error("Username already exists")

        # Hash password and create user
        hashed_password = generate_password_hash(password)
        conn.execute(
            'INSERT INTO users (username, password, credits) VALUES (?, ?, 20)',
            (username, hashed_password)
        )
        conn.commit()
        conn.close()

        return jsonify({
            "status": "success",
            "message": "Registration successful"
        })

    except Exception as e:
        print(f"Registration error: {str(e)}")
        return handle_error("An unexpected error occurred", 500)

@app.route('/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'user')

        if not username or not password:
            return jsonify({'success': False, 'error': 'Missing username or password'}), 400

        conn = get_db_connection()
        
        # Get user from database
        user = conn.execute('''
            SELECT id, username, password, is_admin, credits
            FROM users 
            WHERE username = ?
        ''', (username,)).fetchone()
        
        conn.close()

        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 401

        # Verify password
        if not check_password_hash(user['password'], password):
            return jsonify({'success': False, 'error': 'Invalid password'}), 401

        # Check if role matches
        is_admin = bool(user['is_admin'])
        if (role == 'admin' and not is_admin) or (role == 'user' and is_admin):
            return jsonify({'success': False, 'error': 'Invalid role for this user'}), 403

        # Set session data
        session.clear()  # Clear any existing session
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['is_admin'] = is_admin
        session.permanent = True  # Make session permanent

        return jsonify({
            'success': True,
            'username': user['username'],
            'is_admin': is_admin,
            'credits': user['credits']
        })

    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('home'))

    return send_from_directory(app.static_folder, "profile.html")  # Serve profile page

@app.route('/user/profile')
def get_user_profile():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 403
        
    try:
        conn = get_db_connection()
        user = conn.execute(
            "SELECT username, credits FROM users WHERE id = ?", 
            (session['user_id'],)
        ).fetchone()
        
        # Get scan history with similarity scores
        scans = conn.execute("""
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
        """, (session['user_id'],)).fetchall()
        
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
    finally:
        conn.close()

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
def scan_document():
    if 'user_id' not in session:
        return handle_error("Please login to continue", 403)

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
        conn = get_db_connection()
        user = conn.execute(
            "SELECT credits FROM users WHERE id = ?", 
            (session['user_id'],)
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
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO documents (user_id, filename, content)
            VALUES (?, ?, ?)
        """, (session['user_id'], file.filename, content))
        
        doc_id = cursor.lastrowid

        # Deduct credits
        cursor.execute("""
            UPDATE users 
            SET credits = credits - 1 
            WHERE id = ?
        """, (session['user_id'],))

        # Find similar documents
        similar_docs = conn.execute("""
            SELECT id, filename, content 
            FROM documents 
            WHERE user_id = ? AND id != ?
        """, (session['user_id'], doc_id)).fetchall()

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
            session['user_id'],
            file.filename,
            f"Found {len(matches)} similar documents with similarity: {matches[0]['similarity']:.2f}%" if matches else "No matches found"
        ))

        conn.commit()
        
        # Get remaining credits
        remaining_credits = conn.execute(
            "SELECT credits FROM users WHERE id = ?", 
            (session['user_id'],)
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

    finally:
        conn.close()

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
    conn = get_db_connection()
    current_doc = conn.execute("SELECT content FROM documents WHERE id = ?", (doc_id,)).fetchone()

    if not current_doc:
        return jsonify({"error": "Document not found"}), 404

    current_text = current_doc["content"]
    all_docs = conn.execute("SELECT id, filename, content FROM documents WHERE id != ?", (doc_id,)).fetchall()

    matches = []
    for doc in all_docs:
        similarity = difflib.SequenceMatcher(None, current_text, doc["content"]).ratio()
        if similarity > 0.5:  # Only consider matches above 50%
            matches.append({
                "doc_id": doc["id"],
                "filename": doc["filename"],
                "similarity": round(similarity, 2)
            })

    conn.close()
    return jsonify(matches)

@app.route('/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

# Admin authentication check
def is_admin():
    return session.get("user_id") and session.get("is_admin")

@app.route('/admin/dashboard')
def admin_dashboard():
    if not is_admin():
        return redirect(url_for('home'))
    return send_from_directory(app.static_folder, "admin_dashboard.html")

def admin_required():
    if 'user_id' not in session or session.get('username') != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

@app.route('/admin/users')
def get_all_users():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
        
    try:
        conn = get_db_connection()
        users = conn.execute("""
            SELECT 
                u.username, 
                u.credits,
                COUNT(DISTINCT d.id) as total_documents,
                MAX(d.upload_time) as last_activity
            FROM users u
            LEFT JOIN documents d ON u.id = d.user_id
            WHERE u.is_admin = 0
            GROUP BY u.id
        """).fetchall()
        
        conn.close()
        
        return jsonify([{
            'username': user['username'],
            'credits': user['credits'],
            'total_documents': user['total_documents'] or 0,
            'last_activity': user['last_activity']
        } for user in users])
    except Exception as e:
        print(f"Error getting users: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/admin/delete/<username>', methods=['DELETE'])
def delete_user(username):
    if admin_required():
        return admin_required()

    if username == "admin":
        return jsonify({"error": "Cannot delete admin account"}), 400

    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()

    return jsonify({"success": True})

@app.route('/admin/analytics')
def get_analytics_data():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
        
    try:
        conn = get_db_connection()
        
        # Parse query parameters
        date_range = request.args.get('dateRange', '')
        user_filter = request.args.get('user', '')
        activity_filter = request.args.get('activity', '')
        sort_by = request.args.get('sort', 'date')
        
        # Get basic stats
        total_users = conn.execute(
            "SELECT COUNT(*) as count FROM users WHERE is_admin = 0"
        ).fetchone()['count']
        
        total_credits = conn.execute(
            "SELECT SUM(credits) as sum FROM users WHERE is_admin = 0"
        ).fetchone()['sum'] or 0
        
        # Get daily scan usage for the past week
        usage_data = conn.execute("""
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
        top_users = conn.execute("""
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
        docs_analysis = conn.execute("""
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

        # Close connection
        conn.close()

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

    conn = get_db_connection()
    conn.execute("UPDATE users SET credits = credits + ? WHERE id = ?", (credits, user_id))
    conn.commit()
    conn.close()

    return jsonify({"success": True})

@app.route('/admin/scan_history')
def scan_history():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    
    conn = get_db_connection()
    history = conn.execute("SELECT * FROM scan_history ORDER BY timestamp DESC").fetchall()
    conn.close()
    return jsonify([dict(entry) for entry in history])

# Session configuration
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

# Use a consistent secret key (in production, store this securely)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# Initialize Flask-Session
Session(app)

# Create session directory if it doesn't exist
os.makedirs('./flask_session', exist_ok=True)

@app.before_request
def check_session():
    # Allow static files and authentication endpoints
    public_endpoints = ['static', 'login', 'register', 'home']
    if request.endpoint and request.endpoint not in public_endpoints:
        if 'user_id' in session:
            # Verify user still exists in database
            conn = get_db_connection()
            user = conn.execute('SELECT id FROM users WHERE id = ?', 
                              (session['user_id'],)).fetchone()
            conn.close()
            
            if not user:
                session.clear()
                return jsonify({"error": "Session expired"}), 401
        else:
            return jsonify({"error": "Please login to continue"}), 403

@app.route('/admin/stats')
def get_admin_stats():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
        
    try:
        conn = get_db_connection()
        
        # Get total users (excluding admin)
        total_users = conn.execute(
            "SELECT COUNT(*) as count FROM users WHERE is_admin = 0"
        ).fetchone()['count']
        
        # Get total credits in system
        total_credits = conn.execute(
            "SELECT SUM(credits) as sum FROM users WHERE is_admin = 0"
        ).fetchone()['sum'] or 0
        
        # Get total documents scanned
        total_documents = conn.execute("""
            SELECT COUNT(*) as count 
            FROM documents d
            JOIN users u ON d.user_id = u.id
            WHERE u.is_admin = 0
        """).fetchone()['count']
        
        conn.close()
        
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
        conn = get_db_connection()
        requests = conn.execute("""
            SELECT cr.id, u.username, u.credits as current_credits,
                   cr.requested_amount, cr.request_date
            FROM credit_requests cr
            JOIN users u ON cr.user_id = u.id
            WHERE cr.status = 'pending'
            ORDER BY cr.request_date DESC
        """).fetchall()
        
        conn.close()
        
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
        
        conn = get_db_connection()
        
        # Get request details
        credit_request = conn.execute(
            "SELECT user_id, requested_amount FROM credit_requests WHERE id = ?",
            (request_id,)
        ).fetchone()
        
        if not credit_request:
            conn.close()
            return jsonify({"error": "Request not found"}), 404
            
        if approve:
            # Add credits to user
            conn.execute("""
                UPDATE users 
                SET credits = credits + ? 
                WHERE id = ?
            """, (credit_request['requested_amount'], credit_request['user_id']))
            
        # Update request status
        conn.execute("""
            UPDATE credit_requests 
            SET status = ? 
            WHERE id = ?
        """, ('approved' if approve else 'denied', request_id))
        
        conn.commit()
        conn.close()
        
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
            
        conn = get_db_connection()
        conn.execute("""
            UPDATE users 
            SET credits = credits + ? 
            WHERE username = ?
        """, (amount, username))
        
        conn.commit()
        conn.close()
        
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
        conn = get_db_connection()
        
        # Check if user already has a pending request
        existing_request = conn.execute("""
            SELECT 1 FROM credit_requests 
            WHERE user_id = ? AND status = 'pending'
        """, (session['user_id'],)).fetchone()
        
        if existing_request:
            conn.close()
            return "You already have a pending credit request", 400
        
        # Get user's current credits
        user = conn.execute("""
            SELECT credits FROM users WHERE id = ?
        """, (session['user_id'],)).fetchone()
        
        # Default request amount (you can modify this logic)
        requested_amount = 20
        
        # Create new credit request
        conn.execute("""
            INSERT INTO credit_requests (user_id, requested_amount)
            VALUES (?, ?)
        """, (session['user_id'], requested_amount))
        
        # Log the request
        conn.execute("""
            INSERT INTO activity_log (username, action)
            VALUES (?, ?)
        """, (session['username'], f"Requested {requested_amount} credits"))
        
        conn.commit()
        conn.close()
        
        return "Credit request submitted successfully. An admin will review your request.", 200
        
    except Exception as e:
        print(f"Error requesting credits: {str(e)}")
        if conn:
            conn.close()
        return "Failed to submit credit request", 500

@app.route('/admin/export-data')
def export_analytics_data():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
        
    try:
        conn = get_db_connection()
        
        # Create a string buffer to write CSV data
        si = StringIO()
        writer = csv.writer(si)
        
        # System Overview
        writer.writerow(['System Analytics Overview'])
        writer.writerow(['Generated on:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
        
        # Get system stats
        total_users = conn.execute("SELECT COUNT(*) FROM users WHERE is_admin = 0").fetchone()[0]
        total_docs = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
        total_scans = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
        
        writer.writerow(['Total Users:', total_users])
        writer.writerow(['Total Documents:', total_docs])
        writer.writerow(['Total Scans:', total_scans])
        writer.writerow([])

        # User Activity Summary
        writer.writerow(['User Activity Summary'])
        writer.writerow(['Username', 'Total Documents', 'Total Scans', 'Credits Balance', 
                        'Success Rate', 'Last Activity', 'Avg. Similarity Score', 'Status'])
        
        users_data = conn.execute("""
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
        
        daily_stats = conn.execute("""
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
        
        credit_requests = conn.execute("""
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
        
        conn.close()
        
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
        if conn:
            conn.close()
        return jsonify({"error": "Failed to export data"}), 500

@app.route('/scan/history/<scan_id>', methods=['DELETE'])
def delete_scan_history(scan_id):
    if 'user_id' not in session:
        return handle_error("Please login to continue", 403)
        
    try:
        conn = get_db_connection()
        
        # Verify the scan belongs to the user
        scan = conn.execute("""
            SELECT id FROM scan_history 
            WHERE id = ? AND user_id = ?
        """, (int(scan_id), session['user_id'])).fetchone()
        
        if not scan:
            conn.close()
            return handle_error("Scan history not found or unauthorized", 404)
        
        # Delete the scan history
        conn.execute("DELETE FROM scan_history WHERE id = ?", (int(scan_id),))
        conn.commit()
        conn.close()
        
        return jsonify({
            "status": "success",
            "message": "Scan history deleted successfully"
        })
        
    except Exception as e:
        print(f"Error deleting scan history: {str(e)}")
        if conn:
            conn.close()
        return handle_error("Failed to delete scan history", 500)

if __name__ == '__main__':
    app.run(debug=True)
