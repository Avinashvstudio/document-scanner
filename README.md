# Credit-Based Document Scanning System

A self-contained document scanning and matching system with a built-in credit system. Users get daily free scans and can request additional credits from admins.

## Features

### User Authentication & Role Management
- User registration and login
- Role-based access (Admin/Regular users)
- Profile management
- Secure password hashing

### Credit System
- 20 free scans per day (resets at midnight)
- Credit request system
- Admin approval workflow
- Automated credit tracking

### Document Scanning & Matching
- Text file upload and scanning
- Multiple similarity metrics:
  - Jaccard similarity
  - Sequence matching
  - Cosine similarity
- Detailed match analysis
- Common phrase detection

### Admin Dashboard
- User management
- Credit request handling
- Comprehensive analytics and reporting
- Data export functionality (CSV)

## Technical Stack

- Backend: Python/Flask
- Database: SQLite
- Frontend: HTML, CSS, JavaScript (Vanilla)
- Authentication: Session-based with Flask-Session
- File Storage: Local filesystem

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/document-scanner.git
cd document-scanner
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
python backend/app.py
```

5. Start the application:
```bash
flask run
```

The application will be available at `http://localhost:5000`

## Default Admin Account

- Username: admin
- Password: admin123

## Project Structure

```
document-scanner/
├── backend/
│   ├── app.py              # Main application file
├── frontend/
│   ├── css/
│   │   └── style.css      # Main stylesheet
│   ├── index.html         # Login page
│   ├── profile.html       # User profile
│   ├── upload.html        # Document upload
│   ├── admin.html         # Admin dashboard
│   └── analytics.html     # Analytics dashboard
├── database/              # SQLite database and uploads
├── flask_session/         # Session storage
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## API Endpoints

### Authentication
- `POST /auth/register` - User registration
- `POST /auth/login` - User login
- `POST /auth/logout` - User logout

### User Operations
- `GET /user/profile` - Get user profile
- `POST /scan` - Upload and scan document
- `GET /matches/<doc_id>` - Get similar documents
- `POST /credits/request` - Request additional credits
- `DELETE /scan/history/<scan_id>` - Delete scan history

### Admin Operations
- `GET /admin/users` - List all users
- `GET /admin/analytics` - Get system analytics
- `GET /admin/credit_requests` - View credit requests
- `POST /admin/credit_requests/<request_id>` - Handle credit request
- `POST /admin/add_credits` - Add credits to user
- `GET /admin/export-data` - Export analytics data
- `DELETE /admin/delete/<username>` - Delete user

## Security Features

- Password hashing using Werkzeug
- Session-based authentication
- CSRF protection
- Input validation
- Role-based access control

## License

MIT License
```

```text:requirements.txt
Flask==3.0.0
Werkzeug==3.0.1
Flask-Session==0.5.0
python-dotenv==1.0.0
```
Demo Of the Project

https://github.com/user-attachments/assets/6c7c42ee-a08f-4537-a2c1-0986d58d066d


The README.md provides comprehensive documentation of the system, including:
- Feature overview
- Installation instructions
- Project structure
- Security features

The requirements.txt lists the main Python packages needed to run the application.

Key dependencies:
- Flask: Web framework
- Werkzeug: WSGI utilities (includes password hashing)
- Flask-Session: Session handling
- python-dotenv: Environment variable management
