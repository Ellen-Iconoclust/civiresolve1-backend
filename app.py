from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
import os
import uuid
import jwt
from functools import wraps
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Environment configuration with secure defaults for Render
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32).hex())
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', '').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize database
db = SQLAlchemy(app)

# Enable CORS
if os.environ.get('FLASK_ENV') == 'production':
    frontend_url = os.environ.get('FRONTEND_URL', 'https://Ellen-Iconoclust.github.io')
    CORS(app, origins=[frontend_url])
else:
    CORS(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    avatar = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    issues = db.relationship('Issue', backref='reporter', lazy=True)

class Issue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    issue_type = db.Column(db.String(50), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(300))
    status = db.Column(db.String(20), default='reported')
    reported_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# JWT Token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'error': 'Invalid token'}), 401
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return jsonify({'error': 'Token is invalid'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

@app.before_request
def before_request():
    # Skip database setup for specific routes
    if request.endpoint in ['index', 'health_check']:
        return
    
    # Initialize database if needed
    try:
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        
        # Create tables if they don't exist
        with app.app_context():
            db.create_all()
            
            # Create default admin user if none exists
            admin_user = User.query.filter_by(role='admin').first()
            if not admin_user:
                admin_user = User(
                    name='Administrator',
                    email='admin@city.gov',
                    password_hash=generate_password_hash('admin123'),
                    role='admin'
                )
                db.session.add(admin_user)
                db.session.commit()
                logger.info("Default admin user created")
                
    except Exception as e:
        logger.error(f"Database initialization error: {e}")

@app.route('/')
def index():
    return jsonify({"message": "CityWatch API is running", "status": "healthy"})

@app.route('/health')
def health_check():
    try:
        db.session.execute('SELECT 1')
        return jsonify({"status": "healthy", "database": "connected"})
    except Exception as e:
        return jsonify({"status": "unhealthy", "database": "disconnected", "error": str(e)}), 500

@app.route('/api/verify-token', methods=['GET'])
@token_required
def verify_token(current_user):
    return jsonify({"valid": True, "user": {
        "id": current_user.id,
        "name": current_user.name,
        "email": current_user.email,
        "role": current_user.role
    }})

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        if not data or not data.get('name') or not data.get('email') or not data.get('password'):
            return jsonify({"error": "Name, email and password required"}), 400
        
        if len(data['password']) < 6:
            return jsonify({"error": "Password must be at least 6 characters"}), 400
        
        # Check if user already exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({"error": "User already exists"}), 409
        
        new_user = User(
            name=data['name'],
            email=data['email'],
            password_hash=generate_password_hash(data['password']),
            role='user'
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Generate JWT token
        token = jwt.encode({
            'user_id': new_user.id,
            'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
        }, app.config['SECRET_KEY'])
        
        return jsonify({
            "message": "User created successfully",
            "token": token,
            "user": {
                "id": new_user.id,
                "name": new_user.name,
                "email": new_user.email,
                "role": new_user.role
            }
        })
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({"error": "Email and password required"}), 400
        
        user = User.query.filter_by(email=data['email']).first()
        
        if not user or not check_password_hash(user.password_hash, data['password']):
            return jsonify({"error": "Invalid credentials"}), 401
        
        # Generate JWT token
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
        }, app.config['SECRET_KEY'])
        
        return jsonify({
            "message": "Login successful",
            "token": token,
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role
            }
        })
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/issues', methods=['GET'])
def get_issues():
    try:
        user_id = request.args.get('user_id')
        status_filter = request.args.get('status')
        search_query = request.args.get('search')
        
        query = Issue.query
        
        if user_id:
            query = query.filter_by(reported_by=int(user_id))
        
        if status_filter:
            query = query.filter_by(status=status_filter)
        
        if search_query:
            search_lower = f"%{search_query.lower()}%"
            query = query.filter(
                (Issue.title.ilike(search_lower)) |
                (Issue.description.ilike(search_lower)) |
                (Issue.issue_type.ilike(search_lower))
            )
        
        issues = query.order_by(Issue.created_at.desc()).all()
        
        issues_data = []
        for issue in issues:
            issues_data.append({
                'id': issue.id,
                'title': issue.title,
                'description': issue.description,
                'issue_type': issue.issue_type,
                'latitude': issue.latitude,
                'longitude': issue.longitude,
                'image_url': issue.image_url,
                'status': issue.status,
                'reported_by': issue.reported_by,
                'created_at': issue.created_at.isoformat(),
                'updated_at': issue.updated_at.isoformat()
            })
        
        return jsonify({
            "issues": issues_data,
            "total": len(issues_data)
        })
        
    except Exception as e:
        logger.error(f"Get issues error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/issues', methods=['POST'])
@token_required
def create_issue(current_user):
    try:
        # Get form data
        title = request.form.get('title')
        description = request.form.get('description')
        issue_type = request.form.get('issue_type')
        
        # Parse latitude and longitude as floats
        try:
            latitude = float(request.form.get('latitude', 0))
            longitude = float(request.form.get('longitude', 0))
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid latitude or longitude values"}), 400
        
        if not all([title, issue_type]):
            return jsonify({"error": "Missing required fields"}), 400
        
        # Handle file upload
        image_url = None
        if 'image' in request.files:
            image_file = request.files['image']
            if image_file and image_file.filename:
                filename = secure_filename(image_file.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                
                # Create uploads directory if it doesn't exist
                if not os.path.exists(app.config['UPLOAD_FOLDER']):
                    os.makedirs(app.config['UPLOAD_FOLDER'])
                
                image_file.save(filepath)
                image_url = f"/uploads/{unique_filename}"
        
        new_issue = Issue(
            title=title,
            description=description,
            issue_type=issue_type,
            latitude=latitude,
            longitude=longitude,
            image_url=image_url,
            status='reported',
            reported_by=current_user.id
        )
        
        db.session.add(new_issue)
        db.session.commit()
        
        return jsonify({
            "message": "Issue reported successfully", 
            "issue": {
                'id': new_issue.id,
                'title': new_issue.title,
                'description': new_issue.description,
                'issue_type': new_issue.issue_type,
                'latitude': new_issue.latitude,
                'longitude': new_issue.longitude,
                'image_url': new_issue.image_url,
                'status': new_issue.status,
                'reported_by': new_issue.reported_by,
                'created_at': new_issue.created_at.isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Create issue error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/issues/<int:issue_id>', methods=['PUT'])
@token_required
def update_issue(current_user, issue_id):
    try:
        issue = Issue.query.get_or_404(issue_id)
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Update issue fields
        if 'status' in data:
            issue.status = data['status']
        
        issue.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            "message": "Issue updated successfully", 
            "issue": {
                'id': issue.id,
                'title': issue.title,
                'description': issue.description,
                'issue_type': issue.issue_type,
                'status': issue.status,
                'updated_at': issue.updated_at.isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Update issue error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/issues/<int:issue_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_issue(current_user, issue_id):
    try:
        issue = Issue.query.get_or_404(issue_id)
        
        # Remove image file if exists
        if issue.image_url and issue.image_url.startswith('/uploads/'):
            try:
                filename = issue.image_url.split('/')[-1]
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception as e:
                logger.error(f"Error deleting image file: {e}")
        
        db.session.delete(issue)
        db.session.commit()
        
        return jsonify({"message": "Issue deleted successfully"})
        
    except Exception as e:
        logger.error(f"Delete issue error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/admin/stats', methods=['GET'])
@token_required
@admin_required
def admin_stats(current_user):
    try:
        total_issues = Issue.query.count()
        pending_issues = Issue.query.filter(Issue.status != 'resolved').count()
        resolved_issues = total_issues - pending_issues
        total_users = User.query.filter_by(role='user').count()
        
        return jsonify({
            "total_issues": total_issues,
            "pending_issues": pending_issues,
            "resolved_issues": resolved_issues,
            "total_users": total_users
        })
        
    except Exception as e:
        logger.error(f"Admin stats error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/admin/users', methods=['GET'])
@token_required
@admin_required
def get_users(current_user):
    try:
        search_query = request.args.get('search', '')
        
        query = User.query.filter_by(role='user')
        
        if search_query:
            search_lower = f"%{search_query.lower()}%"
            query = query.filter(
                (User.name.ilike(search_lower)) |
                (User.email.ilike(search_lower))
            )
        
        users = query.all()
        
        users_data = []
        for user in users:
            user_issues = Issue.query.filter_by(reported_by=user.id).all()
            resolved_issues = [i for i in user_issues if i.status == 'resolved']
            
            users_data.append({
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'reports': len(user_issues),
                'resolved': len(resolved_issues),
                'joined_at': user.created_at.isoformat()
            })
        
        return jsonify({"users": users_data})
        
    except Exception as e:
        logger.error(f"Get users error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/admin/users/<int:user_id>/warn', methods=['POST'])
@token_required
@admin_required
def warn_user(current_user, user_id):
    try:
        user = User.query.get_or_404(user_id)
        # In a real implementation, you would store warnings in a database
        return jsonify({"message": f"Warning issued to user {user.name}"})
        
    except Exception as e:
        logger.error(f"Warn user error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/admin/users/<int:user_id>/suspend', methods=['POST'])
@token_required
@admin_required
def suspend_user(current_user, user_id):
    try:
        user = User.query.get_or_404(user_id)
        # In a real implementation, you would mark the user as suspended
        return jsonify({"message": f"User {user.name} suspended"})
        
    except Exception as e:
        logger.error(f"Suspend user error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Create uploads directory if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

if __name__ == '__main__':
    # Create database tables
    with app.app_context():
        db.create_all()
    
    # Check if SECRET_KEY is secure
    if app.config['SECRET_KEY'] == 'fallback-insecure-key-for-dev-only':
        app.config['SECRET_KEY'] = os.urandom(32).hex()
        logger.warning("Using auto-generated SECRET_KEY")
    
    # Check database connection
    try:
        db.session.execute('SELECT 1')
        logger.info("Database connection successful")
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
    
    app.run(debug=os.environ.get('FLASK_ENV') != 'production', host='0.0.0.0', port=5000)   
