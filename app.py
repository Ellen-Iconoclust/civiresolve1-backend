from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import uuid
import jwt
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-insecure-key-for-dev-only')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Enable CORS with stricter settings for production
if os.environ.get('FLASK_ENV') == 'production':
    CORS(app, origins=[os.environ.get('FRONTEND_URL', 'https://Ellen-Iconoclust.github.io')])
else:
    CORS(app)

# In-memory data storage (replace with database in production)
users = [
    {
        'id': 1,
        'name': 'Demo User',
        'email': 'demo@example.com',
        'password_hash': generate_password_hash('password123'),
        'role': 'user',
        'avatar': None,
        'created_at': datetime.utcnow()
    },
    {
        'id': 2,
        'name': 'Administrator',
        'email': 'admin@city.gov',
        'password_hash': generate_password_hash('admin123'),
        'role': 'admin',
        'avatar': None,
        'created_at': datetime.utcnow()
    }
]

issues = []
next_user_id = 3
next_issue_id = 1

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
            current_user = next((u for u in users if u['id'] == data['user_id']), None)
            if not current_user:
                return jsonify({'error': 'Invalid token'}), 401
        except:
            return jsonify({'error': 'Token is invalid'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/')
def index():
    return jsonify({"message": "CityWatch API is running"})

@app.route('/api/verify-token', methods=['GET'])
@token_required
def verify_token(current_user):
    return jsonify({"valid": True, "user": {
        "id": current_user['id'],
        "name": current_user['name'],
        "email': current_user['email'],
        "role": current_user['role']
    }})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data or not data.get('name') or not data.get('email') or not data.get('password'):
        return jsonify({"error": "Name, email and password required"}), 400
    
    if len(data['password']) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    
    # Check if user already exists
    if any(u['email'] == data['email'] for u in users):
        return jsonify({"error": "User already exists"}), 409
    
    global next_user_id
    new_user = {
        'id': next_user_id,
        'name': data['name'],
        'email': data['email'],
        'password_hash': generate_password_hash(data['password']),
        'role': 'user',
        'avatar': None,
        'created_at': datetime.utcnow()
    }
    
    users.append(new_user)
    next_user_id += 1
    
    return jsonify({"message": "User created successfully"})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"error": "Email and password required"}), 400
    
    user = next((u for u in users if u['email'] == data['email']), None)
    
    if not user or not check_password_hash(user['password_hash'], data['password']):
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Generate JWT token
    token = jwt.encode({
        'user_id': user['id'],
        'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
    }, app.config['SECRET_KEY'])
    
    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": {
            "id": user['id'],
            "name": user['name'],
            "email": user['email'],
            "role": user['role']
        }
    })

@app.route('/api/issues', methods=['GET'])
def get_issues():
    user_id = request.args.get('user_id')
    status_filter = request.args.get('status')
    search_query = request.args.get('search')
    
    filtered_issues = issues
    
    if user_id:
        filtered_issues = [i for i in filtered_issues if i['reported_by'] == int(user_id)]
    
    if status_filter:
        filtered_issues = [i for i in filtered_issues if i['status'] == status_filter]
    
    if search_query:
        search_lower = search_query.lower()
        filtered_issues = [i for i in filtered_issues if 
                          search_lower in i['title'].lower() or 
                          search_lower in i['description'].lower() or 
                          search_lower in i['issue_type'].lower()]
    
    return jsonify({
        "issues": filtered_issues,
        "total": len(filtered_issues)
    })

@app.route('/api/issues', methods=['POST'])
@token_required
def create_issue(current_user):
    try:
        # Get form data
        title = request.form.get('title')
        description = request.form.get('description')
        issue_type = request.form.get('issue_type')
        latitude = float(request.form.get('latitude'))
        longitude = float(request.form.get('longitude'))
        
        if not all([title, issue_type, latitude, longitude]):
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
        
        global next_issue_id
        new_issue = {
            'id': next_issue_id,
            'title': title,
            'description': description,
            'issue_type': issue_type,
            'latitude': latitude,
            'longitude': longitude,
            'image_url': image_url,
            'status': 'reported',
            'reported_by': current_user['id'],
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        issues.append(new_issue)
        next_issue_id += 1
        
        return jsonify({"message": "Issue reported successfully", "issue": new_issue})
    
    except ValueError as e:
        return jsonify({"error": "Invalid latitude or longitude values"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/issues/<int:issue_id>', methods=['PUT'])
@token_required
def update_issue(current_user, issue_id):
    issue = next((i for i in issues if i['id'] == issue_id), None)
    if not issue:
        return jsonify({"error": "Issue not found"}), 404
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    # Update issue fields
    if 'status' in data:
        issue['status'] = data['status']
    
    issue['updated_at'] = datetime.utcnow()
    
    return jsonify({"message": "Issue updated successfully", "issue": issue})

@app.route('/api/issues/<int:issue_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_issue(current_user, issue_id):
    global issues
    issue = next((i for i in issues if i['id'] == issue_id), None)
    if not issue:
        return jsonify({"error": "Issue not found"}), 404
    
    # Remove image file if exists
    if issue['image_url'] and issue['image_url'].startswith('/uploads/'):
        try:
            filename = issue['image_url'].split('/')[-1]
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(filepath):
                os.remove(filepath)
        except:
            pass  # Silently fail if file deletion fails
    
    issues = [i for i in issues if i['id'] != issue_id]
    return jsonify({"message": "Issue deleted successfully"})

@app.route('/api/admin/stats', methods=['GET'])
@token_required
@admin_required
def admin_stats(current_user):
    total_issues = len(issues)
    pending_issues = len([i for i in issues if i['status'] != 'resolved'])
    resolved_issues = total_issues - pending_issues
    
    return jsonify({
        "total_issues": total_issues,
        "pending_issues": pending_issues,
        "resolved_issues": resolved_issues
    })

@app.route('/api/admin/users', methods=['GET'])
@token_required
@admin_required
def get_users(current_user):
    search_query = request.args.get('search', '')
    
    # Format user data for admin view
    user_data = []
    for user in users:
        if user['role'] != 'admin':  # Don't show admin users
            user_issues = [i for i in issues if i['reported_by'] == user['id']]
            resolved_issues = [i for i in user_issues if i['status'] == 'resolved']
            
            user_data.append({
                'id': user['id'],
                'name': user['name'],
                'email': user['email'],
                'reports': len(user_issues),
                'resolved': len(resolved_issues),
                'warnings': 0  # Placeholder for warning system
            })
    
    # Filter by search query if provided
    if search_query:
        search_lower = search_query.lower()
        user_data = [u for u in user_data if 
                    search_lower in u['name'].lower() or 
                    search_lower in u['email'].lower()]
    
    return jsonify({"users": user_data})

@app.route('/api/admin/users/<int:user_id>/warn', methods=['POST'])
@token_required
@admin_required
def warn_user(current_user, user_id):
    user = next((u for u in users if u['id'] == user_id), None)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # In a real implementation, you would store warnings in a database
    return jsonify({"message": f"Warning issued to user {user['name']}"})

@app.route('/api/admin/users/<int:user_id>/suspend', methods=['POST'])
@token_required
@admin_required
def suspend_user(current_user, user_id):
    user = next((u for u in users if u['id'] == user_id), None)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # In a real implementation, you would mark the user as suspended
    return jsonify({"message": f"User {user['name']} suspended"})

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Create uploads directory if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

if __name__ == '__main__':
    # Check if SECRET_KEY is the default (insecure)
    if app.config['SECRET_KEY'] == 'fallback-insecure-key-for-dev-only':
        print("⚠️  WARNING: Using default SECRET_KEY. This is insecure for production!")
        print("⚠️  Set a secure SECRET_KEY environment variable")
    
    app.run(debug=os.environ.get('FLASK_ENV') != 'production', host='0.0.0.0', port=5000)
