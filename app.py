from flask import Flask, request, jsonify, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash
import re
from typing import Dict, Tuple
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Rate limiting to prevent abuse
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per day", "10 per minute"]
)

# Simulated user database (in-memory for demo)
users: Dict[str, str] = {
    "admin": generate_password_hash("securepassword123")
}

# Security headers middleware
@app.after_request
def apply_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

def sanitize_input(data: str) -> str:
    """Sanitize input to prevent XSS and injection attacks."""
    # Remove potentially dangerous characters
    clean_data = re.sub(r'[<>;{}]', '', data)
    return clean_data.strip()

def validate_input(data: Dict, required_fields: list) -> Tuple[bool, str]:
    """Validate input data for required fields and format."""
    for field in required_fields:
        if field not in data or not data[field]:
            return False, f"Missing or empty field: {field}"
        # Basic length validation
        if len(str(data[field])) > 100:
            return False, f"Field {field} exceeds maximum length"
    return True, ""

@app.route('/api/v1/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    """Login endpoint with secure authentication."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        # Validate required fields
        is_valid, error = validate_input(data, ['username', 'password'])
        if not is_valid:
            logger.warning(f"Invalid login attempt: {error}")
            return jsonify({"error": error}), 400

        username = sanitize_input(data['username'])
        password = data['password']

        if username in users and check_password_hash(users[username], password):
            logger.info(f"Successful login for user: {username}")
            return jsonify({"message": "Login successful", "token": "dummy-jwt-token"}), 200
        else:
            logger.warning(f"Failed login attempt for user: {username}")
            return jsonify({"error": "Invalid credentials"}), 401

    except Exception as e:
        logger.error(f"Error in login endpoint: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/v1/user', methods=['POST'])
@limiter.limit("10 per minute")
def create_user():
    """Create a new user with validated input."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        # Validate required fields
        is_valid, error = validate_input(data, ['username', 'password'])
        if not is_valid:
            logger.warning(f"Invalid user creation attempt: {error}")
            return jsonify({"error": error}), 400

        username = sanitize_input(data['username'])
        password = data['password']

        # Basic username format validation
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            return jsonify({"error": "Invalid username format"}), 400

        if username in users:
            logger.warning(f"User creation failed: {username} already exists")
            return jsonify({"error": "Username already exists"}), 409

        # Store hashed password
        users[username] = generate_password_hash(password)
        logger.info(f"User created: {username}")
        return jsonify({"message": f"User {username} created successfully"}), 201

    except Exception as e:
        logger.error(f"Error in create_user endpoint: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "API is running"}), 200

if __name__ == '__main__':
    app.run(ssl_context='adhoc', host='0.0.0.0', port=5000)
