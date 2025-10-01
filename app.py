from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
from flask_marshmallow import Marshmallow
from marshmallow import Schema, fields, validate, ValidationError
import os
import pandas as pd
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import uuid
import stripe
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import redis

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    handlers=[
        logging.FileHandler('farmconnect.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Enhanced Config with environment variables - UPDATED FOR RENDER
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///farmconnect.db')
# Fix for PostgreSQL URL format on Render
if app.config['SQLALCHEMY_DATABASE_URI'] and app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'super-secret-jwt-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Email configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', True)
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@farmconnect.com')

# Stripe configuration
app.config['STRIPE_PUBLISHABLE_KEY'] = os.environ.get('STRIPE_PUBLISHABLE_KEY', 'pk_test_your_key_here')
app.config['STRIPE_SECRET_KEY'] = os.environ.get('STRIPE_SECRET_KEY', 'sk_test_your_key_here')

# Redis for caching and rate limiting - UPDATED FOR RENDER
redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
app.config['REDIS_URL'] = redis_url

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
# UPDATED: Remove async_mode for better compatibility
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
CORS(app)
ma = Marshmallow(app)
mail = Mail(app)

# Initialize Stripe
stripe.api_key = app.config['STRIPE_SECRET_KEY']

# Initialize Redis with error handling for Render
try:
    redis_client = redis.from_url(redis_url)
    # Test connection
    redis_client.ping()
    logger.info("Redis connected successfully")
except redis.ConnectionError:
    logger.warning("Redis not available, using in-memory cache")
    # Fallback to simple dict cache
    class SimpleCache:
        def __init__(self):
            self._cache = {}
        
        def get(self, key):
            return self._cache.get(key)
        
        def setex(self, key, time, value):
            self._cache[key] = value
        
        def delete(self, key):
            if key in self._cache:
                del self._cache[key]
    
    redis_client = SimpleCache()

# Rate limiting with fallback for Render
try:
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri=app.config['REDIS_URL']
    )
except:
    # Fallback limiter without Redis
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )

# Enhanced Database Models (Keep your existing models here)
class User(db.Model):
    # ... (keep all your existing model definitions exactly as they are)
    pass

class Farmer(db.Model):
    # ... (keep all your existing model definitions)
    pass

class Consumer(db.Model):
    # ... (keep all your existing model definitions)
    pass

class Product(db.Model):
    # ... (keep all your existing model definitions)
    pass

class MarketData(db.Model):
    # ... (keep all your existing model definitions)
    pass

class Order(db.Model):
    # ... (keep all your existing model definitions)
    pass

class Review(db.Model):
    # ... (keep all your existing model definitions)
    pass

class Notification(db.Model):
    # ... (keep all your existing model definitions)
    pass

# Marshmallow Schemas (Keep your existing schemas)
class UserSchema(Schema):
    # ... (keep all your existing schema definitions)
    pass

class FarmerSchema(Schema):
    # ... (keep all your existing schema definitions)
    pass

class ProductSchema(Schema):
    # ... (keep all your existing schema definitions)
    pass

class ReviewSchema(Schema):
    # ... (keep all your existing schema definitions)
    pass

# Utility functions (Keep your existing utility functions)
def allowed_file(filename: str) -> bool:
    # ... (keep your existing function)
    pass

def generate_unique_filename(filename: str) -> str:
    # ... (keep your existing function)
    pass

def send_email(to: str, subject: str, body: str) -> bool:
    # ... (keep your existing function)
    pass

def send_verification_email(user: User) -> bool:
    # UPDATED: Use dynamic base URL for verification links
    base_url = os.environ.get('BASE_URL', 'http://localhost:5000')
    verification_url = f"{base_url}/verify-email?token={user.verification_token}"
    body = f"""
    <h1>Welcome to FarmConnect!</h1>
    <p>Please verify your email address by clicking the link below:</p>
    <a href="{verification_url}">Verify Email</a>
    <p>If you didn't create an account, please ignore this email.</p>
    """
    return send_email(user.email, "Verify Your FarmConnect Account", body)

def send_password_reset_email(user: User, reset_token: str) -> bool:
    # UPDATED: Use dynamic base URL for reset links
    base_url = os.environ.get('BASE_URL', 'http://localhost:5000')
    reset_url = f"{base_url}/reset-password?token={reset_token}"
    body = f"""
    <h1>Password Reset Request</h1>
    <p>You requested to reset your password. Click the link below:</p>
    <a href="{reset_url}">Reset Password</a>
    <p>This link will expire in 1 hour.</p>
    <p>If you didn't request this, please ignore this email.</p>
    """
    return send_email(user.email, "FarmConnect Password Reset", body)

def admin_required(f):
    # ... (keep your existing function)
    pass

def cache_key(prefix: str, *args) -> str:
    # ... (keep your existing function)
    pass

# Error handlers (Keep your existing error handlers)
@app.errorhandler(413)
def too_large(e):
    # ... (keep your existing function)
    pass

@app.errorhandler(500)
def internal_error(e):
    # ... (keep your existing function)
    pass

@app.errorhandler(404)
def not_found(e):
    # ... (keep your existing function)
    pass

@app.errorhandler(429)
def ratelimit_handler(e):
    # ... (keep your existing function)
    pass

# JWT error handlers (Keep your existing JWT handlers)
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    # ... (keep your existing function)
    pass

@jwt.invalid_token_loader
def invalid_token_callback(error):
    # ... (keep your existing function)
    pass

@jwt.unauthorized_loader
def missing_token_callback(error):
    # ... (keep your existing function)
    pass

# Routes (Keep all your existing routes exactly as they are)
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health_check():
    return jsonify(status="healthy", timestamp=datetime.utcnow().isoformat())

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Enhanced Registration with email verification
@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    # ... (keep all your existing route functions exactly as they are)
    pass

@app.route('/verify-email')
def verify_email():
    # ... (keep all your existing route functions)
    pass

@app.route('/forgot-password', methods=['POST'])
@limiter.limit("3 per minute")
def forgot_password():
    # ... (keep all your existing route functions)
    pass

@app.route('/reset-password', methods=['POST'])
@limiter.limit("3 per minute")
def reset_password():
    # ... (keep all your existing route functions)
    pass

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    # ... (keep all your existing route functions)
    pass

@app.route('/upload_product', methods=['POST'])
@jwt_required()
def upload_product():
    # ... (keep all your existing route functions)
    pass

@app.route('/get_products')
@jwt_required()
def get_products():
    # ... (keep all your existing route functions)
    pass

@app.route('/create_order', methods=['POST'])
@jwt_required()
def create_order():
    # ... (keep all your existing route functions)
    pass

@app.route('/confirm_payment', methods=['POST'])
@jwt_required()
def confirm_payment():
    # ... (keep all your existing route functions)
    pass

@app.route('/submit_review', methods=['POST'])
@jwt_required()
def submit_review():
    # ... (keep all your existing route functions)
    pass

@app.route('/get_reviews')
def get_reviews():
    # ... (keep all your existing route functions)
    pass

@app.route('/admin/users', methods=['GET'])
@jwt_required()
@admin_required
def admin_get_users():
    # ... (keep all your existing route functions)
    pass

@app.route('/admin/users/<int:user_id>', methods=['PUT'])
@jwt_required()
@admin_required
def admin_update_user(user_id):
    # ... (keep all your existing route functions)
    pass

@app.route('/profile', methods=['GET', 'PUT'])
@jwt_required()
def profile():
    # ... (keep all your existing route functions)
    pass

@app.route('/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    # ... (keep all your existing route functions)
    pass

@app.route('/notifications/<int:notification_id>/read', methods=['PUT'])
@jwt_required()
def mark_notification_read(notification_id):
    # ... (keep all your existing route functions)
    pass

@app.route('/market-data')
@jwt_required()
def get_market_data():
    # ... (keep all your existing route functions)
    pass

# WebSocket events (Keep your existing WebSocket events)
@socketio.on('connect')
def handle_connect():
    logger.info('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    logger.info('Client disconnected')

@socketio.on('join_user_room')
def handle_join_user_room(data):
    # ... (keep your existing function)
    pass

# Initialize admin user
def create_admin_user():
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@farmconnect.com')
    admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
    
    existing_admin = User.query.filter_by(email=admin_email, user_type='admin').first()
    if not existing_admin:
        hashed_pw = generate_password_hash(admin_password)
        admin_user = User(
            email=admin_email,
            password=hashed_pw,
            user_type='admin',
            is_verified=True,
            is_active=True
        )
        db.session.add(admin_user)
        db.session.commit()
        logger.info("Admin user created")

# UPDATED: Database initialization function
def initialize_database():
    """Initialize database and create tables"""
    try:
        with app.app_context():
            db.create_all()
            create_admin_user()
            logger.info("Database tables created successfully")
            
            # Create upload directory
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            logger.info("Upload directory created")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")

# UPDATED: Application entry point for Render
if __name__ == '__main__':
    # Initialize database
    initialize_database()
    
    # Get port from environment variable (Render provides this)
    port = int(os.environ.get('PORT', 5000))
    
    # Determine if we're in debug mode
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Run the application
    logger.info(f"Starting FarmConnect server on port {port}")
    socketio.run(app, debug=debug_mode, host='0.0.0.0', port=port)
else:
    # This runs when the app is imported (e.g., by Gunicorn)
    initialize_database()