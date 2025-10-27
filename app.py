from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import json
import logging
from datetime import datetime, timedelta
import uuid
import stripe
from functools import wraps

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    handlers=[
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
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Stripe configuration
app.config['STRIPE_PUBLISHABLE_KEY'] = os.environ.get('STRIPE_PUBLISHABLE_KEY', 'pk_test_your_key_here')
app.config['STRIPE_SECRET_KEY'] = os.environ.get('STRIPE_SECRET_KEY', 'sk_test_your_key_here')

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
CORS(app)

# Simple in-memory cache for Render
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

# Rate limiting with memory storage
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Initialize Stripe
stripe.api_key = app.config['STRIPE_SECRET_KEY']

# Keep all your database models, routes, and utility functions exactly as before
# ... (your existing User, Farmer, Consumer, Product, Order, Review, Notification models)
# ... (your existing routes and utility functions)

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

# Application entry point for Render
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
