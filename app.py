from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import json
import logging
from datetime import datetime, timedelta
import uuid
from functools import wraps

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Basic Config
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///farmconnect.db')
if app.config['SQLALCHEMY_DATABASE_URI'] and app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Initialize extensions
db = SQLAlchemy(app)

# Simple in-memory cache
class SimpleCache:
    def __init__(self): self._cache = {}
    def get(self, key): return self._cache.get(key)
    def setex(self, key, time, value): self._cache[key] = value
    def delete(self, key): 
        if key in self._cache: del self._cache[key]

cache = SimpleCache()

# Database Models (Simplified)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)
    location = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class Farmer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    farm_name = db.Column(db.String(100), nullable=False)
    contact_info = db.Column(db.String(100))

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    farmer_id = db.Column(db.Integer, db.ForeignKey('farmer.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50))
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    image_url = db.Column(db.String(200))
    listed_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_available = db.Column(db.Boolean, default=True)

# Utility functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

def generate_unique_filename(filename):
    ext = filename.rsplit('.', 1)[1].lower()
    return f"{uuid.uuid4().hex}.{ext}"

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health_check():
    return jsonify(status="healthy", timestamp=datetime.utcnow().isoformat())

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data or not data.get('email') or not data.get('password'):
            return jsonify(success=False, message="Email and password required"), 400
        
        if User.query.filter_by(email=data['email']).first():
            return jsonify(success=False, message="User already exists"), 409

        hashed_pw = generate_password_hash(data['password'])
        new_user = User(
            email=data['email'],
            password=hashed_pw,
            user_type=data.get('user_type', 'consumer'),
            location=data.get('location')
        )
        db.session.add(new_user)
        db.session.commit()
        
        logger.info(f"New user registered: {data['email']}")
        return jsonify(success=True, message="Registration successful")
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration error: {e}")
        return jsonify(success=False, message="Registration failed"), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data or not data.get('email') or not data.get('password'):
            return jsonify(success=False, message="Email and password required"), 400
        
        user = User.query.filter_by(email=data.get('email'), is_active=True).first()
        if user and check_password_hash(user.password, data.get('password')):
            logger.info(f"User {user.email} logged in successfully")
            return jsonify(
                success=True, 
                message="Login successful",
                user_type=user.user_type,
                user_id=user.id
            )
        
        return jsonify(success=False, message="Invalid credentials"), 401
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify(success=False, message="Login failed"), 500

@app.route('/products')
def get_products():
    try:
        products = Product.query.filter_by(is_available=True).all()
        product_list = []
        for product in products:
            farmer = Farmer.query.get(product.farmer_id)
            product_list.append({
                'id': product.id,
                'name': product.name,
                'category': product.category,
                'price': product.price,
                'quantity': product.quantity,
                'farmer': farmer.farm_name if farmer else 'Unknown',
                'image_url': product.image_url
            })
        
        return jsonify(products=product_list)
    except Exception as e:
        logger.error(f"Get products error: {e}")
        return jsonify(success=False, message="Failed to fetch products"), 500

def initialize_database():
    """Initialize database and create tables"""
    try:
        with app.app_context():
            db.create_all()
            logger.info("Database tables created successfully")
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    except Exception as e:
        logger.error(f"Database initialization error: {e}")

# Application entry point
if __name__ == '__main__':
    initialize_database()
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
else:
    initialize_database()
