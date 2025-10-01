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

# Enhanced Config with environment variables
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///farmconnect.db')
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

# Redis for caching and rate limiting
app.config['REDIS_URL'] = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')
CORS(app)
ma = Marshmallow(app)
mail = Mail(app)

# Initialize Stripe
stripe.api_key = app.config['STRIPE_SECRET_KEY']

# Initialize Redis
redis_client = redis.from_url(app.config['REDIS_URL'])

# Rate limiting with Redis
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=app.config['REDIS_URL']
)

# Enhanced Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(255), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)  # farmer/consumer/admin
    location = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100))
    
    # Relationships
    farmer_profile = db.relationship('Farmer', backref='user', uselist=False, lazy=True)
    consumer_profile = db.relationship('Consumer', backref='user', uselist=False, lazy=True)
    reviews_given = db.relationship('Review', foreign_keys='Review.reviewer_id', backref='reviewer', lazy=True)
    reviews_received = db.relationship('Review', foreign_keys='Review.reviewee_id', backref='reviewee', lazy=True)

class Farmer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    farm_name = db.Column(db.String(100), nullable=False)
    main_products = db.Column(db.String(200))
    farm_size = db.Column(db.String(50))
    description = db.Column(db.Text)
    contact_info = db.Column(db.String(100))
    rating = db.Column(db.Float, default=0.0)
    total_ratings = db.Column(db.Integer, default=0)
    
    # Relationships
    products = db.relationship('Product', backref='farmer', lazy=True)

class Consumer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    preferences = db.Column(db.String(200))
    dietary_restrictions = db.Column(db.String(200))
    loyalty_points = db.Column(db.Integer, default=0)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    farmer_id = db.Column(db.Integer, db.ForeignKey('farmer.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50))
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit = db.Column(db.String(20), default='kg')
    quality_metrics = db.Column(db.Text)
    image_url = db.Column(db.String(200))
    listed_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_available = db.Column(db.Boolean, default=True)
    tags = db.Column(db.String(200))
    rating = db.Column(db.Float, default=0.0)
    total_reviews = db.Column(db.Integer, default=0)
    
    # Relationships
    reviews = db.relationship('Review', backref='product', lazy=True)

class MarketData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_category = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)
    demand_level = db.Column(db.String(20))  # low, medium, high
    region = db.Column(db.String(50))
    date = db.Column(db.DateTime, default=datetime.utcnow)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    consumer_id = db.Column(db.Integer, db.ForeignKey('consumer.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, confirmed, shipped, delivered, cancelled
    order_date = db.Column(db.DateTime, default=datetime.utcnow)
    payment_intent_id = db.Column(db.String(100))
    shipping_address = db.Column(db.Text)
    tracking_number = db.Column(db.String(100))
    
    # Relationships
    consumer = db.relationship('Consumer', backref='orders')
    product = db.relationship('Product', backref='orders')

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reviewee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Farmer being reviewed
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=True)
    rating = db.Column(db.Integer, nullable=False)  # 1-5
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_verified_purchase = db.Column(db.Boolean, default=False)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), default='info')  # info, success, warning, error
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref='notifications')

# Marshmallow Schemas for validation
class UserSchema(Schema):
    email = fields.Email(required=True)
    password = fields.String(required=True, validate=validate.Length(min=6))
    user_type = fields.String(required=True, validate=validate.OneOf(['farmer', 'consumer']))
    location = fields.String()

class FarmerSchema(Schema):
    farm_name = fields.String(required=True)
    main_products = fields.String()
    farm_size = fields.String()
    description = fields.String()
    contact_info = fields.String()

class ProductSchema(Schema):
    name = fields.String(required=True)
    category = fields.String(required=True)
    price = fields.Float(required=True, validate=validate.Range(min=0))
    quantity = fields.Integer(required=True, validate=validate.Range(min=1))
    unit = fields.String()
    quality_metrics = fields.String()
    tags = fields.String()

class ReviewSchema(Schema):
    rating = fields.Integer(required=True, validate=validate.Range(min=1, max=5))
    comment = fields.String()
    product_id = fields.Integer()

# Utility functions
def allowed_file(filename: str) -> bool:
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_unique_filename(filename: str) -> str:
    ext = filename.rsplit('.', 1)[1].lower()
    unique_name = f"{uuid.uuid4().hex}.{ext}"
    return unique_name

def send_email(to: str, subject: str, body: str) -> bool:
    try:
        msg = Message(
            subject=subject,
            recipients=[to],
            body=body,
            html=body
        )
        mail.send(msg)
        logger.info(f"Email sent to {to}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False

def send_verification_email(user: User) -> bool:
    verification_url = f"http://localhost:5000/verify-email?token={user.verification_token}"
    body = f"""
    <h1>Welcome to FarmConnect!</h1>
    <p>Please verify your email address by clicking the link below:</p>
    <a href="{verification_url}">Verify Email</a>
    <p>If you didn't create an account, please ignore this email.</p>
    """
    return send_email(user.email, "Verify Your FarmConnect Account", body)

def send_password_reset_email(user: User, reset_token: str) -> bool:
    reset_url = f"http://localhost:5000/reset-password?token={reset_token}"
    body = f"""
    <h1>Password Reset Request</h1>
    <p>You requested to reset your password. Click the link below:</p>
    <a href="{reset_url}">Reset Password</a>
    <p>This link will expire in 1 hour.</p>
    <p>If you didn't request this, please ignore this email.</p>
    """
    return send_email(user.email, "FarmConnect Password Reset", body)

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        current_user = get_jwt_identity()
        if current_user.get('type') != 'admin':
            return jsonify(success=False, message="Admin access required"), 403
        return f(*args, **kwargs)
    return decorated

def cache_key(prefix: str, *args) -> str:
    return f"{prefix}:{':'.join(str(arg) for arg in args)}"

# Error handlers
@app.errorhandler(413)
def too_large(e):
    return jsonify(success=False, message="File too large"), 413

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify(success=False, message="Internal server error"), 500

@app.errorhandler(404)
def not_found(e):
    return jsonify(success=False, message="Resource not found"), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify(success=False, message="Rate limit exceeded"), 429

# JWT error handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify(success=False, message="Token has expired"), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify(success=False, message="Invalid token"), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify(success=False, message="Authorization required"), 401

# Routes
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
    try:
        schema = UserSchema()
        data = schema.load(request.get_json())
        
        if User.query.filter_by(email=data['email']).first():
            return jsonify(success=False, message="User already exists"), 409

        hashed_pw = generate_password_hash(data['password'])
        verification_token = uuid.uuid4().hex
        
        new_user = User(
            email=data['email'],
            password=hashed_pw,
            user_type=data['user_type'],
            location=data.get('location'),
            verification_token=verification_token
        )
        db.session.add(new_user)
        db.session.flush()

        if data['user_type'] == 'farmer':
            farmer_schema = FarmerSchema()
            farmer_data = farmer_schema.load(request.get_json())
            new_farmer = Farmer(
                user_id=new_user.id,
                farm_name=farmer_data['farm_name'],
                main_products=farmer_data.get('main_products'),
                farm_size=farmer_data.get('farm_size'),
                description=farmer_data.get('description'),
                contact_info=farmer_data.get('contact_info')
            )
            db.session.add(new_farmer)
        else:
            new_consumer = Consumer(
                user_id=new_user.id,
                preferences=request.json.get('preferences'),
                dietary_restrictions=request.json.get('dietary_restrictions')
            )
            db.session.add(new_consumer)

        db.session.commit()
        
        # Send verification email
        send_verification_email(new_user)
        
        logger.info(f"New user registered: {data['email']} as {data['user_type']}")
        return jsonify(
            success=True, 
            message="Registration successful. Please check your email for verification."
        )
    except ValidationError as e:
        return jsonify(success=False, message="Validation error", errors=e.messages), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration error: {e}")
        return jsonify(success=False, message="Registration failed"), 500

@app.route('/verify-email')
def verify_email():
    token = request.args.get('token')
    if not token:
        return jsonify(success=False, message="Token required"), 400
    
    user = User.query.filter_by(verification_token=token).first()
    if not user:
        return jsonify(success=False, message="Invalid token"), 400
    
    user.is_verified = True
    user.verification_token = None
    db.session.commit()
    
    return jsonify(success=True, message="Email verified successfully")

@app.route('/forgot-password', methods=['POST'])
@limiter.limit("3 per minute")
def forgot_password():
    try:
        email = request.json.get('email')
        if not email:
            return jsonify(success=False, message="Email required"), 400
        
        user = User.query.filter_by(email=email, is_verified=True).first()
        if user:
            reset_token = uuid.uuid4().hex
            user.verification_token = reset_token
            db.session.commit()
            
            send_password_reset_email(user, reset_token)
        
        return jsonify(success=True, message="If the email exists, a reset link has been sent")
    except Exception as e:
        logger.error(f"Forgot password error: {e}")
        return jsonify(success=False, message="Failed to process request"), 500

@app.route('/reset-password', methods=['POST'])
@limiter.limit("3 per minute")
def reset_password():
    try:
        token = request.json.get('token')
        new_password = request.json.get('new_password')
        
        if not token or not new_password:
            return jsonify(success=False, message="Token and new password required"), 400
        
        if len(new_password) < 6:
            return jsonify(success=False, message="Password must be at least 6 characters"), 400
        
        user = User.query.filter_by(verification_token=token).first()
        if not user:
            return jsonify(success=False, message="Invalid token"), 400
        
        user.password = generate_password_hash(new_password)
        user.verification_token = None
        db.session.commit()
        
        return jsonify(success=True, message="Password reset successfully")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Reset password error: {e}")
        return jsonify(success=False, message="Failed to reset password"), 500

# Enhanced Login
@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    try:
        data = request.get_json()
        if not data or not data.get('email') or not data.get('password'):
            return jsonify(success=False, message="Email and password required"), 400
        
        user = User.query.filter_by(email=data.get('email'), is_active=True).first()
        if user and check_password_hash(user.password, data.get('password')):
            if not user.is_verified:
                return jsonify(success=False, message="Please verify your email first"), 403
            
            token = create_access_token(
                identity={'id': user.id, 'type': user.user_type},
                expires_delta=timedelta(hours=24)
            )
            
            # Update last login (you might want to add this field to User model)
            logger.info(f"User {user.email} logged in successfully")
            return jsonify(
                success=True, 
                access_token=token, 
                user_type=user.user_type,
                user_id=user.id
            )
        
        logger.warning(f"Failed login attempt for email: {data.get('email')}")
        return jsonify(success=False, message="Invalid credentials"), 401
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify(success=False, message="Login failed"), 500

# Enhanced Product Upload with validation
@app.route('/upload_product', methods=['POST'])
@jwt_required()
def upload_product():
    try:
        user = get_jwt_identity()
        if user['type'] != 'farmer':
            return jsonify(success=False, message="Unauthorized"), 403

        farmer = Farmer.query.filter_by(user_id=user['id']).first()
        if not farmer:
            return jsonify(success=False, message="Farmer profile not found"), 404

        # Validate with Marshmallow
        schema = ProductSchema()
        data = schema.load(request.form)
        
        # Handle file upload
        file = request.files.get('image')
        filepath = None
        
        if file and file.filename:
            if not allowed_file(file.filename):
                return jsonify(success=False, message="Invalid file type"), 400
            
            filename = secure_filename(file.filename)
            unique_filename = generate_unique_filename(filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(filepath)

        new_product = Product(
            farmer_id=farmer.id,
            name=data['name'],
            category=data['category'],
            price=data['price'],
            quantity=data['quantity'],
            unit=data.get('unit', 'kg'),
            quality_metrics=request.form.get('quality_metrics', '{}'),
            image_url=filepath,
            tags=request.form.get('tags', '')
        )
        
        db.session.add(new_product)
        db.session.commit()

        # Clear cache
        redis_client.delete(cache_key('products'))
        
        # Broadcast in real-time
        socketio.emit('new_product', {
            'id': new_product.id,
            'name': new_product.name,
            'price': new_product.price,
            'category': new_product.category,
            'farmer': farmer.farm_name
        })
        
        logger.info(f"New product uploaded: {new_product.name} by farmer {farmer.id}")
        return jsonify(
            success=True, 
            message="Product uploaded successfully",
            product_id=new_product.id,
            image_url=filepath
        )
    except ValidationError as e:
        return jsonify(success=False, message="Validation error", errors=e.messages), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Product upload error: {e}")
        return jsonify(success=False, message="Product upload failed"), 500

# Enhanced Product Search with caching and advanced filters
@app.route('/get_products')
@jwt_required()
def get_products():
    try:
        # Try cache first
        cache_key_str = cache_key('products', *sorted(request.args.items()))
        cached = redis_client.get(cache_key_str)
        if cached:
            return jsonify(json.loads(cached))
        
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        category = request.args.get('category')
        search = request.args.get('search')
        min_price = request.args.get('min_price', type=float)
        max_price = request.args.get('max_price', type=float)
        location = request.args.get('location')
        min_rating = request.args.get('min_rating', type=float)
        sort_by = request.args.get('sort_by', 'listed_date')
        sort_order = request.args.get('sort_order', 'desc')
        
        # Build query
        query = Product.query.filter_by(is_available=True)
        
        if category:
            query = query.filter(Product.category == category)
            
        if search:
            query = query.filter(
                (Product.name.ilike(f'%{search}%')) | 
                (Product.tags.ilike(f'%{search}%'))
            )
            
        if min_price is not None:
            query = query.filter(Product.price >= min_price)
            
        if max_price is not None:
            query = query.filter(Product.price <= max_price)
            
        if min_rating is not None:
            query = query.filter(Product.rating >= min_rating)
            
        if location:
            query = query.join(Farmer).join(User).filter(User.location.ilike(f'%{location}%'))
        
        # Sorting
        sort_column = getattr(Product, sort_by, Product.listed_date)
        if sort_order == 'desc':
            query = query.order_by(sort_column.desc())
        else:
            query = query.order_by(sort_column.asc())
        
        # Pagination
        products_pagination = query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        product_list = []
        for p in products_pagination.items:
            farmer = Farmer.query.get(p.farmer_id)
            user = User.query.get(farmer.user_id) if farmer else None
            
            product_list.append({
                'id': p.id,
                'name': p.name,
                'category': p.category,
                'price': p.price,
                'quantity': p.quantity,
                'unit': p.unit,
                'farmer': farmer.farm_name if farmer else 'Unknown',
                'farmer_id': farmer.id if farmer else None,
                'location': user.location if user else 'Unknown',
                'image_url': p.image_url,
                'listed_date': p.listed_date.isoformat(),
                'rating': p.rating,
                'total_reviews': p.total_reviews,
                'tags': p.tags.split(',') if p.tags else []
            })
        
        result = {
            'products': product_list,
            'total': products_pagination.total,
            'pages': products_pagination.pages,
            'current_page': page
        }
        
        # Cache for 5 minutes
        redis_client.setex(cache_key_str, 300, json.dumps(result))
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Get products error: {e}")
        return jsonify(success=False, message="Failed to fetch products"), 500

# Enhanced Order Creation with Stripe Payment
@app.route('/create_order', methods=['POST'])
@jwt_required()
def create_order():
    try:
        user = get_jwt_identity()
        if user['type'] != 'consumer':
            return jsonify(success=False, message="Only consumers can create orders"), 403
            
        data = request.get_json()
        product_id = data.get('product_id')
        quantity = data.get('quantity')
        shipping_address = data.get('shipping_address')
        
        if not product_id or not quantity or not shipping_address:
            return jsonify(success=False, message="Product ID, quantity and shipping address required"), 400
            
        product = Product.query.get(product_id)
        if not product or not product.is_available:
            return jsonify(success=False, message="Product not available"), 404
            
        if product.quantity < quantity:
            return jsonify(success=False, message="Insufficient quantity"), 400
            
        consumer = Consumer.query.filter_by(user_id=user['id']).first()
        if not consumer:
            return jsonify(success=False, message="Consumer profile not found"), 404
            
        total_price = product.price * quantity
        
        # Create Stripe Payment Intent
        try:
            payment_intent = stripe.PaymentIntent.create(
                amount=int(total_price * 100),  # Convert to cents
                currency='usd',
                metadata={
                    'product_id': product_id,
                    'consumer_id': consumer.id,
                    'quantity': quantity
                }
            )
        except Exception as e:
            logger.error(f"Stripe error: {e}")
            return jsonify(success=False, message="Payment processing error"), 500
        
        # Create order with pending status
        new_order = Order(
            consumer_id=consumer.id,
            product_id=product_id,
            quantity=quantity,
            total_price=total_price,
            shipping_address=shipping_address,
            payment_intent_id=payment_intent.id,
            status='pending'
        )
        
        db.session.add(new_order)
        db.session.commit()
        
        return jsonify(
            success=True,
            message="Order created successfully",
            order_id=new_order.id,
            total_price=total_price,
            client_secret=payment_intent.client_secret,
            payment_intent_id=payment_intent.id
        )
    except Exception as e:
        db.session.rollback()
        logger.error(f"Create order error: {e}")
        return jsonify(success=False, message="Order creation failed"), 500

@app.route('/confirm_payment', methods=['POST'])
@jwt_required()
def confirm_payment():
    try:
        data = request.get_json()
        payment_intent_id = data.get('payment_intent_id')
        
        if not payment_intent_id:
            return jsonify(success=False, message="Payment intent ID required"), 400
        
        order = Order.query.filter_by(payment_intent_id=payment_intent_id).first()
        if not order:
            return jsonify(success=False, message="Order not found"), 404
        
        # Verify payment with Stripe
        payment_intent = stripe.PaymentIntent.retrieve(payment_intent_id)
        
        if payment_intent.status == 'succeeded':
            order.status = 'confirmed'
            
            # Update product quantity
            product = Product.query.get(order.product_id)
            product.quantity -= order.quantity
            if product.quantity == 0:
                product.is_available = False
            
            # Add loyalty points (1 point per dollar)
            consumer = Consumer.query.get(order.consumer_id)
            consumer.loyalty_points += int(order.total_price)
            
            db.session.commit()
            
            # Clear cache
            redis_client.delete(cache_key('products'))
            
            # Notify farmer
            socketio.emit('new_order', {
                'order_id': order.id,
                'product_name': product.name,
                'quantity': order.quantity,
                'total_price': order.total_price
            })
            
            # Create notification for farmer
            farmer_user = User.query.get(product.farmer.user_id)
            notification = Notification(
                user_id=farmer_user.id,
                title="New Order",
                message=f"New order for {product.name} (Quantity: {order.quantity})",
                type="success"
            )
            db.session.add(notification)
            db.session.commit()
            
            return jsonify(success=True, message="Payment confirmed and order processed")
        else:
            return jsonify(success=False, message="Payment not successful"), 400
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Confirm payment error: {e}")
        return jsonify(success=False, message="Payment confirmation failed"), 500

# Review System
@app.route('/submit_review', methods=['POST'])
@jwt_required()
def submit_review():
    try:
        user = get_jwt_identity()
        schema = ReviewSchema()
        data = schema.load(request.get_json())
        
        # Check if user has purchased the product (for product reviews)
        if data.get('product_id'):
            has_purchased = Order.query.join(Product).filter(
                Order.consumer_id == Consumer.query.filter_by(user_id=user['id']).first().id,
                Product.id == data['product_id'],
                Order.status == 'delivered'
            ).first()
            
            if not has_purchased:
                return jsonify(success=False, message="You can only review purchased products"), 403
        
        # Find the farmer being reviewed
        if data.get('product_id'):
            product = Product.query.get(data['product_id'])
            farmer_id = product.farmer.user_id
        else:
            farmer_id = request.json.get('farmer_id')
            if not farmer_id:
                return jsonify(success=False, message="Farmer ID required for farmer reviews"), 400
        
        new_review = Review(
            reviewer_id=user['id'],
            reviewee_id=farmer_id,
            product_id=data.get('product_id'),
            rating=data['rating'],
            comment=data.get('comment'),
            is_verified_purchase=bool(data.get('product_id'))
        )
        
        db.session.add(new_review)
        
        # Update ratings
        if data.get('product_id'):
            product = Product.query.get(data['product_id'])
            total_rating = product.rating * product.total_reviews + data['rating']
            product.total_reviews += 1
            product.rating = total_rating / product.total_reviews
        else:
            farmer = Farmer.query.filter_by(user_id=farmer_id).first()
            total_rating = farmer.rating * farmer.total_ratings + data['rating']
            farmer.total_ratings += 1
            farmer.rating = total_rating / farmer.total_ratings
        
        db.session.commit()
        
        # Clear cache
        redis_client.delete(cache_key('products'))
        
        return jsonify(success=True, message="Review submitted successfully")
    except ValidationError as e:
        return jsonify(success=False, message="Validation error", errors=e.messages), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Submit review error: {e}")
        return jsonify(success=False, message="Failed to submit review"), 500

@app.route('/get_reviews')
def get_reviews():
    try:
        product_id = request.args.get('product_id')
        farmer_id = request.args.get('farmer_id')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        query = Review.query
        
        if product_id:
            query = query.filter_by(product_id=product_id)
        elif farmer_id:
            farmer = Farmer.query.filter_by(user_id=farmer_id).first()
            if farmer:
                query = query.filter_by(reviewee_id=farmer.user_id, product_id=None)
        
        reviews = query.order_by(Review.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        review_list = []
        for review in reviews.items:
            reviewer = User.query.get(review.reviewer_id)
            review_list.append({
                'id': review.id,
                'reviewer_email': reviewer.email,
                'rating': review.rating,
                'comment': review.comment,
                'created_at': review.created_at.isoformat(),
                'is_verified_purchase': review.is_verified_purchase
            })
        
        return jsonify({
            'reviews': review_list,
            'total': reviews.total,
            'pages': reviews.pages,
            'current_page': page
        })
    except Exception as e:
        logger.error(f"Get reviews error: {e}")
        return jsonify(success=False, message="Failed to fetch reviews"), 500

# Admin Endpoints
@app.route('/admin/users', methods=['GET'])
@jwt_required()
@admin_required
def admin_get_users():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        users = User.query.paginate(page=page, per_page=per_page, error_out=False)
        
        user_list = []
        for user in users.items:
            user_data = {
                'id': user.id,
                'email': user.email,
                'user_type': user.user_type,
                'location': user.location,
                'is_verified': user.is_verified,
                'is_active': user.is_active,
                'created_at': user.created_at.isoformat()
            }
            
            if user.user_type == 'farmer' and user.farmer_profile:
                user_data['farm_name'] = user.farmer_profile.farm_name
            elif user.user_type == 'consumer' and user.consumer_profile:
                user_data['loyalty_points'] = user.consumer_profile.loyalty_points
            
            user_list.append(user_data)
        
        return jsonify({
            'users': user_list,
            'total': users.total,
            'pages': users.pages,
            'current_page': page
        })
    except Exception as e:
        logger.error(f"Admin get users error: {e}")
        return jsonify(success=False, message="Failed to fetch users"), 500

@app.route('/admin/users/<int:user_id>', methods=['PUT'])
@jwt_required()
@admin_required
def admin_update_user(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify(success=False, message="User not found"), 404
        
        data = request.get_json()
        if 'is_active' in data:
            user.is_active = data['is_active']
        
        db.session.commit()
        
        return jsonify(success=True, message="User updated successfully")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Admin update user error: {e}")
        return jsonify(success=False, message="Failed to update user"), 500

# Enhanced Profile Management
@app.route('/profile', methods=['GET', 'PUT'])
@jwt_required()
def profile():
    try:
        user_id = get_jwt_identity()['id']
        user = User.query.get(user_id)
        
        if not user:
            return jsonify(success=False, message="User not found"), 404
        
        if request.method == 'GET':
            profile_data = {
                'email': user.email,
                'user_type': user.user_type,
                'location': user.location,
                'created_at': user.created_at.isoformat(),
                'is_verified': user.is_verified
            }
            
            if user.user_type == 'farmer' and user.farmer_profile:
                farmer = user.farmer_profile
                profile_data.update({
                    'farm_name': farmer.farm_name,
                    'main_products': farmer.main_products,
                    'farm_size': farmer.farm_size,
                    'description': farmer.description,
                    'contact_info': farmer.contact_info,
                    'rating': farmer.rating
                })
            elif user.user_type == 'consumer' and user.consumer_profile:
                consumer = user.consumer_profile
                profile_data.update({
                    'preferences': consumer.preferences,
                    'dietary_restrictions': consumer.dietary_restrictions,
                    'loyalty_points': consumer.loyalty_points
                })
                
            return jsonify(success=True, profile=profile_data)
        
        else:  # PUT
            data = request.get_json()
            
            if 'location' in data:
                user.location = data['location']
            
            if user.user_type == 'farmer' and user.farmer_profile:
                farmer = user.farmer_profile
                if 'farm_name' in data:
                    farmer.farm_name = data['farm_name']
                if 'main_products' in data:
                    farmer.main_products = data['main_products']
                if 'description' in data:
                    farmer.description = data['description']
                if 'contact_info' in data:
                    farmer.contact_info = data['contact_info']
            
            elif user.user_type == 'consumer' and user.consumer_profile:
                consumer = user.consumer_profile
                if 'preferences' in data:
                    consumer.preferences = data['preferences']
                if 'dietary_restrictions' in data:
                    consumer.dietary_restrictions = data['dietary_restrictions']
            
            db.session.commit()
            
            return jsonify(success=True, message="Profile updated successfully")
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Profile error: {e}")
        return jsonify(success=False, message="Profile operation failed"), 500

# Notifications
@app.route('/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    try:
        user_id = get_jwt_identity()['id']
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        notifications = Notification.query.filter_by(user_id=user_id).order_by(
            Notification.created_at.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)
        
        notification_list = []
        for notification in notifications.items:
            notification_list.append({
                'id': notification.id,
                'title': notification.title,
                'message': notification.message,
                'type': notification.type,
                'is_read': notification.is_read,
                'created_at': notification.created_at.isoformat()
            })
        
        return jsonify({
            'notifications': notification_list,
            'total': notifications.total,
            'unread_count': Notification.query.filter_by(user_id=user_id, is_read=False).count()
        })
    except Exception as e:
        logger.error(f"Get notifications error: {e}")
        return jsonify(success=False, message="Failed to fetch notifications"), 500

@app.route('/notifications/<int:notification_id>/read', methods=['PUT'])
@jwt_required()
def mark_notification_read(notification_id):
    try:
        user_id = get_jwt_identity()['id']
        notification = Notification.query.filter_by(id=notification_id, user_id=user_id).first()
        
        if not notification:
            return jsonify(success=False, message="Notification not found"), 404
        
        notification.is_read = True
        db.session.commit()
        
        return jsonify(success=True, message="Notification marked as read")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Mark notification read error: {e}")
        return jsonify(success=False, message="Failed to update notification"), 500

# Market Data Analytics
@app.route('/market-data')
@jwt_required()
def get_market_data():
    try:
        category = request.args.get('category')
        days = request.args.get('days', 30, type=int)
        
        start_date = datetime.utcnow() - timedelta(days=days)
        
        query = MarketData.query.filter(MarketData.date >= start_date)
        
        if category:
            query = query.filter(MarketData.product_category == category)
        
        market_data = query.order_by(MarketData.date.desc()).all()
        
        data_list = []
        for data in market_data:
            data_list.append({
                'category': data.product_category,
                'price': data.price,
                'demand_level': data.demand_level,
                'region': data.region,
                'date': data.date.isoformat()
            })
        
        return jsonify({
            'market_data': data_list,
            'timeframe_days': days
        })
    except Exception as e:
        logger.error(f"Get market data error: {e}")
        return jsonify(success=False, message="Failed to fetch market data"), 500

# WebSocket events
@socketio.on('connect')
def handle_connect():
    logger.info('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    logger.info('Client disconnected')

@socketio.on('join_user_room')
def handle_join_user_room(data):
    user_id = data.get('user_id')
    if user_id:
        socketio.server.enter_room(request.sid, f'user_{user_id}')
        logger.info(f'User {user_id} joined their room')

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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()
        logger.info("Database tables created")
    
    # Create upload directory if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    socketio.run(app, debug=os.environ.get('FLASK_DEBUG', 'False').lower() == 'true', host='0.0.0.0', port=5000)