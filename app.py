from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'farmconnect.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('FC_SECRET', 'dev-secret-key-change-me')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    user_type = db.Column(db.String(20), default='consumer')  # 'farmer' or 'consumer'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100))
    price = db.Column(db.Integer, nullable=False)
    quantity = db.Column(db.Integer, default=0)
    description = db.Column(db.Text)
    image = db.Column(db.String(500))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # null for seed products

@app.before_first_request
def create_tables():
    db.create_all()
    # Seed a couple of products if empty
    if Product.query.count() == 0:
        p1 = Product(name='Tomatoes', price=120, category='vegetables', quantity=100, description='Fresh local tomatoes', image='/static/images/tomatoes.jpg')
        p2 = Product(name='Maize', price=50, category='grains', quantity=200, description='High-quality maize', image='/static/images/maize.jpg')
        db.session.add_all([p1,p2])
        db.session.commit()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/manifest.json')
def manifest():
    return send_from_directory(app.static_folder, 'manifest.json')

# --- Auth API ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')
    user_type = data.get('user_type', 'consumer')
    if not email or not password:
        return jsonify({'ok': False, 'error': 'email and password required'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'ok': False, 'error': 'email exists'}), 400
    u = User(email=email, user_type=user_type)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    session.clear()
    session['user_id'] = u.id
    session['user_type'] = u.user_type
    session.permanent = True
    return jsonify({'ok': True, 'user': {'email': u.email, 'user_type': u.user_type}})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')
    u = User.query.filter_by(email=email).first()
    if not u or not u.check_password(password):
        return jsonify({'ok': False, 'error': 'invalid credentials'}), 401
    session.clear()
    session['user_id'] = u.id
    session['user_type'] = u.user_type
    session.permanent = True
    return jsonify({'ok': True, 'user': {'email': u.email, 'user_type': u.user_type}})

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'ok': True})

# --- Products API ---
@app.route('/api/products', methods=['GET'])
def list_products():
    products = Product.query.all()
    res = []
    for p in products:
        res.append({
            'id': p.id,
            'name': p.name,
            'category': p.category,
            'price': p.price,
            'quantity': p.quantity,
            'description': p.description,
            'image': p.image or '/static/images/placeholder.jpg',
            'owner_id': p.owner_id
        })
    return jsonify({'ok': True, 'products': res})

@app.route('/api/products', methods=['POST'])
def create_product():
    if 'user_id' not in session or session.get('user_type') != 'farmer':
        return jsonify({'ok': False, 'error': 'unauthorized'}), 403
    data = request.get_json() or {}
    name = data.get('name')
    price = data.get('price', 0)
    category = data.get('category')
    quantity = data.get('quantity', 0)
    description = data.get('description')
    image = data.get('image') or '/static/images/placeholder.jpg'
    p = Product(name=name, price=price, category=category, quantity=quantity, description=description, image=image, owner_id=session['user_id'])
    db.session.add(p)
    db.session.commit()
    return jsonify({'ok': True, 'product': {'id': p.id, 'name': p.name}})

@app.route('/api/products/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    if 'user_id' not in session:
        return jsonify({'ok': False, 'error': 'unauthorized'}), 403
    p = Product.query.get(product_id)
    if not p:
        return jsonify({'ok': False, 'error': 'not found'}), 404
    if p.owner_id != session.get('user_id'):
        return jsonify({'ok': False, 'error': 'not your product'}), 403
    db.session.delete(p)
    db.session.commit()
    return jsonify({'ok': True})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
