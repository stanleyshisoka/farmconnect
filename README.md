FarmConnect — Upgraded (Flask + Tailwind PWA)
============================================

What's included
- Flask backend with SQLite (SQLAlchemy)
- Session-based auth (register/login/logout)
- Product CRUD (farmer only for creation/deletion)
- Tailwind CSS via CDN for styling
- PWA support (manifest + service worker)
- Voice search (Web Speech API) and lazy-loading images
- Cart stored in localStorage (frontend)

Quick start (local)
1. python3 -m venv venv
2. source venv/bin/activate   (Windows: venv\Scripts\activate)
3. pip install -r requirements.txt
4. export FLASK_APP=app.py
5. flask run

Notes
- This is a demo starter. For production:
  * Use a proper secret key and environment variables
  * Build Tailwind via npm for production classes
  * Add CSRF protection and stronger auth (Flask-Login or JWT)
  * Use S3 or a CDN for images
  * Add input validation on backend endpoints
