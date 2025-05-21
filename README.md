# Simple Flask Authentication App

A basic web application with user authentication built using Flask.

## Features

- User registration (sign up)
- User login
- Password hashing for security
- Protected dashboard page
- User session management

## Setup

1. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install the required packages:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Open your browser and navigate to `http://localhost:5000`

## Project Structure

- `app.py` - Main application file
- `templates/` - HTML templates
  - `base.html` - Base template with common layout
  - `index.html` - Home page
  - `login.html` - Login page
  - `signup.html` - Registration page
  - `dashboard.html` - Protected dashboard page
- `requirements.txt` - Python dependencies
- `users.db` - SQLite database (created automatically)

## Security Features

- Passwords are hashed using Werkzeug's security functions
- User sessions are managed securely using Flask-Login
- CSRF protection is enabled by default
- SQL injection protection through SQLAlchemy