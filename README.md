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

3. Create a `.env` file in the project root with the following variables:
```bash
FLASK_ENV=development  # or 'production' for production environment
DATABASE_URI=sqlite:///users.db  # For development
UPLOAD_FOLDER=uploads
MAX_CONTENT_LENGTH=16777216  # 16MB in bytes
```

4. Run the application:
```bash
python app.py
```

5. Open your browser and navigate to `http://localhost:5000`

## Environment Variables

The following environment variables can be configured in your `.env` file:

- `FLASK_ENV`: Set to 'development' or 'production'
- `DATABASE_URI`: Database connection string (default: sqlite:///users.db)
- `UPLOAD_FOLDER`: Directory for file uploads (default: uploads)
- `MAX_CONTENT_LENGTH`: Maximum file upload size in bytes (default: 16MB)

Note: The `SECRET_KEY` is automatically generated using `os.urandom(24)` for security.

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
