from flask import Flask
import os
from extensions.extensions import db, login_manager
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
# from models.models import User, File
# from routes.auth_routes import bp_auth
# from routes.dashboard_routes import bp_dashboard
# from routes.file_routes import bp_file

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Configuration from environment variables with fallback values
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///users.db')
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))  # 16MB max file size

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize CSRF protection
csrf = CSRFProtect(app)

db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

from routes.routes import register_blueprints
register_blueprints(app)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # Only enable debug mode in development
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug_mode)