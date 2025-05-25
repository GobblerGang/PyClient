from flask import Flask
import os
from extensions import db, login_manager
from models import User, File, file_shares
from routes import register_blueprints

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

register_blueprints(app)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)