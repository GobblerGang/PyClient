from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Association table for file sharing
file_shares = db.Table('file_shares',
    db.Column('file_id', db.Integer, db.ForeignKey('file.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    files = db.relationship('File', backref='owner', lazy=True)
    shared_files = db.relationship('File', secondary=file_shares, lazy='subquery',
        backref=db.backref('shared_with', lazy=True))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('signup'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('signup'))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        
        if file:
            filename = secure_filename(file.filename)
            # Create unique filename
            unique_filename = f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            
            # Save file info to database
            new_file = File(
                filename=unique_filename,
                original_filename=filename,
                owner_id=current_user.id
            )
            db.session.add(new_file)
            db.session.commit()
            
            flash('File uploaded successfully')
            return redirect(url_for('dashboard'))
    
    return render_template('upload.html')

@app.route('/files')
@login_required
def list_files():
    owned_files = File.query.filter_by(owner_id=current_user.id).all()
    shared_files = current_user.shared_files
    return render_template('files.html', owned_files=owned_files, shared_files=shared_files)

@app.route('/share/<int:file_id>', methods=['GET', 'POST'])
@login_required
def share_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
        flash('You do not have permission to share this file')
        return redirect(url_for('list_files'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        
        if not user:
            flash('User not found')
        elif user.id == current_user.id:
            flash('Cannot share with yourself')
        else:
            file.shared_with.append(user)
            db.session.commit()
            flash(f'File shared with {username}')
            return redirect(url_for('list_files'))
    
    return render_template('share.html', file=file)

@app.route('/revoke/<int:file_id>/<int:user_id>')
@login_required
def revoke_access(file_id, user_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
        flash('You do not have permission to revoke access')
        return redirect(url_for('list_files'))
    
    user = User.query.get_or_404(user_id)
    if user in file.shared_with:
        file.shared_with.remove(user)
        db.session.commit()
        flash(f'Access revoked for {user.username}')
    
    return redirect(url_for('list_files'))

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Check if user has access to the file
    if file.owner_id != current_user.id and current_user not in file.shared_with:
        flash('You do not have permission to download this file')
        return redirect(url_for('list_files'))
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    return send_file(file_path, as_attachment=True, download_name=file.original_filename)

@app.route('/delete/<int:file_id>')
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
        flash('You do not have permission to delete this file')
        return redirect(url_for('list_files'))
    
    # Delete the physical file
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    
    # Delete from database
    db.session.delete(file)
    db.session.commit()
    flash('File deleted successfully')
    return redirect(url_for('list_files'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 