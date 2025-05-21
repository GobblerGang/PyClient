from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from werkzeug.utils import secure_filename
from crypto_utils import KeyPair, PAC, perform_3xdh, encrypt_file, decrypt_file
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import serialization

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

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    identity_key = db.Column(db.String(255), nullable=False)  # Public identity key
    signed_prekey = db.Column(db.String(255), nullable=False)  # Signed pre-key
    opk_list = db.Column(db.Text)  # JSON array of one-time pre-keys
    files = db.relationship('File', backref='owner', lazy=True)
    shared_files = db.relationship('File', secondary='file_shares', lazy='subquery',
        backref=db.backref('shared_with', lazy=True))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_keys(self):
        # Generate identity key pair
        identity_keypair = KeyPair()
        self.identity_key = identity_keypair.get_public_bytes().hex()
        
        # Generate signed pre-key
        signed_prekey = KeyPair()
        self.signed_prekey = signed_prekey.get_public_bytes().hex()
        
        # Generate one-time pre-keys
        opks = [KeyPair().get_public_bytes().hex() for _ in range(10)]
        self.opk_list = json.dumps(opks)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mime_type = db.Column(db.String(127))
    encrypted_blob = db.Column(db.LargeBinary)  # Encrypted file data

class PrivilegeCertificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pac_id = db.Column(db.String(36), unique=True, nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    issuer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_file_key = db.Column(db.Text, nullable=False)
    sender_ephemeral_pubkey = db.Column(db.String(255), nullable=False)
    valid_until = db.Column(db.DateTime, nullable=False)
    revoked = db.Column(db.Boolean, default=False)
    signature = db.Column(db.String(255), nullable=False)

    file = db.relationship('File', backref='privilege_certificates')
    recipient = db.relationship('User', foreign_keys=[recipient_id])
    issuer = db.relationship('User', foreign_keys=[issuer_id])

# Association table for file sharing
file_shares = db.Table('file_shares',
    db.Column('file_id', db.Integer, db.ForeignKey('file.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

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
        
        # Generate cryptographic keys for the user
        user.generate_keys()
        
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
            # Generate a random file key
            file_key = os.urandom(32)
            
            # Read and encrypt the file
            file_data = file.read()
            encrypted_data = encrypt_file(file_data, file_key)
            
            # Save encrypted file
            filename = secure_filename(file.filename)
            unique_filename = f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Save file info to database
            new_file = File(
                filename=unique_filename,
                original_filename=filename,
                owner_id=current_user.id,
                mime_type=file.content_type,
                encrypted_blob=encrypted_data
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
            # Generate ephemeral key pair for this share
            ephemeral_keypair = KeyPair()
            
            # Perform 3XDH key exchange
            shared_secret = perform_3xdh(
                current_user.identity_key,
                user.signed_prekey,
                ephemeral_keypair.private_key
            )
            
            # Derive key for encrypting the file key
            user_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'user file key derivation'
            ).derive(shared_secret)
            
            # Encrypt the file key for this user
            encrypted_file_key = encrypt_file(file_key, user_key)
            
            # Create and sign PAC
            pac = PAC(
                file_id=file.id,
                recipient_id=user.id,
                issuer_id=current_user.id,
                encrypted_file_key=encrypted_file_key.hex(),
                sender_ephemeral_pubkey=ephemeral_keypair.get_public_bytes().hex()
            )
            
            # Sign the PAC
            pac.sign(current_user.identity_key)
            
            # Save PAC to database
            privilege_cert = PrivilegeCertificate(
                pac_id=pac.pac_id,
                file_id=file.id,
                recipient_id=user.id,
                issuer_id=current_user.id,
                encrypted_file_key=pac.encrypted_file_key,
                sender_ephemeral_pubkey=pac.sender_ephemeral_pubkey,
                valid_until=pac.valid_until,
                revoked=pac.revoked,
                signature=pac.signature
            )
            
            db.session.add(privilege_cert)
            db.session.commit()
            
            flash(f'File shared with {username}')
            return redirect(url_for('list_files'))
    
    return render_template('share.html', file=file)

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Get the PAC for this user and file
    pac = PrivilegeCertificate.query.filter_by(
        file_id=file_id,
        recipient_id=current_user.id
    ).first()
    
    if not pac:
        flash('You do not have permission to download this file')
        return redirect(url_for('list_files'))
    
    if pac.revoked:
        flash('Your access to this file has been revoked')
        return redirect(url_for('list_files'))
    
    if datetime.utcnow() > pac.valid_until:
        flash('Your access to this file has expired')
        return redirect(url_for('list_files'))
    
    # Verify PAC signature
    try:
        message = json.dumps({
            'pac_id': pac.pac_id,
            'file_id': pac.file_id,
            'recipient_id': pac.recipient_id,
            'issuer_id': pac.issuer_id,
            'encrypted_file_key': pac.encrypted_file_key,
            'sender_ephemeral_pubkey': pac.sender_ephemeral_pubkey,
            'valid_until': pac.valid_until.isoformat(),
            'revoked': pac.revoked
        }).encode()
        
        # Load issuer's public key
        issuer = User.query.get(pac.issuer_id)
        issuer_public_key = x25519.X25519PublicKey.from_public_bytes(
            bytes.fromhex(issuer.identity_key)
        )
        
        # Verify signature
        issuer_public_key.verify(
            bytes.fromhex(pac.signature),
            message
        )
    except Exception:
        flash('Invalid access certificate')
        return redirect(url_for('list_files'))
    
    # Perform 3XDH to derive the key
    shared_secret = perform_3xdh(
        current_user.identity_key,
        issuer.signed_prekey,
        bytes.fromhex(pac.sender_ephemeral_pubkey)
    )
    
    # Derive key for decrypting the file key
    user_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'user file key derivation'
    ).derive(shared_secret)
    
    # Decrypt the file key
    encrypted_file_key = bytes.fromhex(pac.encrypted_file_key)
    file_key = decrypt_file(encrypted_file_key, user_key)
    
    # Decrypt the file
    decrypted_data = decrypt_file(file.encrypted_blob, file_key)
    
    # Create temporary file
    temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f'temp_{file.original_filename}')
    with open(temp_path, 'wb') as f:
        f.write(decrypted_data)
    
    return send_file(
        temp_path,
        as_attachment=True,
        download_name=file.original_filename,
        mimetype=file.mime_type
    )

@app.route('/revoke/<int:file_id>/<int:user_id>')
@login_required
def revoke_access(file_id, user_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
        flash('You do not have permission to revoke access')
        return redirect(url_for('list_files'))
    
    pac = PrivilegeCertificate.query.filter_by(
        file_id=file_id,
        recipient_id=user_id
    ).first_or_404()
    
    pac.revoked = True
    db.session.commit()
    
    flash(f'Access revoked for {pac.recipient.username}')
    return redirect(url_for('list_files'))

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