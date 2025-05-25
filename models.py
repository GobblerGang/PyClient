from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from extensions import db

# Association table for file sharing
file_shares = db.Table('file_shares',
    db.Column('file_id', db.Integer, db.ForeignKey('file.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    identity_key_public = db.Column(db.String(255))  # Base64 encoded public key
    signed_prekey_public = db.Column(db.String(255))  # Base64 encoded public key
    signed_prekey_signature = db.Column(db.String(255))  # Base64 encoded signature
    # Vault fields
    salt = db.Column(db.String(44))  # Base64 encoded salt (16 bytes -> 24 chars, but 44 for future-proofing)
    identity_key_private_enc = db.Column(db.String(255))
    identity_key_private_nonce = db.Column(db.String(44))
    signed_prekey_private_enc = db.Column(db.String(255))
    signed_prekey_private_nonce = db.Column(db.String(44))
    # Add OPKs as a JSON string field
    opks_json = db.Column(db.Text)  # Store list of base64 public keys as JSON
    # Relationships
    files = db.relationship('File', backref='owner', lazy=True)
    shared_files = db.relationship('File', secondary=file_shares, lazy='subquery',
        backref=db.backref('shared_with', lazy=True))

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mime_type = db.Column(db.String(127), nullable=True)
