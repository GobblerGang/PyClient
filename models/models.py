import base64
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from extensions.extensions import db
from flask import g
from utils.crypto_utils import CryptoUtils

# Association table for file sharing
file_shares = db.Table('file_shares',
    db.Column('file_id', db.Integer, db.ForeignKey('file.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False)  # UUID for user identification
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
    
    
    def get_identity_private_key(self, master_key):
        """
        Decrypt and return the user's identity private key, caching it per-request using Flask's g.
        """
        if not hasattr(g, 'identity_private_key'):
            nonce = base64.b64decode(self.identity_key_private_nonce)
            enc = base64.b64decode(self.identity_key_private_enc)
            decrypted_bytes = CryptoUtils.decrypt_with_key(nonce, enc, master_key, b'identity_key')
            g.identity_private_key = decrypted_bytes
        return g.identity_private_key

#     files = db.relationship('File', backref='owner', lazy=True)
    
# class File(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     uuid = db.Column(db.String(36), unique=True, nullable=False)  # UUID for file identification
#     filename = db.Column(db.String(255), nullable=False)
#     upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
#     mime_type = db.Column(db.String(127), nullable=True)
#     file_nonce = db.Column(db.String(44))  # Nonce for file encryption
#     k_file_encrypted = db.Column(db.String(255))  # Encrypted file key
#     k_file_nonce = db.Column(db.String(44))  # Nonce for file key encryption
    
#     owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)