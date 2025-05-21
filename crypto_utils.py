from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json
import uuid
from datetime import datetime, timedelta

class KeyPair:
    def __init__(self):
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
    
    def get_public_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def get_private_bytes(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

class PAC:
    def __init__(self, file_id, recipient_id, issuer_id, encrypted_file_key, 
                 sender_ephemeral_pubkey, valid_until=None, revoked=False):
        self.pac_id = str(uuid.uuid4())
        self.file_id = file_id
        self.recipient_id = recipient_id
        self.issuer_id = issuer_id
        self.encrypted_file_key = encrypted_file_key
        self.sender_ephemeral_pubkey = sender_ephemeral_pubkey
        self.valid_until = valid_until or (datetime.utcnow() + timedelta(days=365))
        self.revoked = revoked
        self.signature = None

    def to_dict(self):
        return {
            'pac_id': self.pac_id,
            'file_id': self.file_id,
            'recipient_id': self.recipient_id,
            'issuer_id': self.issuer_id,
            'encrypted_file_key': self.encrypted_file_key,
            'sender_ephemeral_pubkey': self.sender_ephemeral_pubkey,
            'valid_until': self.valid_until.isoformat(),
            'revoked': self.revoked,
            'signature': self.signature
        }

    def sign(self, private_key):
        # Create message to sign (excluding signature field)
        message = json.dumps({
            'pac_id': self.pac_id,
            'file_id': self.file_id,
            'recipient_id': self.recipient_id,
            'issuer_id': self.issuer_id,
            'encrypted_file_key': self.encrypted_file_key,
            'sender_ephemeral_pubkey': self.sender_ephemeral_pubkey,
            'valid_until': self.valid_until.isoformat(),
            'revoked': self.revoked
        }).encode()
        
        # Sign the message
        signature = private_key.sign(message)
        self.signature = signature.hex()
        return self.signature

    @classmethod
    def from_dict(cls, data):
        pac = cls(
            file_id=data['file_id'],
            recipient_id=data['recipient_id'],
            issuer_id=data['issuer_id'],
            encrypted_file_key=data['encrypted_file_key'],
            sender_ephemeral_pubkey=data['sender_ephemeral_pubkey'],
            valid_until=datetime.fromisoformat(data['valid_until']),
            revoked=data['revoked']
        )
        pac.pac_id = data['pac_id']
        pac.signature = data['signature']
        return pac

def perform_3xdh(identity_private_key, signed_prekey_public_key, ephemeral_private_key):
    # First DH exchange
    shared1 = identity_private_key.exchange(signed_prekey_public_key)
    
    # Second DH exchange
    shared2 = ephemeral_private_key.exchange(signed_prekey_public_key)
    
    # Third DH exchange
    shared3 = ephemeral_private_key.exchange(identity_private_key.public_key())
    
    # Combine shared secrets
    combined = shared1 + shared2 + shared3
    
    # Derive final key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'3XDH key agreement'
    ).derive(combined)
    
    return derived_key

def encrypt_file(file_data, key):
    # Generate random nonce
    nonce = os.urandom(12)
    
    # Create AESGCM cipher
    cipher = AESGCM(key)
    
    # Encrypt the file
    ciphertext = cipher.encrypt(nonce, file_data, None)
    
    # Return nonce + ciphertext
    return nonce + ciphertext

def decrypt_file(encrypted_data, key):
    # Split nonce and ciphertext
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    
    # Create AESGCM cipher
    cipher = AESGCM(key)
    
    # Decrypt the file
    return cipher.decrypt(nonce, ciphertext, None) 