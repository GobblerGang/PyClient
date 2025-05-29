from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import json
import base64
from argon2.low_level import Type, hash_secret_raw
from typing import Tuple, Dict, Any
from secrets import token_bytes
from utils.dataclasses import PAC

class CryptoUtils:
    @staticmethod
    def derive_master_key(password: str, salt: bytes) -> bytes:
        """Derive a master key from a password and salt using Argon2id."""
        # give reasons for these parameters
        return hash_secret_raw(
            password.encode(),
            salt,
            time_cost=2,
            memory_cost=2**16,
            parallelism=2,
            hash_len=32,
            type=Type.ID,
        )
        
    @staticmethod
    def encrypt_with_key(file_data: bytes, key: bytes, associated_data:bytes=None) -> Tuple[bytes, bytes]:
        """Encrypt file data using AES-GCM."""
        aesgcm = AESGCM(key)
        nonce = token_bytes(12)  
        ciphertext = aesgcm.encrypt(nonce, file_data, associated_data)
        return nonce, ciphertext

    @staticmethod
    def decrypt_with_key(nonce: bytes, ciphertext: bytes, key: bytes, associated_data:bytes=None) -> bytes:
        """Decrypt file data using AES-GCM."""
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    
    @staticmethod
    def generate_identity_keypair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
        """Generate a new Ed25519 identity key pair."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def generate_signed_prekey(identity_key: ed25519.Ed25519PrivateKey) -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey, bytes]:
        """Generate a signed prekey and its signature."""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        signature = identity_key.sign(public_bytes)
        return private_key, public_key, signature

    # @staticmethod
    # def perform_3xdh(
    #     identity_private: x25519.X25519PrivateKey,
    #     identity_public: x25519.X25519PublicKey,
    #     ephemeral_private: x25519.X25519PrivateKey,
    #     ephemeral_public: x25519.X25519PublicKey,
    #     recipient_identity_public: x25519.X25519PublicKey,
    #     recipient_signed_prekey_public: x25519.X25519PublicKey,
    #     recipient_ephemeral_public: x25519.X25519PublicKey
    # ) -> bytes:
    #     """Perform 3XDH key exchange."""
    #     # First DH
    #     shared1 = identity_private.exchange(recipient_ephemeral_public)
    #     # Second DH
    #     shared2 = ephemeral_private.exchange(recipient_identity_public)
    #     # Third DH
    #     shared3 = ephemeral_private.exchange(recipient_signed_prekey_public)

    #     # Derive final key
    #     shared_secret = shared1 + shared2 + shared3
    #     derived_key = HKDF(
    #         algorithm=hashes.SHA256(),
    #         length=32,
    #         salt=None,
    #         info=b'3XDH key agreement'
    #     ).derive(shared_secret)
        
    #     return derived_key

    @staticmethod
    def perform_3xdh_sender(
        identity_private: x25519.X25519PrivateKey,       
        ephemeral_private: x25519.X25519PrivateKey,      
        recipient_identity_public: x25519.X25519PublicKey,  
        recipient_signed_prekey_public: x25519.X25519PublicKey,  
        recipient_one_time_prekey_public: x25519.X25519PublicKey = None,
    ) -> bytes:
        """Perform correct 3XDH key exchange as used in Signal."""
        shared1 = ephemeral_private.exchange(recipient_identity_public)

        shared2 = identity_private.exchange(recipient_signed_prekey_public)

        shared3 = ephemeral_private.exchange(recipient_signed_prekey_public)

        shared_secret = shared1 + shared2 + shared3
        if recipient_one_time_prekey_public:
            shared4 = ephemeral_private.exchange(recipient_one_time_prekey_public)
            shared_secret += shared4

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'3XDH key agreement'
        ).derive(shared_secret)

        return derived_key
    
    @staticmethod
    def perform_3xdh_recipient(
        identity_private: x25519.X25519PrivateKey,          
        signed_prekey_private: x25519.X25519PrivateKey,     
        sender_identity_public: x25519.X25519PublicKey,     
        sender_ephemeral_public: x25519.X25519PublicKey,    
        one_time_prekey_private: x25519.X25519PrivateKey = None    
        ) -> bytes:
        """Perform 3XDH from the receiver's side."""
        shared1 = identity_private.exchange(sender_ephemeral_public)

        shared2 = signed_prekey_private.exchange(sender_identity_public)

        shared3 = signed_prekey_private.exchange(sender_ephemeral_public)

        shared_secret = shared1 + shared2 + shared3
        if one_time_prekey_private:  
            shared4 = one_time_prekey_private.exchange(sender_ephemeral_public)
            shared_secret += shared4

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'3XDH key agreement'
        ).derive(shared_secret)

        return derived_key

    @staticmethod
    def create_pac(
        file_id: str,
        recipient_id: str,
        issuer_id: str,
        encrypted_file_key: bytes,
        encrypted_file_key_nonce: bytes,
        sender_ephemeral_pubkey: bytes,
        valid_until: int,
        identity_key: ed25519.Ed25519PrivateKey,
        filename: str,
        mime_type: str
    ) -> PAC:
        """Create a Privilege Attribute Certificate (PAC) and return as PAC object."""
        pac_dict = {
            "file_id": file_id,
            "recipient_id": recipient_id,
            "issuer_id": issuer_id,
            "encrypted_file_key": base64.b64encode(encrypted_file_key).decode(),
            "encrypted_file_key_nonce": base64.b64encode(encrypted_file_key_nonce).decode(),
            "sender_ephemeral_pubkey": base64.b64encode(sender_ephemeral_pubkey).decode(),
            "valid_until": valid_until,
            "revoked": False,
            "filename": filename,
            "mime_type": mime_type
        }
        # Create signature
        message = json.dumps(pac_dict, sort_keys=True).encode()
        signature = identity_key.sign(message)
        pac_dict["signature"] = base64.b64encode(signature).decode()
        # Return as PAC object
        return PAC(
            recipient_id=recipient_id,
            file_id=file_id,
            valid_until=valid_until,
            encrypted_file_key=pac_dict["encrypted_file_key"],
            signature=pac_dict["signature"],
            issuer_id=issuer_id,
            sender_ephemeral_public=pac_dict["sender_ephemeral_pubkey"],
            k_file_nonce=pac_dict["encrypted_file_key_nonce"],
            filename=filename,
            mime_type=mime_type
        )

    @staticmethod
    def verify_pac(pac: dict, issuer_public_key: ed25519.Ed25519PublicKey) -> bool:
        """Verify a PAC's signature, including metadata."""
        try:
            signature = base64.b64decode(pac["signature"])
            pac_copy = pac.copy()
            del pac_copy["signature"]
            message = json.dumps(pac_copy, sort_keys=True).encode()
            issuer_public_key.verify(signature, message)
            return True
        except Exception:
            return False
