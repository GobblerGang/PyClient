from dataclasses import dataclass, field
from typing import List, Any, Dict, Optional

@dataclass
class Vault:
    salt: str
    ed25519_identity_key_public: str
    ed25519_identity_key_private_enc: str
    ed25519_identity_key_private_nonce: str
    x25519_identity_key_public: str
    x25519_identity_key_private_enc: str
    x25519_identity_key_private_nonce: str
    signed_prekey_public: str
    signed_prekey_signature: str
    signed_prekey_private_enc: str
    signed_prekey_private_nonce: str
    opks: Any = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict) -> 'Vault':
        return cls(
            salt=data["salt"],
            ed25519_identity_key_public=data["ed25519_identity_key_public"],
            ed25519_identity_key_private_enc=data["ed25519_identity_key_private_enc"],
            ed25519_identity_key_private_nonce=data["ed25519_identity_key_private_nonce"],
            x25519_identity_key_public=data["x25519_identity_key_public"],
            x25519_identity_key_private_enc=data["x25519_identity_key_private_enc"],
            x25519_identity_key_private_nonce=data["x25519_identity_key_private_nonce"],
            signed_prekey_public=data["signed_prekey_public"],
            signed_prekey_signature=data["signed_prekey_signature"],
            signed_prekey_private_enc=data["signed_prekey_private_enc"],
            signed_prekey_private_nonce=data["signed_prekey_private_nonce"],
            opks=data.get("opks", [])
        )

    def to_dict(self) -> Dict:
        return {
            "salt": self.salt,
            "ed25519_identity_key_public": self.ed25519_identity_key_public,
            "ed25519_identity_key_private_enc": self.ed25519_identity_key_private_enc,
            "ed25519_identity_key_private_nonce": self.ed25519_identity_key_private_nonce,
            "x25519_identity_key_public": self.x25519_identity_key_public,
            "x25519_identity_key_private_enc": self.x25519_identity_key_private_enc,
            "x25519_identity_key_private_nonce": self.x25519_identity_key_private_nonce,
            "signed_prekey_public": self.signed_prekey_public,
            "signed_prekey_signature": self.signed_prekey_signature,
            "signed_prekey_private_enc": self.signed_prekey_private_enc,
            "signed_prekey_private_nonce": self.signed_prekey_private_nonce,
            "opks": self.opks
        }

class PAC:
    def __init__(self, recipient_id, file_uuid, valid_until, encrypted_file_key, signature, issuer_id, sender_ephemeral_public, k_file_nonce, filename, mime_type, issuer_username):
        self.recipient_id = recipient_id
        self.file_uuid = str(file_uuid)  # Always treat as string UUID
        self.valid_until = valid_until
        self.encrypted_file_key = encrypted_file_key
        self.signature = signature
        self.issuer_id = issuer_id
        self.sender_ephemeral_public = sender_ephemeral_public
        self.k_file_nonce = k_file_nonce
        self.filename = filename
        self.mime_type = mime_type
        self.issuer_username = issuer_username 

    @classmethod
    def from_json(cls, data):
        return cls(
        recipient_id=data.get('recipient_uuid'),
        file_uuid=data.get('file_uuid') or data.get('file_id'),
        valid_until=data.get('valid_until'),
        encrypted_file_key=data.get('encrypted_file_key'),
        signature=data.get('signature'),
        issuer_id=data.get('issuer_uuid'),
        sender_ephemeral_public=data.get('sender_ephemeral_public_key'),
        k_file_nonce=data.get('k_file_nonce') or data.get('nonce') or data.get('encrypted_file_key_nonce'),
        filename=data.get('file_name') or data.get('filename'),
        mime_type=data.get('mime_type'),
        issuer_username=data.get('issuer_username')
    )

    def to_dict(self):
        return {
            'recipient_uuid': self.recipient_id,
            'file_uuid': self.file_uuid,
            'valid_until': self.valid_until,
            'encrypted_file_key': self.encrypted_file_key,
            'signature': self.signature,
            'issuer_uuid': self.issuer_id,
            'sender_ephemeral_public_key': self.sender_ephemeral_public,
            'k_file_nonce': self.k_file_nonce,
            'filename': self.filename,
            'mime_type': self.mime_type,
            'issuer_username': self.issuer_username
        }
        
class FileInfo:
    def __init__(self, file_uuid, name, file_nonce, k_file_encrypted, k_file_nonce, owner_uuid, mime_type=None, filename=None):
        self.file_uuid = str(file_uuid)  # Always treat as string UUID
        self.name = name
        self.file_nonce = file_nonce
        self.k_file_encrypted = k_file_encrypted
        self.k_file_nonce = k_file_nonce
        self.owner_uuid = owner_uuid
        self.mime_type = mime_type
        self.filename = filename or name

    @classmethod
    def from_dict(cls, data):
        return cls(
            file_uuid=data.get('uuid') or data.get('file_id') or data.get('file_uuid'),
            name=data.get('name') or data.get('filename'),
            file_nonce=data.get('file_nonce'),
            k_file_encrypted=data.get('k_file_encrypted'),
            k_file_nonce=data.get('k_file_nonce'),
            owner_uuid=data.get('owner_uuid') or data.get('owner_name'),
            mime_type=data.get('mime_type'),
            filename=data.get('filename')
        )

    def to_dict(self):
        return {
            'file_uuid': self.file_uuid,
            'name': self.name,
            'file_nonce': self.file_nonce,
            'k_file_encrypted': self.k_file_encrypted,
            'k_file_nonce': self.k_file_nonce,
            'owner_uuid': self.owner_uuid,
            'mime_type': self.mime_type,
            'filename': self.filename
        }

