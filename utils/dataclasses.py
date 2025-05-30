from dataclasses import dataclass, field
from typing import List, Any, Dict, Optional

@dataclass
class Vault:
    salt: str
    identity_key_public: str
    signed_prekey_public: str
    signed_prekey_signature: str
    identity_key_private_enc: str
    identity_key_private_nonce: str
    signed_prekey_private_enc: str
    signed_prekey_private_nonce: str
    opks: Any = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict) -> 'Vault':
        return cls(
            salt=data["salt"],
            identity_key_public=data["identity_key_public"],
            signed_prekey_public=data["signed_prekey_public"],
            signed_prekey_signature=data["signed_prekey_signature"],
            identity_key_private_enc=data["identity_key_private_enc"],
            identity_key_private_nonce=data["identity_key_private_nonce"],
            signed_prekey_private_enc=data["signed_prekey_private_enc"],
            signed_prekey_private_nonce=data["signed_prekey_private_nonce"],
            opks=data.get("opks", [])
        )

    def to_dict(self) -> Dict:
        return {
            "salt": self.salt,
            "identity_key_public": self.identity_key_public,
            "signed_prekey_public": self.signed_prekey_public,
            "signed_prekey_signature": self.signed_prekey_signature,
            "identity_key_private_enc": self.identity_key_private_enc,
            "identity_key_private_nonce": self.identity_key_private_nonce,
            "signed_prekey_private_enc": self.signed_prekey_private_enc,
            "signed_prekey_private_nonce": self.signed_prekey_private_nonce,
            "opks": self.opks
        }

class PAC:
    def __init__(self, recipient_id, file_uuid, valid_until, encrypted_file_key, signature, issuer_id, sender_ephemeral_public, k_file_nonce, filename=None, mime_type=None):
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

    @classmethod
    def from_json(cls, data):
        pac_data = data.get('pac', {})
        return cls(
            recipient_id=data.get('recipient_id'),
            file_uuid=data.get('file_uuid') or data.get('file_id'),
            valid_until=pac_data.get('valid_until'),
            encrypted_file_key=pac_data.get('encrypted_file_key'),
            signature=pac_data.get('signature'),
            issuer_id=pac_data.get('issuer_id'),
            sender_ephemeral_public=pac_data.get('sender_ephemeral_public'),
            k_file_nonce=pac_data.get('nonce') or pac_data.get('encrypted_file_key_nonce'),
            filename=pac_data.get('filename'),
            mime_type=pac_data.get('mime_type')
        )

    def to_dict(self):
        return {
            'recipient_id': self.recipient_id,
            'file_uuid': self.file_uuid,
            'valid_until': self.valid_until,
            'encrypted_file_key': self.encrypted_file_key,
            'signature': self.signature,
            'issuer_id': self.issuer_id,
            'sender_ephemeral_public': self.sender_ephemeral_public,
            'k_file_nonce': self.k_file_nonce,
            'filename': self.filename,
            'mime_type': self.mime_type
        }
        
class FileInfo:
    def __init__(self, file_uuid, name, file_nonce, k_file_encrypted, k_file_nonce, owner_id, mime_type=None, filename=None):
        self.file_uuid = str(file_uuid)  # Always treat as string UUID
        self.name = name
        self.file_nonce = file_nonce
        self.k_file_encrypted = k_file_encrypted
        self.k_file_nonce = k_file_nonce
        self.owner_id = owner_id
        self.mime_type = mime_type
        self.filename = filename or name

    @classmethod
    def from_dict(cls, data):
        return cls(
            file_uuid=data.get('file_uuid') or data.get('file_id'),
            name=data.get('name') or data.get('filename'),
            file_nonce=data.get('file_nonce'),
            k_file_encrypted=data.get('k_file_encrypted'),
            k_file_nonce=data.get('k_file_nonce'),
            owner_id=data.get('owner_id') or data.get('owner_name'),
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
            'owner_id': self.owner_id,
            'mime_type': self.mime_type,
            'filename': self.filename
        }

