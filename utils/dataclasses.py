class PAC:
    def __init__(self, recipient_id, file_id, valid_until, encrypted_file_key, signature, issuer_id, sender_ephemeral_public, k_file_nonce):
        self.recipient_id = recipient_id
        self.file_id = file_id
        self.valid_until = valid_until
        self.encrypted_file_key = encrypted_file_key
        self.signature = signature
        self.issuer_id = issuer_id
        self.sender_ephemeral_public = sender_ephemeral_public
        self.k_file_nonce = k_file_nonce

    @classmethod
    def from_json(cls, data):
        pac_data = data.get('pac', {})
        return cls(
            recipient_id=data.get('recipient_id'),
            file_id=data.get('file_id'),
            valid_until=pac_data.get('valid_until'),
            encrypted_file_key=pac_data.get('encrypted_file_key'),
            signature=pac_data.get('signature'),
            issuer_id=pac_data.get('issuer_id'),
            sender_ephemeral_public=pac_data.get('sender_ephemeral_public'),
            k_file_nonce=pac_data.get('nonce')
        )

    def to_dict(self):
        return {
            'recipient_id': self.recipient_id,
            'file_id': self.file_id,
            'valid_until': self.valid_until,
            'encrypted_file_key': self.encrypted_file_key,
            'signature': self.signature,
            'issuer_id': self.issuer_id,
            'sender_ephemeral_public': self.sender_ephemeral_public,
            'k_file_nonce': self.k_file_nonce
        }
        
class FileInfo:
    def __init__(self, file_id, name, type, owner_id):
        self.file_id = file_id
        self.name = name
        self.mime_type = type
        self.owner_id = owner_id

    @classmethod
    def from_dict(cls, data):
        return cls(
            file_id=data.get('file_id'),
            name=data.get('name'),
            type=data.get('type'),
            owner_id=data.get('owner_name')
        )

    def to_dict(self):
        return {
            'file_id': self.file_id,
            'name': self.name,
            'mime_type': self.mime_type,
            'owner_id': self.owner_id
        }
