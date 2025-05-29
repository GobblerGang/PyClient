import os
import mimetypes
from datetime import datetime
from werkzeug.utils import secure_filename
from models.models import File
from extensions.extensions import db
from utils.crypto_utils import CryptoUtils
from utils.key_utils import get_user_vault, try_decrypt_private_keys
import utils.server_utils as server
from utils.dataclasses import PAC, FileInfo
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
import base64
from cryptography.hazmat.primitives import serialization

class FileDownloadError(Exception):
    pass

def create_file_record(file_id, owner_id, k_file_encrypted, filename, file_nonce, k_file_nonce, mime_type):
    file_record = File(
        id=file_id,
        owner_id=owner_id,
        k_file_encrypted=k_file_encrypted,
        filename=filename,
        file_nonce=file_nonce,
        k_file_nonce=k_file_nonce,
        mime_type=mime_type
    )
    db.session.add(file_record)
    db.session.commit()
    return file_record

def revoke_file_access(file, user_id):
    # Revocation logic placeholder
    return True

def upload_file_service(file_storage, user, master_key):
    """Upload a file. All user/session/master_key data must be passed in."""
    file_data = file_storage.read()
    file_storage.seek(0)
    k_file = os.urandom(32)
    file_id = str(int(datetime.now().timestamp()))
    file_nonce, ciphertext = CryptoUtils.encrypt_with_key(file_data, k_file, file_id.encode())
    k_file_nonce, enc_k_file = CryptoUtils.encrypt_with_key(k_file, master_key)
    filename = secure_filename(file_storage.filename)
    mime_type, _ = mimetypes.guess_type(filename)
    create_file_record(
        file_id=file_id,
        owner_id=user.id,
        filename=filename,
        k_file_encrypted=enc_k_file,
        file_nonce=file_nonce,
        k_file_nonce=k_file_nonce,
        mime_type=mime_type
    )
    server.upload_file(
        file_id=file_id,
        file_name=filename,
        file_ciphertext=ciphertext,
        owner_id=user.id,
        mime_type=mime_type,
        file_nonce=file_nonce
    )
    return

def load_x25519_public_key(b64_key):
    """Decode a base64-encoded X25519 public key."""
    return x25519.X25519PublicKey.from_public_bytes(base64.b64decode(b64_key))

def get_user_x25519_private_keys(user, master_key):
    """Decrypt and return the user's X25519 identity and signed prekey private keys."""
    user_vault = get_user_vault(user)
    identity_private_bytes, signed_prekey_private_bytes = try_decrypt_private_keys(user_vault, master_key)
    identity_private = x25519.X25519PrivateKey.from_private_bytes(identity_private_bytes)
    signed_prekey_private = x25519.X25519PrivateKey.from_private_bytes(signed_prekey_private_bytes)
    return identity_private, signed_prekey_private

def get_user_ed25519_private_key(user, master_key):
    """Decrypt and return the user's Ed25519 identity private key."""
    user_vault = get_user_vault(user)
    identity_private_bytes, _ = try_decrypt_private_keys(user_vault, master_key)
    return ed25519.Ed25519PrivateKey.from_private_bytes(identity_private_bytes)

def share_file_with_user_service(file: File, username: str, user, master_key):
    """Share a file with another user. Requires current user and master key."""
    user_to_share = server.get_user_by_name(username)
    if not user_to_share:
        raise ValueError("User not found")
    k_file = CryptoUtils.decrypt_with_key(
        file.k_file_nonce,
        file.k_file_encrypted,
        master_key
    )
    if not k_file:
        raise ValueError("Failed to decrypt file key")
    sender_identity_private = get_user_ed25519_private_key(user, master_key)
    sender_ephemeral_private = x25519.X25519PrivateKey.generate()
    sender_ephemeral_public = sender_ephemeral_private.public_key()
    recipient_keys = server.get_user_keys(user_to_share.id)
    if not recipient_keys:
        raise ValueError("Recipient keys not found")
    recipient_identity_public = load_x25519_public_key(recipient_keys["identity_key_public"])
    recipient_signed_prekey_public = load_x25519_public_key(recipient_keys["signed_prekey_public"])
    shared_key = CryptoUtils.perform_3xdh_sender(
        identity_private=sender_identity_private,
        ephemeral_private=sender_ephemeral_private,
        recipient_identity_public=recipient_identity_public,
        recipient_signed_prekey_public=recipient_signed_prekey_public,
    )
    enc_k_file_nonce, enc_k_file = CryptoUtils.encrypt_with_key(k_file, shared_key)
    valid_until = None
    pac = CryptoUtils.create_pac(
        file_id=file.id,
        recipient_id=user_to_share.id,
        issuer_id=user.id,
        encrypted_file_key=enc_k_file,
        encrypted_file_key_nonce=enc_k_file_nonce,
        sender_ephemeral_pubkey=sender_ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ),
        valid_until=valid_until,
        identity_key=sender_identity_private
    )
    server.send_pac(pac.to_dict())
    return None, user_to_share

def delete_file_from_storage_and_db(file):
    # NOTE: not deleting from server, needs to change
    db.session.delete(file)
    db.session.commit()
    return

def refresh_pacs_service(user):
    pacs_json = server.get_pacs(user.id)
    pacs = [PAC.from_json(pac) for pac in pacs_json]
    return pacs

def refresh_user_file_info_service(user):
    """
    Retrieve both owned and shared file info for the user.
    Returns (owned_files, shared_files) as lists of FileInfo objects.
    """
    file_info_dict = server.get_user_file_info(user.id)
    owned_files = [FileInfo.from_dict(info) for info in file_info_dict.get('owned_files', [])]
    shared_files = [FileInfo.from_dict(info) for info in file_info_dict.get('shared_files', [])]
    return owned_files, shared_files

# def refresh_owned_file_info_service(user):
#     owned_files_json = server.get_user_file_info(user.id)
#     return [FileInfo.from_dict(info) for info in owned_files_json]

def download_file_service(file_id, pacs, user, master_key):
    """Download a file. Requires PACs, user object, and master key."""
    requested_file_pac = next((pac for pac in pacs if pac.file_id == file_id), None)
    if not requested_file_pac:
        raise FileDownloadError('File not found or access denied')
    owner_keys = server.get_user_keys(requested_file_pac.issuer_id)
    if not owner_keys:
        raise FileDownloadError('Owner keys not found')
    owner_identity_public = load_x25519_public_key(owner_keys["identity_key_public"])
    identity_private, signed_prekey_private = get_user_x25519_private_keys(user, master_key)
    shared_key = CryptoUtils.perform_3xdh_recipient(
        identity_private=identity_private,
        signed_prekey_private=signed_prekey_private,
        sender_identity_public=owner_identity_public,
        sender_ephemeral_public=base64.b64decode(requested_file_pac.sender_ephemeral_public),
        one_time_prekey_private=None
    )
    k_file = CryptoUtils.decrypt_with_key(
        requested_file_pac.k_file_nonce,
        requested_file_pac.encrypted_file_key,
        shared_key
    )
    if not k_file:
        raise FileDownloadError('Failed to decrypt file key')
    file_response = server.download_file(file_id=requested_file_pac.file_id)
    if not file_response:
        raise FileDownloadError('Failed to download file')
    file_data = file_response.get('ciphertext')
    if not file_data:
        raise FileDownloadError('File data not found')
    file_data = base64.b64decode(file_data)
    file_nonce = file_response.get('file_nonce')
    if not file_nonce:
        raise FileDownloadError('File nonce not found')
    decrypted_file_data = CryptoUtils.decrypt_with_key(file_nonce, file_data, k_file)
    if not decrypted_file_data:
        raise FileDownloadError('Failed to decrypt file data')
    filename = secure_filename(file_response.get('filename', f"file_{file_id}"))
    mime_type = file_response.get('mime_type', 'application/octet-stream')
    return decrypted_file_data, filename, mime_type
