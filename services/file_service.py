import os
import mimetypes
from datetime import datetime
from werkzeug.utils import secure_filename
from extensions.extensions import db
from utils.crypto_utils import CryptoUtils
from utils.key_utils import get_user_vault, try_decrypt_private_keys
import utils.server_utils as server
from utils.dataclasses import PAC, FileInfo
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization
import base64
import session_manager

class FileDownloadError(Exception):
    pass

def revoke_file_access(file, user_id):
    # Revocation logic placeholder
    return True

def upload_file_service(file_storage, user, master_key):
    """Encrypt and upload a file to the server. No local file record is created."""
    file_data = file_storage.read()
    file_storage.seek(0)
    k_file = os.urandom(32)
    # file_uuid will be set by the server, not here
    file_nonce, ciphertext = CryptoUtils.encrypt_with_key(file_data, k_file)
    k_file_nonce, enc_k_file = CryptoUtils.encrypt_with_key(k_file, master_key)
    filename = secure_filename(file_storage.filename)
    mime_type, _ = mimetypes.guess_type(filename)
    # Only upload to server, do not create a local DB record
    response = server.upload_file(
        file_ciphertext=ciphertext,
        file_name=filename,
        file_uuid=None,  # Set to None or generate if required
        owner_id=user.uuid,
        mime_type=mime_type,
        file_nonce=file_nonce,
        enc_file_k=enc_k_file,
        k_file_nonce=k_file_nonce
    )
    # Expect response: {"file_uuid": str, "success": bool, "error": str}
    if not response or not response.get("success"):
        raise Exception(response.get("error", "Unknown upload error"))
    return response["file_uuid"]  # Optionally return the UUID for UI/session use

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

def share_file_with_user_service(file_info, username: str, user, master_key):
    """
    file_info: a FileInfo or dict from the server (must contain file_uuid, filename, etc)
    """
    user_to_share = server.get_user_by_name(username)
    if not user_to_share:
        raise ValueError("User not found")
    
    k_file = CryptoUtils.decrypt_with_key(
        file_info.k_file_nonce,
        file_info.k_file_encrypted,
        master_key
    )
    if not k_file:
        raise ValueError("Failed to decrypt file key")
    
    sender_identity_private = get_user_ed25519_private_key(user, master_key)
    sender_ephemeral_private = x25519.X25519PrivateKey.generate()
    sender_ephemeral_public = sender_ephemeral_private.public_key()
    
    recipient_keys = server.get_user_keys(user_to_share.uuid)
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
        file_id=file_info.file_uuid,
        recipient_id=user_to_share.uuid,
        issuer_id=user.uuid,
        encrypted_file_key=enc_k_file,
        encrypted_file_key_nonce=enc_k_file_nonce,
        sender_ephemeral_pubkey=sender_ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ),
        valid_until=valid_until,
        identity_key=sender_identity_private,
        filename=file_info.name,
        mime_type=file_info.mime_type
    )
    server.send_pac(pac.to_dict())
    return None, user_to_share

def delete_file_from_storage_and_db(file):
    # NOTE: not deleting from server, needs to change
    db.session.delete(file)
    db.session.commit()
    return

def refresh_pacs_service(user, private_key):
    pacs_json = server.get_user_pacs(user.uuid, private_key)
    received_pacs_json = pacs_json.get('received_pacs', [])
    
    received_pacs = [PAC.from_json(pac) for pac in received_pacs_json]
    
    issued_pacs_json = pacs_json.get('issued_pacs', [])
    
    issued_pacs = [PAC.from_json(pac) for pac in issued_pacs_json]
    
    return received_pacs, issued_pacs


def refresh_owned_file_service(user, private_key):
    owned_files_json = server.get_owned_files(user.uuid, private_key)
    return [FileInfo.from_dict(info) for info in owned_files_json]

def refresh_all_files_service(user, private_key):
    owned_files = refresh_owned_file_service(user, private_key)
    received_pacs, issued_pacs = refresh_pacs_service(user, private_key)
    session_manager.set_session_value('owned_file_info', [f.to_dict() for f in owned_files])
    session_manager.set_session_value('received_pacs', [pac.to_dict() for pac in received_pacs])
    session_manager.set_session_value('issued_pacs', [pac.to_dict() for pac in issued_pacs])
    return owned_files, received_pacs, issued_pacs

def download_file_service(file_uuid, pacs, user, master_key):
    """Download a file. Requires PACs, user object, and master key."""
    requested_file_pac = next((pac for pac in pacs if pac.file_uuid == file_uuid or pac.file_uuid == str(file_uuid)), None)
    if not requested_file_pac:
        raise FileDownloadError('File not found or access denied')
    owner_keys = server.get_user_keys(requested_file_pac.issuer_id)
    if not owner_keys:
        raise FileDownloadError('Owner keys not found')
    # Verify PAC signature before proceeding
    owner_ed25519_pub = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(owner_keys["identity_key_public"]))
    if not CryptoUtils.verify_pac(requested_file_pac.to_dict(), owner_ed25519_pub):
        raise FileDownloadError('PAC signature verification failed')
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
    file_response = server.download_file(file_uuid=requested_file_pac.file_uuid)
    if not file_response:
        raise FileDownloadError('Failed to download file')
    file_data = file_response.get('ciphertext')
    if not file_data:
        raise FileDownloadError('File data not found')
    file_data = base64.b64decode(file_data)
    file_nonce = file_response.get('file_nonce')
    if not file_nonce:
        raise FileDownloadError('File nonce not found')
    # --- Verify file metadata matches PAC ---
    filename = secure_filename(file_response.get('filename', f"file_{file_uuid}"))
    mime_type = file_response.get('mime_type', 'application/octet-stream')
    if requested_file_pac.filename and filename != requested_file_pac.filename:
        raise FileDownloadError('Filename does not match PAC')
    if requested_file_pac.mime_type and mime_type != requested_file_pac.mime_type:
        raise FileDownloadError('MIME type does not match PAC')
    decrypted_file_data = CryptoUtils.decrypt_with_key(file_nonce, file_data, k_file)
    if not decrypted_file_data:
        raise FileDownloadError('Failed to decrypt file data')
    return decrypted_file_data, filename, mime_type
