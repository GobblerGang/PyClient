import json
import os
import mimetypes
from datetime import datetime
from werkzeug.utils import secure_filename
from extensions.extensions import db
from models.models import KEK, User
from utils.crypto_utils import CryptoUtils
from utils.key_utils import get_user_vault, try_decrypt_private_keys
import utils.server_utils as server
from utils.dataclasses import PAC, FileInfo
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization
import base64
import session_manager

from services.kek_service import try_decrypt_kek, get_decrypted_kek

class FileDownloadError(Exception):
    pass

def revoke_file_access(file, user_id):
    # TODO: Implement the logic to revoke file access for the specified user.
    return True

def upload_file_service(file_storage, user, master_key):
    """Encrypt and upload a file to the server. No local file record is created."""
    file_data = file_storage.read()
    file_storage.seek(0)
    k_file = os.urandom(32)
    # file_uuid will be set by the server, not here
    
    kek = get_decrypted_kek(user, master_key)
    
    file_nonce, ciphertext = CryptoUtils.encrypt_with_key(plaintext=file_data, key= k_file)
    k_file_nonce, enc_k_file = CryptoUtils.encrypt_with_key(plaintext=k_file, key=kek)
    filename = secure_filename(file_storage.filename)
    mime_type, _ = mimetypes.guess_type(filename)
    
    ik_priv_bytes = User.get_identity_private_key(self=user, kek=kek)
    ik_priv = ed25519.Ed25519PrivateKey.from_private_bytes(ik_priv_bytes)
    
    
    # Only upload to server, do not create a local DB record
    data, error = server.upload_file(
        file_ciphertext=ciphertext,
        file_name=filename,
        owner_uuid=user.uuid,
        mime_type=mime_type,
        file_nonce=file_nonce,
        enc_file_k=enc_k_file,
        k_file_nonce=k_file_nonce,
        private_key=ik_priv
    )
    # Expect response: {"file_uuid": str, "success": bool, "error": str}
    if not data or not data.get("success"):
        # print("Upload response:", data)
        raise Exception(data.get("error", "Unknown upload error"))
    # print(f"File UUID: {data['file_uuid']}")
    return data["file_uuid"]  # Optionally return the UUID for UI/session use

def load_x25519_public_key(b64_key):
    """Decode a base64-encoded X25519 public key."""
    return x25519.X25519PublicKey.from_public_bytes(base64.b64decode(b64_key))

def get_user_x25519_private_keys(user, kek):
    """Decrypt and return the user's X25519 identity and signed prekey private keys."""
    user_vault = get_user_vault(user)
    _, x_identity_private_bytes, signed_prekey_private_bytes = try_decrypt_private_keys(user_vault, kek)
    identity_private = x25519.X25519PrivateKey.from_private_bytes(x_identity_private_bytes)
    signed_prekey_private = x25519.X25519PrivateKey.from_private_bytes(signed_prekey_private_bytes)
    return identity_private, signed_prekey_private

def get_user_ed25519_private_key(user, kek):
    """Decrypt and return the user's Ed25519 identity private key."""
    user_vault = get_user_vault(user)
    ed_identity_private_bytes, _, _ = try_decrypt_private_keys(user_vault, kek)
    return ed25519.Ed25519PrivateKey.from_private_bytes(ed_identity_private_bytes)

def share_file_with_user_service(file_info, recipient_username: str, user, private_key, kek):
    """
    Share a file with another user.

    Args:
        file_info: A FileInfo or dict from the server (must contain file_uuid, filename, etc).
        recipient_username: The username of the recipient.
        user: The user object of the sender.
        kek: The sender's key encryption key.
        private_key: The sender's private key for signing.

    Returns:
        The user object of the recipient.

    Raises:
        ValueError: If the recipient user is not found, keys are missing, or decryption fails.
    """
    recipient_user, error = server.get_user_by_name(recipient_username)
    if error:
        raise ValueError(f"User not found: {error}")
    
    # may need to encrypt with AAD (file name, mime type, etc.) for verification
    k_file = CryptoUtils.decrypt_with_key(
        nonce= base64.b64decode(file_info.k_file_nonce),
        ciphertext=base64.b64decode(file_info.k_file_encrypted),
        key=kek,
    )
    if not k_file:
        raise ValueError("Failed to decrypt file key")
    
    sender_identity_private_ed25519 = get_user_ed25519_private_key(user=user, kek=kek)
    sender_ephemeral_private = x25519.X25519PrivateKey.generate()
    sender_ephemeral_public = sender_ephemeral_private.public_key()
    # print(f"File info object: {file_info.to_dict()}")
    # print(f"Sharing file {file_info.file_uuid} with {recipient_username}...")
    
    recipient_keys, error = server.get_user_keys(sender_user_uuid=user.uuid,recipient_uuid=recipient_user['uuid'],  private_key=sender_identity_private_ed25519)
    print(f"Recipient keys: {json.dumps(recipient_keys, indent=2)}, Error: {error}")
    if not recipient_keys or error:
        raise ValueError(f"Recipient keys not found: {error}")
    # Use X25519 for key exchange
    recipient_identity_public = load_x25519_public_key(recipient_keys["x25519_identity_key_public"])
    recipient_signed_prekey_public = load_x25519_public_key(recipient_keys["signed_prekey_public"])
    # TODO remove this check in production
    recipient_user_local = User.query.filter_by(uuid=recipient_user['uuid']).first()
    print("Local recipient X25519 public key:", recipient_user_local.x25519_identity_key_public)
    print("Recipient keys x25519_identity_key_public:", recipient_keys["x25519_identity_key_public"])
    if recipient_user_local.x25519_identity_key_public != recipient_keys["x25519_identity_key_public"]:
        raise ValueError("Recipient X25519 identity key public does not match local user record")
    
    # print(f"Recipient identity public key: {recipient_identity_public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)}")
    # print(f"Recipient signed prekey public key: {recipient_signed_prekey_public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)}")

    
    ik_priv_bytes = user.get_x25519_identity_private_key(kek=kek)
    sender_ik_priv_x25519 = x25519.X25519PrivateKey.from_private_bytes(ik_priv_bytes)
    print(f"\n=======\nSender X25519 identity public key: {sender_ik_priv_x25519.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)}\n=======\n")
    if not isinstance(sender_ik_priv_x25519, x25519.X25519PrivateKey):
        raise ValueError("Sender identity private key is not of type X25519PrivateKey")
    shared_key = CryptoUtils.perform_3xdh_sender(
        identity_private=sender_ik_priv_x25519,
        ephemeral_private=sender_ephemeral_private,
        recipient_identity_public=recipient_identity_public,
        recipient_signed_prekey_public=recipient_signed_prekey_public,
    )
    # print(f"Shared key derived: {base64.b64encode(shared_key).decode()}")
    print(f"3XDH sender performed")
    print(f"Shared key: {base64.b64encode(shared_key).decode()}")
    
    enc_k_file_nonce, enc_k_file = CryptoUtils.encrypt_with_key(k_file, shared_key)
    
    valid_until = None
    pac = CryptoUtils.create_pac(
        file_id=file_info.file_uuid,
        recipient_id=recipient_user['uuid'],
        issuer_id=user.uuid,
        encrypted_file_key=enc_k_file,
        encrypted_file_key_nonce=enc_k_file_nonce,
        sender_ephemeral_pubkey=sender_ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ),
        valid_until=valid_until,
        identity_key=sender_identity_private_ed25519,
        filename=file_info.name,
        mime_type=file_info.mime_type,
        issuer_username=user.username
    )
    # print(f"Created PAC: {pac.to_dict()}")
    data, error =server.send_pac(pac=pac, sender_uuid=user.uuid, private_key=sender_identity_private_ed25519)
    if error or not data:
        raise ValueError(f"Failed to send PAC: {error}")
    
    return data['success']

def delete_file_(file):
    # NOTE: needs to be implemented
    return

def refresh_pacs_service(user, private_key):
    pacs_json = server.get_user_pacs(user.uuid, private_key)
    received_pacs_json = pacs_json.get('received_pacs', [])
    # print(json.dumps(received_pacs_json, indent=2))
    received_pacs = [PAC.from_json(pac) for pac in received_pacs_json]
    
    issued_pacs_json = pacs_json.get('issued_pacs', [])
    
    issued_pacs = [PAC.from_json(pac) for pac in issued_pacs_json]
    
    return received_pacs, issued_pacs


def refresh_owned_file_service(user, private_key):
    owned_files_json, error = server.get_owned_files(user.uuid, private_key)
    # print(json.dumps(owned_files_json, indent=2))
    if error:
        print(f"Error fetching owned files: {error}")
        return []
    owned_files_dict = owned_files_json.get('files', [])
    return [FileInfo.from_dict(info) for info in owned_files_dict]

def refresh_all_files_service(user, private_key_bytes):
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    owned_files = refresh_owned_file_service(user=user, private_key=private_key)
    received_pacs, issued_pacs = refresh_pacs_service(user=user, private_key=private_key)
    session_manager.set_session_value('owned_file_info', [f.to_dict() for f in owned_files])
    session_manager.set_session_value('received_pacs', [pac.to_dict() for pac in received_pacs])
    session_manager.set_session_value('issued_pacs', [pac.to_dict() for pac in issued_pacs])
    return owned_files, received_pacs, issued_pacs

def download_file_service(file_uuid, pacs, user, kek, private_key):
    """Download a file. Requires PACs, user object, and kek."""
    requested_file_pac = next((pac for pac in pacs if pac.file_uuid == file_uuid or pac.file_uuid == str(file_uuid)), None)
    if not requested_file_pac:
        raise FileDownloadError('File not found or access denied')
    
    # ik_priv_bytes = User.get_identity_private_key(self=user, kek=kek)
    # ik_priv_x25519 = x25519.X25519PrivateKey.from_private_bytes(ik_priv_bytes)
    
    issuer_keys, error = server.get_user_keys(sender_user_uuid=user.uuid, recipient_uuid=requested_file_pac.issuer_id, private_key=private_key)
    
    if not issuer_keys:
        raise FileDownloadError('Owner keys not found')
    
    # Verify PAC signature before proceeding
    issuer_ed25519_pub = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(issuer_keys["ed25519_identity_key_public"]))
    if not CryptoUtils.verify_pac(requested_file_pac.to_dict(), issuer_ed25519_pub):
        raise FileDownloadError('PAC signature verification failed')
    
    print("PAC signature verified successfully")
    
    issuer_identity_public = load_x25519_public_key(issuer_keys["x25519_identity_key_public"])
    identity_private, signed_prekey_private = get_user_x25519_private_keys(user, kek)
    
    # issuer_user_local = User.query.filter_by(uuid=requested_file_pac.issuer_id).first()
    # print(f"Local issuer public key: {issuer_user_local.identity_key_public}")
    # print(f"Issuer keys x identity public key: {issuer_keys['x25519_identity_key_public']}")
    # if issuer_user_local.identity_key_public != issuer_keys["x25519_identity_key_public"]:
        # raise FileDownloadError('Issuer identity key public does not match local user record')
    
    print(requested_file_pac.sender_ephemeral_public)
    sender_ephemeral_public_x25519 = load_x25519_public_key(requested_file_pac.sender_ephemeral_public)
    
    # check types of keys being sent
    if not isinstance(identity_private, x25519.X25519PrivateKey) or not isinstance(signed_prekey_private, x25519.X25519PrivateKey):
        raise FileDownloadError("Identity or signed prekey private key is not of type X25519PrivateKey")
    
    
    shared_key = CryptoUtils.perform_3xdh_recipient(
        identity_private=identity_private,
        signed_prekey_private=signed_prekey_private,
        sender_identity_public=issuer_identity_public,
        sender_ephemeral_public=sender_ephemeral_public_x25519,
        one_time_prekey_private=None
    )
    print(f"Shared key derived: {base64.b64encode(shared_key).decode()}")
    print(f"Requested file PAC: {requested_file_pac.to_dict()}")
    print(f"K_file_nonce: {requested_file_pac.k_file_nonce}")
    print(f"Encrypted file key: {requested_file_pac.encrypted_file_key}")
    k_file = CryptoUtils.decrypt_with_key(
        nonce=base64.b64decode(requested_file_pac.k_file_nonce),
        ciphertext=base64.b64decode(requested_file_pac.encrypted_file_key),
        key=shared_key
    )
    if not k_file:
        raise FileDownloadError('Failed to decrypt file key')
    file_response, error = server.download_file(file_uuid=requested_file_pac.file_uuid, private_key=private_key, user_uuid=user.uuid)
    if not file_response:
        raise FileDownloadError(f'Failed to download file: {error}')
    file_data = file_response.get('encrypted_blob')
    if not file_data:
        raise FileDownloadError('File data not found')
    file_data = base64.b64decode(file_data)
    file_nonce_b64 = file_response.get('file_nonce')
    file_nonce = base64.b64decode(file_nonce_b64)
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

def get_file_info_service(file_uuid, master_key, user):
    """Get file information by UUID."""
    kek = get_decrypted_kek(user, master_key)
    ik_priv_bytes = User.get_identity_private_key(self=user, kek=kek)
    ik_priv = ed25519.Ed25519PrivateKey.from_private_bytes(ik_priv_bytes)
    
    data, error = server.get_file_info(file_uuid=file_uuid, private_key=ik_priv, user_uuid=user.uuid)
    if error or not data:
        raise ValueError(f"Failed to get file info: {error}")
    file_info = FileInfo.from_dict(data)
    if not file_info:
        raise ValueError("File info not found or invalid format")
    return file_info
