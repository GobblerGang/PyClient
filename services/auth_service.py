import base64
import json
from flask import flash
from models.models import User, KEK
from extensions.extensions import db
from utils.key_utils import (
    try_decrypt_private_keys, verify_decrypted_keys, get_user_vault, decrypt_all_opks, keypairs_from_opk_bytes, generate_user_vault
)
from utils.secure_master_key import MasterKey
import utils.server_utils as server
from utils.dataclasses import Vault
from utils.crypto_utils import CryptoUtils
from cryptography.exceptions import InvalidTag
from services.kek_service import format_aad, encrypt_kek
from cryptography.hazmat.primitives.asymmetric import ed25519
from services.kek_service import try_decrypt_kek
import os

def create_user_service(username, email, vault: Vault, user_uuid, kek_dict: dict):
    kek_timestamp = json.loads(base64.b64decode(kek_dict['aad']).decode())['timestamp']
    user_data = {
        "user": {
            "uuid": user_uuid,
            "username": username,
            "email": email,
            "salt": vault.salt
        },
        "keys": {
            "ed25519_identity_key_public": vault.ed25519_identity_key_public,
            "x25519_identity_key_public": vault.x25519_identity_key_public,
            "signed_prekey_public": vault.signed_prekey_public,
            "signed_prekey_signature": vault.signed_prekey_signature,
            "opks": vault.opks  
        },
        "kek": {
            "enc_kek_cyphertext": kek_dict['enc_kek'],
            "nonce": kek_dict['kek_nonce'],
            "updated_at": kek_timestamp
        }
    }
    response = server.create_user(user_data)
    if not response or not isinstance(response, dict):
        return None, 'No response from server. Please try again later.'
    if not response.get("success"):
        error_msg = f"Server error: {response.get('error', 'Unknown error')}"
        return None, error_msg
    user = User(
        username=username,
        email=email,
        ed25519_identity_key_public=vault.ed25519_identity_key_public,
        ed25519_identity_key_private_enc=vault.ed25519_identity_key_private_enc,
        ed25519_identity_key_private_nonce=vault.ed25519_identity_key_private_nonce,
        x25519_identity_key_public=vault.x25519_identity_key_public,
        x25519_identity_key_private_enc=vault.x25519_identity_key_private_enc,
        x25519_identity_key_private_nonce=vault.x25519_identity_key_private_nonce,
        signed_prekey_public=vault.signed_prekey_public,
        signed_prekey_signature=vault.signed_prekey_signature,
        signed_prekey_private_enc=vault.signed_prekey_private_enc,
        signed_prekey_private_nonce=vault.signed_prekey_private_nonce,
        opks_json=json.dumps(vault.opks),
        salt=vault.salt,
        uuid=user_uuid
    )
    db.session.add(user)
    db.session.commit()
    kek = KEK(
        enc_kek=kek_dict['enc_kek'],
        kek_nonce=kek_dict['kek_nonce'],
        user_id=user.id,
        updated_at=kek_timestamp
    )
    db.session.add(kek)
    db.session.commit()
    return user, None

def import_user_keys_service(username, password, keyfile):
    if User.query.filter_by(username=username).first():
        return None, 'User already exists. Please log in.'
    try:
        keys = json.load(keyfile)
    except Exception:
        return None, 'Invalid key file format.'
    server_user, error = server.get_user_by_name(username)
    if error:
        return None, f'Error fetching user data: {error}'
    salt = base64.b64decode(server_user['salt']) if isinstance(server_user['salt'], str) else server_user['salt']
    master_key = derive_master_key(password, salt)
    kek_info, error = server.get_kek_info(server_user['uuid'])
    if error or not kek_info:
        return None, 'Failed to communicate with the server.'
    kek, _ = try_decrypt_kek(kek_info=kek_info, user_uuid=server_user['uuid'], master_key=master_key)
    vault = Vault(
        ed25519_identity_key_public=keys['ed25519_identity_key_public'],
        ed25519_identity_key_private_enc=keys['ed25519_identity_key_private_enc'],
        ed25519_identity_key_private_nonce=keys['ed25519_identity_key_private_nonce'],
        x25519_identity_key_public=keys['x25519_identity_key_public'],
        x25519_identity_key_private_enc=keys['x25519_identity_key_private_enc'],
        x25519_identity_key_private_nonce=keys['x25519_identity_key_private_nonce'],
        signed_prekey_public=keys['signed_prekey_public'],
        signed_prekey_signature=keys['signed_prekey_signature'],
        signed_prekey_private_enc=keys['signed_prekey_private_enc'],
        signed_prekey_private_nonce=keys['signed_prekey_private_nonce'],
        salt=server_user['salt'],
        opks=keys['opks']
    )
    try:
        ed_identity_private_bytes, x_identity_private_bytes, spk_private_bytes = try_decrypt_private_keys(vault, kek)
        if not verify_decrypted_keys(ed_identity_private_bytes, x_identity_private_bytes, spk_private_bytes, vault):
            return None, 'Key verification failed. Wrong password or corrupted file.'
    except Exception:
        return None, 'Failed to decrypt or verify keys. Wrong password or corrupted file.'
    user = User(
        username=username,
        email=server_user.get('email', ''),
        ed25519_identity_key_public=keys['ed25519_identity_key_public'],
        ed25519_identity_key_private_enc=keys['ed25519_identity_key_private_enc'],
        ed25519_identity_key_private_nonce=keys['ed25519_identity_key_private_nonce'],
        x25519_identity_key_public=keys['x25519_identity_key_public'],
        x25519_identity_key_private_enc=keys['x25519_identity_key_private_enc'],
        x25519_identity_key_private_nonce=keys['x25519_identity_key_private_nonce'],
        signed_prekey_public=keys['signed_prekey_public'],
        signed_prekey_signature=keys['signed_prekey_signature'],
        signed_prekey_private_enc=keys['signed_prekey_private_enc'],
        signed_prekey_private_nonce=keys['signed_prekey_private_nonce'],
        opks_json=json.dumps(keys['opks']),
        salt=server_user['salt'],
        uuid=server_user.get('uuid')
    )
    db.session.add(user)
    db.session.commit()
    kek = KEK(
        enc_kek=kek_info['enc_kek_cyphertext'],
        kek_nonce=kek_info['nonce'],
        user_id=user.id,
        updated_at=kek_info['updated_at']
    )
    db.session.add(kek)
    db.session.commit()
    return user, None

def login_user_service(username: str, password: str):
    """
    Handles user login logic: user lookup, password check, KEK decryption, and error handling.
    Returns (user, error_message) where user is the User object if successful, else None.
    """
    user = User.query.filter_by(username=username).first()
    if not user:
        server_user, _ = server.get_user_by_name(username)
        if server_user:
            return None, 'User found on server, but not in local database. Please import your key bundle.'
        return None, 'User not found'
    if not password:
        return None, 'Password is required'
    vault = get_user_vault(user)
    salt = base64.b64decode(vault.salt)
    master_key = derive_master_key(password, salt)
    kek_info, error = server.get_kek_info(user.uuid)
    server_updated_at = kek_info.get('updated_at') if kek_info else None
    if error or not kek_info:
        MasterKey().clear()
        return None, 'Failed to communicate with the server.'
    # Check KEK freshness before proceeding
    is_fresh, freshness_error = check_kek_freshness(user)
    if not is_fresh:
        kek, kek_error = decrypt_kek_with_error_handling(kek_info, user.uuid, password, salt)
        if kek_error:
            # Do NOT update local KEK, notify user of possible tampering
            return None, freshness_error
        # If decryption succeeds, update local KEK and allow login
        if hasattr(user, 'kek') and user.kek and server_updated_at and user.kek.updated_at != server_updated_at:
            user.kek.enc_kek = kek_info.get('enc_kek_cyphertext')
            user.kek.kek_nonce = kek_info.get('nonce')
            user.kek.updated_at = server_updated_at
            db.session.commit()
        return user, None
    kek, kek_error = decrypt_kek_with_error_handling(kek_info, user.uuid, password, salt)
    if kek_error:
        MasterKey().clear()
        return None, 'Failed to log in. Wrong password or tampered KEK data.'
    
    return user, None



def change_password_service(user, old_password, new_password):
    """
    Handles the business logic for changing a user's password, including KEK-based authentication
    and KEK re-encryption. Returns (success, error_message).
    The vault is encrypted with the KEK and does not need to be re-encrypted or changed.
    """
    vault = get_user_vault(user)
    salt = base64.b64decode(vault.salt)
    kek_info, _ = server.get_kek_info(user.uuid)
    # Decrypt KEK with old password (via master key)
    kek, kek_error = decrypt_kek_with_error_handling(kek_info, user.uuid, old_password, salt)
    if kek_error:
        return False, kek_error
    # Check KEK freshness before proceeding
    is_fresh, freshness_error = check_kek_freshness(user)
    if not is_fresh:
        return False, freshness_error
    # Derive new master key and re-encrypt KEK
    new_salt = os.urandom(16)
    new_master_key = derive_master_key(new_password, new_salt)
    kek_dict = encrypt_kek(
        kek,
        new_master_key,
        user_uuid=user.uuid
    )
    # Update only KEK and salt fields; vault remains unchanged
    new_timestamp = json.loads(base64.b64decode(kek_dict['aad']).decode())['timestamp']
    user.salt = base64.b64encode(new_salt).decode()
    user.enc_kek = kek_dict['enc_kek']
    user.kek_nonce = kek_dict['kek_nonce']
    user.kek_aad = kek_dict['aad']
    user.kek_updated_at = new_timestamp
    
    # Decrypt IK priv for header signing
    ik_priv_bytes = User.get_identity_private_key(self=user, kek=kek)
    ik_priv = ed25519.Ed25519PrivateKey.from_private_bytes(ik_priv_bytes)
    
    new_kek_info, error = server.update_kek_info(kek_nonce=kek_dict['kek_nonce'], 
                           encrypted_kek=kek_dict['enc_kek'], 
                           updated_at=new_timestamp, 
                           user_uuid=user.uuid,
                           ik_priv=ik_priv)
    if error:
        return False, error
    print(f"KEK updated successfully for user {user.username} with new timestamp {new_timestamp}")
    print(f"New KEK: {new_kek_info}")
    db.session.commit()
    MasterKey().clear()
    return True, None

def derive_master_key(password, salt):
    """Derive a master key from password and salt, and set it in MasterKey singleton."""
    master_key = MasterKey().derive_key(password, salt)
    MasterKey().set_key(master_key)
    return master_key

def decrypt_kek_with_error_handling(kek_info, user_uuid, password, salt):
    """Try to decrypt KEK with error handling, returning (kek, error_message)."""
    try:
        # Derive the master key from password and salt
        master_key = derive_master_key(password, salt)
        kek, _ = try_decrypt_kek(
            kek_info,
            user_uuid=user_uuid,
            master_key=master_key
        )
    except Exception as e:
        # MasterKey().clear()
        return None, 'Failed to decrypt KEK with provided password.'
    return kek, None

# def decrypt_vault_with_error_handling(vault, master_key, user):
#     """Try to decrypt vault private keys and OPKs, returning (identity_private_bytes, spk_private_bytes, decrypted_opks, error_message)."""
#     try:
#         identity_private_bytes, spk_private_bytes = try_decrypt_private_keys(vault, master_key)
#         decrypted_opks = decrypt_all_opks(user.opks_json, master_key)
#         return identity_private_bytes, spk_private_bytes, decrypted_opks, None
#     except Exception:
#         MasterKey().clear()
#         return None, None, None, 'Failed to decrypt vault with provided password.'

def check_kek_freshness(user):
    """
    Fetch the latest KEK info from the server and compare updated_at with the local user's KEK.
    Returns (True, None) if up-to-date, (False, error_message) if not.
    """
    server_kek_info, server_error = server.get_kek_info(user.uuid)
    if server_error or not server_kek_info:
        return False, 'Failed to communicate with the server to verify KEK freshness.'
    server_updated_at = server_kek_info.get('updated_at')
    local_updated_at = user.kek.updated_at
    print(f"Local updated_at: {local_updated_at}, Server updated_at: {server_updated_at}")
    if server_updated_at and local_updated_at != server_updated_at:
        return False, f"Your password was changed on another device. Please use the new password. Server updated at: {server_updated_at}"
    return True, None

