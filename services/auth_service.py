import base64
import json
from flask import flash
from models.models import User
from extensions.extensions import db
from utils.key_utils import (
    try_decrypt_private_keys, verify_decrypted_keys, get_user_vault
)
from utils.secure_master_key import MasterKey
import utils.server_utils as server

def create_user_service(username, email, vault):
    #TODO we are sending opks with public and private keys, this is an issue that needs fixed (tbh get rid of opks)
    user_data = {
        "username": username,
        "email": email,
        "identity_key_public": vault["identity_key_public"],
        "signed_prekey_public": vault["signed_prekey_public"],
        "signed_prekey_signature": vault["signed_prekey_signature"],
        "salt": vault["salt"],
        "opks_json": json.dumps(vault["opks"])
    }
    response = server.create_user(user_data)
    if not response or not isinstance(response, dict):
        return None, 'No response from server. Please try again later.'
    if response.get("success"):
        uuid = response.get("uuid")
    else:
        error_msg = response.get("error", "Unknown error")
        return None, error_msg
    if not uuid:
        return None, 'User creation failed. Please try again.'
    user = User(
        username=username,
        email=email,
        identity_key_public=vault["identity_key_public"],
        signed_prekey_public=vault["signed_prekey_public"],
        signed_prekey_signature=vault["signed_prekey_signature"],
        salt=vault["salt"],
        identity_key_private_enc=vault["identity_key_private_enc"],
        identity_key_private_nonce=vault["identity_key_private_nonce"],
        signed_prekey_private_enc=vault["signed_prekey_private_enc"],
        signed_prekey_private_nonce=vault["signed_prekey_private_nonce"],
        opks_json=json.dumps(vault["opks"]),
        uuid=uuid
    )
    db.session.add(user)
    db.session.commit()
    return user, None

def import_user_keys_service(username, password, keyfile):
    try:
        keys = json.load(keyfile)
    except Exception:
        return None, 'Invalid key file format.'
    server_user, error = server.get_user_by_name(username)
    
    if error:
        return None, f'Error fetching user data: {error}'
    salt = base64.b64decode(server_user['salt']) if isinstance(server_user['salt'], str) else server_user['salt']
    master_key = MasterKey().derive_key(password, salt)
    vault = {
        'identity_key_public': keys['identity_key_public'],
        'signed_prekey_public': keys['signed_prekey_public'],
        'signed_prekey_signature': keys['signed_prekey_signature'],
        'salt': server_user['salt'],
        'identity_key_private_enc': keys['identity_key_private_enc'],
        'identity_key_private_nonce': keys['identity_key_private_nonce'],
        'signed_prekey_private_enc': keys['signed_prekey_private_enc'],
        'signed_prekey_private_nonce': keys['signed_prekey_private_nonce'],
        'opks': keys['opks']
    }
    try:
        identity_private_bytes, spk_private_bytes = try_decrypt_private_keys(vault, master_key)
        if not verify_decrypted_keys(identity_private_bytes, spk_private_bytes, vault):
            return None, 'Key verification failed. Wrong password or corrupted file.'
    except Exception:
        return None, 'Failed to decrypt or verify keys. Wrong password or corrupted file.'
    user = User(
        username=username,
        email=server_user.get('email', ''),
        identity_key_public=keys['identity_key_public'],
        signed_prekey_public=keys['signed_prekey_public'],
        signed_prekey_signature=keys['signed_prekey_signature'],
        salt=server_user['salt'],
        identity_key_private_enc=keys['identity_key_private_enc'],
        identity_key_private_nonce=keys['identity_key_private_nonce'],
        signed_prekey_private_enc=keys['signed_prekey_private_enc'],
        signed_prekey_private_nonce=keys['signed_prekey_private_nonce'],
        opks_json=json.dumps(keys['opks']),
        uuid=server_user.get('uuid')
    )
    db.session.add(user)
    db.session.commit()
    return user, None
