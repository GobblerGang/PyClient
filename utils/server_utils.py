"""This module currently contains temporary functions for future server operations."""
import requests
from config import SERVER_URL, SERVER_PORT
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import base64

def get_server_nonce(user_uuid: str):
    server_url = f"{SERVER_URL}:{SERVER_PORT}/api/nonce"
    response = requests.get(server_url, params={"user_uuid": user_uuid})
    response.raise_for_status()
    return response.json()["nonce"]

def sign_payload(payload: bytes, nonce: str, private_key: Ed25519PrivateKey) -> str:
    message = payload + nonce.encode()
    signature = private_key.sign(message)
    return base64.b64encode(signature).decode()

def set_headers(private_key: Ed25519PrivateKey, user_id: int, payload: bytes):
    """
    Set headers for server requests, including signature, nonce and user ID.
    """
    nonce = get_server_nonce(str(user_id))
    if not nonce:
        raise ValueError("Failed to retrieve nonce from server.")
    signature = sign_payload(payload, nonce, private_key)
    return {
        "X-User-ID": str(user_id),
        "X-Nonce": nonce,
        "X-Signature": signature,
    }

def get_user_by_name(user_name: str):
    """
    NOTE: This function will be used to retrieve 
    a user by their ID from the server.
    EXPECTED JSON response structure:
    {
        "id": int,
        "username": str,
        "email": str,
        "identity_key_public": str,
        "signed_prekey_public": str,
        "signed_prekey_signature": str,
        "opks": dict (may not use these)
    }
    If the user is not found, it returns None.
    """
    return ""

def upload_file(file_ciphertext: bytes, file_name: str, file_uuid: str, owner_id: str, **args):
    """
    NOTE: This function will be used to upload a file to the server.
    Expected JSON body structure:
    {
        "file_uuid": str,  # UUID
        "file_name": str,
        "enc_file_ciphertext": base64 encoded,
        "owner_id": str,  # UUID
        "mime_type": str,
        "file_nonce": str,
        "enc_file_k": str,
        "k_file_nonce": str
    }
    """
    print(f"Uploading {file_name} for user {owner_id} (file UUID: {file_uuid})...")
    return True  # Simulate successful upload

def get_user_keys(user_uuid: str):
    """
    NOTE: This function will be used to retrieve a user's keys from the server.
    It currently does not implement actual key retrieval logic.
    Expected JSON response structure:
    {
        "identity_key_public": str,
        "signed_prekey_public": str,
        "signed_prekey_signature": str,
        "opks": dict (may not use these)
    }
    """
    from models.models import User
    user = User.query.filter_by(uuid=user_uuid).first()
    if user:
        return {
            "identity_key_public": user.identity_key_public,
            "signed_prekey_public": user.signed_prekey_public,
            "signed_prekey_signature": user.signed_prekey_signature,
            "opks": user.opks_json
        }
    return None  # User not found

def send_pac(pac):
    """
    Temporary placeholder for sending a PAC to the server.
    Accepts the PAC object as a parameter.
    Expected JSON body structure:
    {
        "recipient_id": int,
        "file_id": int,
        "valid_until": str,
        "encrypted_file_key": str,
        "signature": str,
        "issuer_id": int,
        "sender_ephemeral_public": str,
        "k_file_nonce": str,
        "filename": str,
        "mime_type": str
    }
    """
    print(f"PAC sent: {pac}")
    return True

# def get_pacs(recipient_uuid: str):
#     """
#     Retrieve all PACs (shared files) for a given recipient from the server.
#     Returns a list of PAC JSON objects, or an empty list if none found.
#     Expected JSON response structure:
#     [
#         {
#             "pac": {
#                 "recipient_id": int,
#                 "file_id": int,
#                 "valid_until": str,
#                 "encrypted_file_key": str,
#                 "signature": str,
#                 "issuer_id": int,
#                 "sender_ephemeral_public": str,
#                 "k_file_nonce": str,
#                 "filename": str,
#                 "mime_type": str
#             },
#         },
#         ...
#     ]
#     """
#     try:
#         server_url = f"{SERVER_URL}:{SERVER_PORT}/api/pacs"
#         params = {"recipient_uuid": recipient_uuid}
#         response = requests.get(server_url, params=params)
#         response.raise_for_status()
#         return response.json()
#     except Exception as e:
#         print(f"Error retrieving PACs: {e}")
#         return []

# def get_shared_file_info(file_ids):
#     """
#     Retrieve file info (name, type, owner name) for a list of file IDs from the server.
#     Returns a list of dicts with keys: file_id, name, type, owner_name.
#     """
#     try:
#         server_url = f"{SERVER_URL}:{SERVER_PORT}/api/file_info"
#         response = requests.post(server_url, json={"file_ids": file_ids})
#         response.raise_for_status()
#         return response.json()  # Expecting a list of file info dicts
#     except Exception as e:
#         print(f"Error retrieving file info: {e}")
#         return []

# def get_user_file_info(owner_uuid: str):
#     """
#     Retrieve file info for files owned by a specific user, and files shared with them.
#     Returns a dict with two arrays:
#       {
#         'owned_files': [FileInfo JSON dicts...],
#         'shared_files': [FileInfo JSON dicts...]
#       }
#     Each array contains dicts with keys: file_id, name, type, owner_id (or owner_name if needed).
#     """
#     try:
#         server_url = f"{SERVER_URL}:{SERVER_PORT}/api/owned_files"
#         params = {"owner_uuid": owner_uuid}
#         response = requests.get(server_url, params=params)
#         response.raise_for_status()
#         # Expecting a dict: { 'owned_files': [...], 'shared_files': [...] }
#         return response.json()
#     except Exception as e:
#         print(f"Error retrieving owned/shared file info: {e}")
#         return {"owned_files": [], "shared_files": []}
    
def download_file(file_uuid: str):
    """
    Retrieve an encrypted file by its UUID from the server.
    Expected JSON response structure:
    {
        "file_uuid": str,  # UUID
        "ciphertext": base64 encoded bytes,
        "filename": str,
        "file_nonce": str,
        "mime_type": str,
    }
    """
    try:
        server_url = f"{SERVER_URL}:{SERVER_PORT}/api/files/{file_uuid}"
        response = requests.get(server_url)
        response.raise_for_status()
        return response.json()  # Expecting JSON, not raw content
    except Exception as e:
        print(f"Error retrieving file {file_uuid}: {e}")
        return None
    
def create_user(user_data):
    """
    Create a new user on the server.
    Accepts a User object and returns True if successful, False otherwise.
    Expected JSON body structure:
    {
        "username": str,
        "email": str,
        "identity_key_public": str,
        "signed_prekey_public": str,
        "signed_prekey_signature": str,
        "salt": str,  # Base64 encoded salt
        "opks": dict (may not use these)
    }
    Expected response:
    {
        "uuid": str,
        "success": bool,
        "error": str (if any)
    }
    """
    try:
        server_url = f"{SERVER_URL}:{SERVER_PORT}/api/users"
        response = requests.post(server_url, json=user_data)
        response.raise_for_status()
        return response.json()  # User created successfully
    except Exception as e:
        return {"success": False, "error": str(e)}

def get_owned_files(user_id: str, private_key: Ed25519PrivateKey):
    """
    Retrieve all files owned by the user using the X-User-ID header.
    Returns a list of FileInfo JSON dicts.
    """
    try:
        server_url = f"{SERVER_URL}:{SERVER_PORT}/api/files/owned"
        headers = set_headers(private_key, user_id, b"")
        response = requests.get(server_url, headers=headers)
        response.raise_for_status()
        return response.json().get('owned_files', [])
    except Exception as e:
        print(f"Error retrieving owned files: {e}")
        return []

def get_user_pacs(user_id: str, private_key: Ed25519PrivateKey):
    """
    Retrieve all PACs for the user (received and issued) using the X-User-ID header.
    Returns a dict: { 'received_pacs': [...], 'issued_pacs': [...] }
    """
    try:
        server_url = f"{SERVER_URL}:{SERVER_PORT}/api/files/pacs/"
        headers = set_headers(private_key, user_id, b"")
        response = requests.get(server_url, headers=headers)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error retrieving PACs: {e}")
        return {"received_pacs": [], "issued_pacs": []}