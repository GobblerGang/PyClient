"""This module currently contains temporary functions for future server operations."""
import requests
from config import SERVER_URL, SERVER_PORT

def get_user_by_name(user_name: str):
    """
    NOTE: This function will be used to retrieve 
    a user by their ID from the server.
    """
    from models import User
    return User.query.filter_by(username=user_name).first() or None

def upload_file(file_ciphertext: bytes, file_name: str, owner_id: int, **args):
    """
    NOTE: This function will be used to upload a file to the server.
    It currently does not implement actual file upload logic.
    """
    # Placeholder for file upload logic
    print(f"Uploading {file_name} for user {owner_id}...")
    return True  # Simulate successful upload

def get_user_keys(user_id: int):
    """
    NOTE: This function will be used to retrieve a user's keys from the server.
    It currently does not implement actual key retrieval logic.
    """
    from models import User
    user = User.query.get(user_id)
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
    """
    print(f"PAC sent: {pac}")
    return True

def get_pacs(recipient_id: int):
    """
    Retrieve all PACs (shared files) for a given recipient from the server.
    Returns a list of PAC JSON objects, or an empty list if none found.
    Expected JSON response structure:
    [
        {
            "pac": {
                "recipient_id": int,
                "file_id": int,
                "valid_until": str,
                "encrypted_file_key": str,
                "signature": str,
                "issuer_id": int,
                "sender_ephemeral_public": str,
                "nonce": str,
            },
        },
        ...
    ]
    """
    try:
        server_url = f"{SERVER_URL}:{SERVER_PORT}/api/pacs"
        params = {"recipient_id": recipient_id}
        response = requests.get(server_url, params=params)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error retrieving PACs: {e}")
        return []

def get_shared_file_info(file_ids):
    """
    Retrieve file info (name, type, owner name) for a list of file IDs from the server.
    Returns a list of dicts with keys: file_id, name, type, owner_name.
    """
    try:
        server_url = f"{SERVER_URL}:{SERVER_PORT}/api/file_info"
        response = requests.post(server_url, json={"file_ids": file_ids})
        response.raise_for_status()
        return response.json()  # Expecting a list of file info dicts
    except Exception as e:
        print(f"Error retrieving file info: {e}")
        return []

def get_owned_file_info(owner_id: int):
    """
    Retrieve file info for files owned by a specific user.
    Returns a list of dicts with keys: file_id, name, type, owner_name.
    """
    try:
        server_url = f"{SERVER_URL}:{SERVER_PORT}/api/owned_files"
        params = {"owner_id": owner_id}
        response = requests.get(server_url, params=params)
        response.raise_for_status()
        return response.json()  # Expecting a list of owned file info dicts
    except Exception as e:
        print(f"Error retrieving owned file info: {e}")
        return []
    
def download_file(file_id: int):
    """
    Retrieve an encrypted file by its ID from the server.
    Expected JSON response structure:
    {
        "file_id": int,
        "ciphertext": base64 encoded bytes,
        "filename": str,
        "nonce": str
        "mime_type": str,
    }
    """
    try:
        server_url = f"{SERVER_URL}:{SERVER_PORT}/api/files/{file_id}"
        response = requests.get(server_url)
        response.raise_for_status()
        return response.content 
    except Exception as e:
        print(f"Error retrieving file {file_id}: {e}")
        return None