import requests
from config import SERVER_URL, SERVER_PORT
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import base64
import json


api_url = f"{SERVER_URL}:{SERVER_PORT}/api"

#---Helper functions for server communication---
def parse_server_response(response):
    try:
        data = response.json()
        print(f"Server response code: {response.status_code}")
    except Exception:
        data = {}
    if response.status_code != 200:
        error_msg = data.get('error', f'HTTP {response.status_code}')
        return None, error_msg
    if 'error' in data:
        return None, data['error']
    return data, None

# def send_request()

def get_server_nonce(user_uuid: str):
    server_url = f"{SERVER_URL}:{SERVER_PORT}/api/nonce/{user_uuid}"
    response = requests.get(server_url)
    response.raise_for_status()
    return response.json()["nonce"]

def sign_payload(payload: bytes, nonce: str, private_key: Ed25519PrivateKey) -> str:
    message = payload + nonce.encode()
    signature = private_key.sign(message)
    return base64.b64encode(signature).decode()

def set_headers(private_key: Ed25519PrivateKey, user_uuid: str, payload):
    """
    Set headers for server requests, including signature, nonce and user ID.
    Accepts payload as dict or bytes. If dict, will encode as JSON bytes.
    """
    if isinstance(payload, dict):
        payload_bytes = json.dumps(payload).encode()
    elif isinstance(payload, bytes):
        payload_bytes = payload
    else:
        raise TypeError("Payload must be dict or bytes")
    nonce = get_server_nonce(user_uuid)
    if not nonce:
        raise ValueError("Failed to retrieve nonce from server.")
    signature = sign_payload(payload_bytes, nonce, private_key)
    return {
        "X-User-UUID": user_uuid,
        "X-Nonce": nonce,
        "X-Signature": signature,
    }

def create_user(user_data):
    """
    Create a new user on the server.
    Accepts a user_data dict and returns a dict with keys: success, uuid, error (if any).
    """
    try:
        server_url = f"{SERVER_URL}:{SERVER_PORT}/api/register"
        # print(f"Creating user at {server_url} with data: {user_data}")
        response = requests.post(server_url, json=user_data)
        # Try to parse JSON even on error status
        try:
            resp_json = response.json()
        except Exception:
            resp_json = {}
        if response.status_code == 201:
            return {
                "success": True,
                "uuid": resp_json.get("user_uuid"),
                "error": None
            }
        else:
            # Return error message from server if present
            return {
                "success": False,
                "uuid": None,
                "error": resp_json.get("error", f"HTTP {response.status_code}")
            }
    except Exception as e:
        print(f"Error creating user: {e}")
        return {"success": False, "error": str(e), "uuid": None}

def get_new_user_uuid():
    """
    Get a new UUID for a user from the server.
    Returns a string UUID or None if an error occurs.
    """
    url = f"{SERVER_URL}:{SERVER_PORT}/api/generate-uuid"
    try:
        response = requests.get(url)
        print(f"Server response code: {response.status_code}")
        # print(f"Response from server: {response.status_code}, {response.text}")
        if response.status_code != 200:
            try:
                error_msg = response.json().get('error', 'Unknown error')
            except Exception:
                error_msg = 'Unknown error'
            return None, error_msg
        data = response.json().get('uuid')
        if 'error' in data:
            return None, data['error']
        return data, None
    except Exception as e:
        return None, str(e)

def get_kek_info(user_uuid: str):
    url = f"{api_url}/kek/{user_uuid}"
    response = requests.get(url)
    data, error = parse_server_response(response)
    if error:
        return None, error
    return data, None

def update_kek_info(encrypted_kek: str, kek_nonce: str, updated_at:str, user_uuid: str, ik_priv: Ed25519PrivateKey):
    """
    Update the KEK information for a user.
    Takes ik_priv as param for header signature.
    Takes user_uuid from header
    Accepts a dict with KEK information.
    Returns a tuple: (success, error).
    """
    url = f"{api_url}/change-password"
    payload_dict= {
        "enc_kek_cyphertext": encrypted_kek,
        "nonce": kek_nonce,
        "updated_at": updated_at,
    }
    headers = set_headers(private_key=ik_priv, user_uuid=user_uuid, payload=payload_dict)
    response = requests.put(url, json=payload_dict, headers=headers)
    data, error = parse_server_response(response)
    if error:
        return False, error
    return data, None

def get_user_by_name(username: str):
    """
    NOTE: This function retrieves a user by their username from the server.
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
    Returns a tuple: (data, error), where `data` is the user information if found,
    and `error` is an error message if the user is not found or an exception occurs.
    """
    url = f"{url}/users/{username}"
    response = requests.get(url)
    data, error = parse_server_response(response)
    if error:
        return None, error
    return data, None

    

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

