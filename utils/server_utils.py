import requests
from config import SERVER_URL
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import base64
import json

from utils.dataclasses import PAC


api_url = f"{SERVER_URL}/api"

#---Helper functions for server communication---
def parse_server_response(response):
    try:
        data = response.json()
        print(f"Server response code: {response.status_code}")
    except Exception:
        data = {}
    # Only return error if 'error' is present in the response data
    if 'error' in data:
        return None, data['error']
    return data, None

# def send_request()

def get_server_nonce(user_uuid: str):
    server_url = f"{SERVER_URL}/api/nonce/{user_uuid}"
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
        server_url = f"{SERVER_URL}/api/register"
        # print(f"Creating user at {server_url} with data: {user_data}")
        print(f"{json.dumps(user_data, indent=2)}")
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
    url = f"{SERVER_URL}/api/generate-uuid"
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
        # except Exception as e:
        # return None, str(e)

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
        "ed25519_identity_key_public": str,
        "x25519_identity_key_public": str,
        "signed_prekey_public": str,
        "signed_prekey_signature": str,
        "opks": dict (may not use these)
    }
    Returns a tuple: (data, error), where `data` is the user information if found,
    and `error` is an error message if the user is not found or an exception occurs.
    """
    url = f"{api_url}/users/{username}"
    response = requests.get(url)
    data, error = parse_server_response(response)
    if error:
        return None, error
    return data, None

def upload_file(file_ciphertext: bytes, file_name: str, owner_uuid: str, mime_type: str, file_nonce: str, enc_file_k: bytes, k_file_nonce: str, private_key: bytes):
    """
    NOTE: This function will be used to upload a file to the server.
    Expected JSON body structure:
    {
        "file_name": str,
        "enc_file_ciphertext": base64 encoded,
        "mime_type": str,
        "file_nonce": str,
        "enc_file_k": str,
        "k_file_nonce": str
    }
    """
    payload = {
        "file_name": file_name,
        "enc_file_ciphertext": base64.b64encode(file_ciphertext).decode(),
        "mime_type": mime_type,
        "file_nonce": base64.b64encode(file_nonce).decode(),
        "enc_file_k": base64.b64encode(enc_file_k).decode(),
        "k_file_nonce": base64.b64encode(k_file_nonce).decode()
    }
    headers = set_headers(private_key=private_key, user_uuid=owner_uuid, payload=payload)
    url = f"{SERVER_URL}/api/files/upload"
    response = requests.post(url, json=payload, headers=headers)
    data, error = parse_server_response(response)
    return data, error

def get_user_keys(sender_user_uuid: str, recipient_uuid, private_key: Ed25519PrivateKey):
    """
    NOTE: This function will be used to retrieve a user's keys from the server.
    Expected JSON response structure:
    {
        "ed25519_identity_key_public": str,
        "x25519_identity_key_public": str,
        "signed_prekey_public": str,
        "signed_prekey_signature": str,
        "opks": dict (may not use these)
    }
    """
    server_url = f"{SERVER_URL}/api/users/keys/{recipient_uuid}"
    headers = set_headers(private_key=private_key, user_uuid=sender_user_uuid, payload=b"")
    response = requests.get(server_url, headers=headers)
    data, error = parse_server_response(response)
    return data, error

def send_pac(pac: PAC, sender_uuid: str, private_key: Ed25519PrivateKey):
    """
    Temporary placeholder for sending a PAC to the server.
    Accepts the PAC object as a parameter.
    Expected JSON body structure:
    {
        "recipient_uuid": int,
        "file_uuid": int,
        "valid_until": str,
        "encrypted_file_key": str,
        "signature": str,
        "sender_ephemeral_public": str,
        "k_file_nonce": str,
    }
    """
    payload = {
        "recipient_uuid": pac.recipient_id,
        "file_uuid": pac.file_uuid,
        "valid_until": pac.valid_until,
        "encrypted_file_key": pac.encrypted_file_key,
        "signature": pac.signature,
        "sender_ephemeral_public": pac.sender_ephemeral_public,
        "k_file_nonce": pac.k_file_nonce,
    }
    headers= set_headers(private_key=private_key, user_uuid=sender_uuid, payload=payload)
    server_url = f"{SERVER_URL}/api/files/share"
    response = requests.post(server_url, json=payload, headers=headers)
    data, error = parse_server_response(response)
    return data, error

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
        server_url = f"{SERVER_URL}/api/files/{file_uuid}"
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
    server_url = f"{SERVER_URL}/api/files/owned"
    headers = set_headers(private_key, user_id, b"")
    # response = requests.get(server_url, headers=headers)
    # response.raise_for_status()
    # return response.json().get('owned_files', [])
    response = requests.get(server_url, headers=headers)
    data, error = parse_server_response(response)
    return data, error

def get_user_pacs(user_id: str, private_key: Ed25519PrivateKey):
    """
    Retrieve all PACs for the user (received and issued) using the X-User-ID header.
    Returns a dict: { 'received_pacs': [...], 'issued_pacs': [...] }
    """
    try:
        server_url = f"{SERVER_URL}/api/files/pacs"
        headers = set_headers(private_key, user_id, b"")
        response = requests.get(server_url, headers=headers)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error retrieving PACs: {e}")
        return {"received_pacs": [], "issued_pacs": []}

def get_file_info(file_uuid: str, user_uuid: str, private_key: Ed25519PrivateKey):
    """
    Retrieve file information by UUID.
    Returns a dict with file information or None if not found.
    """
    server_url = f"{SERVER_URL}/api/files/info/{file_uuid}"
    headers = set_headers(private_key, user_uuid, b"")
    response = requests.get(server_url, headers=headers)
    data, error = parse_server_response(response)
    return data, error
