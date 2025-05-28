"""This module currently contains temporary functions for future server operations."""

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