import json
import datetime
from models.models import KEK, User
from utils.crypto_utils import CryptoUtils
import base64

def encrypt_kek(kek: bytes, master_key: bytes, user_uuid: str) -> dict:
    """Encrypt the KEK with AAD user uuid and timestamp."""
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(f"Encrypting KEK for user {user_uuid} at {timestamp}")
    aad = format_aad(user_uuid, timestamp)
    nonce, encrypted_kek = CryptoUtils.encrypt_with_key(kek, master_key, aad)
    return {
        "enc_kek": base64.b64encode(encrypted_kek).decode(),
        "kek_nonce": base64.b64encode(nonce).decode(),
        "aad": base64.b64encode(aad).decode(),
    }

def format_aad(user_uuid: str, timestamp) -> bytes:
    aad = json.dumps({"user_uuid": user_uuid, "timestamp": timestamp}, separators=(",", ":")).encode()
    # aad = format_aad(user_uuid, timestamp)
    print("AAD (string):", aad.decode())
    print("AAD (hex): 0x" + aad.hex().upper())
    return aad

def get_decrypted_kek(user: User, master_key: bytes) -> bytes:
    kek_obj = KEK.query.filter_by(user_id=user.id).first()
    kek_info = {
        "enc_kek_cyphertext": kek_obj.enc_kek,
        "nonce": kek_obj.kek_nonce,
        "updated_at": kek_obj.updated_at,
    }
    kek, _ =  try_decrypt_kek(kek_info=kek_info, master_key=master_key, user_uuid=user.uuid)
    if not kek:
        raise Exception("Failed to decrypt KEK for file upload")
    return kek

def try_decrypt_kek(kek_info, user_uuid, master_key):
    """
    Attempts to decrypt the KEK using the provided master key.
    Returns the decrypted KEK or raises an exception if decryption fails.
    """
    enc_kek = base64.b64decode(kek_info['enc_kek_cyphertext'])
    kek_nonce = base64.b64decode(kek_info['nonce'])
    updated_at = kek_info.get('updated_at')
    # user_uuid = kek_info.get('user_uuid')
    aad = format_aad(user_uuid=user_uuid, timestamp=updated_at)
    kek =CryptoUtils.decrypt_with_key(nonce=kek_nonce, ciphertext=enc_kek, key=master_key, associated_data=aad)
    return kek, aad
