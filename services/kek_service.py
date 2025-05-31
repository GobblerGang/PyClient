import json
import datetime
from utils.crypto_utils import CryptoUtils
import base64

def encrypt_kek(kek: bytes, master_key: bytes, user_uuid: str) -> dict:
    """Encrypt the KEK with AAD user uuid and timestamp."""
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    aad = format_aad(user_uuid, timestamp)
    nonce, encrypted_kek = CryptoUtils.encrypt_with_key(kek, master_key, aad)
    # print("encrypted_kek type:", type(encrypted_kek))
    # print("encrypted_kek repr:", repr(encrypted_kek))
    # print("encrypted_kek len:", len(encrypted_kek))
    # print(base64.b64encode(encrypted_kek).decode())
    return {
        "enc_kek": base64.b64encode(encrypted_kek).decode(),
        "kek_nonce": base64.b64encode(nonce).decode(),
        "aad": base64.b64encode(aad).decode(),
    }

def format_aad(user_uuid: str, timestamp) -> bytes:
    aad = json.dumps({"user_uuid": user_uuid, "timestamp": timestamp}, separators=(",", ":")).encode()
    return aad
