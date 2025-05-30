import json
import datetime
from utils.crypto_utils import CryptoUtils
import base64

def encrypt_kek(kek: bytes, master_key: bytes, user_uuid: str) -> dict:
    """Encrypt the KEK with AAD user uuid and timestamp."""
    # user_uuid = user.uuid
    aad = format_aad(user_uuid)
    encrypted_kek, nonce = CryptoUtils.encrypt_with_key(kek, master_key, aad)
    
    return {
        "enc_kek":base64.encode( encrypted_kek).decode(),
        "kek_nonce":base64.encode(nonce).decode(),
        "aad": base64.encode(aad).decode(),
    }
    
def format_aad(user_uuid: str) -> str:
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat() 
    aad = json.dumps({"user_uuid": user_uuid, "timestamp": timestamp}, separators=(",",":")).encode()
    return aad

