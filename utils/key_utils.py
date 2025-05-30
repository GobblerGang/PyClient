import base64
import json
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization
from utils.crypto_utils import CryptoUtils
from utils.secure_master_key import MasterKey

def b64e(b):
    return base64.b64encode(b).decode()

def get_user_vault(user):
    return {
        "salt": user.salt,
        "identity_key_public": user.identity_key_public,
        "signed_prekey_public": user.signed_prekey_public,
        "signed_prekey_signature": user.signed_prekey_signature,
        "identity_key_private_enc": user.identity_key_private_enc,
        "identity_key_private_nonce": user.identity_key_private_nonce,
        "signed_prekey_private_enc": user.signed_prekey_private_enc,
        "signed_prekey_private_nonce": user.signed_prekey_private_nonce,
        "opks": user.opks_json if user.opks_json else "[]"
    }


def try_decrypt_private_keys(vault: dict, master_key: bytes):
    ik_enc = base64.b64decode(vault["identity_key_private_enc"])
    ik_nonce = base64.b64decode(vault["identity_key_private_nonce"])
    spk_enc = base64.b64decode(vault["signed_prekey_private_enc"])
    spk_nonce = base64.b64decode(vault["signed_prekey_private_nonce"])
    identity_private_bytes = CryptoUtils.decrypt_with_key(ik_nonce, ik_enc, master_key, b'identity_key')
    spk_private_bytes = CryptoUtils.decrypt_with_key(spk_nonce, spk_enc, master_key, b'signed_prekey')
    return identity_private_bytes, spk_private_bytes

def verify_decrypted_keys(identity_private_bytes, spk_private_bytes, vault):
    identity_private = ed25519.Ed25519PrivateKey.from_private_bytes(identity_private_bytes)
    spk_private = x25519.X25519PrivateKey.from_private_bytes(spk_private_bytes)
    identity_public = identity_private.public_key()
    spk_public = spk_private.public_key()
    identity_public_b64 = base64.b64encode(identity_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )).decode()
    spk_public_b64 = base64.b64encode(spk_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )).decode()
    return (
        identity_public_b64 == vault["identity_key_public"] and
        spk_public_b64 == vault["signed_prekey_public"]
    )

def generate_user_vault(identity_private, identity_public, spk_private, spk_public, spk_signature, salt, master_key, opks):
    ik_nonce, ik_enc = CryptoUtils.encrypt_with_key(
        identity_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        master_key,
        b'identity_key')
    spk_nonce, spk_enc = CryptoUtils.encrypt_with_key(
        spk_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        master_key,
        b'signed_prekey')
    opks_json_list = []
    for opk_private, opk_public in opks:
        opk_pub_b64 = b64e(opk_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ))
        opk_nonce, opk_enc = CryptoUtils.encrypt_with_key(
            opk_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ),
            master_key,
            b'opk')
        opks_json_list.append({
            "public": opk_pub_b64,
            "private_enc": b64e(opk_enc),
            "private_nonce": b64e(opk_nonce)
        })
    return {
        "salt": b64e(salt),
        "identity_key_public": b64e(identity_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )),
        "signed_prekey_public": b64e(spk_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )),
        "signed_prekey_signature": b64e(spk_signature),
        "identity_key_private_enc": b64e(ik_enc),
        "identity_key_private_nonce": b64e(ik_nonce),
        "signed_prekey_private_enc": b64e(spk_enc),
        "signed_prekey_private_nonce": b64e(spk_nonce),
        "opks": opks_json_list
    }

def decrypt_all_opks(opks_json, master_key):
    opks_json_list = json.loads(opks_json)
    decrypted_opks = []
    for opk in opks_json_list:
        opk_private_bytes = CryptoUtils.decrypt_with_key(
            base64.b64decode(opk["private_nonce"]),
            base64.b64decode(opk["private_enc"]),
            master_key,
            b'opk')
        decrypted_opks.append((opk_private_bytes, base64.b64decode(opk["public"])))
    return decrypted_opks

def keypairs_from_opk_bytes(decrypted_opks):
    opk_keypairs = []
    for priv_bytes, pub_bytes in decrypted_opks:
        opk_private = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
        opk_public = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
        opk_keypairs.append((opk_private, opk_public))
    return opk_keypairs
