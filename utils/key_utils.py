import base64
import json
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization
from utils.crypto_utils import CryptoUtils
from utils.secure_master_key import MasterKey
from utils.dataclasses import Vault
from models.models import KEK

def b64e(b):
    return base64.b64encode(b).decode()

def get_user_vault(user):
    return Vault(
        salt=user.salt,
        ed25519_identity_key_public=user.ed25519_identity_key_public,
        ed25519_identity_key_private_enc=user.ed25519_identity_key_private_enc,
        ed25519_identity_key_private_nonce=user.ed25519_identity_key_private_nonce,
        x25519_identity_key_public=user.x25519_identity_key_public,
        x25519_identity_key_private_enc=user.x25519_identity_key_private_enc,
        x25519_identity_key_private_nonce=user.x25519_identity_key_private_nonce,
        signed_prekey_public=user.signed_prekey_public,
        signed_prekey_signature=user.signed_prekey_signature,
        signed_prekey_private_enc=user.signed_prekey_private_enc,
        signed_prekey_private_nonce=user.signed_prekey_private_nonce,
        opks=user.opks_json if user.opks_json else []
    )


def try_decrypt_private_keys(vault: Vault, kek: bytes):
    ed_ik_enc = base64.b64decode(vault.ed25519_identity_key_private_enc)
    ed_ik_nonce = base64.b64decode(vault.ed25519_identity_key_private_nonce)
    x_ik_enc = base64.b64decode(vault.x25519_identity_key_private_enc)
    x_ik_nonce = base64.b64decode(vault.x25519_identity_key_private_nonce)
    spk_enc = base64.b64decode(vault.signed_prekey_private_enc)
    spk_nonce = base64.b64decode(vault.signed_prekey_private_nonce)
    ed_identity_private_bytes = CryptoUtils.decrypt_with_key(ed_ik_nonce, ed_ik_enc, kek, b'ed25519_identity_key')
    x_identity_private_bytes = CryptoUtils.decrypt_with_key(x_ik_nonce, x_ik_enc, kek, b'x25519_identity_key')
    spk_private_bytes = CryptoUtils.decrypt_with_key(spk_nonce, spk_enc, kek, b'signed_prekey')
    return ed_identity_private_bytes, x_identity_private_bytes, spk_private_bytes


def verify_decrypted_keys(ed_identity_private_bytes, x_identity_private_bytes, spk_private_bytes, vault: Vault):
    ed_identity_private = ed25519.Ed25519PrivateKey.from_private_bytes(ed_identity_private_bytes)
    x_identity_private = x25519.X25519PrivateKey.from_private_bytes(x_identity_private_bytes)
    spk_private = x25519.X25519PrivateKey.from_private_bytes(spk_private_bytes)
    ed_identity_public = ed_identity_private.public_key()
    x_identity_public = x_identity_private.public_key()
    spk_public = spk_private.public_key()
    ed_identity_public_b64 = base64.b64encode(ed_identity_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )).decode()
    x_identity_public_b64 = base64.b64encode(x_identity_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )).decode()
    spk_public_b64 = base64.b64encode(spk_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )).decode()
    return (
        ed_identity_public_b64 == vault.ed25519_identity_key_public and
        x_identity_public_b64 == vault.x25519_identity_key_public and
        spk_public_b64 == vault.signed_prekey_public
    )

def generate_user_vault(
    ed25519_identity_private, ed25519_identity_public,
    x25519_identity_private, x25519_identity_public,
    spk_private, spk_public, spk_signature, salt, kek, opks
):
    # Encrypt both identity privates
    ed_ik_nonce, ed_ik_enc = CryptoUtils.encrypt_with_key(
        ed25519_identity_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        kek,
        b'ed25519_identity_key'
    )
    x_ik_nonce, x_ik_enc = CryptoUtils.encrypt_with_key(
        x25519_identity_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        kek,
        b'x25519_identity_key'
    )
    spk_nonce, spk_enc = CryptoUtils.encrypt_with_key(
        spk_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        kek,
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
            kek,
            b'opk')
        opks_json_list.append({
            "public": opk_pub_b64,
            "private_enc": b64e(opk_enc),
            "private_nonce": b64e(opk_nonce)
        })
    return Vault(
        salt=b64e(salt),
        ed25519_identity_key_public=b64e(ed25519_identity_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )),
        ed25519_identity_key_private_enc=b64e(ed_ik_enc),
        ed25519_identity_key_private_nonce=b64e(ed_ik_nonce),
        x25519_identity_key_public=b64e(x25519_identity_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )),
        x25519_identity_key_private_enc=b64e(x_ik_enc),
        x25519_identity_key_private_nonce=b64e(x_ik_nonce),
        signed_prekey_public=b64e(spk_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )),
        signed_prekey_signature=b64e(spk_signature),
        signed_prekey_private_enc=b64e(spk_enc),
        signed_prekey_private_nonce=b64e(spk_nonce),
        opks=opks_json_list
    )

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

# def encrypt_and_store_kek(kek: bytes, master_key: bytes) -> KEK:
#     """Encrypt the KEK with the master key."""
#     nonce, ciphertext = CryptoUtils.encrypt_with_key(kek, master_key, b'kek')
#     return base64.b64encode(nonce + ciphertext).decode('utf-8')