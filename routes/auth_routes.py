import base64
import json
import os
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, current_user

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from models.models import User
from extensions.extensions import login_manager, db
from utils.crypto_utils import CryptoUtils
from utils.key_utils import (
    try_decrypt_private_keys, verify_decrypted_keys, generate_user_vault, decrypt_all_opks, keypairs_from_opk_bytes,
    get_user_vault, derive_master_key_from_login, b64e
)
from utils.secure_master_key import MasterKey
from session_manager import clear_session
import utils.server_utils as server

bp_auth = Blueprint('auth', __name__)

server_db = {}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Helper functions ---
def username_exists(username):
    return User.query.filter_by(username=username).first() is not None

def email_exists(email):
    return User.query.filter_by(email=email).first() is not None

def create_user(username, email, vault):
    user_data = {
        "username": username,
        "email": email,
        "identity_key_public": vault["identity_key_public"],
        "signed_prekey_public": vault["signed_prekey_public"],
        "signed_prekey_signature": vault["signed_prekey_signature"],
        "salt": vault["salt"],
        "identity_key_private_enc": vault["identity_key_private_enc"],
        "identity_key_private_nonce": vault["identity_key_private_nonce"],
        "signed_prekey_private_enc": vault["signed_prekey_private_enc"],
        "signed_prekey_private_nonce": vault["signed_prekey_private_nonce"],
        "opks_json": json.dumps(vault["opks"])
    }
    response = server.create_user(user_data)
    if not response or not isinstance(response, dict):
        flash('No response from server. Please try again later.')
        return None

    if response.get("success"):
        uuid = response.get("uuid")
    else:
        error_msg = response.get("error", "Unknown error")
        flash(error_msg)
        return None

    if not uuid:
        flash('User creation failed. Please try again.')
        return None
    
    user = User(
        username=username,
        email=email,
        identity_key_public=vault["identity_key_public"],
        signed_prekey_public=vault["signed_prekey_public"],
        signed_prekey_signature=vault["signed_prekey_signature"],
        salt=vault["salt"],
        identity_key_private_enc=vault["identity_key_private_enc"],
        identity_key_private_nonce=vault["identity_key_private_nonce"],
        signed_prekey_private_enc=vault["signed_prekey_private_enc"],
        signed_prekey_private_nonce=vault["signed_prekey_private_nonce"],
        opks_json=json.dumps(vault["opks"]),
        uuid= uuid
    )
    db.session.add(user)
    db.session.commit()
    return user

# --- Routes ---
@bp_auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        
        if username_exists(username):
            flash('Username already exists')
            return redirect(url_for('auth.signup'))
        
        email = request.form.get('email')
        if email_exists(email):
            flash('Email already registered')
            return redirect(url_for('auth.signup'))
        
        # Take password input
        password = request.form.get('password')
        # generate a salt
        salt = os.urandom(16)
        master_key = MasterKey().derive_key(password, salt)
        MasterKey().set_key(master_key)
        # generate identity keypair, signed prekey pair
        identity_private, identity_public = CryptoUtils.generate_identity_keypair()
        spk_private, spk_public, spk_signature = CryptoUtils.generate_signed_prekey(identity_private)
        # generate 100 OPKs
        opks = [CryptoUtils.generate_identity_keypair() for _ in range(100)]
        
        vault = generate_user_vault(identity_private, identity_public, spk_private, spk_public, spk_signature, salt, master_key, opks)
        
        # Sends user info to server and stores user in local database
        if not create_user(username, email, vault):
            flash('Failed to create user. Server may be down or busy.')
            MasterKey().clear()
            return redirect(url_for('auth.signup'))
        
        flash('Registration successful! Please login.')
        MasterKey().clear()
        return redirect(url_for('auth.login'))
    return render_template('signup.html')

@bp_auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if not user:
            flash('User not found')
            return render_template('login.html')
        vault = get_user_vault(user)
        try:
            salt = base64.b64decode(vault["salt"])
            master_key = MasterKey().derive_key(password, salt)
            MasterKey().set_key(master_key)
            # print("Master key derived and set successfully")
            
            identity_private_bytes, spk_private_bytes = try_decrypt_private_keys(vault, master_key)
            # print("Private keys decrypted successfully")
            
            if not verify_decrypted_keys(identity_private_bytes, spk_private_bytes, vault):
                flash('Key mismatch! Vault or server data corrupted.')
                MasterKey().clear()
                return render_template('login.html')
        except Exception:
            flash('Failed to decrypt keys. Wrong password?')
            MasterKey().clear()
            return render_template('login.html')
        flash('Login successful!')
        login_user(user)
        return redirect(url_for('dashboard.dashboard'))
    return render_template('login.html')

@bp_auth.route('/logout')
def logout():
    logout_user()
    clear_session()
    return redirect(url_for('main.index'))

@bp_auth.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if not current_user.is_authenticated:
        flash('You must be logged in to change your password.')
        return redirect(url_for('auth.login'))
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        user = User.query.get(current_user.id)
        vault = get_user_vault(user)
        try:
            old_salt = base64.b64decode(vault["salt"])
            old_master_key = MasterKey().derive_key(old_password, old_salt)
            MasterKey().set_key(old_master_key)
            identity_private_bytes, spk_private_bytes = try_decrypt_private_keys(vault, old_master_key)
            decrypted_opks = decrypt_all_opks(user.opks_json, old_master_key)
        except Exception:
            flash('Old password is incorrect.')
            MasterKey().clear()
            return render_template('change_password.html')
        new_salt = os.urandom(16)
        new_master_key = MasterKey().derive_key(new_password, new_salt)
        MasterKey().set_key(new_master_key)
        from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
        identity_private = ed25519.Ed25519PrivateKey.from_private_bytes(identity_private_bytes)
        spk_private = x25519.X25519PrivateKey.from_private_bytes(spk_private_bytes)
        opk_keypairs = keypairs_from_opk_bytes(decrypted_opks)
        spk_public = spk_private.public_key()
        spk_signature = base64.b64decode(user.signed_prekey_signature)
        new_vault = generate_user_vault(
            identity_private,
            identity_private.public_key(),
            spk_private,
            spk_public,
            spk_signature,
            new_salt,
            new_master_key,
            opk_keypairs
        )
        user.salt = new_vault["salt"]
        user.identity_key_private_enc = new_vault["identity_key_private_enc"]
        user.identity_key_private_nonce = new_vault["identity_key_private_nonce"]
        user.signed_prekey_private_enc = new_vault["signed_prekey_private_enc"]
        user.signed_prekey_private_nonce = new_vault["signed_prekey_private_nonce"]
        user.opks_json = json.dumps(new_vault["opks"])
        db.session.commit()
        flash('Password changed successfully!')
        MasterKey().clear()
        return redirect(url_for('dashboard.dashboard'))
    return render_template('change_password.html')
