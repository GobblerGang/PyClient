import base64
import io
import json
import os
from flask import Blueprint, render_template, request, redirect, send_file, url_for, flash
from flask_login import login_user, logout_user, current_user

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from models.models import User, KEK
from extensions.extensions import login_manager, db
from utils.crypto_utils import CryptoUtils
from utils.key_utils import (
    try_decrypt_private_keys, verify_decrypted_keys, generate_user_vault, decrypt_all_opks, keypairs_from_opk_bytes,
    get_user_vault
)
from utils.secure_master_key import MasterKey
from session_manager import clear_session
import utils.server_utils as server
from services.auth_service import create_user_service, import_user_keys_service, login_user_service, change_password_service
from utils.dataclasses import Vault
from services.kek_service import encrypt_kek
from cryptography.exceptions import InvalidTag

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

def create_user(username, email, vault: Vault, user_uuid, kek: dict):
    user, error = create_user_service(username, email, vault, user_uuid, kek)
    if error:
        None, error
    return user, error

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
        if not password:
            flash('Password is required')
            return redirect(url_for('auth.signup'))
        
        salt = os.urandom(16)
        master_key = MasterKey().derive_key(password, salt)
        MasterKey().set_key(master_key)
        
        # Generate KEK
        kek = os.urandom(32)
        
        # generate identity keypair, signed prekey pair
        identity_private, identity_public = CryptoUtils.generate_identity_keypair()
        spk_private, spk_public, spk_signature = CryptoUtils.generate_signed_prekey(identity_private)
        # generate 100 OPKs
        opks = [CryptoUtils.generate_identity_keypair() for _ in range(100)]
        
        # Encrypt identity and signed prekey private keys with KEK
        vault = generate_user_vault(identity_private, identity_public, spk_private, spk_public, spk_signature, salt, kek, opks)
        
        user_uuid, error = server.get_new_user_uuid()
        user_uuid_str = str(user_uuid)
        # print(f'User UUID: {user_uuid}, Error: {error}')
        if error:
            flash(f'Error communicating with the server. Please try again later')
            return redirect(url_for('auth.signup'))
        
        
        # Encrypt KEK with the master key, timestamp and user UUID as AAD
        kek_dict = encrypt_kek(kek, master_key, user_uuid_str)
        # print("enc_kek:", kek_dict['enc_kek'])
        # print("kek_nonce:", kek_dict['kek_nonce'])
        # print("aad:", kek_dict['aad'])
        # Sends user info to server and stores user in local database
        user, error = create_user(username, email, vault,user_uuid_str, kek_dict)
        if not user:
            print(f'Error creating user: {error}')
            flash(f'Failed to create user: {error}')
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
        user, error = login_user_service(username, password)
        if error:
            flash(error)
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
        success, error = change_password_service(user, old_password, new_password)
        if not success:
            flash(f"Error changing password: {error}")
            return render_template('change_password.html')
        flash('Password changed successfully!')
        return redirect(url_for('dashboard.dashboard'))
    return render_template('change_password.html')

@bp_auth.route('/export_keys', methods=['POST'])
def export_user_keys():
    # this route is used to export user keys to a json file. this should only be available to the user themselves
    if not current_user.is_authenticated:
        flash('You must be logged in to export your keys.')
        return redirect(url_for('auth.login'))
    
    vault = get_user_vault(current_user)
    keys = {
        "identity_key_public": vault.identity_key_public,
        "signed_prekey_public": vault.signed_prekey_public,
        "signed_prekey_signature": vault.signed_prekey_signature,
        "identity_key_private_enc": vault.identity_key_private_enc,
        "identity_key_private_nonce": vault.identity_key_private_nonce,
        "signed_prekey_private_enc": vault.signed_prekey_private_enc,
        "signed_prekey_private_nonce": vault.signed_prekey_private_nonce,
        "opks": vault.opks
    }
    
    filename = f"{current_user.username}_keys.json"
    json_bytes = json.dumps(keys, indent=4).encode('utf-8')
    file_obj = io.BytesIO(json_bytes)
    file_obj.seek(0)
    flash('Keys exported successfully! Download the file below.')
    # Return the file for download
    
    return send_file(file_obj, as_attachment=True, download_name=filename, mimetype='application/json')

@bp_auth.route('/import_keys', methods=['GET', 'POST'])
def import_user_keys():
    # POST: handle import
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        keyfile = request.files.get('keyfile')
        if not username or not password or not keyfile:
            flash('All fields are required.')
            return redirect(url_for('auth.import_user_keys'))
        user, error = import_user_keys_service(username, password, keyfile)
        if error:
            flash(error)
            return redirect(url_for('auth.import_user_keys'))
        flash('Keys imported and user added. You can now log in.')
        return redirect(url_for('auth.login'))
    return render_template('import_keys.html')

