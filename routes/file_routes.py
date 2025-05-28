from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from datetime import datetime
import os
from models.models import File
from extensions.extensions import db
from utils.crypto_utils import CryptoUtils
from utils.secure_master_key import MasterKey
import requests
import mimetypes
import utils.server_utils as server
import base64

bp_file = Blueprint('file', __name__)
 
# --- Helper functions ---

def create_file_record(file_id, owner_id, k_file_encrypted, filename, file_nonce, k_file_nonce, mime_type):
    file_record = File(
        id=file_id,
        owner_id=owner_id,
        k_file_encrypted=k_file_encrypted,
        filename=filename,
        file_nonce=file_nonce,
        k_file_nonce=k_file_nonce,
        mime_type=mime_type
    )
    db.session.add(file_record)
    db.session.commit()
    return file_record

def revoke_file_access(file, user_id):
    # Revocation logic placeholder
    return True

def upload(file_storage):
    # Read file data directly from the FileStorage object
    file_data = file_storage.read()
    file_storage.seek(0)  # Reset pointer in case it's needed elsewhere
    k_file = os.urandom(32)
    file_id = str(int(datetime.now().timestamp()))
    file_nonce, ciphertext = CryptoUtils.encrypt_with_key(file_data, k_file, file_id.encode())
    k_file_nonce, enc_k_file = CryptoUtils.encrypt_with_key(k_file, MasterKey().get_key())
    filename = secure_filename(file_storage.filename)
    mime_type, _ = mimetypes.guess_type(filename)
    create_file_record(
        file_id=file_id,
        owner_id=current_user.id,
        filename=filename,
        k_file_encrypted=enc_k_file,
        file_nonce=file_nonce,
        k_file_nonce=k_file_nonce,
        mime_type=mime_type
    )
    
    server.upload_file(
        file_id=file_id,
        file_name=filename,
        file_ciphertext=ciphertext,
        owner_id=current_user.id,
        mime_type=mime_type,
        file_nonce=file_nonce
    )
    return

def get_owned_and_shared_files(user):
    return [], []  # Placeholder for owned and shared files

def share_file_with_user(file: File, username: str):
    user_to_share = server.get_user_by_name(username)
    if not user_to_share:
        return "User not found", None
    k_file = CryptoUtils.decrypt_with_key(
        file.k_file_nonce,
        file.k_file_encrypted,
        MasterKey().get_key()
    )
    if not k_file:
        return "Failed to decrypt file key", None
    # Retrieve sender's keys from vault
    from utils.key_utils import get_user_vault, try_decrypt_private_keys
    sender_vault = get_user_vault(current_user)
    sender_identity_private_bytes, _ = try_decrypt_private_keys(sender_vault, MasterKey().get_key())
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.hazmat.primitives import serialization
    sender_identity_private = ed25519.Ed25519PrivateKey.from_private_bytes(sender_identity_private_bytes)
    sender_identity_public = sender_identity_private.public_key()
    sender_ephemeral_private = x25519.X25519PrivateKey.generate()
    sender_ephemeral_public = sender_ephemeral_private.public_key()
    # Retrieve recipient keys from server utils
    recipient_keys = server.get_recipient_keys(user_to_share.id)
    if not recipient_keys:
        return "Recipient keys not found", None
    import base64
    recipient_identity_public_bytes = base64.b64decode(recipient_keys["identity_key_public"])
    recipient_signed_prekey_public_bytes = base64.b64decode(recipient_keys["signed_prekey_public"])
    recipient_identity_public = x25519.X25519PublicKey.from_public_bytes(recipient_identity_public_bytes)
    recipient_signed_prekey_public = x25519.X25519PublicKey.from_public_bytes(recipient_signed_prekey_public_bytes)
    # Perform 3XDH
    shared_key = CryptoUtils.perform_3xdh(
        sender_ephemeral_private,
        sender_ephemeral_public,
        sender_ephemeral_private,
        sender_ephemeral_public,
        recipient_identity_public,
        recipient_signed_prekey_public,
        sender_ephemeral_public
    )
    # Encrypt k_file with derived shared key
    enc_k_file_nonce, enc_k_file = CryptoUtils.encrypt_with_key(k_file, shared_key)
    # PAC creation
    valid_until = None  # Set as needed
    pac = CryptoUtils.create_pac(
        file_id=file.id,
        recipient_id=user_to_share.id,
        issuer_id=current_user.id,
        encrypted_file_key=enc_k_file,
        encrypted_file_key_nonce=enc_k_file_nonce,
        sender_ephemeral_pubkey=sender_ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ),
        valid_until=valid_until,
        identity_key=sender_identity_private
    )
    # Send PAC to server (now takes the pac object)
    server.send_pac(pac)
    return None, user_to_share

def delete_file_from_storage_and_db(file):
    return db.session.delete(file) and db.session.commit()  # Placeholder for deletion logic

# --- Routes ---
@bp_file.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        if file:
            upload(file)
            flash('File uploaded successfully')
            return redirect(url_for('dashboard.dashboard'))
    return render_template('upload.html')

@bp_file.route('/files')
@login_required
def list_files():
    owned_files, shared_files = get_owned_and_shared_files(current_user)
    return render_template('files.html', owned_files=owned_files, shared_files=shared_files)

@bp_file.route('/share/<int:file_id>', methods=['GET', 'POST'])
@login_required
def share_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
        flash('You do not have permission to share this file')
        return redirect(url_for('file.list_files'))
    if request.method == 'POST':
        username = request.form.get('username')
        share_file_with_user(file, username)
        flash(f'File shared with {username}')
        return redirect(url_for('file.list_files'))
    return render_template('share.html', file=file)

@bp_file.route('/revoke/<int:file_id>/<int:user_id>')
@login_required
def revoke_access(file_id, user_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
        flash('You do not have permission to revoke access')
        return redirect(url_for('file.list_files'))
    revoke_file_access(file, user_id)
    flash('Access revoked successfully')
    return redirect(url_for('file.list_files'))

@bp_file.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file.filename)
    return send_file(file_path, as_attachment=True, download_name=file.original_filename)

@bp_file.route('/delete/<int:file_id>')
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
        flash('You do not have permission to delete this file')
        return redirect(url_for('file.list_files'))
    delete_file_from_storage_and_db(file)
    flash('File deleted successfully')
    return redirect(url_for('file.list_files'))
