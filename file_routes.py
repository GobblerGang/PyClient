from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from datetime import datetime
import os
from models import File, User
from extensions import db
from crypto_utils import CryptoUtils

bp_file = Blueprint('file', __name__)

# --- Helper functions ---
def save_encrypted_file(file, owner_id):
    file_key = os.urandom(32)
    file_data = file.read()
    nonce, encrypted_data = CryptoUtils.encrypt_with_key(file_data, file_key)
    filename = secure_filename(file.filename)
    unique_filename = f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{filename}"
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
    with open(file_path, 'wb') as f:
        f.write(nonce + encrypted_data)
    new_file = File(
        filename=unique_filename,
        original_filename=filename,
        owner_id=owner_id,
        mime_type=file.content_type
    )
    db.session.add(new_file)
    db.session.commit()
    return new_file

def get_owned_and_shared_files(user):
    owned_files = File.query.filter_by(owner_id=user.id).all()
    shared_files = user.shared_files
    return owned_files, shared_files

def share_file_with_user(file, username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return 'User not found', None
    if user.id == current_user.id:
        return 'Cannot share with yourself', None
    # Sharing logic placeholder
    return None, user

def revoke_file_access(file, user_id):
    # Revocation logic placeholder
    return True

def delete_file_from_storage_and_db(file):
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file.filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    db.session.delete(file)
    db.session.commit()

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
            save_encrypted_file(file, current_user.id)
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
        error, user = share_file_with_user(file, username)
        if error:
            flash(error)
        else:
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
