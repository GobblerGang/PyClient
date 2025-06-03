from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file
from flask_login import login_required, current_user
# from models.models import File
from utils.dataclasses import *
from services.file_service import *
from utils.secure_master_key import MasterKey
import session_manager
import io
from services.kek_service import get_decrypted_kek

bp_file = Blueprint('file', __name__)
 
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
            master_key = MasterKey().get()
            try:
                upload_file_service(file, current_user, master_key)
                flash('File uploaded successfully')
            except Exception as e:
                flash(f'Upload failed: {str(e)}')
            return redirect(url_for('dashboard.dashboard'))
    return render_template('upload.html')

@bp_file.route('/files')
@login_required
def list_files():
    try:
        master_key = MasterKey().get()
        kek = get_decrypted_kek(current_user, master_key)
        owned_files, received_pacs, issued_pacs = refresh_all_files_service(current_user, User.get_identity_private_key(self=current_user, kek=kek))
        # print(f"Received PACs: {[pac.to_dict() for pac in received_pacs]}")
    except Exception as e:
        flash(f'Error refreshing file info: {str(e)}')
        owned_files, received_pacs = [], []  # Default to empty lists
    return render_template('files.html', owned_files=owned_files, shared_files=received_pacs)

@bp_file.route('/share/<file_uuid>', methods=['GET', 'POST'])
@login_required
def share_file(file_uuid):
    # file = File.query.filter_by(uuid=file_uuid).first_or_404()
    master_key = MasterKey().get()
    kek = get_decrypted_kek(current_user, master_key)
    

    file = get_file_info_service(file_uuid=file_uuid, user=current_user,master_key=master_key)
    if not file:
        flash('File not found')
        return redirect(url_for('file.list_files'))
    # Check if the current user is the owner of the file
    # print(f"File owner ID: {file.owner_uuid}, Current user ID: {current_user.uuid}")
    if file.owner_uuid != current_user.uuid:
        flash('You do not have permission to share this file')
        return redirect(url_for('file.list_files'))
    if request.method == 'POST':
        recipient_username = request.form.get('username')
        
        try:
            identity_private_key = User.get_identity_private_key(self=current_user, kek=kek)
            _ = share_file_with_user_service(file_info=file, recipient_username=recipient_username, user=current_user, private_key=identity_private_key, kek=kek)    
            flash(f'File shared with {recipient_username}')
        except Exception as e:
            flash(f'Error sharing file: {str(e)}')
        return redirect(url_for('file.list_files'))
    return render_template('share.html', file=file)

@bp_file.route('/revoke/<file_uuid>/<user_uuid>')
@login_required
def revoke_access(file_uuid, user_uuid):
    master_key = MasterKey().get()
    _, issued_pacs = refresh_pacs_service(current_user, current_user.get_identity_private_key(master_key))
    file = next((f for f in issued_pacs if f.file_uuid == file_uuid), None)
    
    if file.owner_id != current_user.uuid:
        flash('You do not have permission to revoke access')
        return redirect(url_for('file.list_files'))
    try:
        revoke_file_access(file, user_uuid)
        flash('Access revoked successfully')
    except Exception as e:
        flash(f'Error revoking access: {str(e)}')
    return redirect(url_for('file.list_files'))

@bp_file.route('/download/<file_uuid>')
@login_required
def download_file(file_uuid):
    # try:
    master_key = MasterKey().get()
    kek = get_decrypted_kek(current_user, master_key)
    priv_key_bytes = current_user.get_identity_private_key(kek)
    priv_key_ed25519 = ed25519.Ed25519PrivateKey.from_private_bytes(priv_key_bytes)
    received_pacs, _ = refresh_pacs_service(current_user, priv_key_ed25519)
    # print(f"Received PACs: {[pac.to_dict() for pac in received_pacs]}")
    # print(f"File UUID: {file_uuid}")
    file_data, filename, mime_type = download_file_service(file_uuid, received_pacs, current_user, kek, priv_key_ed25519)
    return send_file(
        io.BytesIO(file_data),
        as_attachment=True,
        download_name=filename,
        mimetype=mime_type
    )
    # except FileDownloadError as e:
    #     flash(str(e))
    #     return redirect(url_for('file.list_files'))
    # except Exception as e:
    #     flash(f'Error downloading file: {str(e)}')
    #     return redirect(url_for('file.list_files'))

@bp_file.route('/delete/<file_uuid>')
@login_required
def delete_file(file_uuid):
    owned_files = refresh_owned_file_service(current_user, MasterKey().get())
    file = next((f for f in owned_files if f.uuid == file_uuid), None)
    if not file:
        flash('File not found')
        return redirect(url_for('file.list_files'))
    
    if file.owner_uuid != current_user.uuid:
        flash('You do not have permission to delete this file')
        return redirect(url_for('file.list_files'))
    try:
        delete_file_(file)
        flash('File deleted successfully')
    except Exception as e:
        flash(f'Error deleting file: {str(e)}')
    return redirect(url_for('file.list_files'))
