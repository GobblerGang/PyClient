from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file
from flask_login import login_required, current_user
# from models.models import File
from utils.dataclasses import *
from services.file_service import *
from utils.secure_master_key import MasterKey
import session_manager
import io

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
        owned_files, received_pacs, issued_pacs=refresh_all_files_service(current_user, MasterKey().get())
    except Exception as e:
        flash(f'Error refreshing file info: {str(e)}')
    return render_template('files.html', owned_files=owned_files, shared_files=received_pacs)

@bp_file.route('/share/<file_uuid>', methods=['GET', 'POST'])
@login_required
def share_file(file_uuid):
    # file = File.query.filter_by(uuid=file_uuid).first_or_404()
    owned_files = refresh_owned_file_service(current_user,MasterKey().get())
    file = next((f for f in owned_files if f.uuid == file_uuid), None)
    if not file:
        flash('File not found')
        return redirect(url_for('file.list_files'))
    # Check if the current user is the owner of the file
    if file.owner_id != current_user.uuid:
        flash('You do not have permission to share this file')
        return redirect(url_for('file.list_files'))
    if request.method == 'POST':
        username = request.form.get('username')
        master_key = MasterKey().get()
        try:
            error, user_to_share = share_file_with_user_service(file, username, current_user, master_key)
            if error:
                flash(error)
            else:
                flash(f'File shared with {username}')
        except Exception as e:
            flash(f'Error sharing file: {str(e)}')
        return redirect(url_for('file.list_files'))
    return render_template('share.html', file=file)

@bp_file.route('/revoke/<file_uuid>/<user_uuid>')
@login_required
def revoke_access(file_uuid, user_uuid):
    _, issued_pacs = refresh_pacs_service(current_user, MasterKey().get())
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
    try:
        received_pacs, _ = refresh_pacs_service(current_user, MasterKey().get())
        master_key = MasterKey().get()
        file_data, filename, mime_type = download_file_service(file_uuid, received_pacs, current_user, master_key)
        return send_file(
            io.BytesIO(file_data),
            as_attachment=True,
            download_name=filename,
            mimetype=mime_type
        )
    except FileDownloadError as e:
        flash(str(e))
        return redirect(url_for('file.list_files'))
    except Exception as e:
        flash(f'Error downloading file: {str(e)}')
        return redirect(url_for('file.list_files'))

@bp_file.route('/delete/<file_uuid>')
@login_required
def delete_file(file_uuid):
    owned_files = refresh_owned_file_service(current_user, MasterKey().get())
    file = next((f for f in owned_files if f.uuid == file_uuid), None)
    if not file:
        flash('File not found')
        return redirect(url_for('file.list_files'))
    
    if file.owner_id != current_user.uuid:
        flash('You do not have permission to delete this file')
        return redirect(url_for('file.list_files'))
    try:
        delete_file_(file)
        flash('File deleted successfully')
    except Exception as e:
        flash(f'Error deleting file: {str(e)}')
    return redirect(url_for('file.list_files'))
