from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file
from flask_login import login_required, current_user
from models.models import File
from utils.dataclasses import *
from services.file_service import (
    upload_file_service, share_file_with_user_service, revoke_file_access, delete_file_from_storage_and_db, download_file_service, FileDownloadError,
    refresh_pacs_service, refresh_user_file_info_service
)
from utils.secure_master_key import MasterKey
from session_manager import get_pacs_from_session
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
        owned_files, shared_files = refresh_user_file_info_service(current_user)
        session['owned_file_info'] = [f.to_dict() for f in owned_files]
        session['shared_file_info'] = [f.to_dict() for f in shared_files]
    except Exception as e:
        flash(f'Error refreshing file info: {str(e)}')
        session['owned_file_info'] = []
        session['shared_file_info'] = []
    return render_template('files.html', owned_files=session.get('owned_file_info', []), shared_files=session.get('shared_file_info', []))

@bp_file.route('/share/<int:file_id>', methods=['GET', 'POST'])
@login_required
def share_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
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

@bp_file.route('/revoke/<int:file_id>/<int:user_id>')
@login_required
def revoke_access(file_id, user_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
        flash('You do not have permission to revoke access')
        return redirect(url_for('file.list_files'))
    try:
        revoke_file_access(file, user_id)
        flash('Access revoked successfully')
    except Exception as e:
        flash(f'Error revoking access: {str(e)}')
    return redirect(url_for('file.list_files'))

@bp_file.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    try:
        pacs = refresh_pacs_service(current_user)
        # pacs = get_pacs_from_session()
        master_key = MasterKey().get()
        file_data, filename, mime_type = download_file_service(file_id, pacs, current_user, master_key)
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

@bp_file.route('/delete/<int:file_id>')
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id:
        flash('You do not have permission to delete this file')
        return redirect(url_for('file.list_files'))
    try:
        delete_file_from_storage_and_db(file)
        flash('File deleted successfully')
    except Exception as e:
        flash(f'Error deleting file: {str(e)}')
    return redirect(url_for('file.list_files'))
