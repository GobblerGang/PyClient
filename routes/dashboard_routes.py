from flask import Blueprint, render_template
from flask_login import login_required

bp_dashboard = Blueprint('dashboard', __name__)

@bp_dashboard.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')
