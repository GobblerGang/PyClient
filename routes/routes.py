from flask import Blueprint, render_template

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    return render_template('index.html')

from routes.auth_routes import bp_auth
from routes.dashboard_routes import bp_dashboard
from routes.file_routes import bp_file

def register_blueprints(app):
    app.register_blueprint(bp)
    app.register_blueprint(bp_auth)
    app.register_blueprint(bp_dashboard)
    app.register_blueprint(bp_file)
