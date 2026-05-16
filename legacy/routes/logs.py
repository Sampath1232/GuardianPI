from flask import Blueprint, render_template

logs_bp = Blueprint('logs', __name__)

LOG_FILE = 'logs/threat.log'

@logs_bp.route('/logs')
def logs():

    try:

        with open(LOG_FILE, 'r') as file:

            content = file.read()

    except:

        content = "No logs yet."

    return render_template(
        'logs.html',
        logs=content
    )