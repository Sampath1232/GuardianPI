from flask import Blueprint, render_template, jsonify

from modules.intrusion_detection import detect_threats

alerts_bp = Blueprint('alerts', __name__)

@alerts_bp.route('/alerts')
def alerts_page():

    return render_template('alerts.html')


@alerts_bp.route('/api/threats')
def get_threats():

    threats = detect_threats()

    return jsonify(threats)