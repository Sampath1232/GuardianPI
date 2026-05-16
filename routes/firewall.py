from flask import Blueprint

from modules.firewall import enable_firewall

firewall_bp = Blueprint('firewall', __name__)

@firewall_bp.route('/firewall/enable')

def firewall_enable():

    enable_firewall()

    return "Firewall Enabled"