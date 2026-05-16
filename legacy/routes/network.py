from flask import Blueprint, render_template, jsonify

from modules.network_scan import scan_network

network_bp = Blueprint('network', __name__)

@network_bp.route('/network')
def network_page():

    return render_template('network.html')


@network_bp.route('/api/network-scan')
def network_scan_api():

    result = scan_network('scanme.nmap.org')

    return jsonify(result)