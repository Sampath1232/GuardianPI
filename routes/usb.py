from flask import Blueprint, render_template, jsonify

from modules.usb_monitor import get_usb_devices

usb_bp = Blueprint('usb', __name__)

@usb_bp.route('/usb')
def usb_page():

    return render_template('usb.html')


@usb_bp.route('/api/usb')
def usb_api():

    devices = get_usb_devices()

    return jsonify(devices)