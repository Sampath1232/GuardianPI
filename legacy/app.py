from flask import Flask, render_template, jsonify
from modules.system_monitor import get_system_stats
from routes.logs import logs_bp
from routes.upload import upload_bp
from routes.network import network_bp
from routes.firewall import firewall_bp
from routes.alerts import alerts_bp
from routes.usb import usb_bp
from config import IS_LINUX

# Create Flask app FIRST
app = Flask(__name__)

# Register routes
app.register_blueprint(logs_bp)
app.register_blueprint(upload_bp)
app.register_blueprint(network_bp)
app.register_blueprint(firewall_bp)
app.register_blueprint(alerts_bp)
app.register_blueprint(usb_bp)

# Linux-only imports
if IS_LINUX:

    from modules.linux.firewall import enable_firewall


@app.route('/')
def index():

    return render_template('index.html')


@app.route('/api/stats')
def stats():

    return jsonify(get_system_stats())


if __name__ == '__main__':

    app.run(
        host='127.0.0.1',
        port=5000,
        debug=True
    )