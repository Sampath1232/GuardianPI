from flask import Blueprint, render_template, request
import os

from modules.malware_scan import scan_file

upload_bp = Blueprint('upload', __name__)

UPLOAD_FOLDER = 'static/uploads'


@upload_bp.route('/upload', methods=['GET', 'POST'])

def upload():

    result = None

    if request.method == 'POST':

        file = request.files['file']

        filepath = os.path.join(UPLOAD_FOLDER, file.filename)

        file.save(filepath)

        result = scan_file(filepath)

    return render_template(
        'upload.html',
        result=result
    )