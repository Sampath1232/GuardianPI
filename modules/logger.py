from datetime import datetime

LOG_FILE = 'logs/threat.log'

def log_threat(message):

    timestamp = datetime.now().strftime(
        '%Y-%m-%d %H:%M:%S'
    )

    log_entry = f"[{timestamp}] {message}\n"

    with open(LOG_FILE, 'a') as file:

        file.write(log_entry)