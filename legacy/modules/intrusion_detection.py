import psutil

from modules.logger import log_threat

BLACKLIST = [

    'hydra',
    'nmap',
    'netcat',
    'nc',
    'john'
]

def detect_threats():

    threats = []

    for process in psutil.process_iter(['name']):

        try:

            process_name = process.info['name']

            if process_name:

                process_name = process_name.lower()

                for bad in BLACKLIST:

                    if bad in process_name:

                        threat = {

                            "threat": process_name,

                            "status": "Suspicious Process Detected"
                        }

                        threats.append(threat)

                        log_threat(
                            f"Threat Detected: {process_name}"
                        )

        except:

            pass

    return threats