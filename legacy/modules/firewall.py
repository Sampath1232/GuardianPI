import subprocess

def enable_firewall():

    command = "sudo ufw enable"

    subprocess.run(command, shell=True)


def block_ip(ip):

    command = f"sudo ufw deny from {ip}"

    subprocess.run(command, shell=True)