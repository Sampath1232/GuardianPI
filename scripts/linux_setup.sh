#!/bin/bash

echo "Installing GuardianPi Linux Dependencies"

sudo apt update

sudo apt install -y \
python3-pip \
python3-venv \
nmap \
aide \
rkhunter \
ufw \
net-tools

python3 -m venv venv

source venv/bin/activate

pip install -r requirements.txt

echo "GuardianPi Ready"