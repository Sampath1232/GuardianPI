#!/bin/bash

echo "Installing GuardianPi..."

sudo apt update && sudo apt upgrade -y

sudo apt install -y python3-pip
sudo apt install -y python3-venv
sudo apt install -y nmap
sudo apt install -y aide
sudo apt install -y rkhunter
sudo apt install -y ufw

python3 -m venv venv

source venv/bin/activate

pip install -r requirements.txt

mkdir -p logs
mkdir -p scans/reports
mkdir -p scans/quarantine
mkdir -p static/uploads

chmod +x scripts/*.sh

echo "GuardianPi Installed Successfully"