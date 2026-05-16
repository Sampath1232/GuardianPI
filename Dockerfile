FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN apt update && apt install -y \
    nmap \
    aide \
    rkhunter \
    ufw

RUN pip install -r requirements.txt

EXPOSE 5000

CMD ["python", "app.py"]