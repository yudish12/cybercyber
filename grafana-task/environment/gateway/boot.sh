#!/usr/bin/env bash
set -e

awk -v h="$(hostname)" '$2==h{print $1}' /etc/hosts | sort -u > /vchan/web_ip.tmp && mv /vchan/web_ip.tmp /vchan/web_ip


echo "[gateway] running setup..."
python3 /app/setup.py

echo "[gateway] starting gateway..."
exec gunicorn -b 0.0.0.0:8080 -w 1 --timeout 60 app:app
