#!/usr/bin/env bash
# سكربت User Data اختياري لنشر SecureLens تلقائياً عند إنشاء نسخة EC2 (Ubuntu).
# يُلصق محتوى هذا الملف داخل حقل "User data" عند إنشاء الـ Instance بمنصة AWS.

set -euo pipefail

apt-get update -y
apt-get install -y git python3 python3-venv python3-pip nginx

cd /opt
git clone https://github.com/your-org/securelens.git securelens || true
cd securelens

bash scripts/setup_linux.sh

cp deploy/nginx.conf /etc/nginx/sites-available/securelens.conf
ln -sf /etc/nginx/sites-available/securelens.conf /etc/nginx/sites-enabled/securelens.conf
systemctl reload nginx

cp deploy/securelens.service /etc/systemd/system/securelens.service
systemctl daemon-reload
systemctl enable --now securelens
