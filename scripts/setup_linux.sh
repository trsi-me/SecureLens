#!/usr/bin/env bash
# سكربت أتمتة تجهيز SecureLens على Ubuntu أو CentOS.
# الاستخدام: sudo bash scripts/setup_linux.sh

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> تجهيز SecureLens في: ${PROJECT_DIR}"

if command -v apt-get >/dev/null 2>&1; then
    echo "==> نظام Ubuntu/Debian مكتشف، تثبيت الحزم..."
    apt-get update -y
    apt-get install -y python3 python3-venv python3-pip
elif command -v yum >/dev/null 2>&1; then
    echo "==> نظام CentOS/RHEL مكتشف، تثبيت الحزم..."
    yum install -y python3 python3-pip
else
    echo "تحذير: لم يتم التعرف على مدير الحزم تلقائياً، تأكد من تثبيت Python 3.10+ يدوياً."
fi

cd "${PROJECT_DIR}"

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

if [ ! -f .env ]; then
    cp .env.example .env
    echo "==> تم إنشاء ملف .env من .env.example، عدّل القيم قبل التشغيل بالإنتاج."
fi

echo "==> التجهيز اكتمل. للتشغيل المحلي: source .venv/bin/activate && python app.py"
echo "==> للتشغيل بالإنتاج خلف Nginx/Apache: راجع مجلد deploy/"
