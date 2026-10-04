"""نقطة دخول WSGI لتشغيل SecureLens خلف Gunicorn في بيئة إنتاج.

الاستخدام (من جذر المشروع):
    gunicorn --workers 3 --bind 127.0.0.1:8000 deploy.wsgi:app
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app  # noqa: E402
