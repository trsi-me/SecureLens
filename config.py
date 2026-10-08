import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'scans.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Optional: connect a real AI provider for smarter recommendations.
    # If left empty, the built-in rule-based Arabic/English recommendation
    # engine (scanner/recommendations.py) is used instead.
    AI_PROVIDER = os.environ.get("AI_PROVIDER", "")  # "openai" | "anthropic" | ""
    AI_API_KEY = os.environ.get("AI_API_KEY", "")

    # Safety limits
    REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "10"))
    MAX_REDIRECTS = int(os.environ.get("MAX_REDIRECTS", "5"))
    USER_AGENT = os.environ.get(
        "SCANNER_USER_AGENT",
        "SecureLens/1.0 (+security-checkup; passive-scanner; contact-site-owner-only)",
    )
