import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def _default_client_secret():
    # Prefer env override, then project root, then instance folder
    env_path = os.environ.get('GMAIL_CLIENT_SECRET_FILE')
    if env_path:
        return env_path
    root_path = os.path.join(BASE_DIR, 'client_secret.json')
    instance_path = os.path.join(BASE_DIR, 'instance', 'client_secret.json')
    return root_path if os.path.exists(root_path) else instance_path

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_secret_key_here'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///phishorucad.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Gmail API settings
    GMAIL_CLIENT_SECRET_FILE = _default_client_secret()
    GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

    # VirusTotal API
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY') or 'your_virustotal_api_key'

    # Notification email (SMTP) settings
    SMTP_HOST = os.environ.get('SMTP_HOST')
    SMTP_PORT = int(os.environ.get('SMTP_PORT') or 587)
    SMTP_USER = os.environ.get('SMTP_USER')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
    SMTP_USE_TLS = (os.environ.get('SMTP_USE_TLS', 'true').lower() == 'true')
    MAIL_FROM = os.environ.get('MAIL_FROM') or SMTP_USER or 'no-reply@phishorucad.local'
