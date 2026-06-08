import os
import sys

# Ensure app runs from project virtualenv to avoid slow/broken global user-site imports on Windows.
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_VENV = os.path.join(PROJECT_DIR, ".venv")
if os.path.isdir(PROJECT_VENV):
    in_venv = (hasattr(sys, "real_prefix") or (getattr(sys, "base_prefix", sys.prefix) != sys.prefix))
    exe_lower = (sys.executable or "").lower()
    venv_lower = PROJECT_VENV.lower()
    if (not in_venv) or (venv_lower not in exe_lower):
        print("[startup] Wrong Python environment detected.")
        print(f"[startup] Current interpreter: {sys.executable}")
        print("[startup] Use one of these commands from project root:")
        print(r"  .\run_local.ps1")
        print(r"  .\.venv\Scripts\python.exe app.py")
        sys.exit(1)

# Workaround: disable SQLAlchemy C extensions to avoid slow WMI calls on Windows (platform.win32_ver hang).
os.environ.setdefault("DISABLE_SQLALCHEMY_CEXT", "1")
os.environ.setdefault("SQLALCHEMY_DISABLE_CEXT", "1")
# SQLAlchemy 2.x runtime flag actually used by sqlalchemy.util._has_cy
os.environ.setdefault("DISABLE_SQLALCHEMY_CEXT_RUNTIME", "1")

# Additional workaround: short-circuit platform.win32_ver to avoid WMI hangs on some Windows setups
if sys.platform.startswith("win"):
    import platform
    try:
        platform.win32_ver = lambda release='', version='', csd='', ptype='': ('', '', '', '')
    except Exception:
        pass

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from models import db, User, ActivityLog, PhishingDetection, MaliciousLink, ReportedPhishingLink
from config import Config
from flask_bcrypt import Bcrypt
import smtplib
from email.mime.text import MIMEText
import re
import base64
import ast
import json
import requests
from urllib.parse import urlparse
from sqlalchemy import inspect, text

# Lazy Gmail imports to avoid slow/blocked startup on some Windows/Python setups
GMAIL_ENABLED = False
GMAIL_DISABLE_REASON = ""
Flow = build = Credentials = Request = None


def load_gmail_modules():
    """
    Best-effort import of Gmail dependencies.
    Called lazily to avoid startup hangs when packages scan site-packages on Windows/Python 3.13.
    """
    global GMAIL_ENABLED, GMAIL_DISABLE_REASON, Flow, build, Credentials, Request
    if GMAIL_ENABLED or GMAIL_DISABLE_REASON:
        return GMAIL_ENABLED
    try:
        from google_auth_oauthlib.flow import Flow as _Flow
        from googleapiclient.discovery import build as _build
        from google.oauth2.credentials import Credentials as _Credentials
        from google.auth.transport.requests import Request as _Request
        Flow, build, Credentials, Request = _Flow, _build, _Credentials, _Request
        GMAIL_ENABLED = True
    except Exception as exc:  # pragma: no cover - import-time guard
        GMAIL_DISABLE_REASON = f"Gmail disabled: {exc}"
    return GMAIL_ENABLED

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
bcrypt = Bcrypt(app)

with app.app_context():
    db.create_all()
    try:
        inspector = inspect(db.engine)
        user_columns = {col['name'] for col in inspector.get_columns('user')}
        if 'telegram_chat_id' not in user_columns:
            db.session.execute(text("ALTER TABLE user ADD COLUMN telegram_chat_id VARCHAR(64)"))
            db.session.commit()
    except Exception as exc:
        db.session.rollback()
        print(f'[db] Schema update warning: {exc}')

EMAIL_ENABLED = bool(Config.SMTP_HOST and Config.SMTP_USER and Config.SMTP_PASSWORD)


def get_bot_token():
    return os.environ.get('BOT_TOKEN', '').strip()


def current_user():
    uid = session.get('user_id')
    return User.query.get(uid) if uid else None


def send_email(to_email, subject, body):
    """Best-effort SMTP sender; silently skips when not configured."""
    if not EMAIL_ENABLED or not to_email:
        return False

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = Config.MAIL_FROM
    msg['To'] = to_email

    try:
        with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT) as server:
            if Config.SMTP_USE_TLS:
                server.starttls()
            server.login(Config.SMTP_USER, Config.SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as exc:
        print(f'[mail] Failed to send to {to_email}: {exc}')
        return False


def notify_user_of_analysis(user, result):
    if not user:
        return False
    status = result.get('status', 'Link Checked')
    severity = result.get('severity', '').upper()
    reasons = '\n- '.join(result.get('reasons', []))
    body = (
        f'Hello {user.name},\n\n'
        f'Your link analysis is complete.\n'
        f'URL: {result.get("url") or result.get("domain")}\n'
        f'Status: {status} ({severity})\n'
        f'Why: - {reasons}\n\n'
        'Stay safe,\nPhishOruCad'
    )
    return send_email(user.email, f'Link analysis result: {status}', body)


def notify_other_users(excluding_user_id, url, result):
    """Alert other users when an unsafe link is confirmed."""
    try:
        others = User.query.filter(User.id != excluding_user_id).all() if excluding_user_id else User.query.all()
    except Exception:
        others = []

    sent = 0
    if not others:
        return sent

    status = result.get('status', 'Unsafe link')
    reasons = '\n- '.join(result.get('reasons', []))
    body = (
        f'Alert: A suspicious link was reported.\n'
        f'URL: {url}\n'
        f'Status: {status}\n'
        f'Reasons:\n- {reasons}\n\n'
        'Do not click this link if you receive it.'
    )
    for user in others:
        if send_email(user.email, 'Unsafe link reported', body):
            sent += 1
    return sent


def normalize_report_url(url):
    if not url:
        return ''
    return url.strip().lower()


def is_valid_telegram_chat_id(chat_id):
    """Allow only numeric Telegram chat IDs (user/group IDs)."""
    value = (chat_id or '').strip()
    if not value:
        return False
    # Prevent accidental bot token / username usage.
    if value.startswith('@') or ':' in value:
        return False
    return bool(re.fullmatch(r'-?\d+', value))


def send_telegram_message(chat_id, message):
    bot_token = get_bot_token()
    if not bot_token:
        print('[telegram] BOT_TOKEN not configured; skipping Telegram message.')
        return False
    if not is_valid_telegram_chat_id(chat_id):
        print(f'[telegram] Invalid chat_id "{chat_id}". Skipping.')
        return False

    api_url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
    payload = {'chat_id': str(chat_id).strip(), 'text': message}
    try:
        response = requests.post(api_url, data=payload, timeout=10)
        if response.status_code != 200:
            print(f'[telegram] Failed to send to {chat_id}: HTTP {response.status_code} {response.text}')
            return False
        response_json = response.json()
        if not response_json.get('ok'):
            print(f'[telegram] Telegram API rejected chat_id {chat_id}: {response_json}')
            return False
        return True
    except Exception as exc:
        print(f'[telegram] Error sending to {chat_id}: {exc}')
        return False


def broadcast_telegram_alert(url, reporter_user_id=None):
    message = (
        "⚠️ Phishing Alert!\n"
        "This link has been reported as malicious:\n\n"
        f"{url}\n\n"
        "Avoid clicking this link."
    )
    query = User.query.filter(
        User.telegram_chat_id.isnot(None),
        User.telegram_chat_id != ''
    )
    if reporter_user_id is not None:
        query = query.filter(User.id != reporter_user_id)
    users = query.all()

    sent_count = 0
    for user in users:
        chat_id = (user.telegram_chat_id or '').strip()
        print(f'[telegram] Candidate user_id={user.id}, chat_id={chat_id}')
        if not is_valid_telegram_chat_id(chat_id):
            print(f'[telegram] Skipping invalid chat_id for user_id={user.id}')
            continue
        if send_telegram_message(chat_id, message):
            sent_count += 1
    print(f'[telegram] Reporter user_id={reporter_user_id}; users notified={sent_count}')
    return sent_count

def log_activity(user_id, action):
    log = ActivityLog(user_id=user_id, action=action)
    db.session.add(log)
    db.session.commit()

def log_detection(user_id, detection_type, input_data, result):
    det = PhishingDetection(user_id=user_id, detection_type=detection_type, input_data=input_data, result=str(result))
    db.session.add(det)
    db.session.commit()


def parse_detection_result(raw_result):
    if not raw_result:
        return {}
    try:
        return json.loads(raw_result)
    except Exception:
        pass
    try:
        return ast.literal_eval(raw_result)
    except Exception:
        return {"raw": raw_result}


def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

def get_gmail_service():
    """Return authenticated Gmail service or None; refresh tokens when needed."""
    if not load_gmail_modules():
        print("[gmail] Disabled:", GMAIL_DISABLE_REASON or "Imports failed")
        return None
    creds_info = session.get('gmail_credentials')
    if not creds_info:
        print("[gmail] No credentials in session")
        return None
    try:
        creds = Credentials(**creds_info)
        if creds.expired and creds.refresh_token:
            if Request is None:
                print('[gmail] Request transport not available.')
                return None
            creds.refresh(Request())
            session['gmail_credentials'] = credentials_to_dict(creds)
        return build('gmail', 'v1', credentials=creds)
    except Exception as exc:
        print(f"[gmail] Failed to build service: {exc}")
        return None

def classify_gmail_email(sender, subject, body, urls):
    reasons = []
    suspicious_domains = {'paypal-security.com', 'login-verify.net', 'support-update.com'}
    blacklist_keywords = ['urgent', 'verify', 'password', 'reset', 'account', 'click', 'login', 'confirm']
    shortened_hosts = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly'}

    # sender analysis
    sender_domain = sender.split('@')[-1].lower() if '@' in sender else sender.lower()
    if sender_domain in suspicious_domains:
        reasons.append(f'Sender domain appears on blacklist: {sender_domain}')

    # keyword analysis
    combined = f'{subject} {body}'.lower()
    found_keywords = [kw for kw in blacklist_keywords if kw in combined]
    if found_keywords:
        reasons.append(f'Phishing keywords detected: {", ".join(found_keywords)}')

    # url analysis
    for url in urls:
        host = urlparse(url).netloc.lower()
        if host in suspicious_domains:
            reasons.append(f'Link points to blacklisted domain: {host}')
        if host in shortened_hosts:
            reasons.append(f'Shortened URL detected: {host}')

    risk = 'phishing' if reasons else 'safe'
    status_label = 'Phishing' if risk == 'phishing' else 'Safe'
    return {'risk': risk, 'status': status_label, 'reasons': reasons or ['No phishing indicators found']}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        telegram_chat_id = request.form.get('telegram_chat_id', '').strip() or None
        password = request.form['password']
        
        # Basic validation
        if not all([name, email, phone, password]):
            flash('All fields are required')
            return redirect(url_for('signup'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters')
            return redirect(url_for('signup'))
        
        # Check if email exists
        existing = User.query.filter_by(email=email).first()
        if existing:
            flash('Email already registered')
            return redirect(url_for('signup'))

        if telegram_chat_id:
            if not is_valid_telegram_chat_id(telegram_chat_id):
                flash('Invalid Telegram Chat ID. Use numeric chat ID only.')
                return redirect(url_for('signup'))
            existing_chat = User.query.filter_by(telegram_chat_id=telegram_chat_id).first()
            if existing_chat:
                flash('This Telegram Chat ID is already linked to another account')
                return redirect(url_for('signup'))
        
        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(
            name=name,
            email=email,
            phone=phone,
            telegram_chat_id=telegram_chat_id,
            password_hash=hashed
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Account created successfully! Please login.')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            log_activity(user.id, 'Login')
            return redirect(url_for('dashboard'))
        
        flash('Invalid email or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    user_id = session.pop('user_id', None)
    if user_id:
        log_activity(user_id, 'Logout')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/whatsapp_link')
def whatsapp_link():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('whatsapp_link.html')

@app.route('/api/whatsapp_link', methods=['POST'])
def api_whatsapp_link():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json() or request.form
    url = data.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    from link_analysis import analyze_whatsapp_link
    result = analyze_whatsapp_link(url)
    log_detection(session['user_id'], 'whatsapp_link', url, result)
    return jsonify(result)

@app.route('/link_check', methods=['GET', 'POST'])
def link_check():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = current_user()
    if not user or not user.email:
        flash('Please login with a valid email address to analyze links.')
        return redirect(url_for('login'))
    result = None
    if request.method == 'POST':
        url = request.form['url']
        if url:
            from link_analysis import analyze_link
            result = analyze_link(url)
            log_detection(session['user_id'], 'link', url, result)
            log_activity(session['user_id'], f'Link analyzed ({result.get("severity")})')
            notify_user_of_analysis(user, result)

    return render_template('link_check.html', result=result)

@app.route('/api/report_link', methods=['POST'])
def report_link():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json() or request.form
    url = (data.get('url') or '').strip()
    if not url:
        return jsonify({'error': 'URL is required'}), 400

    from link_analysis import analyze_link
    verified_result = analyze_link(url)
    if verified_result.get('severity') != 'unsafe':
        log_activity(session['user_id'], 'Report rejected - link verified as safe/medium')
        return jsonify({
            'ok': False,
            'message': 'Link is not unsafe after verification. No alert sent.'
        }), 200

    normalized_url = normalize_report_url(url)
    existing = ReportedPhishingLink.query.filter_by(url=normalized_url).first()
    if existing:
        log_activity(session['user_id'], 'Duplicate phishing report blocked')
        return jsonify({
            'ok': False,
            'message': 'This phishing link was already reported. Duplicate alert skipped.'
        }), 200

    try:
        record = ReportedPhishingLink(url=normalized_url, reported_by_user_id=session['user_id'])
        db.session.add(record)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        print(f'[report] Failed to store reported link: {exc}')
        return jsonify({'ok': False, 'message': 'Failed to save report. Please try again.'}), 500

    telegram_sent = broadcast_telegram_alert(url, reporter_user_id=session['user_id'])
    email_sent = notify_other_users(session['user_id'], url, verified_result)
    log_activity(
        session['user_id'],
        f'Phishing link reported (Telegram: {telegram_sent}, Email: {email_sent})'
    )
    return jsonify({
        'ok': True,
        'telegram_sent': telegram_sent,
        'email_sent': email_sent,
        'message': f'Alert sent. Telegram: {telegram_sent}, Email: {email_sent}'
    }), 200

@app.route('/qr_check', methods=['GET', 'POST'])
@app.route('/email_check', methods=['GET', 'POST'])
def qr_check():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    result = None
    if request.method == 'POST':
        file = request.files.get('qr_image')
        from qr_analysis import analyze_qr, analyze_qr_content
        if file and file.filename:
            result = analyze_qr(file)
            log_detection(session['user_id'], 'qr', f'File: {file.filename}', result)
        else:
            result = {'error': 'Please choose a QR code image file to analyze.'}

    return render_template('qr_check.html', result=result)

@app.route('/website_check', methods=['GET', 'POST'])
def website_check():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    result = None
    if request.method == 'POST':
        url = request.form['url']
        if url:
            from website_analysis import analyze_website
            result = analyze_website(url)
            log_detection(session['user_id'], 'website', url, result)
    
    return render_template('website_check.html', result=result)

@app.route('/file_check', methods=['GET', 'POST'])
def file_check():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    result = None
    if request.method == 'POST':
        # Check if file was uploaded
        file = request.files.get('file')
        file_url = request.form.get('file_url', '').strip()
        recursive = request.form.get('recursive_scan', 'on') == 'on'

        if file and file.filename:
            # Save uploaded file temporarily
            import tempfile
            import os
            from pathlib import Path
            
            # Check if it's a folder or single file
            temp_dir = tempfile.mkdtemp()
            file_path = os.path.join(temp_dir, file.filename)
            file.save(file_path)
            
            try:
                from file_analysis import analyze_file, analyze_folder, assess_overall_risk
                
                # Determine if file or folder
                if os.path.isdir(file_path):
                    result = analyze_folder(file_path, recursive=recursive)
                else:
                    result = analyze_file(file_path)
                
                # Add risk assessment
                result = assess_overall_risk(result)
                log_detection(session['user_id'], 'file', f'File: {file.filename}', result)
            except Exception as e:
                result = {'error': f'Analysis error: {str(e)}'}
            finally:
                # Clean up temp file/folder
                import shutil
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)

        elif file_url:
            # Analyze file from URL
            import requests
            from file_analysis import analyze_file, assess_overall_risk
            
            try:
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                response = requests.get(file_url, timeout=30, headers=headers, allow_redirects=True)
                
                if response.status_code == 200:
                    # Save to temp file
                    import tempfile
                    temp_dir = tempfile.mkdtemp()
                    file_name = Path(file_url).name or 'downloaded_file'
                    file_path = os.path.join(temp_dir, file_name)
                    
                    with open(file_path, 'wb') as f:
                        f.write(response.content)
                    
                    try:
                        from file_analysis import analyze_file, assess_overall_risk
                        result = analyze_file(file_path)
                        result = assess_overall_risk(result)
                        log_detection(session['user_id'], 'file', f'URL: {file_url}', result)
                    finally:
                        import shutil
                        if os.path.exists(temp_dir):
                            shutil.rmtree(temp_dir, ignore_errors=True)
                else:
                    result = {'error': f'Failed to download file: HTTP {response.status_code}'}
            except Exception as e:
                result = {'error': f'Error downloading file: {str(e)}'}
        else:
            result = {'error': 'Please upload a file/folder or provide a URL.'}

    return render_template('file_check.html', result=result)

def assess_apk_risk(result):
    """Assess risk level of APK based on analysis results."""
    if result.get('error'):
        return result

    risk_factors = []
    risk_level = 'low'

    # Check permissions for suspicious ones
    suspicious_permissions = [
        'android.permission.READ_SMS',
        'android.permission.SEND_SMS',
        'android.permission.READ_CONTACTS',
        'android.permission.CALL_PHONE',
        'android.permission.RECORD_AUDIO',
        'android.permission.CAMERA',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.ACCESS_COARSE_LOCATION',
        'android.permission.READ_EXTERNAL_STORAGE',
        'android.permission.WRITE_EXTERNAL_STORAGE'
    ]

    permissions = result.get('permissions', [])
    suspicious_found = [p for p in permissions if any(sp in p for sp in suspicious_permissions)]

    if len(suspicious_found) > 5:
        risk_factors.append(f"High number of suspicious permissions ({len(suspicious_found)})")
        risk_level = 'high'
    elif len(suspicious_found) > 2:
        risk_factors.append(f"Multiple suspicious permissions ({len(suspicious_found)})")
        risk_level = 'medium'

    # Check for network-related permissions
    network_perms = [p for p in permissions if 'INTERNET' in p or 'NETWORK' in p or 'ACCESS_WIFI' in p]
    if network_perms:
        risk_factors.append("App can access network/internet")

    # Check package name for suspicious patterns
    package = result.get('package', '')
    if any(susp in package.lower() for susp in ['hack', 'spy', 'keylog', 'malware', 'trojan']):
        risk_factors.append("Suspicious package name")
        risk_level = 'high'

    result['risk_level'] = risk_level
    result['risk_factors'] = risk_factors
    return result

@app.route('/gmail_auth')
def gmail_auth():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if not load_gmail_modules():
        return render_template('gmail_check.html', good_mail=[], bad_mail=[], error=GMAIL_DISABLE_REASON or 'Gmail integration is disabled on this server.')
    try:
        if not os.path.exists(Config.GMAIL_CLIENT_SECRET_FILE):
            return render_template('gmail_check.html', good_mail=[], bad_mail=[], error='Gmail authentication is not configured. Please add client_secret.json.')
        flow = Flow.from_client_secrets_file(
            Config.GMAIL_CLIENT_SECRET_FILE,
            scopes=Config.GMAIL_SCOPES,
            redirect_uri=url_for('gmail_callback', _external=True)
        )
    except Exception as e:
        return render_template('gmail_check.html', good_mail=[], bad_mail=[], error='Gmail authentication is not configured. Please add client_secret.json.')
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def gmail_callback():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if not load_gmail_modules():
        return redirect(url_for('gmail_check'))
    state = session.get('oauth_state')
    try:
        flow = Flow.from_client_secrets_file(
            Config.GMAIL_CLIENT_SECRET_FILE,
            scopes=Config.GMAIL_SCOPES,
            state=state,
            redirect_uri=url_for('gmail_callback', _external=True)
        )
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        session['gmail_credentials'] = credentials_to_dict(credentials)
        print("[gmail] OAuth success; credentials stored in session.")
        return redirect(url_for('gmail_check'))
    except Exception as exc:
        print(f"[gmail] OAuth callback failed: {exc}")
        flash('Gmail authentication failed. Please retry.')
        return redirect(url_for('gmail_check'))


@app.route('/email_analysis', methods=['GET', 'POST'])
def email_analysis():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = current_user()
    result = None
    error = None
    
    if request.method == 'POST':
        email_text = request.form.get('email_text', '').strip()
        if not email_text:
            error = 'Please enter email text to analyze.'
        else:
            try:
                import pickle
                
                base_dir = os.path.dirname(os.path.abspath(__file__))
                model_path = os.path.join(base_dir, 'model.pkl')
                vectorizer_path = os.path.join(base_dir, 'vectorizer.pkl')
                
                # Check if model files exist
                if not os.path.exists(model_path) or not os.path.exists(vectorizer_path):
                    error = '❌ Model not trained. Please run: python train.py'
                else:
                    # Load model and vectorizer
                    with open(model_path, 'rb') as f:
                        model = pickle.load(f)
                    with open(vectorizer_path, 'rb') as f:
                        vectorizer = pickle.load(f)
                    
                    # Clean text
                    def clean_email_text(text):
                        text = text.lower()
                        text = re.sub(r'http[s]?://\S+|www\.\S+', ' ', text)
                        text = re.sub(r'[^a-z\s]', ' ', text)
                        text = re.sub(r'\s+', ' ', text).strip()
                        return text
                    
                    text_clean = clean_email_text(email_text)
                    
                    # Make prediction
                    features = vectorizer.transform([text_clean])
                    prediction = model.predict(features)[0]
                    probabilities = model.predict_proba(features)[0]
                    
                    # Get prediction label and probabilities
                    pred_label = 'Spam' if prediction == 1 else 'Not Spam'
                    spam_prob = float(probabilities[1]) if len(probabilities) > 1 else 0.0
                    ham_prob = float(probabilities[0]) if len(probabilities) > 0 else 1.0
                    
                    result = {
                        'label': pred_label,
                        'spam_probability': spam_prob,
                        'ham_probability': ham_prob,
                        'text': email_text[:200] + '...' if len(email_text) > 200 else email_text
                    }
                    
                    log_detection(session['user_id'], 'email_spam_manual', email_text[:100], result)
                    log_activity(session['user_id'], 'Email analyzed (manual)')
                    
            except Exception as exc:
                print(f"[email_analysis] Error: {exc}")
                import traceback
                traceback.print_exc()
                error = f'Error analyzing email: {str(exc)}'

    return render_template(
        'email_analysis.html',
        result=result,
        error=error,
        user_email=user.email if user else '',
    )

def extract_message_body(message):
    payload = message.get('payload', {})
    body = ''
    if 'parts' in payload:
        for part in payload['parts']:
            data = part.get('body', {}).get('data')
            if data:
                body += base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
    else:
        data = payload.get('body', {}).get('data')
        if data:
            body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
    if not body:
        body = message.get('snippet', '')
    return body

def parse_message_meta(message):
    headers = message.get('payload', {}).get('headers', [])
    meta = {'subject': '', 'sender': '', 'date': '', 'snippet': message.get('snippet', '')}
    for h in headers:
        name = h.get('name')
        value = h.get('value')
        if name == 'Subject':
            meta['subject'] = value
        elif name == 'From':
            meta['sender'] = value
        elif name == 'Date':
            meta['date'] = value
    meta['body'] = extract_message_body(message)
    meta['urls'] = re.findall(r'https?://[^\s]+', meta['body'])
    return meta


def scan_spam_folder(service, max_results=50, label_ids=None):
    """Fetch messages from the Gmail spam folder and classify them."""
    label_ids = label_ids or ['SPAM']
    messages = []
    try:
        list_resp = service.users().messages().list(
            userId='me',
            labelIds=label_ids,
            maxResults=max_results
        ).execute()
    except Exception as exc:
        print(f"[gmail] Error listing spam messages: {exc}")
        raise

    ids = list_resp.get('messages', [])
    if not ids:
        return messages

    for msg in ids:
        try:
            full = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
            meta = parse_message_meta(full)
            risk = classify_gmail_email(meta['sender'], meta['subject'], meta['body'], meta['urls'])
            messages.append({**meta, **risk})
        except Exception as exc:
            print(f"[gmail] Error fetching message {msg.get('id')}: {exc}")
            continue
    return messages

@app.route('/gmail_check')
def gmail_check():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    service = get_gmail_service()
    if not service:
        return render_template('gmail_check.html', good_mail=[], bad_mail=[], error='Gmail integration unavailable or not authenticated.')

    messages = []
    try:
        list_resp = service.users().messages().list(userId='me', labelIds=['SPAM'], maxResults=25).execute()
        ids = list_resp.get('messages', [])
        for msg in ids:
            full = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
            meta = parse_message_meta(full)
            risk = classify_gmail_email(meta['sender'], meta['subject'], meta['body'], meta['urls'])
            messages.append({**meta, **risk})
    except Exception as e:
        print(f"[gmail] Inbox/Spam fetch failed: {e}")
        return render_template('gmail_check.html', good_mail=[], bad_mail=[], error='Error fetching Gmail messages.')

    good_mail = [m for m in messages if m['risk'] == 'safe']
    bad_mail = [m for m in messages if m['risk'] == 'phishing']
    log_detection(session['user_id'], 'gmail', 'Gmail Inbox Scan', {'good': len(good_mail), 'bad': len(bad_mail)})
    return render_template('gmail_check.html', good_mail=good_mail, bad_mail=bad_mail)

if __name__ == '__main__':
    # On some Windows/Python setups the Werkzeug debugger/reloader can hang; default them off here.
    debug_flag = os.environ.get('FLASK_DEBUG', '0') == '1'
    use_reloader = os.environ.get('FLASK_USE_RELOADER', '0') == '1'
    if sys.platform.startswith("win"):
        # Work around Click console stream issues on some Windows + Python 3.13 setups.
        try:
            import flask.cli as flask_cli
            flask_cli.show_server_banner = lambda *args, **kwargs: None
        except Exception as exc:
            print(f"[startup] Could not patch Flask banner: {exc}")
    app.run(debug=debug_flag, use_reloader=use_reloader)
