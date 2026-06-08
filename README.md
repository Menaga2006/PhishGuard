# PhishOrucad - Real-Time Phishing Link Detection and Alert System

A comprehensive cybersecurity web application for detecting various types of phishing threats including links, emails, QR codes, APK files, and websites.

## Features

- **User Authentication**: Secure signup/login with bcrypt password hashing
- **Link Analysis**: URL structure, SSL check, domain reputation, keyword detection
- **Email Analysis**: Content analysis for phishing keywords and spam indicators
- **QR Code Analysis**: Upload and scan QR codes for malicious URLs
- **APK Analysis**: Static analysis of Android APK files for malware and permissions
- **Website Analysis**: Domain checks, SSL verification, phishing indicators
- **Activity Logging**: Track user actions and detection results
- **MySQL Database**: Persistent storage for users and detection data

## Tech Stack

- **Backend**: Python Flask
- **Frontend**: HTML, CSS, Bootstrap
- **Database**: MySQL
- **Security**: bcrypt, input validation, secure sessions

## Installation

### Prerequisites

- Python 3.8+
- MySQL Server
- pip (Python package manager)

### Setup

1. **Clone or download the project**
   ```bash
   cd phishproject
   ```

2. **Create virtual environment**
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # On Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Setup MySQL Database**
   - Install MySQL Server
   - Create a database named `phishorucad`
   - Update `config.py` with your MySQL credentials:
     ```python
     SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://username:password@localhost/phishorucad'
     ```

5. **Configure API Keys (Optional)**
   - For VirusTotal integration: Set `VIRUSTOTAL_API_KEY` in environment or config
   - For Gmail API: Place `client_secret.json` in project root

6. **Run the application**
   ```bash
   python app.py
   ```

7. **Access the application**
   - Open http://localhost:5000 in your browser
   - Create an account and start analyzing threats

## Project Structure

```
phishproject/
├── app.py                 # Main Flask application
├── config.py              # Configuration settings
├── models.py              # Database models
├── link_analysis.py       # Link analysis module
├── email_analysis.py      # Email analysis module
├── qr_analysis.py         # QR code analysis module
├── apk_analysis.py        # APK analysis module
├── website_analysis.py    # Website analysis module
├── requirements.txt       # Python dependencies
├── templates/             # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── signup.html
│   ├── dashboard.html
│   ├── link_check.html
│   ├── email_check.html
│   ├── qr_check.html
│   ├── apk_check.html
│   └── website_check.html
├── static/                # Static assets
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── script.js
└── README.md
```

## Security Notes

- **APK Analysis**: Performed statically without installation or execution
- **Input Validation**: All user inputs are validated and sanitized
- **Password Security**: Passwords are hashed using bcrypt
- **Session Management**: Secure Flask sessions with secret keys
- **No File Execution**: Uploaded files are analyzed without running them

## API Integrations

- **VirusTotal**: For APK malware scanning (requires API key)
- **Gmail API**: For email analysis (requires OAuth setup)
- **WHOIS**: For domain age checking
- **SSL Verification**: Built-in Python SSL module

## Usage

1. Register a new account or login
2. Access the dashboard
3. Choose an analysis tool:
   - Enter URLs for link/website analysis
   - Paste email content for email analysis
   - Upload images for QR code analysis
   - Upload APK files for Android app analysis
4. View detailed analysis results with risk assessments

## Development

- Run in debug mode: `python app.py`
- Database migrations: Flask-Migrate can be added for schema changes
- Testing: Add unit tests for analysis functions

## License

This project is for educational and cybersecurity purposes. Use responsibly and in compliance with applicable laws.

## Disclaimer

This tool provides analysis based on known patterns and indicators. It is not foolproof and should be used as part of a comprehensive security strategy.