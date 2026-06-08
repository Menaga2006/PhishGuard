# Launch the Flask app using the project virtualenv with safer defaults on Windows.
# Usage: in PowerShell from repo root: `.\run_local.ps1`

# Prevent Python from loading user-site packages (avoids global site-packages/WMI slowdowns)
$env:PYTHONNOUSERSITE = "1"

# Reduce SQLAlchemy WMI overhead on Windows by disabling C extensions
$env:DISABLE_SQLALCHEMY_CEXT = "1"
$env:SQLALCHEMY_DISABLE_CEXT = "1"

# If you need Gmail on Python 3.13, uncomment the next line
# $env:ALLOW_GMAIL_ON_PY313 = "1"

.\.venv\Scripts\python.exe app.py
