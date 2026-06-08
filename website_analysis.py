import os
import csv
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    whois = None
    WHOIS_AVAILABLE = False
from datetime import datetime
import difflib
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
MALICIOUS_CSV = os.path.join(DATA_DIR, "malicious_links.csv")
SAFE_DATASET_TXT = os.path.join(DATA_DIR, "safe_sites_from_dataset.txt")
SAFE_1000_TXT = os.path.join(DATA_DIR, "safe_links_1000.txt")
PHISH_1000_TXT = os.path.join(DATA_DIR, "phishing_links_1000.txt")
TYPO_MESSAGE = "This URL contains a possible spelling mistake or suspicious domain. Please verify before proceeding."


def _clean_url_value(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        return ""
    # Users sometimes paste dataset rows like: http://example.com,0
    if value.lower().startswith(("http://", "https://")) and "," in value:
        value = value.split(",", 1)[0].strip()
    return value


def _normalized_domain(parsed):
    host = (parsed.hostname or parsed.netloc or "").lower().strip()
    if host.startswith("www."):
        host = host[4:]
    return host


def _load_malicious_sets():
    urls = set()
    domains = set()
    if not os.path.exists(MALICIOUS_CSV):
        return urls, domains
    try:
        with open(MALICIOUS_CSV, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                raw = _clean_url_value((row.get("url") or "")).lower()
                if not raw:
                    continue
                parsed = urlparse(raw if "://" in raw else f"http://{raw}")
                domain = _normalized_domain(parsed)
                # Treat every entry in malicious_links.csv as malicious (user-provided list of fake sites)
                urls.add(parsed.geturl())
                if domain:
                    domains.add(domain)
    except Exception:
        pass
    return urls, domains


def _load_safe_sets():
    urls = set()
    domains = set()
    if not os.path.exists(SAFE_DATASET_TXT):
        return urls, domains
    try:
        with open(SAFE_DATASET_TXT, encoding="utf-8") as f:
            for line in f:
                raw = line.strip().lower()
                if not raw:
                    continue
                parsed = urlparse(raw if "://" in raw else f"http://{raw}")
                urls.add(parsed.geturl())
                domain = _normalized_domain(parsed)
                if domain:
                    domains.add(domain)
    except Exception:
        pass
    return urls, domains


def _load_plain_url_list(file_path):
    urls = set()
    domains = set()
    if not os.path.exists(file_path):
        return urls, domains
    try:
        with open(file_path, encoding="utf-8") as f:
            for line in f:
                raw = line.strip().lower()
                if not raw:
                    continue
                parsed = urlparse(raw if "://" in raw else f"http://{raw}")
                urls.add(parsed.geturl())
                domain = _normalized_domain(parsed)
                if domain:
                    domains.add(domain)
    except Exception:
        pass
    return urls, domains


MAL_URLS, MAL_DOMAINS = _load_malicious_sets()
SAFE_URLS, SAFE_DOMAINS = _load_safe_sets()
SAFE_1000_URLS, SAFE_1000_DOMAINS = _load_plain_url_list(SAFE_1000_TXT)
PHISH_1000_URLS, PHISH_1000_DOMAINS = _load_plain_url_list(PHISH_1000_TXT)


def _detect_typo_domain(domain: str):
    """
    Lightweight typo/typosquat detection focused on obvious mistakes
    (extra/missing characters, close matches to safe domains).
    """
    if not domain:
        return False, "", None

    core = domain
    if core.startswith('www.'):
        core = core[4:]
    parts = core.split('.')
    if len(parts) > 2:
        core = '.'.join(parts[-2:])

    prefix = domain.split('.')[0]
    if prefix != 'www' and prefix.startswith('w') and len(prefix) >= 2:
        return True, TYPO_MESSAGE, None

    if re.search(r'(.)\1\1', core) or core.startswith('wwww'):
        return True, TYPO_MESSAGE, None

    close_matches = difflib.get_close_matches(core, SAFE_DOMAINS, n=1, cutoff=0.82)
    if close_matches:
        suggestion = close_matches[0]
        if suggestion != core:
            return True, f"{TYPO_MESSAGE} Did you mean: {suggestion}?", suggestion

    return False, "", None


def analyze_website(url):
    """
    Analyze website with simple heuristics and return severity, badge, color, and reasons.
    """
    result = {}
    reasons = []
    try:
        normalized_url = _clean_url_value(url)
        if not normalized_url:
            return {'error': 'Error analyzing website: URL is required'}
        if '://' not in normalized_url:
            normalized_url = f'https://{normalized_url}'

        parsed = urlparse(normalized_url)
        domain = _normalized_domain(parsed)

        typo_flag, typo_reason, suggestion = _detect_typo_domain(domain)
        if typo_flag:
            reasons = [typo_reason or TYPO_MESSAGE]
            color_map = {'warning': '#fd7e14'}
            result.update({
                'url': url,
                'ssl': 'Not analyzed (typo suspected)',
                'domain_age': 'Not analyzed',
                'phishing_indicators': 'Not analyzed',
                'blacklist': 'Not analyzed',
                'overall': 'Warning - possible typo domain',
                'severity': 'warning',
                'badge': 'warning',
                'color': color_map['warning'],
                'reasons': reasons,
                'typo_detected': True,
                'suggested_domain': suggestion
            })
            return result

        normalized_lower = normalized_url.lower()

        # Hard match against malicious datasets
        if (
            normalized_lower in MAL_URLS
            or domain in MAL_DOMAINS
            or normalized_lower in PHISH_1000_URLS
            or domain in PHISH_1000_DOMAINS
        ):
            severity = 'unsafe'
            badge = 'danger'
            color_map = {'safe': '#198754', 'medium': '#fd7e14', 'unsafe': '#dc3545'}
            result.update({
                'url': normalized_url,
                'ssl': 'Unknown',
                'domain_age': 'Not checked (blocked by dataset hit)',
                'phishing_indicators': 'N/A (dataset hit)',
                'blacklist': 'Matched local phishing dataset',
                'overall': 'High Risk - Listed as malicious',
                'severity': severity,
                'badge': badge,
                'color': color_map[severity],
                'reasons': ['URL/domain found in local phishing dataset']
            })
            return result

        # Hard match against safe datasets (only after malicious checks)
        if (
            normalized_lower in SAFE_URLS
            or domain in SAFE_DOMAINS
            or normalized_lower in SAFE_1000_URLS
            or domain in SAFE_1000_DOMAINS
        ):
            severity = 'safe'
            badge = 'success'
            color_map = {'safe': '#198754', 'medium': '#fd7e14', 'unsafe': '#dc3545'}
            result.update({
                'url': normalized_url,
                'ssl': 'Not checked (safe list hit)',
                'domain_age': 'Not checked (safe list hit)',
                'phishing_indicators': 'N/A (safe list hit)',
                'blacklist': 'N/A',
                'overall': 'Low Risk - Listed as safe',
                'severity': severity,
                'badge': badge,
                'color': color_map[severity],
                'reasons': ['URL/domain found in local safe dataset']
            })
            return result

        # SSL Check
        if normalized_url.startswith('https://'):
            ssl = 'Secure (HTTPS)'
        else:
            ssl = 'Insecure (HTTP)'
            reasons.append('Site does not use HTTPS')

        # Domain Reputation
        if WHOIS_AVAILABLE:
            try:
                w = whois.whois(domain)
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if creation_date:
                    age_days = (datetime.now() - creation_date).days
                    if age_days < 365:
                        domain_age = f'Suspicious - Domain age: {age_days} days'
                        reasons.append(f'Very new domain ({age_days} days old)')
                    else:
                        domain_age = f'Safe - Domain age: {age_days} days'
                else:
                    domain_age = 'Unable to check domain age'
                    reasons.append('Could not verify domain age')
            except Exception:
                domain_age = 'Unable to check domain age'
                reasons.append('Could not verify domain age')
        else:
            domain_age = 'WHOIS not available - could not check domain age'
            reasons.append('WHOIS module not available - could not verify domain age')

        # Fetch Page Content
        found_indicators = []
        phishing_indicators_text = 'Unavailable (could not fetch page content)'
        try:
            response = requests.get(normalized_url, timeout=10, verify=False)  # verify=False for self-signed, but in prod use True
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            # Phishing Indicators
            text_content = soup.get_text().lower()
            phishing_indicators = ['login', 'password', 'bank', 'paypal', 'credit card', 'social security', 'urgent', 'verify']
            found_indicators = [i for i in phishing_indicators if i in text_content]
            if found_indicators:
                phishing_indicators_text = f'Found: {", ".join(found_indicators)}'
                reasons.append(f'Page contains sensitive keywords: {", ".join(found_indicators)}')
            else:
                phishing_indicators_text = 'None found'
        except requests.RequestException as exc:
            reasons.append(f'Could not fetch website content: {exc}')

        # Blacklist Check (placeholder)
        blacklist = 'Blacklist check requires external service integration'

        # Overall risk scoring
        risk_score = 0
        if not normalized_url.startswith('https://'):
            risk_score += 1
        if 'Suspicious' in domain_age:
            risk_score += 1
        if found_indicators:
            risk_score += 1
        if phishing_indicators_text.startswith('Unavailable'):
            risk_score += 1

        if risk_score >= 2:
            severity = 'unsafe'
            overall = 'High Risk - Potential Phishing Site'
            badge = 'danger'
        elif risk_score == 1:
            severity = 'medium'
            overall = 'Medium Risk'
            badge = 'warning'
        else:
            severity = 'safe'
            overall = 'Low Risk'
            badge = 'success'

        color_map = {'safe': '#198754', 'medium': '#fd7e14', 'unsafe': '#dc3545'}
        final_reasons = reasons or ['No strong signals detected; proceed with caution']

        result.update({
            'url': normalized_url,
            'ssl': ssl,
            'domain_age': domain_age,
            'phishing_indicators': phishing_indicators_text,
            'blacklist': blacklist,
            'overall': overall,
            'severity': severity,
            'badge': badge,
            'color': color_map.get(severity, '#6c757d'),
            'reasons': final_reasons
        })

    except Exception as e:
        result['error'] = f'Error analyzing website: {str(e)}'

    return result
