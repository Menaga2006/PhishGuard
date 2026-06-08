import os
import csv
import re
import difflib
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    whois = None
    WHOIS_AVAILABLE = False
from urllib.parse import urlparse
from datetime import datetime

from models import db, MaliciousLink

try:
    import joblib  # lightweight loader for scikit-learn models
except Exception:  # pragma: no cover
    joblib = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
DATASET_PATH = os.path.join(DATA_DIR, 'malicious_links.csv')  # optional Kaggle dump


def _load_list(filename):
    path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(path):
        return set()
    with open(path, 'r', encoding='utf-8') as f:
        return {line.strip().lower() for line in f if line.strip()}


SAFE_SET = _load_list('safe_links.txt')
PHISH_SET = _load_list('phishing_links.txt')
SAFE_URLS_1000 = _load_list('safe_links_1000.txt')
PHISH_URLS_1000 = _load_list('phishing_links_1000.txt')
SAFE_DATASET_URLS = _load_list('safe_sites_from_dataset.txt')
_DATASET_SEEDED = False
_ML_MODEL = None
_TYPO_MESSAGE = "Spelling mistake detected in the link. Please verify the domain before proceeding."


def _normalize_domain(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    if ':' in host:
        host = host.split(':')[0]
    # Only strip the standard www. prefix (not wwww/ww)
    if host.startswith('www.') and not host.startswith('wwww.'):
        host = host[4:]
    return host


def _normalize_host(value: str) -> str:
    """Normalize a domain-like string or URL into host only."""
    value = (value or '').strip().lower()
    if not value:
        return ''
    parsed = urlparse(value if '://' in value else f'http://{value}')
    host = parsed.netloc or parsed.path
    host = host.lower()
    if ':' in host:
        host = host.split(':')[0]
    if host.startswith('www.') and not host.startswith('wwww.'):
        host = host[4:]
    return host


def _canonicalize_url_for_match(value: str) -> str:
    """
    Canonical URL form for set membership checks.
    Keeps host/path/query but ignores scheme and trailing slash differences.
    """
    value = (value or '').strip()
    if not value:
        return ''
    parsed = urlparse(value if '://' in value else f'http://{value}')
    host = _normalize_host(parsed.netloc or parsed.path)
    path = (parsed.path or '').strip()
    if path and path != '/':
        path = path.rstrip('/')
    query = parsed.query or ''
    canon = f'{host}{path}'
    if query:
        canon = f'{canon}?{query}'
    return canon.lower()


def _detect_typo_domain(domain: str):
    """
    Detect obvious typos/typosquats before doing any classification.
    Returns (flag: bool, reason: str, suggested: str|None).
    """
    if not domain:
        return False, "", None

    # Strip common subdomains so typo detection focuses on the registrable part
    core = domain
    if core.startswith('www.'):
        core = core[4:]
    parts = core.split('.')
    if len(parts) > 2:
        core = '.'.join(parts[-2:])  # use eTLD+1 approximation

    # Prefix like wwww.example.com or ww.example.com
    prefix = domain.split('.')[0]
    if prefix != 'www' and prefix.startswith('w') and len(prefix) >= 2:
        return True, _TYPO_MESSAGE, None

    # Pattern: extra leading/trailing characters (e.g., wwww.google.com, gooogle.com)
    if re.search(r'(.)\1\1', core) or core.startswith('wwww') or core.endswith('..'):
        return True, _TYPO_MESSAGE, None

    # Close-match against known safe domains to catch missing / swapped characters
    close_matches = difflib.get_close_matches(core, KNOWN_SAFE_DOMAINS, n=1, cutoff=0.82)
    if close_matches:
        suggestion = close_matches[0]
        if suggestion != core:
            return True, f"Spelling mistake detected in the link domain. Did you mean: {suggestion}?", suggestion

    return False, "", None


def _safe_dataset_domains():
    domains = set()
    for u in SAFE_DATASET_URLS:
        parsed = urlparse(u if '://' in u else f'http://{u}')
        if parsed.netloc:
            domains.add(parsed.netloc.lower())
    return domains


SAFE_DATASET_DOMAINS = _safe_dataset_domains()


def _build_known_safe_domains():
    domains = set()
    for value in (SAFE_SET | SAFE_URLS_1000 | SAFE_DATASET_URLS):
        host = _normalize_host(value)
        if host and '.' in host:
            domains.add(host)
    return domains


KNOWN_SAFE_DOMAINS = _build_known_safe_domains()
SAFE_URLS_1000_CANON = {_canonicalize_url_for_match(u) for u in SAFE_URLS_1000 if u.strip()}
PHISH_URLS_1000_CANON = {_canonicalize_url_for_match(u) for u in PHISH_URLS_1000 if u.strip()}
SAFE_DATASET_URLS_CANON = {_canonicalize_url_for_match(u) for u in SAFE_DATASET_URLS if u.strip()}


def _typosquat_reason(domain):
    for safe in KNOWN_SAFE_DOMAINS:
        if domain == safe:
            continue
        ratio = difflib.SequenceMatcher(None, domain, safe).ratio()
        if ratio >= 0.82:
            return f'Domain resembles {safe} (possible typo). Did you mean: {safe}?'
    return None


def _purpose_from_url(url: str) -> str:
    text = url.lower()
    buckets = {
        'Credential harvesting': ['login', 'signin', 'auth', 'password', 'account', 'verify'],
        'Financial theft': ['bank', 'payment', 'wallet', 'upi', 'paypal', 'invoice', 'credit'],
        'Prize / giveaway scam': ['prize', 'lottery', 'reward', 'bonus', 'gift', 'winner'],
        'Malware / download bait': ['download', 'update', 'install', 'setup', 'exe', 'apk'],
    }
    for label, keywords in buckets.items():
        if any(k in text for k in keywords):
            return label
    return 'General browsing / no obvious phishing intent'


def _seed_dataset_from_csv(limit: int | None = None):
    """
    Best-effort import of an offline malicious links CSV (e.g., Kaggle dataset).
    Executed once per process; adds any rows that are not already present.
    """
    global _DATASET_SEEDED
    if _DATASET_SEEDED:
        return

    _DATASET_SEEDED = True
    if not os.path.exists(DATASET_PATH):
        return

    try:
        new_rows = []
        with open(DATASET_PATH, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader):
                if limit and idx >= limit:
                    break
                raw_url = row.get('url') or row.get('URL') or row.get('phish_url') or row.get('phishing_url')
                label_raw = str(row.get('label') or row.get('Label') or row.get('type') or '').strip().lower()
                is_phish = label_raw in {'1', 'true', 'phish', 'phishing', 'malware', 'defacement'}
                if not raw_url:
                    continue
                domain = _normalize_domain(raw_url)
                if not domain:
                    continue
                exists = MaliciousLink.query.filter(
                    (MaliciousLink.domain == domain) | (MaliciousLink.url == raw_url)
                ).first()
                if exists:
                    continue
                new_rows.append(
                    MaliciousLink(
                        url=raw_url.strip(),
                        domain=domain,
                        label=label_raw or ('phishing' if is_phish else 'benign'),
                        source='kaggle_dataset'
                    )
                )
        if new_rows:
            db.session.bulk_save_objects(new_rows)
            db.session.commit()
    except Exception:
        db.session.rollback()


def _load_ml_model():
    """Load a serialized scikit-learn model if available."""
    global _ML_MODEL
    if _ML_MODEL or not joblib:
        return _ML_MODEL
    model_path = os.path.join(DATA_DIR, 'phish_model.pkl')
    if os.path.exists(model_path):
        try:
            _ML_MODEL = joblib.load(model_path)
        except Exception:
            _ML_MODEL = None
    return _ML_MODEL


def _lookup_malicious(domain: str, url: str):
    _seed_dataset_from_csv()
    try:
        # exact match first
        hit = MaliciousLink.query.filter(
            (MaliciousLink.domain == domain) | (MaliciousLink.url == url)
        ).first()
        if hit:
            return hit

        # suffix/pattern match (e.g., secure.paypal.com vs paypal.com)
        candidates = MaliciousLink.query.filter(db.func.length(MaliciousLink.domain) <= len(domain)).all()
        for cand in candidates:
            if domain.endswith(cand.domain):
                return cand
        return None
    except Exception:
        return None


def _extract_features(url: str, domain: str):
    parsed = urlparse(url)
    path = parsed.path or ''
    query = parsed.query or ''
    text = url.lower()
    features = {
        'len_url': len(url),
        'len_domain': len(domain),
        'num_dots': domain.count('.'),
        'has_ip': 1 if re.search(r'^\d{1,3}(\.\d{1,3}){3}$', domain) else 0,
        'has_at': 1 if '@' in url else 0,
        'uses_https': 1 if parsed.scheme == 'https' else 0,
        'path_len': len(path),
        'query_len': len(query),
        'suspicious_kw': sum(k in text for k in ['login', 'verify', 'update', 'password', 'bank', 'free', 'win']),
        'special_chars': sum(text.count(ch) for ch in ['%', '#', '&', ';', '=']),
    }
    return features


def _ml_predict_prob(url: str, domain: str, heuristic_score: int):
    """
    Returns probability (0-1) of phishing using ML model if present,
    otherwise derives a probability from heuristic score.
    """
    model = _load_ml_model()
    if model:
        feats = _extract_features(url, domain)
        # Preserve column order if model was trained with a fixed list
        feature_vec = [
            feats['len_url'],
            feats['len_domain'],
            feats['num_dots'],
            feats['has_ip'],
            feats['has_at'],
            feats['uses_https'],
            feats['path_len'],
            feats['query_len'],
            feats['suspicious_kw'],
            feats['special_chars'],
        ]
        try:
            proba = model.predict_proba([feature_vec])[0][1]
            return float(proba)
        except Exception:
            pass

    # Fallback: map heuristic score (0-100ish) to 0-1
    return min(0.99, max(0.01, heuristic_score / 100.0))


def analyze_link(url: str):
    domain = _normalize_domain(url)
    canonical_url = _canonicalize_url_for_match(url)
    reasons = []
    heuristic_score = 0
    purpose = _purpose_from_url(url)
    source_hit = None
    url_lower = url.lower()

    if not domain:
        return {
            'url': url,
            'domain': '',
            'severity': 'medium',
            'status': 'Unknown',
            'color': '#fd7e14',
            'badge': 'warning',
            'reasons': ['Could not parse domain from URL'],
            'purpose': 'Unknown',
            'score': heuristic_score,
            'legacy_status': 'POTENTIALLY SUSPICIOUS LINK'
        }

    typo_flag, typo_reason, suggestion = _detect_typo_domain(domain)
    if typo_flag:
        reasons.append(typo_reason or _TYPO_MESSAGE)
        heuristic_score += 20

    # Exact URL hits from safe list (highest priority)
    if url_lower in SAFE_DATASET_URLS or canonical_url in SAFE_DATASET_URLS_CANON or domain in SAFE_DATASET_DOMAINS:
        return {
            'url': url,
            'domain': domain,
            'severity': 'safe',
            'status': 'Safe',
            'color': '#198754',
            'badge': 'success',
            'reasons': ['URL/domain found in safe_sites_from_dataset list'],
            'purpose': 'Trusted / dataset-marked safe website',
            'score': heuristic_score,
            'source_hit': 'safe_sites_from_dataset',
            'legacy_status': 'SAFE LINK'
        }

    # Exact URL hits from sampled lists (phishing or curated safe)
    url_lower = url.lower()
    if url_lower in PHISH_URLS_1000 or canonical_url in PHISH_URLS_1000_CANON:
        phish_reasons = list(reasons) if reasons else []
        phish_reasons.append('URL found in high-confidence phishing sample list')
        return {
            'url': url,
            'domain': domain,
            'severity': 'unsafe',
            'status': 'Unsafe',
            'color': '#dc3545',
            'badge': 'danger',
            'reasons': phish_reasons,
            'purpose': purpose,
            'score': 90,
            'source_hit': 'phishing_links_1000.txt',
            'typo_detected': typo_flag,
            'suggested_domain': suggestion,
            'legacy_status': 'PHISHING LINK'
        }
    if url_lower in SAFE_URLS_1000 or canonical_url in SAFE_URLS_1000_CANON:
        reasons.append('URL appears in curated safe sample list')

    safe_candidate = domain in SAFE_SET
    if safe_candidate:
        reasons.append('Domain appears in curated safe database')

    # Database of known malicious links (Kaggle or curated)
    known = _lookup_malicious(domain, url)
    if domain in PHISH_SET:
        heuristic_score += 85
        reasons.append('Domain found in local phishing blocklist')
        source_hit = 'local_list'
    if known:
        source_hit = known.source or 'malicious dataset'
        label = str(known.label or '').lower()
        if label in {'1', 'true', 'phish', 'phishing', 'malware', 'defacement'}:
            heuristic_score += 85
            reasons.append(f'Found in malicious link database (source: {source_hit})')
            color_map = {'safe': '#198754', 'medium': '#fd7e14', 'unsafe': '#dc3545'}
            return {
                'url': url,
                'domain': domain,
                'severity': 'unsafe',
                'status': 'Unsafe',
                'color': color_map['unsafe'],
                'badge': 'danger',
                'reasons': reasons,
                'purpose': purpose,
                'score': heuristic_score,
                'source_hit': source_hit,
                'typo_detected': typo_flag,
                'suggested_domain': suggestion,
                'legacy_status': 'PHISHING LINK'
            }
        elif label in {'0', 'benign', 'legit', 'safe'}:
            reasons.append(f'Found as benign in dataset (source: {source_hit})')
            safe_candidate = True

    # Heuristic / AI-lite signals
    text = url.lower()
    suspicious_keywords = ['login', 'password', 'bank', 'paypal', 'free', 'win', 'urgent', 'click', 'verify', 'reset']
    if any(k in text for k in suspicious_keywords):
        heuristic_score += 15
        reasons.append('Contains phishing-related keywords')

    if domain.count('.') > 2:
        heuristic_score += 10
        reasons.append('Domain has an unusually high number of dots')

    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
    if any(s in domain for s in shorteners):
        heuristic_score += 25
        reasons.append('URL shortener detected')

    if re.search(r'//\d{1,3}(\.\d{1,3}){3}', url):
        heuristic_score += 25
        reasons.append('Uses raw IP address instead of domain')

    if urlparse(url).scheme != 'https':
        heuristic_score += 10
        reasons.append('Not using HTTPS')

    typo = _typosquat_reason(domain)
    if typo:
        heuristic_score += 20
        reasons.append(typo)

    # Domain age / reputation (basic WHOIS)
    if WHOIS_AVAILABLE:
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age_days = (datetime.now() - creation_date).days
            if age_days < 180:
                heuristic_score += 20
                reasons.append(f'Domain is very new ({age_days} days old)')
        except Exception:
            heuristic_score += 5
            reasons.append('Could not verify domain age/reputation')
    else:
        heuristic_score += 5
        reasons.append('WHOIS module not available - could not verify domain age')

    ml_prob = _ml_predict_prob(url, domain, heuristic_score)
    reasons.append(f'AI model phishing probability: {ml_prob:.2f}')

    # Final classification: must pass both DB (already checked) and AI thresholds to be Safe
    if ml_prob >= 0.70:
        severity = 'unsafe'
        status = 'Unsafe'
        badge = 'danger'
        legacy_status = 'PHISHING LINK'
    elif ml_prob >= 0.40 or heuristic_score >= 40:
        severity = 'medium'
        status = 'Medium Risk'
        badge = 'warning'
        legacy_status = 'POTENTIALLY SUSPICIOUS LINK'
    else:
        severity = 'safe'
        status = 'Safe'
        badge = 'success'
        legacy_status = 'SAFE LINK'

    # Only allow Safe when both AI probability is low and domain was not flagged; safe list adds confidence
    if severity == 'safe' and not safe_candidate:
        reasons.append('Passed ML screen with low risk but not in safe database')
    elif severity == 'safe' and safe_candidate:
        reasons.append('Low ML risk and appears in safe database')

    color_map = {'safe': '#198754', 'medium': '#fd7e14', 'unsafe': '#dc3545'}
    final_reasons = reasons or ['No strong signals detected; proceed with caution']

    return {
        'url': url,
        'domain': domain,
        'severity': severity,
        'status': status,
        'color': color_map.get(severity, '#6c757d'),
        'badge': badge,
        'reasons': final_reasons,
        'purpose': purpose,
        'score': heuristic_score,
        'source_hit': source_hit,
        'typo_detected': typo_flag,
        'suggested_domain': suggestion,
        'legacy_status': legacy_status
    }


def analyze_whatsapp_link(url):
    base = analyze_link(url)
    severity = base.get('severity', 'medium')
    risk_level = 'safe' if severity == 'safe' else ('danger' if severity == 'unsafe' else 'caution')
    safe = severity == 'safe'
    return {
        'url': url,
        'overall': base.get('status'),
        'risk_level': risk_level,
        'safe': safe,
        'reasons': base.get('reasons', []),
        'details': base
    }
