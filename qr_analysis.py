from pyzbar.pyzbar import decode
from PIL import Image
from PIL import ImageOps
import re
from link_analysis import analyze_link

# Common URL shorteners used for phishing redirects
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly', 'cutt.ly', 'is.gd', 'rebrand.ly'
}

TRUSTED_DOMAINS = {
    'nptel.ac.in', 'iitb.ac.in', 'iitm.ac.in'
}
TRUSTED_SUFFIXES = ('.gov', '.gov.in', '.govt.in', '.edu', '.edu.in', '.ac.in')


def _is_trusted_domain(domain: str) -> bool:
    d = domain.lower()
    return d in TRUSTED_DOMAINS or d.endswith(TRUSTED_SUFFIXES)


def _normalize_domain(url: str) -> str:
    """Lightweight domain extractor; mirrors link_analysis behavior for leading www/ports."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    if ':' in host:
        host = host.split(':')[0]
    if host.startswith('www.') and not host.startswith('wwww.'):
        host = host[4:]
    return host


def _purpose_from_text(text: str) -> str:
    lower = text.lower()
    buckets = {
        'payment link': ['upi', 'pay', 'payment', 'wallet', 'invoice'],
        'authentication / login': ['otp', 'login', 'signin', 'verify', 'password'],
        'contact/info page': ['contact', 'about', 'info'],
        'promo / offer': ['offer', 'coupon', 'sale', 'discount', 'deal'],
    }
    for label, kws in buckets.items():
        if any(k in lower for k in kws):
            return label
    return 'general information'


def _classify_text_payload(text: str):
    lower = text.lower()
    suspicious_keywords = ['password', 'otp', 'verify', 'bank', 'pay', 'credit', 'prize', 'free', 'urgent']
    suspicious_cmds = [
        r'rm\s+-rf\s+/', r'curl\s+.+\|\s*sh', r'wget\s+.+\|\s*sh', r'powershell\s+-enc',
        r'cmd\.exe\s+/c', r'base64\s+-d', r'\.exe\b', r'\.bat\b'
    ]
    reasons = []
    # UPI payment intents: default to safe (with caution) and whitelist trusted beneficiaries
    if lower.startswith('upi://'):
        payee = None
        m = re.search(r'pa=([^&]+)', lower)
        if m:
            payee = m.group(1)
        trusted_payee = payee and any(tag in payee for tag in ['iitm', 'iitmadras', 'iitb', 'gov', '.gov.in', '.edu', '.ac.in'])
        if trusted_payee:
            severity = 'safe'
            status = 'Safe'
            reasons.append('Trusted UPI beneficiary detected')
        else:
            severity = 'medium'
            status = 'Caution'
            reasons.append('UPI payment link; verify payee before proceeding')
        # Skip generic keyword escalation for UPI flows
    elif any(re.search(pat, lower) for pat in suspicious_cmds):
        severity = 'unsafe'
        status = 'Unsafe'
        reasons.append('Content resembles a command/script payload')
    elif re.search(r'[\\w\\.]+@[\\w\\.]+', lower):
        severity = 'unsafe'
        status = 'Unsafe'
        reasons.append('Contains an email target; treat with caution')
    elif any(k in lower for k in suspicious_keywords):
        severity = 'unsafe'
        status = 'Unsafe'
        reasons.append('Suspicious keywords detected in QR content')
    if not reasons:
        severity = 'safe'
        status = 'Safe'
        reasons.append('No risky keywords or commands detected in QR content')

    purpose = _purpose_from_text(text)
    color_map = {'safe': '#198754', 'unsafe': '#dc3545', 'medium': '#fd7e14'}
    badge = 'success' if severity == 'safe' else ('warning' if severity == 'medium' else 'danger')
    verdict = 'SAFE' if severity == 'safe' else ('CAUTION' if severity == 'medium' else 'UNSAFE')
    explanation = reasons[0] if reasons else 'No issues detected'
    return {
        'payload_type': 'text',
        'content': text,
        'severity': severity,
        'status': status,
        'color': color_map[severity],
        'badge': badge,
        'purpose': purpose,
        'reasons': reasons,
        'verdict': verdict,
        'explanation': explanation
    }


def analyze_qr_content(content: str):
    """
    Analyze raw QR content (URL or text).
    """
    # Normalize common obfuscations like hxxp:// to http:// for analysis
    normalized = re.sub(r'^hxxp(s?)://', r'http\1://', content, flags=re.IGNORECASE)
    url_match = re.match(r'https?://', normalized, re.IGNORECASE)

    if url_match:
        from urllib.parse import urlparse
        domain = _normalize_domain(normalized)
        scheme = urlparse(normalized).scheme.lower()

        # Immediate allow for verified/trusted domains
        if _is_trusted_domain(domain):
            reasons = ['Trusted academic/government domain']
            return {
                'payload_type': 'url',
                'extracted_url': content,
                'domain': domain,
                'severity': 'safe',
                'status': 'Safe (trusted domain)',
                'color': '#198754',
                'badge': 'success',
                'reasons': reasons,
                'purpose': 'Trusted site',
                'verdict': 'SAFE',
                'explanation': reasons[0],
            }

        result = analyze_link(normalized)

        # Map severity to requested verdicts
        severity = result.get('severity')
        if severity == 'safe':
            verdict = 'SAFE'
        elif severity == 'unsafe':
            verdict = 'UNSAFE'
        else:
            verdict = 'CAUTION'
        reasons = result.get('reasons', [])

        # Flag URL shorteners explicitly for QR flows
        domain = result.get('domain', '')
        if domain in URL_SHORTENERS and 'URL shortener detected' not in reasons:
            reasons.insert(0, 'URL shortener detected')

        # Flag obfuscated hxxp scheme
        if normalized != content and 'Obfuscated URL (hxxp->http)' not in reasons:
            reasons.insert(0, 'Obfuscated URL (hxxp->http) detected')

        # Strong phishing signals override to UNSAFE
        phishing_signals = [
            'phish', 'phishing', 'login', 'verify', 'secure', 'account'
        ]
        if any(sig in normalized.lower() for sig in phishing_signals) or any('phish' in r.lower() for r in reasons):
            result['severity'] = 'unsafe'
            verdict = 'UNSAFE'
            result['status'] = 'Unsafe'
            result['badge'] = 'danger'
            result['color'] = '#dc3545'
            if not any('phish' in r.lower() for r in reasons):
                reasons.insert(0, 'Phishing-related terms detected in URL')

        # Explanation tailored to verdict
        if verdict == 'UNSAFE':
            explanation = reasons[0] if reasons else 'Phishing patterns detected'
        elif verdict == 'CAUTION':
            if scheme == 'https':
                explanation = reasons[0] if reasons else 'Unknown domain; HTTPS and no strong phishing patterns detected'
            else:
                explanation = reasons[0] if reasons else 'Unknown domain; lacks HTTPS; no strong phishing patterns detected'
        else:  # SAFE
            if _is_trusted_domain(domain):
                explanation = 'Verified/trusted site'
            else:
                explanation = reasons[0] if reasons else 'Unknown domain but likely safe (no phishing patterns detected)'
        result.update({
            'payload_type': 'url',
            'extracted_url': content,
            'verdict': verdict,
            'explanation': explanation,
            'reasons': reasons,
        })
        return result
    return _classify_text_payload(content)


def analyze_qr(image_file):
    """
    Decode QR from an image and analyze its payload.
    """
    try:
        # Convert to RGB to support WEBP/other formats uniformly
        base_img = Image.open(image_file).convert("RGB")

        candidates = []
        candidates.append(base_img)

        gray = ImageOps.grayscale(base_img)
        candidates.append(gray)
        candidates.append(ImageOps.autocontrast(gray))

        # Hard threshold often helps weak QR contrast.
        bw = gray.point(lambda p: 255 if p > 140 else 0)
        candidates.append(bw)

        # Upscale to help tiny QR images.
        w, h = base_img.size
        if min(w, h) < 800:
            upscaled = base_img.resize((w * 2, h * 2), Image.Resampling.LANCZOS)
            candidates.append(upscaled)
            up_gray = ImageOps.grayscale(upscaled)
            candidates.append(ImageOps.autocontrast(up_gray))

        # Try common rotations for camera images with orientation issues.
        rotated = []
        for img in candidates:
            rotated.append(img)
            rotated.append(img.rotate(90, expand=True))
            rotated.append(img.rotate(180, expand=True))
            rotated.append(img.rotate(270, expand=True))

        for img in rotated:
            decoded_objects = decode(img)
            if decoded_objects:
                raw_data = decoded_objects[0].data
                data = raw_data.decode('utf-8', errors='replace')
                if data.strip():
                    return analyze_qr_content(data)

        return {'error': 'No QR code found in image. Try a clearer image with the full QR visible.'}
    except Exception as e:
        return {'error': f'Error processing image: {str(e)}'}
