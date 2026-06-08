from androguard.core.bytecodes.apk import APK
import requests
import os
from urllib.parse import urlparse

def analyze_apk(apk_file_path):
    result = {}
    try:
        apk = APK(apk_file_path)
        
        # Basic Info
        result['package'] = apk.get_package()
        result['version'] = apk.get_androidversion_name()
        result['permissions'] = apk.get_permissions()
        
        # Suspicious Permissions
        suspicious_perms = [
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.READ_CONTACTS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.CAMERA'
        ]
        found_suspicious = [p for p in result['permissions'] if p in suspicious_perms]
        if found_suspicious:
            result['suspicious_permissions'] = found_suspicious
        else:
            result['suspicious_permissions'] = 'None'
        
        # Activities (potential phishing)
        activities = apk.get_activities()
        result['activities'] = activities
        
        # Services
        services = apk.get_services()
        result['services'] = services
        
        # Receivers
        receivers = apk.get_receivers()
        result['receivers'] = receivers
        
        # VirusTotal Check (placeholder - requires API key)
        # In real implementation, upload file to VirusTotal
        result['virustotal'] = 'VirusTotal API integration required for malware scan'
        
        # Overall Risk
        risk_score = len(found_suspicious)
        if risk_score > 3:
            result['overall'] = 'High Risk - Potential Malware'
        elif risk_score > 0:
            result['overall'] = 'Medium Risk'
        else:
            result['overall'] = 'Low Risk'
    
    except Exception as e:
        result['error'] = f'Error analyzing APK: {str(e)}'
    
    return result

def analyze_apk_link(apk_url, api_key=None):
    """
    Download APK from URL and perform full analysis.
    """
    import tempfile
    import zipfile
    
    result = {
        'url': apk_url,
        'source': 'URL',
        'error': None
    }
    
    # Standard headers to avoid being blocked
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    try:
        # Step 1: Download the APK file
        print(f"Downloading APK from: {apk_url}")
        response = requests.get(apk_url, timeout=30, headers=headers, allow_redirects=True)
        if response.status_code != 200:
            result['error'] = f'Failed to download APK: HTTP {response.status_code}'
            return result
        
        # Step 2: Validate that downloaded content is a valid ZIP/APK file
        # APK files are ZIP archives, so they should start with the ZIP magic number PK
        if not response.content.startswith(b'PK'):
            # Check if we got HTML instead
            content_preview = response.content[:200].decode('utf-8', errors='ignore').lower()
            if '<html' in content_preview or '<!doctype' in content_preview:
                result['error'] = 'URL returned HTML instead of APK file. The URL may require authentication or be invalid.'
            else:
                result['error'] = 'Downloaded file is not a valid APK file (not a ZIP archive). Expected APK format.'
            return result
        
        # Step 3: Additional validation - try to open as ZIP
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as temp_file:
                temp_file.write(response.content)
                temp_path = temp_file.name
            
            # Verify it's a valid ZIP
            with zipfile.ZipFile(temp_path, 'r') as zf:
                # Basic validation that it's a zip
                pass
        except zipfile.BadZipFile:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            result['error'] = 'File is not a valid ZIP/APK archive. Downloaded content may be corrupted or incomplete.'
            return result
        
        # Step 4: Analyze the downloaded APK
        print(f"Analyzing downloaded APK from: {apk_url}")
        apk_result = analyze_apk(temp_path)
        
        # Merge results
        result.update(apk_result)
        
        # Clean up temp file
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    
    except requests.exceptions.Timeout:
        result['error'] = 'Timeout: URL took too long to respond. The server may be slow or unreachable.'
    except requests.exceptions.ConnectionError:
        result['error'] = 'Connection error: Unable to reach URL. Check if the URL is correct and accessible.'
    except requests.exceptions.InvalidURL:
        result['error'] = 'Invalid URL format. Please provide a valid APK download URL.'
    except Exception as e:
        result['error'] = f'Error analyzing APK: {str(e)}'
    
    return result
