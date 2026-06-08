"""
File & Folder Security Analysis Module
Analyzes APK files, documents, executables, images, archives, and entire folders for security threats.
"""

import os
import hashlib
import zipfile
import tempfile
from pathlib import Path
from datetime import datetime

# Suspicious patterns for different file types
SUSPICIOUS_EXTENSIONS = ['.exe', '.bat', '.cmd', '.com', '.msi', '.scr', '.pif', '.vbs', '.js', '.jar', '.sh', '.ps1']
DANGEROUS_EXTENSIONS = ['.exe', '.scr', '.bat', '.vbs', '.js', '.msi', '.com']

SUSPICIOUS_KEYWORDS = [
    'malware', 'virus', 'trojan', 'ransomware', 'keylogger', 'backdoor',
    'hack', 'crack', 'keygen', 'patch', 'loader', 'stealer', 'miner'
]

# File signatures (magic bytes) for identification
FILE_SIGNATURES = {
    'apk': b'PK\x03\x04',
    'zip': b'PK\x03\x04',
    'pdf': b'%PDF',
    'png': b'\x89PNG',
    'jpg': b'\xff\xd8\xff',
    'gif': b'GIF87a',
    'gif89': b'GIF89a',
    'exe': b'MZ',
    'docx': b'PK\x03\x04',
    'txt': None  # Text files have no specific signature
}

# Risk weights for file extensions
EXTENSION_RISK_WEIGHTS = {
    '.exe': 10,
    '.scr': 10,
    '.bat': 8,
    '.cmd': 8,
    '.vbs': 9,
    '.js': 7,
    '.msi': 6,
    '.jar': 5,
    '.apk': 4,
    '.sh': 6,
    '.ps1': 7,
    '.pdf': 2,
    '.docx': 1,
    '.doc': 1,
    '.xlsx': 1,
    '.xls': 1,
    '.txt': 0,
    '.jpg': 0,
    '.jpeg': 0,
    '.png': 0,
    '.gif': 0,
    '.zip': 2,
    '.rar': 2,
    '.7z': 2,
}


def get_file_signature(file_path):
    """Read first bytes to identify file type."""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(16)
            return header
    except:
        return b''


def identify_file_type(file_path):
    """Identify file type based on extension and signature."""
    ext = Path(file_path).suffix.lower()
    signature = get_file_signature(file_path)
    
    # Check signature first
    for file_type, sig in FILE_SIGNATURES.items():
        if sig and signature.startswith(sig):
            return file_type
    
    return ext.lstrip('.') if ext else 'unknown'


def calculate_file_hash(file_path, algorithm='sha256'):
    """Calculate file hash for integrity check."""
    try:
        hash_func = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        return f"Error: {str(e)}"


def analyze_apk(file_path):
    """Analyze APK file for Android-specific threats."""
    result = {
        'file_type': 'apk',
        'file_name': os.path.basename(file_path),
        'file_size': os.path.getsize(file_path)
    }
    
    try:
        from androguard.core.bytecodes.apk import APK
        apk = APK(file_path)
        
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
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_CALL_LOG',
            'android.permission.WRITE_CALL_LOG'
        ]
        found_suspicious = [p for p in result['permissions'] if p in suspicious_perms]
        result['suspicious_permissions'] = found_suspicious
        
        # Activities (potential phishing)
        result['activities'] = apk.get_activities()
        result['services'] = apk.get_services()
        result['receivers'] = apk.get_receivers()
        
        # Risk assessment
        risk_score = len(found_suspicious)
        if risk_score > 3:
            result['risk_level'] = 'high'
            result['risk_factors'] = [f'{len(found_suspicious)} dangerous permissions found']
        elif risk_score > 0:
            result['risk_level'] = 'medium'
            result['risk_factors'] = [f'{len(found_suspicious)} suspicious permissions']
        else:
            result['risk_level'] = 'low'
            result['risk_factors'] = ['No suspicious permissions']
            
    except Exception as e:
        result['error'] = f'APK Analysis Error: {str(e)}'
        result['risk_level'] = 'unknown'
    
    return result


def analyze_document(file_path):
    """Analyze document files (PDF, DOCX, TXT) for suspicious content."""
    result = {
        'file_type': 'document',
        'file_name': os.path.basename(file_path),
        'file_size': os.path.getsize(file_path)
    }
    
    ext = Path(file_path).suffix.lower()
    result['extension'] = ext
    
    try:
        if ext == '.pdf':
            # Basic PDF analysis
            with open(file_path, 'rb') as f:
                content = f.read(10000)  # Read first 10KB
                content_str = content.decode('utf-8', errors='ignore').lower()
                
                # Check for suspicious patterns
                suspicious_found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in content_str]
                if suspicious_found:
                    result['suspicious_content'] = suspicious_found
                    result['risk_level'] = 'medium'
                else:
                    result['risk_level'] = 'low'
                    
        elif ext in ['.docx', '.xlsx', '.pptx']:
            # Office Open XML files are ZIP-based
            try:
                with zipfile.ZipFile(file_path, 'r') as zf:
                    file_list = zf.namelist()
                    # Check for macros or suspicious files
                    suspicious_files = [f for f in file_list if 'vbaProject.bin' in f or 'macro' in f.lower()]
                    if suspicious_files:
                        result['suspicious_content'] = suspicious_files
                        result['risk_level'] = 'medium'
                    else:
                        result['risk_level'] = 'low'
            except:
                result['risk_level'] = 'low'
                
        elif ext == '.txt':
            # Text file analysis
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(10000).lower()
                suspicious_found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in content]
                if suspicious_found:
                    result['suspicious_content'] = suspicious_found
                    result['risk_level'] = 'low'
                else:
                    result['risk_level'] = 'low'
                    
        else:
            result['risk_level'] = 'low'
            
    except Exception as e:
        result['error'] = f'Document Analysis Error: {str(e)}'
        result['risk_level'] = 'unknown'
    
    return result


def analyze_executable(file_path):
    """Analyze executable files for suspicious behavior."""
    result = {
        'file_type': 'executable',
        'file_name': os.path.basename(file_path),
        'file_size': os.path.getsize(file_path)
    }
    
    ext = Path(file_path).suffix.lower()
    result['extension'] = ext
    
    try:
        # Check file signature
        signature = get_file_signature(file_path)
        
        if ext == '.exe':
            if signature.startswith(b'MZ'):
                result['valid_pe'] = True
                result['risk_level'] = 'medium'  # Executables always medium risk
                result['risk_factors'] = ['Executable file - requires careful analysis']
            else:
                result['risk_level'] = 'high'
                result['risk_factors'] = ['Invalid PE signature']
                
        elif ext in ['.bat', '.cmd']:
            # Batch files - check content
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read().lower()
                if any(kw in content for kw in ['del ', 'format', 'rd /s', 'rmdir', 'net user', 'reg delete']):
                    result['risk_level'] = 'high'
                    result['risk_factors'] = ['Contains destructive commands']
                else:
                    result['risk_level'] = 'medium'
                    
        elif ext == '.vbs':
            result['risk_level'] = 'medium'
            result['risk_factors'] = ['Visual Basic Script - potential for malicious code']
            
        elif ext == '.ps1':
            result['risk_level'] = 'medium'
            result['risk_factors'] = ['PowerShell script - can execute system commands']
            
        elif ext == '.jar':
            result['risk_level'] = 'medium'
            result['risk_factors'] = ['Java executable - verify source']
            
        else:
            result['risk_level'] = 'medium'
            
    except Exception as e:
        result['error'] = f'Executable Analysis Error: {str(e)}'
        result['risk_level'] = 'unknown'
    
    return result


def analyze_image(file_path):
    """Analyze image files for steganography or embedded content."""
    result = {
        'file_type': 'image',
        'file_name': os.path.basename(file_path),
        'file_size': os.path.getsize(file_path)
    }
    
    ext = Path(file_path).suffix.lower()
    result['extension'] = ext
    
    try:
        # Basic image validation
        signature = get_file_signature(file_path)
        
        if ext in ['.jpg', '.jpeg']:
            if signature[:3] == b'\xff\xd8\xff':
                result['valid_image'] = True
                result['risk_level'] = 'low'
            else:
                result['risk_level'] = 'warning'
                result['risk_factors'] = ['Invalid JPEG signature']
                
        elif ext == '.png':
            if signature[:4] == b'\x89PNG':
                result['valid_image'] = True
                result['risk_level'] = 'low'
            else:
                result['risk_level'] = 'warning'
                
        elif ext == '.gif':
            result['valid_image'] = True
            result['risk_level'] = 'low'
            
        else:
            result['risk_level'] = 'low'
            
    except Exception as e:
        result['error'] = f'Image Analysis Error: {str(e)}'
        result['risk_level'] = 'unknown'
    
    return result


def analyze_archive(file_path):
    """Analyze archive files (ZIP, RAR, 7z) for suspicious contents."""
    result = {
        'file_type': 'archive',
        'file_name': os.path.basename(file_path),
        'file_size': os.path.getsize(file_path)
    }
    
    ext = Path(file_path).suffix.lower()
    result['extension'] = ext
    
    try:
        if ext == '.zip':
            with zipfile.ZipFile(file_path, 'r') as zf:
                file_list = zf.namelist()
                result['file_count'] = len(file_list)
                
                # Check for dangerous files inside
                dangerous_files = [f for f in file_list if any(f.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS)]
                if dangerous_files:
                    result['contained_files'] = dangerous_files[:10]  # Limit to 10
                    result['risk_level'] = 'high'
                    result['risk_factors'] = [f'Contains {len(dangerous_files)} potentially dangerous files']
                else:
                    result['risk_level'] = 'low'
                    
        elif ext in ['.rar', '.7z']:
            result['risk_level'] = 'medium'
            result['risk_factors'] = ['Archive file - contents unknown until extracted']
            
        else:
            result['risk_level'] = 'low'
            
    except Exception as e:
        result['error'] = f'Archive Analysis Error: {str(e)}'
        result['risk_level'] = 'unknown'
    
    return result


def analyze_file(file_path):
    """Main file analysis function - dispatches to appropriate analyzer."""
    if not os.path.exists(file_path):
        return {'error': 'File not found', 'risk_level': 'unknown'}
    
    if os.path.isdir(file_path):
        return analyze_folder(file_path)
    
    ext = Path(file_path).suffix.lower()
    file_type = identify_file_type(file_path)
    
    # Route to appropriate analyzer
    if ext == '.apk' or file_type == 'apk':
        return analyze_apk(file_path)
    elif ext in ['.pdf', '.doc', '.docx', '.xlsx', '.xls', '.pptx', '.ppt', '.txt']:
        return analyze_document(file_path)
    elif ext in ['.exe', '.bat', '.cmd', '.vbs', '.js', '.msi', '.jar', '.sh', '.ps1', '.com', '.scr', '.pif']:
        return analyze_executable(file_path)
    elif ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.webp']:
        return analyze_image(file_path)
    elif ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
        return analyze_archive(file_path)
    else:
        # Default analysis for unknown files
        result = {
            'file_type': 'unknown',
            'file_name': os.path.basename(file_path),
            'file_size': os.path.getsize(file_path),
            'extension': ext,
            'risk_level': 'low'
        }
        return result


def analyze_folder(folder_path, recursive=True):
    """Analyze entire folder recursively."""
    if not os.path.isdir(folder_path):
        return {'error': 'Not a valid directory', 'risk_level': 'unknown'}
    
    results = {
        'folder_name': os.path.basename(folder_path),
        'folder_path': folder_path,
        'file_type': 'folder',
        'files': [],
        'summary': {
            'total': 0,
            'safe': 0,
            'warning': 0,
            'unsafe': 0,
            'unknown': 0
        }
    }
    
    try:
        path = Path(folder_path)
        
        # Collect all files
        if recursive:
            all_files = list(path.rglob('*'))
        else:
            all_files = list(path.glob('*'))
        
        # Filter to only files (not directories)
        files = [f for f in all_files if f.is_file()]
        
        results['summary']['total'] = len(files)
        
        # Analyze each file
        for file_path in files:
            try:
                file_result = analyze_file(str(file_path))
                risk = file_result.get('risk_level', 'unknown')
                
                # Add to results
                results['files'].append({
                    'path': str(file_path),
                    'name': file_path.name,
                    'result': file_result,
                    'risk': risk
                })
                
                # Update summary
                if risk in results['summary']:
                    results['summary'][risk] += 1
                    
            except Exception as e:
                results['files'].append({
                    'path': str(file_path),
                    'name': file_path.name,
                    'result': {'error': str(e)},
                    'risk': 'unknown'
                })
                results['summary']['unknown'] += 1
        
        # Determine folder risk level
        if results['summary']['unsafe'] > 0:
            results['risk_level'] = 'high'
        elif results['summary']['warning'] > 0:
            results['risk_level'] = 'medium'
        elif results['summary']['unknown'] > results['summary']['total'] * 0.5:
            results['risk_level'] = 'warning'
        else:
            results['risk_level'] = 'low'
            
    except Exception as e:
        results['error'] = f'Folder Analysis Error: {str(e)}'
        results['risk_level'] = 'unknown'
    
    return results


def assess_overall_risk(results):
    """Assess overall risk based on analysis results."""
    if results.get('error'):
        return results
    
    risk_level = results.get('risk_level', 'low')
    risk_factors = results.get('risk_factors', [])
    
    # For folder results, aggregate risk
    if results.get('file_type') == 'folder':
        summary = results.get('summary', {})
        total = summary.get('total', 0)
        
        if total == 0:
            risk_level = 'warning'
            risk_factors.append('Empty folder')
        elif summary.get('unsafe', 0) > 0:
            risk_level = 'high'
            risk_factors.append(f"{summary['unsafe']} unsafe files found")
        elif summary.get('warning', 0) > 0:
            risk_level = 'medium'
            risk_factors.append(f"{summary['warning']} files with warnings")
    
    results['risk_level'] = risk_level
    results['risk_factors'] = risk_factors
    
    return results