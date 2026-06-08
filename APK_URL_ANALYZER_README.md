# APK & URL Security Analyzer

A Streamlit web application for analyzing Android APK files and URLs for security threats.

## Features

- **APK Analysis**: Upload Android APK files to analyze permissions and assess security risks
- **URL Analysis**: Enter URLs to check for phishing and suspicious patterns
- **Risk Assessment**: Classifies threats as Safe, Suspicious, or Malicious
- **Detailed Reports**: Provides specific reasons for risk classifications
- **Clean UI**: Modern Streamlit interface with color-coded risk levels

## APK Analysis Features

- **Permission Extraction**: Uses Androguard to extract all requested permissions
- **Dangerous Permission Detection**: Identifies high-risk permissions like SMS access, location, camera
- **Risk Scoring**: Rule-based classification system
- **Comprehensive Report**: Shows package info, activities, services, and receivers

## URL Analysis Features

- **Pattern Detection**: Identifies suspicious keywords and URL structures
- **Domain Analysis**: Checks for typosquatting and suspicious domains
- **HTTPS Verification**: Warns about non-encrypted connections
- **IP Address Detection**: Flags URLs using IP addresses instead of domains
- **Short URL Detection**: Identifies URL shortening services

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
pip install streamlit
```

2. Run the application:
```bash
streamlit run apk_url_analyzer.py
```

## Usage

### APK Analysis
1. Click on the "APK Analysis" tab
2. Upload an APK file using the file uploader
3. Click "Analyze APK" to start the analysis
4. Review the risk assessment and detailed findings

### URL Analysis
1. Click on the "URL Analysis" tab
2. Enter a URL in the text input field
3. Click "Analyze URL" to start the analysis
4. Review the security assessment and recommendations

## Risk Levels

- **🟢 Safe**: Low security risk
- **🟡 Suspicious**: Potential security concerns - exercise caution
- **🔴 Malicious**: High security risk - avoid using

## Technical Details

- **APK Analysis**: Uses Androguard library for APK parsing
- **URL Analysis**: Leverages existing link analysis functions with pattern matching
- **Risk Classification**: Rule-based system with heuristic scoring
- **File Handling**: Temporary file processing - no permanent storage

## Security Considerations

- Uploaded APK files are processed temporarily and deleted after analysis
- No files are stored permanently on the server
- URL analysis is performed client-side with no external API calls (except for existing link analysis functions)

## Dependencies

- streamlit
- androguard
- requests
- urllib3
- Existing project dependencies (Flask, etc.)

## Integration

This application integrates with the existing phishing detection project:
- Uses `apk_analysis.py` for APK processing
- Uses `link_analysis.py` for URL analysis
- Maintains compatibility with existing Flask application