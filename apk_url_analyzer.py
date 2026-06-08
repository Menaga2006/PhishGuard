import streamlit as st
import os
import tempfile
import requests
from urllib.parse import urlparse
import re

# Import existing analysis functions
from apk_analysis import analyze_apk, analyze_apk_link
from link_analysis import analyze_link

# Page configuration
st.set_page_config(
    page_title="APK & URL Security Analyzer",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .risk-safe {
        background-color: #d4edda;
        color: #155724;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #c3e6cb;
    }
    .risk-suspicious {
        background-color: #fff3cd;
        color: #856404;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #ffeaa7;
    }
    .risk-malicious {
        background-color: #f8d7da;
        color: #721c24;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #f5c6cb;
    }
    .analysis-section {
        background-color: #f8f9fa;
        padding: 1.5rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
        border: 1px solid #dee2e6;
    }
</style>
""", unsafe_allow_html=True)

def get_risk_class(risk_level):
    """Get CSS class for risk level styling."""
    if risk_level.lower() == 'safe':
        return 'risk-safe'
    elif risk_level.lower() == 'suspicious':
        return 'risk-suspicious'
    elif risk_level.lower() == 'malicious':
        return 'risk-malicious'
    else:
        return 'risk-suspicious'

def analyze_apk_file(uploaded_file):
    """Analyze uploaded APK file."""
    st.markdown('<div class="analysis-section">', unsafe_allow_html=True)
    st.subheader("📱 APK File Analysis")

    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp_file:
        tmp_file.write(uploaded_file.getvalue())
        tmp_path = tmp_file.name

    try:
        # Analyze the APK
        with st.spinner("Analyzing APK file..."):
            result = analyze_apk(tmp_path)

        if 'error' in result:
            st.error(f"❌ Analysis Error: {result['error']}")
            return

        # Display basic information
        col1, col2 = st.columns(2)
        with col1:
            st.write("**Package Name:**", result.get('package', 'Unknown'))
            st.write("**Version:**", result.get('version', 'Unknown'))

        with col2:
            st.write("**Total Permissions:**", len(result.get('permissions', [])))
            st.write("**Activities:**", len(result.get('activities', [])))

        # Permissions Analysis
        st.subheader("🔐 Permissions Analysis")

        # Dangerous permissions to check
        dangerous_permissions = [
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_PHONE_STATE',
            'android.permission.CALL_PHONE',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.WAKE_LOCK'
        ]

        permissions = result.get('permissions', [])
        found_dangerous = [p for p in permissions if p in dangerous_permissions]

        if found_dangerous:
            st.warning(f"⚠️ Found {len(found_dangerous)} dangerous permissions:")
            for perm in found_dangerous:
                st.write(f"• {perm}")
        else:
            st.success("✅ No dangerous permissions found")

        # Risk Assessment
        st.subheader("🎯 Risk Assessment")

        # Simple rule-based classification
        risk_score = 0
        reasons = []

        # High-risk permissions
        high_risk_perms = [
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.READ_CONTACTS',
            'android.permission.CALL_PHONE'
        ]

        high_risk_found = [p for p in permissions if p in high_risk_perms]
        if high_risk_found:
            risk_score += 3
            reasons.append(f"High-risk permissions found: {', '.join(high_risk_found)}")

        # Medium-risk permissions
        medium_risk_perms = [
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_PHONE_STATE'
        ]

        medium_risk_found = [p for p in permissions if p in medium_risk_perms and p not in high_risk_found]
        if medium_risk_found:
            risk_score += 2
            reasons.append(f"Medium-risk permissions found: {', '.join(medium_risk_found)}")

        # Internet permission (common but can be risky)
        if 'android.permission.INTERNET' in permissions:
            risk_score += 1
            reasons.append("Internet access permission (common but can be used for malicious purposes)")

        # Determine risk level
        if risk_score >= 5:
            risk_level = "MALICIOUS"
            risk_description = "High risk of malware - contains multiple dangerous permissions"
        elif risk_score >= 3:
            risk_level = "SUSPICIOUS"
            risk_description = "Suspicious permissions detected - exercise caution"
        else:
            risk_level = "SAFE"
            risk_description = "Low risk - appears to be a legitimate app"

        # Display risk result
        risk_class = get_risk_class(risk_level)
        st.markdown(f'<div class="{risk_class}">', unsafe_allow_html=True)
        st.markdown(f"### {risk_level}")
        st.write(f"**{risk_description}**")
        if reasons:
            st.write("**Reasons:**")
            for reason in reasons:
                st.write(f"• {reason}")
        st.markdown('</div>', unsafe_allow_html=True)

        # Additional details
        with st.expander("📋 Detailed Analysis"):
            st.write("**All Permissions:**")
            if permissions:
                for perm in sorted(permissions):
                    st.write(f"• {perm}")
            else:
                st.write("No permissions found")

            st.write(f"**Activities:** {len(result.get('activities', []))}")
            st.write(f"**Services:** {len(result.get('services', []))}")
            st.write(f"**Receivers:** {len(result.get('receivers', []))}")

    except Exception as e:
        st.error(f"❌ Error analyzing APK: {str(e)}")

    finally:
        # Clean up temporary file
        try:
            os.unlink(tmp_path)
        except:
            pass

    st.markdown('</div>', unsafe_allow_html=True)

def analyze_url_input(url):
    """Analyze entered URL for security."""
    st.markdown('<div class="analysis-section">', unsafe_allow_html=True)
    st.subheader("🔗 URL Security Analysis")

    if not url.strip():
        st.warning("Please enter a URL to analyze")
        st.markdown('</div>', unsafe_allow_html=True)
        return

    # Basic URL validation
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        with st.spinner("Analyzing URL..."):
            # Use existing link analysis function
            result = analyze_link(url)

        # Display URL information
        parsed = urlparse(url)
        col1, col2 = st.columns(2)
        with col1:
            st.write("**Domain:**", result.get('domain', parsed.netloc))
            st.write("**Protocol:**", parsed.scheme.upper())

        with col2:
            st.write("**Path:**", parsed.path or '/')
            st.write("**Query:**", 'Present' if parsed.query else 'None')

        # Risk Assessment
        st.subheader("🎯 Security Assessment")

        # Extract risk information from analysis result
        status = result.get('status', 'Unknown')
        severity = result.get('severity', 'medium')
        reasons = result.get('reasons', [])

        # Map severity to risk level
        if severity == 'safe':
            risk_level = "SAFE"
        elif severity == 'unsafe':
            risk_level = "MALICIOUS"
        elif severity == 'warning':
            risk_level = "SUSPICIOUS"
        else:
            risk_level = "SUSPICIOUS"

        # Additional checks for suspicious patterns
        suspicious_indicators = [
            'login', 'password', 'bank', 'paypal', 'credit', 'card',
            'verify', 'secure', 'account', 'update', 'confirm',
            'free', 'win', 'prize', 'gift', 'urgent'
        ]

        url_lower = url.lower()
        found_suspicious = [word for word in suspicious_indicators if word in url_lower]

        if found_suspicious and risk_level == "SAFE":
            risk_level = "SUSPICIOUS"
            reasons.append(f"Suspicious keywords in URL: {', '.join(found_suspicious)}")

        # Check for IP address instead of domain
        if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
            reasons.append("URL uses IP address instead of domain name")
            risk_level = "SUSPICIOUS"

        # Check for unusual port
        if parsed.port and parsed.port not in [80, 443, 8080]:
            reasons.append(f"Unusual port number: {parsed.port}")
            risk_level = "SUSPICIOUS"

        # Check for long subdomains (potential typosquatting)
        if parsed.netloc.count('.') > 2:
            reasons.append("Multiple subdomains detected")
            risk_level = "SUSPICIOUS"

        # Check for URL shortening services
        shortening_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
        if any(service in parsed.netloc for service in shortening_services):
            reasons.append("URL shortening service detected - cannot verify destination")
            risk_level = "SUSPICIOUS"

        # Check for non-HTTPS
        if parsed.scheme != 'https':
            reasons.append("Not using HTTPS encryption")
            if risk_level == "SAFE":
                risk_level = "SUSPICIOUS"

        # Display risk result
        risk_class = get_risk_class(risk_level)
        st.markdown(f'<div class="{risk_class}">', unsafe_allow_html=True)
        st.markdown(f"### {risk_level}")
        st.write(f"**Status:** {status}")
        if reasons:
            st.write("**Detected Issues:**")
            for reason in reasons:
                st.write(f"• {reason}")
        else:
            st.write("✅ No obvious security issues detected")
        st.markdown('</div>', unsafe_allow_html=True)

        # Recommendations
        st.subheader("💡 Recommendations")
        if risk_level == "MALICIOUS":
            st.error("🚨 **Do not visit this URL!** It appears to be malicious.")
        elif risk_level == "SUSPICIOUS":
            st.warning("⚠️ **Exercise caution** with this URL. Consider:")
            st.write("• Verify the URL is legitimate")
            st.write("• Check for HTTPS encryption")
            st.write("• Avoid entering sensitive information")
        else:
            st.success("✅ **URL appears safe** to visit")

    except Exception as e:
        st.error(f"❌ Error analyzing URL: {str(e)}")

    st.markdown('</div>', unsafe_allow_html=True)

def main():
    # Main header
    st.markdown('<h1 class="main-header">🔒 APK & URL Security Analyzer</h1>', unsafe_allow_html=True)
    st.markdown("""
    Analyze Android APK files and URLs for security threats. Upload an APK file or enter a URL to get started.
    """)

    # Sidebar with information
    with st.sidebar:
        st.header("ℹ️ About")
        st.write("""
        This tool helps you analyze:
        - **APK Files**: Extract permissions and assess security risks
        - **URLs**: Check for phishing and suspicious patterns

        **Risk Levels:**
        - 🟢 **Safe**: Low security risk
        - 🟡 **Suspicious**: Potential security concerns
        - 🔴 **Malicious**: High security risk
        """)

        st.header("🔧 Features")
        st.write("""
        - Permission analysis for APKs
        - URL pattern detection
        - Risk assessment
        - No file storage required
        """)

    # Main content
    tab1, tab2 = st.tabs(["📱 APK Analysis", "🔗 URL Analysis"])

    with tab1:
        st.header("Android APK Security Analysis")

        with st.form(key="apk_analysis_form"):
            uploaded_file = st.file_uploader(
                "Choose an APK file to analyze",
                type=['apk'],
                help="Upload an Android APK file for security analysis"
            )

            analyze_apk_button = st.form_submit_button("🔍 Analyze APK")

            if uploaded_file is not None and analyze_apk_button:
                st.success(f"✅ File uploaded: {uploaded_file.name}")
                analyze_apk_file(uploaded_file)
            elif analyze_apk_button:
                st.warning("Please upload an APK file before analysis.")
            else:
                st.info("👆 Upload an APK file to begin analysis")

        with st.expander("📋 What gets analyzed?"):
            st.write("""
            **APK Analysis includes:**
            - Package name and version
            - All permissions requested
            - Dangerous permissions detection
            - Risk assessment based on permissions
            - Activity, service, and receiver counts
            """)

    with tab2:
        st.header("URL Security Analysis")

        with st.form(key="url_analysis_form"):
            url_input = st.text_input(
                "Enter URL to analyze",
                placeholder="https://example.com",
                help="Enter a complete URL including https:// or http://"
            )

            analyze_url_button = st.form_submit_button("🔍 Analyze URL")

            if analyze_url_button:
                analyze_url_input(url_input)

        with st.expander("🔍 Example URLs to test"):
            st.write("""
            **Safe URLs:**
            - https://www.google.com
            - https://github.com

            **Suspicious URLs (for testing):**
            - http://paypal-secure-login.com
            - https://bankofamerica-verification.net
            - http://192.168.1.1/login
            """)

if __name__ == "__main__":
    main()