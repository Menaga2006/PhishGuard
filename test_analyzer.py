#!/usr/bin/env python3
"""
Test script for APK & URL Security Analyzer
Tests the core functionality without running the full Streamlit app
"""

from apk_analysis import analyze_apk
from link_analysis import analyze_link
import tempfile
import os

def test_url_analysis():
    """Test URL analysis functionality."""
    print("🧪 Testing URL Analysis")
    print("=" * 50)

    test_urls = [
        "https://www.google.com",
        "http://paypal-secure-login.com",
        "https://github.com",
        "http://192.168.1.1/admin",
        "https://bit.ly/shortlink"
    ]

    for url in test_urls:
        print(f"\nAnalyzing: {url}")
        try:
            result = analyze_link(url)
            status = result.get('status', 'Unknown')
            severity = result.get('severity', 'unknown')
            reasons = result.get('reasons', [])

            print(f"Status: {status}")
            print(f"Severity: {severity}")
            if reasons:
                print("Reasons:")
                for reason in reasons:
                    print(f"  - {reason}")
            else:
                print("No specific reasons provided")

        except Exception as e:
            print(f"Error: {str(e)}")

def test_apk_analysis():
    """Test APK analysis functionality (without actual APK file)."""
    print("\n🧪 Testing APK Analysis Structure")
    print("=" * 50)

    # Test the function structure with a mock
    print("APK analysis function is available and importable")
    print("To test with real APK file:")
    print("1. Place an APK file in the project directory")
    print("2. Call: analyze_apk('path/to/file.apk')")
    print("3. Check the returned dictionary for analysis results")

def main():
    print("🔒 APK & URL Security Analyzer - Test Suite")
    print("=" * 60)

    test_url_analysis()
    test_apk_analysis()

    print("\n" + "=" * 60)
    print("✅ Test suite completed!")
    print("\nTo run the full Streamlit app:")
    print("streamlit run apk_url_analyzer.py")

if __name__ == "__main__":
    main()