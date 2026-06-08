import streamlit as st
import os
import pickle
import base64
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from spam_classifier import SpamClassifier
import pandas as pd

# Page configuration
st.set_page_config(
    page_title="Email Spam Detector",
    page_icon="📧",
    layout="wide"
)

# Define the scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate_gmail():
    """Authenticate and return Gmail service."""
    creds = None
    # The file token.pickle stores the user's access and refresh tokens
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    service = build('gmail', 'v1', credentials=creds)
    return service

def get_email_body(service, msg_id):
    """Get the full body of an email."""
    try:
        message = service.users().messages().get(userId='me', id=msg_id, format='full').execute()

        # Extract the body
        payload = message['payload']
        body = ""

        if 'parts' in payload:
            # Multipart message
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part['body'].get('data', '')
                    if data:
                        body += base64.urlsafe_b64decode(data).decode('utf-8')
                elif part['mimeType'] == 'text/html':
                    # For simplicity, we'll use plain text
                    continue
        else:
            # Single part message
            data = payload['body'].get('data', '')
            if data:
                body = base64.urlsafe_b64decode(data).decode('utf-8')

        return body
    except Exception as e:
        st.error(f"Error getting email body: {e}")
        return ""

def main():
    st.title("📧 Email Spam Detection System")
    st.markdown("Analyze your Gmail inbox for spam emails using machine learning!")

    # Initialize classifier
    classifier = SpamClassifier()

    # Sidebar for configuration
    st.sidebar.header("Configuration")

    # Train/Load model section
    st.sidebar.subheader("Model Status")
    if classifier.load_model():
        st.sidebar.success("✅ Model loaded successfully!")
    else:
        st.sidebar.warning("⚠️ Model not found. Training new model...")
        with st.sidebar:
            if st.button("Train Model"):
                with st.spinner("Training model..."):
                    accuracy = classifier.train()
                st.success(f"Model trained with {accuracy:.2%} accuracy!")

    # Manual email analysis section
    st.sidebar.subheader("Manual Analysis")
    manual_email = st.sidebar.text_area("Enter email text to analyze:", height=100)

    if st.sidebar.button("Analyze Email"):
        if manual_email.strip():
            result = classifier.predict(manual_email)
            highlighted = classifier.highlight_suspicious_words(manual_email)
            links = classifier.extract_links(manual_email)

            st.sidebar.subheader("Analysis Result")
            if result['label'] == 'spam':
                st.sidebar.error(f"🚨 SPAM ({result['probability']:.1%} confidence)")
            else:
                st.sidebar.success(f"✅ SAFE ({result['probability']:.1%} confidence)")

            st.sidebar.subheader("Suspicious Words")
            st.sidebar.markdown(highlighted)

            if links:
                st.sidebar.subheader("Links Found")
                for link in links:
                    st.sidebar.write(f"🔗 {link}")
        else:
            st.sidebar.warning("Please enter email text to analyze.")

    # Main content
    tab1, tab2 = st.tabs(["📬 Gmail Analysis", "📊 Model Performance"])

    with tab1:
        st.header("Gmail Inbox Analysis")

        col1, col2 = st.columns([1, 3])

        with col1:
            max_emails = st.slider("Number of emails to analyze:", 1, 50, 10)
            if st.button("🔍 Analyze Gmail Inbox", type="primary"):
                analyze_gmail_emails(classifier, max_emails)

        with col2:
            st.info("Click 'Analyze Gmail Inbox' to scan your recent emails for spam. "
                   "The system will authenticate with Gmail and analyze each email using "
                   "the trained machine learning model.")

    with tab2:
        st.header("Model Performance")

        # Show sample predictions
        st.subheader("Sample Predictions")

        sample_emails = [
            "Hi John, let's meet for lunch tomorrow at 12pm. Best regards, Sarah",
            "URGENT: Your account has been suspended. Click here to verify: http://fakebank.com/verify",
            "Congratulations! You've won $1,000,000! Send your bank details to claim",
            "Meeting reminder: Project review at 3pm in conference room B"
        ]

        results = []
        for email in sample_emails:
            result = classifier.predict(email)
            results.append({
                'Email': email[:50] + "..." if len(email) > 50 else email,
                'Prediction': result['label'].upper(),
                'Spam Probability': f"{result['spam_probability']:.1%}",
                'Confidence': f"{result['probability']:.1%}"
            })

        df = pd.DataFrame(results)
        st.dataframe(df, use_container_width=True)

        # Model info
        st.subheader("Model Information")
        st.write("**Algorithm:** Multinomial Naive Bayes with TF-IDF vectorization")
        st.write("**Features:** 5000 most important words")
        st.write("**Training Data:** Sample dataset with spam and legitimate emails")

def analyze_gmail_emails(classifier, max_results):
    """Analyze emails from Gmail and display results."""
    try:
        # Authenticate Gmail
        with st.spinner("Authenticating with Gmail..."):
            service = authenticate_gmail()

        st.success("✅ Successfully connected to Gmail!")

        # Fetch emails
        with st.spinner(f"Fetching {max_results} latest emails..."):
            results = service.users().messages().list(userId='me', maxResults=max_results).execute()
            messages = results.get('messages', [])

        if not messages:
            st.warning("No emails found in your inbox.")
            return

        # Progress bar
        progress_bar = st.progress(0)
        status_text = st.empty()

        # Analyze each email
        email_results = []

        for i, msg in enumerate(messages):
            status_text.text(f"Analyzing email {i+1}/{len(messages)}...")

            # Get message details
            msg_detail = service.users().messages().get(
                userId='me', id=msg['id'], format='metadata',
                metadataHeaders=['Subject', 'From', 'Date']
            ).execute()

            # Extract headers
            headers = msg_detail.get('payload', {}).get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
            date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown Date')

            # Get email body
            body = get_email_body(service, msg['id'])

            # Combine subject and body for analysis
            full_text = f"{subject} {body}"

            # Analyze for spam
            result = classifier.predict(full_text)

            # Highlight suspicious words
            highlighted = classifier.highlight_suspicious_words(full_text[:200] + "...")

            # Extract links
            links = classifier.extract_links(full_text)

            email_results.append({
                'Subject': subject,
                'From': sender,
                'Date': date,
                'Prediction': result['label'].upper(),
                'Spam Probability': result['spam_probability'],
                'Highlighted Text': highlighted,
                'Links': links
            })

            progress_bar.progress((i + 1) / len(messages))

        progress_bar.empty()
        status_text.empty()

        # Display results
        st.header(f"📊 Analysis Results ({len(email_results)} emails)")

        # Summary statistics
        spam_count = sum(1 for r in email_results if r['Prediction'] == 'SPAM')
        safe_count = len(email_results) - spam_count

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Emails", len(email_results))
        with col2:
            st.metric("Spam Detected", spam_count, f"{spam_count/len(email_results)*100:.1f}%")
        with col3:
            st.metric("Safe Emails", safe_count, f"{safe_count/len(email_results)*100:.1f}%")

        # Display individual results
        for i, result in enumerate(email_results, 1):
            with st.expander(f"📧 Email {i}: {result['Subject'][:50]}..."):
                col1, col2 = st.columns([1, 2])

                with col1:
                    st.write(f"**From:** {result['From']}")
                    st.write(f"**Date:** {result['Date']}")

                    # Prediction with color
                    if result['Prediction'] == 'SPAM':
                        st.error(f"🚨 **{result['Prediction']}** ({result['Spam Probability']:.1%})")
                    else:
                        st.success(f"✅ **{result['Prediction']}** ({1-result['Spam Probability']:.1%})")

                with col2:
                    st.write("**Suspicious Words:**")
                    st.markdown(result['Highlighted Text'])

                    if result['Links']:
                        st.write(f"**Links Found ({len(result['Links'])}):**")
                        for link in result['Links'][:5]:  # Show first 5 links
                            st.write(f"🔗 {link}")
                        if len(result['Links']) > 5:
                            st.write(f"... and {len(result['Links']) - 5} more links")
                    else:
                        st.write("**Links Found:** None")

    except Exception as e:
        st.error(f"Error analyzing emails: {str(e)}")
        st.info("Make sure you have valid Gmail credentials and the 'credentials.json' file in the project directory.")

if __name__ == "__main__":
    main()