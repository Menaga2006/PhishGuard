import os
import pickle
import base64
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from spam_classifier import SpamClassifier

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
                    # For simplicity, we'll use plain text, but you could parse HTML
                    continue
        else:
            # Single part message
            data = payload['body'].get('data', '')
            if data:
                body = base64.urlsafe_b64decode(data).decode('utf-8')

        return body
    except Exception as e:
        print(f"Error getting email body: {e}")
        return ""

def fetch_and_analyze_emails(max_results=10):
    """Fetch emails from Gmail and analyze them for spam."""
    # Authenticate and get Gmail service
    service = authenticate_gmail()

    # Initialize spam classifier
    classifier = SpamClassifier()

    # Load the trained model
    if not classifier.load_model():
        print("Training model first...")
        classifier.train()

    try:
        # List the latest messages
        results = service.users().messages().list(userId='me', maxResults=max_results).execute()
        messages = results.get('messages', [])

        print(f"\n{'='*80}")
        print(f"ANALYZING {len(messages)} LATEST EMAILS FOR SPAM")
        print(f"{'='*80}\n")

        for i, msg in enumerate(messages, 1):
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
            highlighted_text = classifier.highlight_suspicious_words(full_text[:200] + "...")

            # Extract links
            links = classifier.extract_links(full_text)

            # Print results
            print(f"Email {i}:")
            print(f"  Subject: {subject}")
            print(f"  From: {sender}")
            print(f"  Date: {date}")
            print(f"  Prediction: {result['label'].upper()}")
            print(f"  Spam Probability: {result['spam_probability']:.2%}")
            print(f"  Ham Probability: {result['ham_probability']:.2%}")
            print(f"  Suspicious Words: {highlighted_text}")
            if links:
                print(f"  Links Found: {len(links)}")
                for link in links[:3]:  # Show first 3 links
                    print(f"    - {link}")
                if len(links) > 3:
                    print(f"    ... and {len(links) - 3} more")
            else:
                print("  Links Found: None"
            print(f"{'-'*60}\n")

    except Exception as e:
        print(f"Error fetching emails: {e}")

if __name__ == "__main__":
    # Run the analysis
    fetch_and_analyze_emails(max_results=5)  # Analyze 5 latest emails