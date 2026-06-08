import os
import pickle
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

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

def fetch_latest_emails(service, max_results=10):
    """Fetch the latest emails with subject and snippet."""
    try:
        # List the latest messages
        results = service.users().messages().list(userId='me', maxResults=max_results).execute()
        messages = results.get('messages', [])

        emails = []
        for msg in messages:
            # Get the message details
            msg_detail = service.users().messages().get(userId='me', id=msg['id'], format='metadata',
                                                        metadataHeaders=['Subject']).execute()

            # Extract subject
            headers = msg_detail.get('payload', {}).get('headers', [])
            subject = next((header['value'] for header in headers if header['name'] == 'Subject'), 'No Subject')

            # Extract snippet
            snippet = msg_detail.get('snippet', 'No Snippet')

            emails.append({
                'id': msg['id'],
                'subject': subject,
                'snippet': snippet
            })

        return emails

    except Exception as error:
        print(f'An error occurred: {error}')
        return []

if __name__ == '__main__':
    # Authenticate and get service
    service = authenticate_gmail()

    # Fetch latest 10 emails
    emails = fetch_latest_emails(service, 10)

    # Print the results
    for email in emails:
        print(f"Subject: {email['subject']}")
        print(f"Snippet: {email['snippet']}")
        print("-" * 50)