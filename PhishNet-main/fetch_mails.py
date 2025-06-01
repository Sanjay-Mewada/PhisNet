from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import base64
import email

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def authenticate_gmail():
    """Authenticate and return Gmail service instance"""
    creds = None
    flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
    creds = flow.run_local_server(port=8080, redirect_uri_trailing_slash=True)
    return build("gmail", "v1", credentials=creds)

def get_emails(service, max_results=10):
    """Fetch emails from Gmail"""
    results = service.users().messages().list(userId="me", maxResults=max_results).execute()
    messages = results.get("messages", [])

    email_list = []
    for msg in messages:
        msg_data = service.users().messages().get(userId="me", id=msg["id"]).execute()
        msg_snippet = msg_data.get("snippet", "")
        email_list.append(msg_snippet)

    return email_list

if __name__ == "__main__":
    service = authenticate_gmail()
    emails = get_emails(service)
    for email in emails:
        print(email)