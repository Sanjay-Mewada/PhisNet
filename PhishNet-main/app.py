from flask import Flask, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
import html, base64, re, os, json
import os
import cohere
import secrets


from dotenv import load_dotenv

# === Load environment variables (for COHERE API Key only) ===
load_dotenv()

# === Initialize Flask App ===
app = Flask(__name__)
app.secret_key ="2da99a19297c25f7ebec570f2798e904"


# === MySQL Configuration ===
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+mysqlconnector://{os.getenv('DB_USERNAME')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}/{os.getenv('DB_NAME')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# === Gmail API Scopes ===
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

COHERE_API_KEY = os.getenv('COHERE_API_KEY')


co = cohere.Client(COHERE_API_KEY)

# === Email Model ===
class EmailAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(300))
    sender = db.Column(db.String(300))
    snippet = db.Column(db.Text)
    sentiment = db.Column(db.String(50))
    category = db.Column(db.String(50))
    deadline = db.Column(db.String(100))
    action_items = db.Column(db.Text)  # JSON string
    priority = db.Column(db.String(50))
    phishing_detected = db.Column(db.String(10))
    explanation = db.Column(db.Text)

# === Email Analyzer ===
def analyze_email(email_text):
    def clean_text(text):
        text = re.sub(r"[^\x00-\x7F]+", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    email_text = clean_text(email_text)

    if len(email_text) < 2:
        return {
            "sentiment": "Too short", "category": "Too short", "deadline": "Too short",
            "action_items": [], "priority": "Too short", "phishing_detected": "Too short",
            "explanation": "Too short"
        }

    prompt = f"""
You are an intelligent Email Triage Assistant. Analyze the following email and return JSON like:
{{
  "sentiment": "", "category": "", "deadline": "", "action_items": [], "priority": "", 
  "phishing_detected": "", "explanation": ""
}}

Email:
\"\"\"{email_text}\"\"\"
"""
    try:
        response = co.generate(model="command-r-plus", prompt=prompt, max_tokens=500, temperature=0.5)
        return json.loads(response.generations[0].text.strip())
    except Exception as e:
        print("Cohere error:", e)
        return {
            "sentiment": "Error", "category": "Error", "deadline": "Error",
            "action_items": [], "priority": "Error", "phishing_detected": "Error",
            "explanation": str(e)
        }

# === Gmail Auth ===
def authenticate_gmail():
    creds = Credentials(
        token=session['access_token'],
        refresh_token=session.get('refresh_token'),
        token_uri=session.get('token_uri'),
        client_id=session.get('client_id'),
        client_secret=session.get('client_secret')
    )
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        session['access_token'] = creds.token
    return build('gmail', 'v1', credentials=creds)

# === Fetch Emails ===
def get_emails():
    try:
        service = authenticate_gmail()
        results = service.users().messages().list(userId="me", maxResults=5).execute()
        messages = results.get("messages", [])

        for msg in messages:
            msg_data = service.users().messages().get(userId="me", id=msg["id"]).execute()
            payload = msg_data.get("payload", {})
            headers = payload.get("headers", [])

            subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
            sender = next((h["value"] for h in headers if h["name"] == "From"), "Unknown")

            body = ""
            parts = payload.get("parts", [])
            if parts:
                for part in parts:
                    if part.get("mimeType") == "text/plain":
                        data = part.get("body", {}).get("data", "")
                        if data:
                            body = base64.urlsafe_b64decode(data.encode("UTF-8")).decode("utf-8", errors="ignore")
                            break
            else:
                body = html.unescape(msg_data.get("snippet", ""))

            if not body:
                body = msg_data.get("snippet", "")

            analysis = analyze_email(body)

            # Check if already exists (optional logic to prevent duplicates)
            if EmailAnalysis.query.filter_by(subject=subject, sender=sender).first():
                continue

            # Save to DB
            email_entry = EmailAnalysis(
                subject=subject,
                sender=sender,
                snippet=body[:300],
                sentiment=analysis.get("sentiment", ""),
                category=analysis.get("category", ""),
                deadline=analysis.get("deadline", ""),
                action_items=json.dumps(analysis.get("action_items", [])),
                priority=analysis.get("priority", ""),
                phishing_detected=analysis.get("phishing_detected", ""),
                explanation=analysis.get("explanation", "")
            )
            db.session.add(email_entry)
            db.session.commit()

    except Exception as e:
        print("Email fetch error:", e)

# === Routes ===
@app.route("/authorize")
def authorize():
    flow = InstalledAppFlow.from_client_secrets_file(
        r"C:\Users\sanja\OneDrive\Documents\credentials.json", SCOPES
    )
    creds = flow.run_local_server(port=5002)
    session['access_token'] = creds.token
    session['refresh_token'] = creds.refresh_token
    session['token_uri'] = creds.token_uri
    session['client_id'] = creds.client_id
    session['client_secret'] = creds.client_secret
    return redirect(url_for('index'))

@app.route("/")
def index():
    if 'access_token' not in session:
        return redirect(url_for('authorize'))

    get_emails()
    emails = EmailAnalysis.query.order_by(EmailAnalysis.id.desc()).all()
    return render_template("index.html", email_analysis=emails)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('index'))

# === Run the App ===
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)
