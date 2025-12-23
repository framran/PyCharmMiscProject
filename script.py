import requests
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone

# ----------------------
# CONFIGURATION
# ----------------------
OKTA_ORG_URL = "https://your-org.okta.com"
OKTA_API_TOKEN = "YOUR_OKTA_API_TOKEN"

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "alertsender@example.com"
SMTP_PASSWORD = "EMAIL_PASSWORD"

ALERT_RECIPIENT = "security-team@example.com"
ALERT_SENDER = SMTP_USERNAME

# ----------------------
# EMAIL FUNCTION
# ----------------------
def send_email(subject, body):
    msg = EmailMessage()
    msg["From"] = ALERT_SENDER
    msg["To"] = ALERT_RECIPIENT
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)

# ----------------------
# OKTA LOG CHECK
# ----------------------
def check_user_deactivations():
    headers = {
        "Authorization": f"SSWS {OKTA_API_TOKEN}",
        "Accept": "application/json"
    }

    # Check events from last 5 minutes
    since_time = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()

    params = {
        "filter": 'eventType eq "user.lifecycle.deactivate"',
        "since": since_time,
        "limit": 50
    }

    response = requests.get(
        f"{OKTA_ORG_URL}/api/v1/logs",
        headers=headers,
        params=params
    )

    response.raise_for_status()
    events = response.json()

    for event in events:
        actor = event.get("actor", {})
        target = event.get("target", [{}])[0]

        admin = actor.get("alternateId", "Unknown admin")
        user = target.get("alternateId", "Unknown user")
        time = event.get("published")

        subject = f"Okta Alert: User Deactivated ({user})"
        body = (
            f"An Okta user has been deactivated.\n\n"
            f"User: {user}\n"
            f"Deactivated by: {admin}\n"
            f"Time: {time}\n"
        )

        send_email(subject, body)

# ----------------------
# MAIN
# ----------------------
if __name__ == "__main__":
    check_user_deactivations()