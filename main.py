from flask import Flask, redirect, request, session
from flask_session import Session
import requests
import uuid
import os
import urllib.parse
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24)

# 使用服务器端 Session 存储，防止 Cookie 丢失
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
TENANT_ID = os.getenv("TENANT_ID")
REDIRECT_URI = "http://localhost:5000/callback"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE = "openid profile email OnlineMeetings.Read OnlineMeetingTranscript.Read.All Calendars.Read User.Read"

@app.route("/")
def home():
    return '<a href="/login">🔐 Click here to log in with Microsoft</a>'

@app.route("/login")
def login():
    state = str(uuid.uuid4())
    session["oauth_state"] = state
    auth_url = (
        f"{AUTHORITY}/oauth2/v2.0/authorize?"
        f"client_id={CLIENT_ID}&response_type=code&redirect_uri={REDIRECT_URI}"
        f"&response_mode=query&scope={SCOPE}&state={state}"
    )
    return redirect(auth_url)

@app.route("/callback")
def callback():
    if request.args.get("state") != session.get("oauth_state"):
        return "❌ State mismatch", 400

    code = request.args.get("code")
    token_url = f"{AUTHORITY}/oauth2/v2.0/token"
    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    token_response = requests.post(token_url, data=data, headers=headers).json()

    if "access_token" in token_response:
        session["access_token"] = token_response["access_token"]
        return redirect("/meetings")
    else:
        return f"❌ Token error: {token_response}", 400

@app.route("/meetings")
def meetings():
    token = session.get("access_token")
    if not token:
        return redirect("/login")

    headers = {"Authorization": f"Bearer {token}"}

    # 获取近 30 天会议事件
    start = datetime.utcnow() - timedelta(days=30)
    end = datetime.utcnow()
    url = f"https://graph.microsoft.com/v1.0/me/calendar/calendarView?startDateTime={start.isoformat()}Z&endDateTime={end.isoformat()}Z"
    events_resp = requests.get(url, headers=headers).json()
    output = "<h2>📅 Past 30 Days Events</h2><ul>"

    for event in events_resp.get("value", []):
        subject = event.get("subject", "None")
        join_url = event.get("onlineMeeting") and event["onlineMeeting"].get("joinUrl")
        if not join_url:
            continue

        encoded_url = urllib.parse.quote(join_url, safe="")
        meeting_lookup_url = f"https://graph.microsoft.com/v1.0/me/onlineMeetings?$filter=JoinWebUrl eq '{encoded_url}'"
        meeting_resp = requests.get(meeting_lookup_url, headers=headers).json()
        meetings = meeting_resp.get("value", [])

        transcript_text = ""
        if meetings:
            meeting_id = meetings[0]["id"]
            transcripts_url = f"https://graph.microsoft.com/beta/me/onlineMeetings/{meeting_id}/transcripts"
            transcripts_resp = requests.get(transcripts_url, headers=headers).json()
            transcript_list = transcripts_resp.get("value", [])

            if transcript_list:
                transcript_id = transcript_list[0]["id"]
                content_url = f"https://graph.microsoft.com/beta/me/onlineMeetings/{meeting_id}/transcripts/{transcript_id}/content"
                content_headers = headers.copy()
                content_headers["Accept"] = "text/vtt"
                content_resp = requests.get(content_url, headers=content_headers)
                if content_resp.status_code == 200:
                    transcript_text = f"<details><summary>📝 Transcript</summary><pre>{content_resp.text}</pre></details>"

        output += f"<li>{subject} - Join Link: {join_url} {transcript_text}</li>"

    output += "</ul>"
    return output

if __name__ == "__main__":
    app.run(port=5000, debug=True, use_reloader=False)
