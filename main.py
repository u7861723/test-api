from flask import Flask, redirect, request, session, render_template
from flask_session import Session
import requests
import uuid
import os
import urllib.parse
from datetime import datetime, timedelta
import re
import openai

# ✅ DeepSeek client
openai.api_key = "sk-95aca95db16343f4a019f3b3b8c8c76f"
openai.api_base = "https://api.deepseek.com/v1"

def analyze_meeting_transcript(transcript_text):
    prompt = f"""
You are a smart meeting assistant.
Given the transcript below, please:
1. Give the date and title of the meeting.
2. Provide a concise **meeting summary**.
3. List **meeting minutes** with time-order key points.
4. List what we have done and what we need to do in the future.
5. Identify any **next steps or action items**, action items should be in detailed description and assign responsible people if mentioned.

Transcript:
\"\"\"
{transcript_text}
\"\"\"
"""
    response = openai.ChatCompletion.create(
        model="deepseek-chat",
        messages=[
            {"role": "system", "content": "You are a helpful AI meeting assistant."},
            {"role": "user", "content": prompt}
        ],
        stream=False
    )
    return response.choices[0].message['content']


def parse_vtt_with_speakers(vtt_text):
    lines = vtt_text.strip().splitlines()
    transcript_html = "<details><summary>🗣️ Full Transcript</summary><ul>"
    cue = []
    for line in lines:
        if "-->" in line:
            cue = []
        elif line.strip() == "":
            if cue:
                for entry in cue:
                    match = re.match(r"<v\s+([^>]+)>(.*)", entry)
                    if match:
                        speaker, text = match.groups()
                        transcript_html += f"<li><strong>{speaker}:</strong> {text.strip()}</li>"
                    else:
                        transcript_html += f"<li>{entry.strip()}</li>"
            cue = []
        else:
            cue.append(line)
    transcript_html += "</ul></details>"
    return transcript_html


# ✅ Flask App Setup
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

CLIENT_ID = "2d0df75c-6bc1-446f-bcf0-a22aea96c9b3"
CLIENT_SECRET = "U7p8Q~vHMHQyI8ZpZu5-R7CaaPV_pXOSwvXgTakG"
TENANT_ID = "22438506-028b-45c7-9bd3-8badf683d7e3"
REDIRECT_URI = "https://test-api-aht9.onrender.com/callback"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE = "openid profile email OnlineMeetings.Read OnlineMeetingTranscript.Read.All Calendars.Read User.Read"

@app.route("/")
def home():
    if 'access_token' in session:
        return redirect('/meetings')
    return render_template('login.html')

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
        return redirect("/")

    headers = {"Authorization": f"Bearer {token}"}
    events_list = []

    start = datetime.utcnow() - timedelta(days=30)
    end = datetime.utcnow()
    url = f"https://graph.microsoft.com/v1.0/me/calendar/calendarView?startDateTime={start.isoformat()}Z&endDateTime={end.isoformat()}Z"
    events_resp = requests.get(url, headers=headers).json()

    for event in events_resp.get("value", []):
        event_data = {
            'subject': event.get("subject", "Untitled Meeting"),
            'start': datetime.fromisoformat(event.get("start", {}).get("dateTime", "").replace('Z', '')),
            'join_url': event.get("onlineMeeting", {}).get("joinUrl"),
            'transcript_html': None
        }
        
        if event_data['join_url']:
            encoded_url = urllib.parse.quote(event_data['join_url'], safe="")
            meeting_lookup_url = f"https://graph.microsoft.com/v1.0/me/onlineMeetings?$filter=JoinWebUrl eq '{encoded_url}'"
            meeting_resp = requests.get(meeting_lookup_url, headers=headers).json()
            meetings = meeting_resp.get("value", [])

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
                        vtt_text = content_resp.text
                        try:
                            ai_summary = analyze_meeting_transcript(vtt_text)
                            event_data['transcript_html'] = f"""
                            <details>
                                <summary>🤖 AI Meeting Summary</summary>
                                <div class="p-3 bg-light rounded">
                                    {ai_summary}
                                </div>
                            </details>
                            {parse_vtt_with_speakers(vtt_text)}
                            """
                        except Exception as e:
                            event_data['transcript_html'] = f"<div class='text-danger'><i class='fas fa-exclamation-circle me-1'></i>AI Analysis Failed: {str(e)}</div>"

        events_list.append(event_data)

    return render_template('meetings.html', events=events_list)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)