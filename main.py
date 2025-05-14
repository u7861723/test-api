from flask import Flask, redirect, request, session, render_template
from flask_session import Session
import requests
import uuid
import os
import urllib.parse
from datetime import datetime, timedelta
import re
import openai
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ✅ DeepSeek client
openai.api_key = "sk-95aca95db16343f4a019f3b3b8c8c76f"
openai.api_base = "https://api.deepseek.com/v1"

def analyze_meeting_transcript(transcript_text, max_retries=3):
    """Analyze meeting transcript with retry mechanism"""
    for attempt in range(max_retries):
        try:
            prompt = f"""
You are a smart meeting assistant. Please analyze the meeting transcript and provide a well-formatted summary.
Please structure your response in the following format:

# Meeting Summary

## Meeting Details
- Date: [Meeting Date]
- Title: [Meeting Title]

## Executive Summary
[Provide a concise 2-3 sentence summary of the meeting]

## Key Points
1. [First key point]
2. [Second key point]
3. [Third key point]
...

## Action Items
- [ ] [Action item 1] - [Responsible person]
- [ ] [Action item 2] - [Responsible person]
...

## Next Steps
1. [Next step 1]
2. [Next step 2]
...

Transcript:
\"\"\"
{transcript_text}
\"\"\"
"""
            response = openai.ChatCompletion.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": "You are a helpful AI meeting assistant. Always format your response in markdown with clear sections and bullet points."},
                    {"role": "user", "content": prompt}
                ],
                stream=False
            )
            return response.choices[0].message['content']
        except Exception as e:
            logger.error(f"AI analysis attempt {attempt + 1} failed: {str(e)}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
            else:
                raise

def parse_vtt_with_speakers(vtt_text):
    """Parse VTT text with error handling"""
    try:
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
    except Exception as e:
        logger.error(f"Error parsing VTT: {str(e)}")
        return "<div class='text-danger'>Error parsing transcript</div>"

def get_meeting_transcriptions(meeting_id, headers):
    """Get all transcription IDs for a meeting"""
    try:
        url = f"https://graph.microsoft.com/beta/me/onlineMeetings/{meeting_id}/transcripts"
        logger.info(f"Requesting transcript IDs from: {url}")
        response = requests.get(url, headers=headers, timeout=10)
        
        logger.info(f"Transcript IDs response status: {response.status_code}")
        
        if response.status_code == 200:
            transcripts = response.json().get("value", [])
            if transcripts:
                transcript_ids = [t["id"] for t in transcripts]
                logger.info(f"✅ Retrieved {len(transcript_ids)} transcription IDs: {transcript_ids}")
                return transcript_ids, None
            else:
                logger.info("❌ No transcription found.")
                return [], "No transcriptions available for this meeting"
        else:
            error_msg = f"Failed to retrieve transcriptions (Error {response.status_code})"
            try:
                error_details = response.json()
                logger.error(f"❌ {error_msg}: {error_details}")
            except:
                logger.error(f"❌ {error_msg}")
            return [], error_msg
    except Exception as e:
        error_msg = f"Error getting transcriptions: {str(e)}"
        logger.error(error_msg)
        return [], error_msg

def get_transcript_content_by_id(meeting_id, transcript_id, headers):
    """Get transcript content using transcript ID"""
    try:
        content_url = f"https://graph.microsoft.com/beta/me/onlineMeetings/{meeting_id}/transcripts/{transcript_id}/content"
        content_headers = headers.copy()
        content_headers["Accept"] = "text/vtt"
        
        logger.info(f"Requesting transcript content from: {content_url}")
        content_resp = requests.get(content_url, headers=content_headers, timeout=10)
        
        logger.info(f"Transcript content response status: {content_resp.status_code}")
        
        if content_resp.status_code == 200:
            logger.info("Successfully retrieved transcript content")
            return content_resp.text, None
        elif content_resp.status_code == 402:
            logger.warning("Premium subscription required for this transcript")
            return None, {
                'type': 'premium_required',
                'message': 'This meeting transcript requires a premium subscription.',
                'html': """
                <div class="premium-message">
                    <i class="fas fa-crown me-1"></i>
                    <strong>Premium Feature</strong>
                    <p class="mb-0">This meeting transcript requires a premium subscription.</p>
                    <small>Please contact your administrator to upgrade your subscription.</small>
                </div>
                """
            }
        else:
            error_message = f"Failed to get transcript (Error {content_resp.status_code})"
            try:
                error_details = content_resp.json()
                logger.error(f"Error details: {error_details}")
            except:
                logger.error(error_message)
            return None, {
                'type': 'error',
                'message': error_message,
                'html': f"""
                <div class="text-warning">
                    <i class="fas fa-exclamation-triangle me-1"></i>
                    {error_message}
                </div>
                """
            }
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error for transcript: {str(e)}")
        return None, {
            'type': 'error',
            'message': "Network error while fetching transcript",
            'html': """
            <div class="text-warning">
                <i class="fas fa-exclamation-triangle me-1"></i>
                Network error while fetching transcript
            </div>
            """
        }

def generate_admin_consent_url():
    """Generate admin consent URL"""
    state = str(uuid.uuid4())
    session["admin_consent_state"] = state
    admin_consent_url = (
        f"{AUTHORITY}/adminconsent?"
        f"client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}"
        f"&state={state}"
    )
    return admin_consent_url

def generate_user_consent_url(user_email):
    """Generate user consent URL for admin"""
    state = str(uuid.uuid4())
    session["user_consent_state"] = state
    # Encode user email in state to identify the user
    encoded_email = urllib.parse.quote(user_email)
    user_consent_url = (
        f"{AUTHORITY}/adminconsent?"
        f"client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}"
        f"&state={state}"
        f"&user_email={encoded_email}"
    )
    return user_consent_url

def check_permissions(token):
    """Check if user has required permissions"""
    try:
        headers = {"Authorization": f"Bearer {token}"}
        # Check if user has transcript permissions
        url = "https://graph.microsoft.com/v1.0/me"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            user_data = response.json()
            logger.info(f"User permissions check successful for {user_data.get('userPrincipalName')}")
            return True, None
        elif response.status_code == 403:
            # Get user email for consent URL
            user_email = user_data.get('userPrincipalName') if user_data else None
            if user_email:
                user_consent_url = generate_user_consent_url(user_email)
                return False, {
                    'type': 'permission_denied',
                    'message': 'You do not have the required permissions.',
                    'user_consent_url': user_consent_url,
                    'user_email': user_email
                }
            else:
                return False, {
                    'type': 'permission_denied',
                    'message': 'You do not have the required permissions. Please contact your administrator.'
                }
        else:
            error_msg = f"Permission check failed (Error {response.status_code})"
            try:
                error_details = response.json()
                logger.error(f"❌ {error_msg}: {error_details}")
            except:
                logger.error(f"❌ {error_msg}")
            return False, {
                'type': 'error',
                'message': error_msg
            }
    except Exception as e:
        error_msg = f"Error checking permissions: {str(e)}"
        logger.error(error_msg)
        return False, {
            'type': 'error',
            'message': error_msg
        }

def refresh_token(refresh_token):
    """Refresh access token using refresh token"""
    try:
        token_url = f"{AUTHORITY}/oauth2/v2.0/token"
        data = {
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": refresh_token,
            "scope": SCOPE,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = requests.post(token_url, data=data, headers=headers)
        
        if response.status_code == 200:
            token_data = response.json()
            session["access_token"] = token_data["access_token"]
            if "refresh_token" in token_data:
                session["refresh_token"] = token_data["refresh_token"]
            return True, None
        else:
            logger.error(f"Token refresh failed: {response.status_code}")
            return False, "Failed to refresh token"
    except Exception as e:
        logger.error(f"Error refreshing token: {str(e)}")
        return False, str(e)

def get_latest_meeting_with_transcript(headers):
    """Get the latest meeting with transcript"""
    try:
        # Get meetings from the last 30 days
        start = datetime.utcnow() - timedelta(days=30)
        end = datetime.utcnow()
        url = f"https://graph.microsoft.com/v1.0/me/calendar/calendarView?startDateTime={start.isoformat()}Z&endDateTime={end.isoformat()}Z"
        
        logger.info("Fetching calendar events...")
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 401:  # Token expired
            logger.info("Token expired, attempting to refresh...")
            refresh_token = session.get("refresh_token")
            if refresh_token:
                success, error = refresh_token(refresh_token)
                if success:
                    headers["Authorization"] = f"Bearer {session['access_token']}"
                    response = requests.get(url, headers=headers, timeout=10)
                else:
                    return None, "Failed to refresh token"
            else:
                return None, "Token expired"
        
        events = response.json().get("value", [])
        if not events:
            return None, "No meetings found in the last 30 days"
        
        # Sort events by start time (newest first)
        events.sort(key=lambda x: x.get("start", {}).get("dateTime", ""), reverse=True)
        
        # Try each meeting until we find one with a transcript
        for event in events:
            try:
                join_url = event.get("onlineMeeting", {}).get("joinUrl")
                if not join_url:
                    continue
                
                # Get meeting ID
                encoded_url = urllib.parse.quote(join_url, safe="")
                meeting_lookup_url = f"https://graph.microsoft.com/v1.0/me/onlineMeetings?$filter=JoinWebUrl eq '{encoded_url}'"
                
                meeting_resp = requests.get(meeting_lookup_url, headers=headers, timeout=10)
                if meeting_resp.status_code == 401:  # Token expired
                    logger.info("Token expired during meeting lookup, attempting to refresh...")
                    refresh_token = session.get("refresh_token")
                    if refresh_token:
                        success, error = refresh_token(refresh_token)
                        if success:
                            headers["Authorization"] = f"Bearer {session['access_token']}"
                            meeting_resp = requests.get(meeting_lookup_url, headers=headers, timeout=10)
                        else:
                            continue
                
                meetings = meeting_resp.json().get("value", [])
                if not meetings:
                    continue
                
                meeting_id = meetings[0]["id"]
                logger.info(f"Found meeting ID: {meeting_id} for {event.get('subject', 'Untitled Meeting')}")
                
                # Get transcript IDs
                transcript_ids, error = get_meeting_transcriptions(meeting_id, headers)
                if error or not transcript_ids:
                    continue
                
                # Try to get transcript content
                for transcript_id in transcript_ids:
                    vtt_text, error_message = get_transcript_content_by_id(meeting_id, transcript_id, headers)
                    if vtt_text:
                        try:
                            ai_summary = analyze_meeting_transcript(vtt_text)
                            return {
                                'subject': event.get("subject", "Untitled Meeting"),
                                'start': datetime.fromisoformat(event.get("start", {}).get("dateTime", "").replace('Z', '')),
                                'join_url': join_url,
                                'transcript_html': f"""
                                <div class="meeting-summary">
                                    {ai_summary}
                                </div>
                                """,
                                'status': 'success'
                            }, None
                        except Exception as e:
                            logger.error(f"AI analysis failed: {str(e)}")
                            continue
                
            except Exception as e:
                logger.error(f"Error processing meeting: {str(e)}")
                continue
        
        return None, "No meetings with transcripts found"
        
    except Exception as e:
        logger.error(f"Error getting latest meeting: {str(e)}")
        return None, str(e)

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
    if request.args.get("state") == session.get("user_consent_state"):
        # Handle user consent callback
        if "error" in request.args:
            error = request.args.get("error")
            error_description = request.args.get("error_description", "Unknown error")
            logger.error(f"User consent failed: {error} - {error_description}")
            return render_template('login.html', error=f"User consent failed: {error_description}")
        
        # User consent successful, redirect to login
        return redirect("/login")
    
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
        # Check permissions after getting token
        has_permissions, error = check_permissions(token_response["access_token"])
        if not has_permissions:
            session.clear()
            return render_template('login.html', error=error)
        return redirect("/meetings")
    else:
        return f"❌ Token error: {token_response}", 400

@app.route("/meetings")
def meetings():
    token = session.get("access_token")
    if not token:
        return redirect("/")

    headers = {"Authorization": f"Bearer {token}"}
    error_message = None

    try:
        # Get the latest meeting with transcript
        meeting_data, error = get_latest_meeting_with_transcript(headers)
        
        if error:
            error_message = error
            return render_template('meetings.html', events=[], error=error_message)
        
        if meeting_data:
            return render_template('meetings.html', events=[meeting_data], error=None)
        else:
            return render_template('meetings.html', events=[], error="No meetings with transcripts found")
            
    except Exception as e:
        logger.error(f"Error in meetings route: {str(e)}")
        return render_template('meetings.html', events=[], error="Failed to load meetings. Please try again later.")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)