from flask import Flask, redirect, request, session, render_template
from flask_session import Session
import requests
import uuid
import os
import urllib.parse
from datetime import datetime, timedelta
import re
import logging
import time
import markdown
from functools import lru_cache

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Azure OpenAI 配置
AZURE_OPENAI_API_KEY = "2SHKaZLHvA86Afv9cl8P3H5A39yxcH7VFAFIPKZHNBuiWii9ZA4lJQQJ99BEACHYHv6XJ3w3AAAAACOG0A1O"
AZURE_OPENAI_ENDPOINT = "https://u7761-maoqersn-eastus2.cognitiveservices.azure.com"
AZURE_OPENAI_API_VERSION = "2025-01-01-preview"
AZURE_OPENAI_DEPLOYMENT_NAME = "o3-mini"

# 在文件开头添加调试信息
logger.info("Environment variables:")
logger.info(f"HTTP_PROXY: {os.environ.get('HTTP_PROXY')}")
logger.info(f"HTTPS_PROXY: {os.environ.get('HTTPS_PROXY')}")

# 添加 Azure OpenAI 配置日志
logger.info("Azure OpenAI configuration:")
logger.info(f"API Endpoint: {AZURE_OPENAI_ENDPOINT}")
logger.info(f"API Version: {AZURE_OPENAI_API_VERSION}")
logger.info(f"Deployment Name: {AZURE_OPENAI_DEPLOYMENT_NAME}")

# 添加简单的内存缓存
class MeetingCache:
    def __init__(self):
        self.cache = {}
        self.expiry = {}

    def set(self, meeting_id, data):
        self.cache[meeting_id] = data
        self.expiry[meeting_id] = datetime.now() + timedelta(hours=1)

    def get(self, meeting_id):
        if meeting_id in self.cache:
            if datetime.now() < self.expiry[meeting_id]:
                return self.cache[meeting_id]
            else:
                del self.cache[meeting_id]
                del self.expiry[meeting_id]
        return None

meeting_cache = MeetingCache()

# 在分析函数中使用缓存
@lru_cache(maxsize=100)
def analyze_meeting_transcript(transcript_text, max_retries=3):
    """Analyze meeting transcript with retry mechanism"""
    for attempt in range(max_retries):
        try:
            # 构造 API URL
            url = f"{AZURE_OPENAI_ENDPOINT}/openai/deployments/{AZURE_OPENAI_DEPLOYMENT_NAME}/chat/completions?api-version={AZURE_OPENAI_API_VERSION}"
            
            # 设置请求头
            headers = {
                "api-key": AZURE_OPENAI_API_KEY,
                "Content-Type": "application/json"
            }
            
            # 构造请求体
            data = {
                "model": "o3-mini",
                "messages": [
                    {"role": "system", "content": """I'm providing a meeting transcript. Please generate meeting minutes with a particular focus on working-group.
While covering the general meeting flow, please ensure the minutes thoroughly detail:
Key Discussion Points related to working-group:
Decisions Made regarding working-group:
Action Items specifically concerning working-group: (Include assigned person and deadline if available).
A brief summary of other topics discussed.
Overall list of attendees (if discernible).
Date and Time (if discernible).
Format the output clearly in markdown with proper sections and bullet points."""},
                    {"role": "user", "content": transcript_text}
                ]
            }
            
            # 添加请求日志
            logger.info(f"Sending request to {url}")
            
            # 发送请求
            response = requests.post(url, headers=headers, json=data, timeout=30)
            
            # 添加详细的错误日志
            if response.status_code != 200:
                logger.error(f"API Error: Status {response.status_code}")
                logger.error(f"Response headers: {response.headers}")
                try:
                    error_details = response.json()
                    logger.error(f"Error details: {error_details}")
                except:
                    logger.error(f"Raw response: {response.text}")
                response.raise_for_status()
            
            # 解析响应
            response_data = response.json()
            if not response_data.get("choices") or not response_data["choices"][0].get("message", {}).get("content"):
                raise ValueError("Invalid response format")
                
            logger.info("AI analysis completed successfully")
            return response_data["choices"][0]["message"]["content"]
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error: {str(e)}")
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                logger.info(f"Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                raise
        except ValueError as e:
            logger.error(f"Invalid response: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
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
    """Get all transcription IDs for a meeting using /me/onlineMeetings/ API"""
    try:
        url = f"https://graph.microsoft.com/beta/me/onlineMeetings/{meeting_id}/transcripts"
        response = requests.get(url, headers=headers, timeout=5)  # 减少超时时间
        
        if response.status_code == 200:
            transcripts = response.json().get("value", [])
            if transcripts:
                transcript_ids = [t["id"] for t in transcripts]
                logger.info(f"Found {len(transcript_ids)} transcript(s) for meeting {meeting_id[:10]}...")
                return transcript_ids, None
            return [], "No transcriptions available"
        return [], f"Failed to retrieve transcriptions (Error {response.status_code})"
    except Exception as e:
        return [], f"Error getting transcriptions: {str(e)}"

def get_transcript_content_by_id(meeting_id, transcript_id, headers):
    """Get transcript content using /me/onlineMeetings/ API"""
    logger.info(f"[get_transcript_content_by_id] Start for meeting_id: {meeting_id}, transcript_id: {transcript_id}")
    try:
        content_url = f"https://graph.microsoft.com/beta/me/onlineMeetings/{meeting_id}/transcripts/{transcript_id}/content"
        content_headers = headers.copy()
        content_headers["Accept"] = "text/vtt"
        logger.info(f"[get_transcript_content_by_id] Requesting transcript content from: {content_url}")
        logger.info("[get_transcript_content_by_id] Before sending request for transcript content")
        content_resp = requests.get(content_url, headers=content_headers, timeout=10)
        logger.info("[get_transcript_content_by_id] After sending request for transcript content")
        logger.info(f"[get_transcript_content_by_id] Transcript content response status: {content_resp.status_code}")
        if content_resp.status_code == 200:
            logger.info("[get_transcript_content_by_id] Successfully retrieved transcript content")
            return content_resp.text, None
        elif content_resp.status_code == 402:
            try:
                error_details = content_resp.json()
                error_message = error_details.get('error', {}).get('message', 'This meeting transcript requires a premium subscription.')
                logger.warning(f"[get_transcript_content_by_id] PaymentRequired details: {error_details}")
            except Exception as e:
                error_message = 'This meeting transcript requires a premium subscription.'
                logger.warning(f"[get_transcript_content_by_id] PaymentRequired, Exception: {str(e)}")
            return None, {
                'type': 'premium_required',
                'message': error_message,
                'html': f"""
                <div class=\"premium-message\">
                    <i class=\"fas fa-crown me-1\"></i>
                    <strong>Premium Feature</strong>
                    <p class=\"mb-0\">{error_message}</p>
                    <small>Please contact your administrator to upgrade your subscription.</small>
                </div>
                """
            }
        else:
            error_message = f"Failed to get transcript (Error {content_resp.status_code})"
            try:
                error_details = content_resp.json()
                logger.error(f"[get_transcript_content_by_id] Error details: {error_details}")
            except Exception as e:
                logger.error(f"[get_transcript_content_by_id] {error_message}, Exception: {str(e)}")
            return None, {
                'type': 'error',
                'message': error_message,
                'html': f"""
                <div class=\"text-warning\">
                    <i class=\"fas fa-exclamation-triangle me-1\"></i>
                    {error_message}
                </div>
                """
            }
    except requests.exceptions.RequestException as e:
        logger.error(f"[get_transcript_content_by_id] Request error for transcript: {str(e)}")
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

def get_meeting_transcriptions_with_retry(meeting_id, headers, max_retries=2, delay=2):
    """带重试机制的获取会议记录，减少重试次数和等待时间"""
    for attempt in range(max_retries):
        transcript_ids, error = get_meeting_transcriptions(meeting_id, headers)
        if transcript_ids:
            return transcript_ids, None
        if attempt < max_retries - 1:
            time.sleep(delay)
    return [], "No transcriptions available after retries"

def check_meeting_recording_settings(meeting_id, headers):
    """检查会议录制设置"""
    try:
        url = f"https://graph.microsoft.com/v1.0/me/onlineMeetings/{meeting_id}"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            meeting_data = response.json()
            recording_enabled = meeting_data.get('allowMeetingChat', False)
            logger.info(f"Meeting recording settings: {meeting_data}")
            return recording_enabled
        return False
    except Exception as e:
        logger.error(f"Error checking meeting settings: {str(e)}")
        return False

def check_transcript_status(meeting_id, headers):
    """检查会议记录状态"""
    try:
        url = f"https://graph.microsoft.com/beta/me/onlineMeetings/{meeting_id}/transcripts"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('@odata.count', 0) == 0:
                # 检查会议是否已结束
                meeting_url = f"https://graph.microsoft.com/v1.0/me/onlineMeetings/{meeting_id}"
                meeting_response = requests.get(meeting_url, headers=headers)
                if meeting_response.status_code == 200:
                    meeting_data = meeting_response.json()
                    end_time = datetime.fromisoformat(meeting_data.get('endDateTime', '').replace('Z', ''))
                    if datetime.utcnow() < end_time:
                        return 'in_progress'
                    return 'not_available'
            return 'available'
        return 'error'
    except Exception as e:
        logger.error(f"Error checking transcript status: {str(e)}")
        return 'error'

def process_meeting_transcript(meeting_id, transcript_content):
    try:
        # 检查缓存
        cached_result = meeting_cache.get(meeting_id)
        if cached_result:
            logger.info(f"Using cached result for meeting {meeting_id}")
            return cached_result

        # 分析会议记录
        ai_summary = analyze_meeting_transcript(transcript_content)
        
        # 转换 Markdown 为 HTML
        html_content = markdown.markdown(
            ai_summary,
            extensions=['extra', 'nl2br']
        )
        
        result = {
            'status': 'success',
            'html_content': html_content,
            'markdown_content': ai_summary
        }
        
        # 缓存结果
        meeting_cache.set(meeting_id, result)
        
        return result
            
    except ValueError as ve:
        logger.error(f"Validation error: {str(ve)}")
        return {
            'status': 'error',
            'message': f"Invalid input: {str(ve)}"
        }
    except Exception as e:
        logger.error(f"Processing failed: {str(e)}")
        return {
            'status': 'error',
            'message': f"Processing failed: {str(e)}"
        }

def test_azure_openai_connection():
    """Test Azure OpenAI connection and configuration"""
    try:
        # 构造测试请求
        url = f"{AZURE_OPENAI_ENDPOINT}/openai/deployments/{AZURE_OPENAI_DEPLOYMENT_NAME}/chat/completions?api-version={AZURE_OPENAI_API_VERSION}"
        headers = {
            "api-key": AZURE_OPENAI_API_KEY,
            "Content-Type": "application/json"
        }
        data = {
            "model": "o3-mini",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Hello, this is a test message."}
            ]
        }

        # 打印配置信息
        logger.info("Testing Azure OpenAI connection with configuration:")
        logger.info(f"Endpoint: {AZURE_OPENAI_ENDPOINT}")
        logger.info(f"Deployment: {AZURE_OPENAI_DEPLOYMENT_NAME}")
        logger.info(f"API Version: {AZURE_OPENAI_API_VERSION}")
        logger.info(f"API Key (first 10 chars): {AZURE_OPENAI_API_KEY[:10]}...")

        # 发送测试请求
        logger.info("Sending test request...")
        response = requests.post(url, headers=headers, json=data, timeout=30)
        
        # 检查响应
        if response.status_code == 200:
            logger.info("✅ Connection test successful!")
            return True
        else:
            logger.error(f"❌ Connection test failed with status {response.status_code}")
            logger.error(f"Response headers: {response.headers}")
            try:
                error_details = response.json()
                logger.error(f"Error details: {error_details}")
            except:
                logger.error(f"Raw response: {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Connection test failed with error: {str(e)}")
        return False

def get_latest_meeting_with_transcript(headers):
    """Get the latest meeting with transcript"""
    try:
        # 获取最近7天的会议
        start = datetime.utcnow() - timedelta(days=7)
        end = datetime.utcnow()
        url = f"https://graph.microsoft.com/v1.0/me/calendar/calendarView?startDateTime={start.isoformat()}Z&endDateTime={end.isoformat()}Z&$top=5&$orderby=start/dateTime desc"
        
        response = requests.get(url, headers=headers, timeout=5)
        
        if response.status_code == 401:  # Token expired
            refresh_token = session.get("refresh_token")
            if refresh_token:
                success, error = refresh_token(refresh_token)
                if success:
                    headers["Authorization"] = f"Bearer {session['access_token']}"
                    response = requests.get(url, headers=headers, timeout=5)
                else:
                    return None, "Failed to refresh token"
            else:
                return None, "Token expired"
        
        events = response.json().get("value", [])
        if not events:
            return None, "No meetings found in the last 7 days"
        
        # 遍历会议
        for event in events:
            join_url = event.get("onlineMeeting", {}).get("joinUrl")
            if not join_url:
                continue
            
            # 获取会议ID
            encoded_url = urllib.parse.quote(join_url, safe="")
            meeting_lookup_url = f"https://graph.microsoft.com/v1.0/me/onlineMeetings?$filter=JoinWebUrl eq '{encoded_url}'"
            
            meeting_resp = requests.get(meeting_lookup_url, headers=headers, timeout=5)
            if meeting_resp.status_code == 401:
                continue
            
            meetings = meeting_resp.json().get("value", [])
            if not meetings:
                continue
            
            meeting_id = meetings[0]["id"]
            transcript_ids, error = get_meeting_transcriptions_with_retry(meeting_id, headers)
            
            if transcript_ids:
                # 只获取第一个可用的会议记录
                transcript_id = transcript_ids[0]
                vtt_text, error_message = get_transcript_content_by_id(meeting_id, transcript_id, headers)
                
                if vtt_text:
                    try:
                        ai_summary = analyze_meeting_transcript(vtt_text)
                        ai_summary_html = markdown.markdown(ai_summary, extensions=['extra', 'nl2br'])
                        return {
                            'subject': event.get("subject", "Untitled Meeting"),
                            'start': datetime.fromisoformat(event.get("start", {}).get("dateTime", "").replace('Z', '')),
                            'join_url': join_url,
                            'transcript_html': f"""
                            <div class="meeting-summary">
                                {ai_summary_html}
                            </div>
                            """,
                            'status': 'success'
                        }, None
                    except Exception as e:
                        logger.error(f"AI analysis failed: {str(e)}")
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

CLIENT_ID = os.environ.get("CLIENT_ID", "080b1826-6d96-4ab4-b614-ccbd4a0114d7")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "rp_8Q~~kQGivK_C5PotHmck5WX8O3tXqkSjc9apR")
TENANT_ID = os.environ.get("TENANT_ID", "22438506-028b-45c7-9bd3-8badf683d7e3")
REDIRECT_URI = "https://test-api-aht9.onrender.com/callback"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE = "openid profile email OnlineMeetings.Read OnlineMeetingTranscript.Read.All Calendars.Read User.Read"

logger.info(f"[Startup] Using CLIENT_ID (app id): {CLIENT_ID}")

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
    logger.info(f"[meetings route] Using CLIENT_ID (app id): {CLIENT_ID}")
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

# 在应用启动时运行测试
if __name__ == "__main__":
    # 运行连接测试
    if not test_azure_openai_connection():
        logger.error("Azure OpenAI connection test failed. Please check your configuration.")
        exit(1)
        
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)