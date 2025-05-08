import requests
import os

# Your Azure AD credentials
CLIENT_ID = "2d0df75c-6bc1-446f-bcf0-a22aea96c9b3"
CLIENT_SECRET = "U7p8Q~vHMHQyI8ZpZu5-R7CaaPV_pXOSwvXgTakG"
TENANT_ID = "22438506-028b-45c7-9bd3-8badf683d7e3"
USER_ID = "70154120-c7da-45f8-9f7b-fb660e8694a3"
JOIN_WEB_URL = "https://teams.microsoft.com/l/meetup-join/19%3ameeting_YmIyMWNkYmQtODVlMS00YmU5LWE1OWItMTgwN2RlM2VmMzYy%40thread.v2/0?context=%7b%22Tid%22%3a%2222438506-028b-45c7-9bd3-8badf683d7e3%22%2c%22Oid%22%3a%2270154120-c7da-45f8-9f7b-fb660e8694a3%22%7d"# Function to get Access Token
def get_access_token():
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "https://graph.microsoft.com/.default"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = requests.post(url, data=data, headers=headers)
    if response.status_code == 200:
        print("✅ Access Token successfully retrieved!")
        return response.json()["access_token"]
    else:
        print("❌ Failed to retrieve Access Token:", response.json())
        return None

# Function to get Meeting ID using the join URL
def get_meeting_by_join_url(join_url):
    access_token = get_access_token()
    if not access_token:
        return None

    url = f"https://graph.microsoft.com/v1.0/users/{USER_ID}/onlineMeetings?$filter=JoinWebUrl eq '{join_url}'"
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        meetings = response.json().get("value", [])
        if meetings:
            meeting_id = meetings[0]["id"]
            print(f"✅ Meeting ID retrieved successfully: {meeting_id}")
            return meeting_id
        else:
            print("❌ No meeting found.")
            return None
    else:
        print("❌ Failed to retrieve meeting:", response.json())
        return None

# Function to get all transcription IDs for the meeting
def get_meeting_transcriptions(meeting_id):
    access_token = get_access_token()
    if not access_token:
        return None

    url = f"https://graph.microsoft.com/beta/users/{USER_ID}/onlineMeetings/{meeting_id}/transcripts"
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        transcripts = response.json().get("value", [])
        if transcripts:
            transcript_ids = [t["id"] for t in transcripts]
            print(f"✅ Retrieved {len(transcript_ids)} transcription IDs: {transcript_ids}")
            return transcript_ids
        else:
            print("❌ No transcription found.")
            return []
    else:
        print("❌ Failed to retrieve meeting transcriptions:", response.json())
        return []

# Function to download each transcription separately
def download_transcriptions(meeting_id, transcript_ids):
    access_token = get_access_token()
    if not access_token:
        return None

    os.makedirs("transcriptions", exist_ok=True)  # Create a folder to store transcriptions

    for i, transcript_id in enumerate(transcript_ids):
        url = f"https://graph.microsoft.com/beta/users/{USER_ID}/onlineMeetings/{meeting_id}/transcripts/{transcript_id}/content"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "text/vtt",  # Change format if needed (try "text/plain")
        }

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            transcript_text = response.text
            file_name = f"transcriptions/meeting_transcription_part_{i+1}.vtt"
            with open(file_name, "w", encoding="utf-8") as file:
                file.write(transcript_text)
            print(f"✅ Transcription {i+1} downloaded successfully: {file_name}")
        else:
            print(f"❌ Failed to download transcription {i+1}:", response.json())

# **Main execution flow**
if __name__ == "__main__":
    meeting_id = get_meeting_by_join_url(JOIN_WEB_URL)

    if meeting_id:
        transcript_ids = get_meeting_transcriptions(meeting_id)

        if transcript_ids:
            download_transcriptions(meeting_id, transcript_ids)
