from flask import Flask, redirect, url_for, session, request, jsonify
from flask_oauthlib.client import OAuth
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')  # Use the secret key from the .env file
oauth = OAuth(app)

# Configuring Google OAuth 2.0
google = oauth.remote_app(
    'google',
    consumer_key=os.getenv('GOOGLE_CLIENT_ID'),  # Use the client ID from the .env file
    consumer_secret=os.getenv('GOOGLE_CLIENT_SECRET'),  # Use the client secret from the .env file
    request_token_params={
        'scope': 'https://www.googleapis.com/auth/youtube'
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

@app.route('/')
def index():
    return 'Welcome! Please <a href="/login">login</a> to continue.'

# Login route
@app.route('/login')
def login():
    return google.authorize(callback=url_for('authorized', _external=True))

# Logout route
@app.route('/logout')
def logout():
    session.pop('google_token', None)
    return redirect(url_for('index'))

# Google OAuth callback
@app.route('/login/authorized')
def authorized():
    response = google.authorized_response()
    if response is None or response.get('access_token') is None:
        return 'Access denied: reason={} error={}'.format(
            request.args.get('error_reason'),
            request.args.get('error_description')
        )

    # Save the access token in the session
    session['google_token'] = (response['access_token'], '')
    return redirect(url_for('get_stream_key'))

# Token getter
@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

# Route to get the YouTube stream key
@app.route('/stream_key')
def get_stream_key():
    if 'google_token' not in session:
        return redirect(url_for('login'))

    access_token = session.get('google_token')[0]
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    # Step 1: Create a live stream
    stream_data = {
        "snippet": {
            "title": "My Live Stream"
        },
        "cdn": {
            "ingestionType": "rtmp",
            "resolution": "720p",
            "frameRate": "30fps"
        }
    }

    stream_response = requests.post(
        'https://www.googleapis.com/youtube/v3/liveStreams?part=snippet,cdn',
        headers=headers,
        json=stream_data
    )

    if not stream_response.ok:
        return 'Failed to create live stream: ' + stream_response.text

    stream = stream_response.json()
    stream_id = stream['id']

    # Step 2: Create a live broadcast
    broadcast_data = {
        "snippet": {
            "title": "My Live Broadcast",
            "scheduledStartTime": (datetime.utcnow() + timedelta(minutes=1)).isoformat("T") + "Z",
            "scheduledEndTime": (datetime.utcnow() + timedelta(hours=1)).isoformat("T") + "Z"
        },
        "status": {
            "privacyStatus": "private"
        },
        "contentDetails": {
            "enableAutoStart": True,
            "enableAutoStop": True
        }
    }

    broadcast_response = requests.post(
        'https://www.googleapis.com/youtube/v3/liveBroadcasts?part=snippet,status,contentDetails',
        headers=headers,
        json=broadcast_data
    )

    if not broadcast_response.ok:
        return 'Failed to create live broadcast: ' + broadcast_response.text

    broadcast = broadcast_response.json()
    broadcast_id = broadcast['id']

    # Step 3: Bind the live stream to the broadcast
    bind_response = requests.post(
        f'https://www.googleapis.com/youtube/v3/liveBroadcasts/bind?id={broadcast_id}&part=id,contentDetails&streamId={stream_id}',
        headers=headers
    )

    if not bind_response.ok:
        return 'Failed to bind live stream to broadcast: ' + bind_response.text

    # API call to get live broadcasts from YouTube
    response = requests.get(
        'https://www.googleapis.com/youtube/v3/liveBroadcasts?part=snippet,contentDetails&broadcastStatus=upcoming',
        headers=headers
    )

    if response.ok:
        data = response.json()
        if 'items' in data and len(data['items']) > 0:
            # Extract the stream key (stream's ingestion address and key)
            stream_response = requests.get(
                f'https://www.googleapis.com/youtube/v3/liveStreams?part=cdn&id={stream_id}',
                headers=headers
            )
            if stream_response.ok:
                stream_data = stream_response.json()
                ingestion_info = stream_data['items'][0]['cdn']['ingestionInfo']
                stream_url = ingestion_info['ingestionAddress']
                stream_name = ingestion_info['streamName']
                return f'Your stream URL: {stream_url}<br>Your stream key: {stream_name}'
            else:
                return 'Failed to retrieve stream ingestion info: ' + stream_response.text
        else:
            return 'No upcoming live broadcasts found.'
    else:
        return 'Failed to retrieve live broadcasts: ' + response.text

if __name__ == '__main__':
    app.run(debug=True)
