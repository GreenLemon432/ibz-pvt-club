from flask import Flask, render_template, request, redirect, session, url_for
import json
import os
import base64
from email.mime.text import MIMEText

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from googleapiclient.errors import HttpError

# TESTING
import google
from google.oauth2 import id_token
from google.auth.transport import requests as grequests

# TESTING ONLY
import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change to a secure secret key!

SCOPES = [
    'https://www.googleapis.com/auth/gmail.send',
    'openid',
    'https://www.googleapis.com/auth/userinfo.email'
]

API_SERVICE_NAME = 'gmail'
API_VERSION = 'v1'


def send_email(credentials, form_data):
    """Use Gmail API to send an email with form data."""
    try:
        service = googleapiclient.discovery.build(
            API_SERVICE_NAME, API_VERSION, credentials=credentials)

        email_text = f"""
New Signup Form Submission:

Name: {form_data.get('first_name', '')} {form_data.get('last_name', '')}
Email: {form_data.get('email', '')}
Birthday: {form_data.get('birthday', '')}
Phone: {form_data.get('phone', '')}
City: {form_data.get('city', '')}
Country: {form_data.get('country', '')}
Arrival: {form_data.get('arrival', '')}
User Type: {form_data.get('user_type', '')}
"""

        message = MIMEText(email_text)
        message['to'] = 'privateclubibiza@gmail.com'       # Your destination email
        message['from'] = 'privateclubibiza@gmail.com'     # Your Gmail address (must match OAuth account)
        message['subject'] = 'New Signup Form Submission'

        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        body = {'raw': raw_message}

        response = service.users().messages().send(userId='me', body=body).execute()
        print("Gmail API Response", response)
        return True
    except HttpError as error:
        print(f'An error occurred: {error}')
        return False


@app.route('/', methods=['GET', 'POST'])
def index():
    message = None

    if request.method == 'POST':
        form_data = request.form.to_dict()
        session['form_data'] = form_data

        if 'credentials' not in session:
            # Redirect to Google OAuth2 consent flow if no credentials yet
            return redirect(url_for('authorize'))

        # Load credentials from session
        credentials = google.oauth2.credentials.Credentials(**session['credentials'])

        # Try sending email
        if send_email(credentials, form_data):
            message = "Form submitted and email sent!"
        else:
            message = "Form submitted but failed to send email."

        return render_template('index.html', message=message)

    # GET request - just show form, no message
    return render_template('index.html', message=message)

@app.route('/authorize')
def authorize():
    client_config = json.loads(os.environ["GOOGLE_CREDENTIALS_JSON"])
    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        client_config,
        scopes=SCOPES
    )
    # Use your deployed URL here directly, to avoid mismatch
    flow.redirect_uri = 'https://ibz-pvt-club.onrender.com/oauth2callback'

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')

    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session.get('state')
    client_config = json.loads(os.environ["GOOGLE_CREDENTIALS_JSON"])
    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        client_config,
        scopes=SCOPES
    )
    # Use your deployed URL here directly, to avoid mismatch
    flow.redirect_uri = 'https://ibz-pvt-club.onrender.com/oauth2callback'

    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

    form_data = session.get('form_data')

    # TESTING Verify which email is linked to the token
    req = grequests.Request()
    id_info = id_token.verify_oauth2_token(credentials.id_token, req, credentials.client_id)
    print("Email associated with token:", id_info['email'])  # Check this in your console/logs

    form_data = session.get('form_data')
    if form_data and send_email(credentials, form_data):
        message = "Form submitted and email sent!"
    else:
        message = "Form submitted but failed to send email."

    return render_template('index.html', message=message)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
