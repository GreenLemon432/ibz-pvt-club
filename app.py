from flask import Flask, render_template, request, redirect, session, url_for
import os
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change to a secure secret key!


def send_email(form_data):
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

    msg = MIMEText(email_text)
    msg['Subject'] = 'New Signup Form Submission'
    msg['From'] = 'privateclubibiza@gmail.com'
    msg['To'] = 'privateclubibiza@gmail.com'

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login('privateclubibiza@gmail.com', os.environ.get("GMAIL_APP_PASSWORD"))
            server.send_message(msg)
        print("Email sent successfully!")
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False


@app.route('/', methods=['GET', 'POST'])
def index():
    message = None

    if request.method == 'POST':
        form_data = request.form.to_dict()

        if send_email(form_data):
            message = "Form submitted and email sent!"
        else:
            message = "Form submitted but failed to send email."

    return render_template('index.html', message=message)

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('private_policy.html')

@app.route('/terms')
def terms_and_services():
    return render_template('terms.html')

if __name__ == '__main__':
    app.run(debug=True)

