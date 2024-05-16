from flask import Flask, redirect, url_for, session, jsonify
from flask_oauthlib.client import OAuth
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
import secrets

app = Flask(__name__)
app.config['GOOGLE_ID'] = "<google_id>"
app.config['GOOGLE_SECRET'] = "<google_secret>"
app.config['SECRET_KEY'] = secrets.token_hex(24)
app.debug = True

oauth = OAuth(app)
google = oauth.remote_app(
    'google',
    consumer_key=app.config.get('GOOGLE_ID'),
    consumer_secret=app.config.get('GOOGLE_SECRET'),
    request_token_params={
        'scope': 'email openid profile'
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

@app.route('/')
def index():
    if 'google_token' in session:
        me = google.get('userinfo')
        return jsonify({"data": me.data})
    return redirect(url_for('login'))

@app.route('/login')
def login():
    return google.authorize(callback=url_for('authorized', _external=True))

@app.route('/logout')
def logout():
    session.pop('google_token', None)
    return redirect(url_for('index'))

@app.route('/login/authorized')
@google.authorized_handler
def authorized(resp):
    session['google_token'] = (resp['access_token'], '')
    return redirect(url_for('index'))

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

if __name__ == '__main__':
    app.run()
