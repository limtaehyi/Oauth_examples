from flask import Flask, redirect, url_for, session, jsonify
from authlib.integrations.flask_client import OAuth
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
import secrets

app = Flask(__name__)
app.config['GOOGLE_ID'] = "<google_id>"
app.config['GOOGLE_SECRET'] = "<google_secret>"
app.config['SECRET_KEY'] = secrets.token_hex(24)
app.debug = True

oauth = OAuth(app)

oauth.register(
    name='google',
    client_id=app.config['GOOGLE_ID'],
    client_secret=app.config['GOOGLE_SECRET'],
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v3/',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
)

@app.route('/')
def index():
    token = session.get('token')
    if token:
        resp = oauth.google.get('userinfo', token=token)
        if resp.ok:
            return jsonify(resp.json())
        else:
            return f"Failed to fetch user info: {resp.text}", 400
    return redirect(url_for('login'))

@app.route('/login')
def login():
    return oauth.google.authorize_redirect(redirect_uri=url_for('authorized', _external=True))

@app.route('/logout')
def logout():
    session.pop('token', None)
    return redirect(url_for('index'))

@app.route('/login/authorized')
def authorized():
    token = oauth.google.authorize_access_token()
    session['token'] = token
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
