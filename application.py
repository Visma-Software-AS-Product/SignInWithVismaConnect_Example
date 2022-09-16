import os

from flask import Flask, url_for, redirect, session, render_template
from authlib.integrations.flask_client import OAuth
from functools import wraps

# Creates the Flask-application 
app = Flask(__name__) 
# Sets a secret key for the session cookie
app.secret_key = os.environ.get('SECRET_KEY')

# Configuring the Authlib OAuth Client for Visma Connect
oauth = OAuth(app)
vismaconnect = oauth.register(
    name='Visma Connect',
    client_id=os.environ.get('CONNECT_CLIENT_ID'),
    client_secret=os.environ.get('CONNECT_CLIENT_SECRET'),
    access_token_url='https://connect.visma.com/connect/token',
    access_token_params=None,
    authorize_url='https://connect.visma.com/connect/authorize',
    authorize_params=None,
    api_base_url='https://connect.visma.com/connect/',
    client_kwargs={'scope': 'openid profile email'}
)

# Creates a decorator-function to be used on all functions that requires a logged in user
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if dict(session).get('name', None) is None: # Checks if the session contains a name of the user, if not redirect to the login-function
            return redirect(url_for('loginpage'))
        return f(*args, **kwargs)
    return decorated_function

# The route for the index-page. This page requires a logged in user
@app.route('/')
@login_required
def index():
    # Render the main page with values from the session
    return render_template('index.html', 
        name = dict(session).get('name', None), 
        email = dict(session).get('email', None), 
        firstname = dict(session).get('firstName', None),
        familyname = dict(session).get('familyName', None), 
        picture = dict(session).get('picture', None))

# The route for the login-page
@app.route('/loginpage')
def loginpage():
    # Renders the login-page to the user
    return render_template('login.html')

# The login-function reachable at route /login
@app.route('/login')
def login():
    # Creates the Visma Connect OAuth Client
    vismaconnect = oauth.create_client('Visma Connect')
    # Generates the authorize redirect-uri (must be registered with the application in Visma Developer Portal) 
    redirect_uri = url_for('authorize', _external=True)
    # Starts the authorization and redirect-process
    return vismaconnect.authorize_redirect(redirect_uri)

# The authorize-function (redirect-uri)
@app.route('/authorize')
def authorize():
    # Creates the Visma Connect OAuth Client
    vismaconnect = oauth.create_client('Visma Connect')
    # Collects the access-token
    token = vismaconnect.authorize_access_token()

    # Makes a call the get the user-information for the current user
    resp = vismaconnect.get('userinfo', token = token)
    # Checks for valid response-code (200-series)
    resp.raise_for_status()
    # Gets the user-info object from the response
    user_info = resp.json()

    # Sets the users name, email and profileinfo in the session
    session["name"] = user_info["name"]
    session["email"] = user_info["email"]    
    session["firstName"] = user_info["given_name"]
    session["familyName"] = user_info["family_name"]
    session["picture"] = user_info["picture"]

    # Redirects to the index-function
    return redirect('/')

# Function/route for logging out the user
@app.route('/logout')
def logout():
    # Cleans all the information in the session
    for key in list(session.keys()):
        session.pop(key)

    # redirects to the Visma Connect logout-function
    return redirect('https://connect.visma.com/logout')    