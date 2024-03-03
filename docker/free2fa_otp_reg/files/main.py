# main.py
# Copyright (C) 2024 Voloskov Aleksandr Nikolaevich

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""OTP Registration Portal Master File."""
import json
import logging
import base64
import os
import socket
import sqlite3
import re
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO

from flask import (Flask, request, render_template, send_file,
                   session, redirect, url_for, Blueprint, jsonify)
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired

import pyotp
import pyrad
import qrcode
import pytz
from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pyrad.packet import AccessRequest, AccessAccept
from config import Config


app = Flask(__name__)
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['MAX_LOGIN_ATTEMPTS'] = Config.MAX_LOGIN_ATTEMPTS
app.config['BLOCK_DURATION_MINUTES'] = Config.BLOCK_DURATION_MINUTES
# Set the session lifetime in minutes
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(
    minutes=Config.SESSION_LIFETIME)

reg_blueprint = Blueprint(
    'reg', __name__, url_prefix='/reg', static_folder='static')


if Config.LANGUAGE == 'ru':
    import ru_ru as loc
elif Config.LANGUAGE == 'en':
    import en_en as loc
else:
    # default value if language is not defined
    import en_en as loc

app.secret_key = os.getenv("OTP_SESSION_SECRET_KEY")
csrf = CSRFProtect(app)
DATABASE_PATH = '/opt/db/users.db'
LOGIN_ROUTE = 'reg.login'
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO,
                    format=LOG_FORMAT,
                    datefmt='%Y-%m-%d %H:%M:%S')

logger = logging.getLogger(__name__)


class FileStorage:
    """
    The FileStorage class is designed to protect against password brute force,
    managing temporary locks and controlling login attempts through file storage.
    """

    def __init__(self, filename):
        self.filename = filename

    def load(self):
        """
        Loads and returns the data from the specified file. If the file does not exist,
        returns an empty dictionary.
        """
        try:
            with open(self.filename, "r", encoding="utf-8") as file:  # Specify encoding
                return json.load(file)
        except FileNotFoundError:
            return {}

    def save(self, data):
        """
        Saves the given data to the specified file using JSON format.
        """
        with open(self.filename, "w", encoding="utf-8") as file:  # Specify encoding
            json.dump(data, file)


class RegistrationForm(FlaskForm):
    """
    The RegistrationForm class is designed to create a registration form in a Flask application,
    including login fields and a registration button.
    Flask application, including fields for login and registration button.
    """
    login = StringField('Login', validators=[DataRequired()])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    """
    The LoginForm class is designed to create a login form in a Flask application,
    containing fields for username and password, as well as a button for login.
    """
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


def login_required(func):
    """
    The login_required decorator defines a function that requires the user to
    authenticate before accessing protected routes. If the user
    is not authenticated, they are redirected to the login page.
    """
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session or not session['authenticated']:
            return redirect(url_for(LOGIN_ROUTE))
        return func(*args, **kwargs)
    return decorated_function


# File for storing information about login attempts
ATTEMPTS_FILE = "login_attempts.json"


def add_csp_header(response):
    """
    Adds a Content-Security-Policy (CSP) header to the response. The CSP restricts the sources
    from which resources can be downloaded, improving the security of the web application.
    In this case, the 'default-src 'self'' policy means that all resources must be downloaded
    from the same source as the document itself.
    """
    # CSP policy example:
    # default-src 'self' means that all resources must be downloaded from the same source
    # script-src 'self' https://trusted.cdn.com
    # allows scripts to be downloaded from the same source and from the specified CDN
    csp_policy = (
        "default-src 'self';"
    )
    response.headers['Content-Security-Policy'] = csp_policy
    return response


def get_login_attempts():
    """
    Loads and returns the number of login attempts from the file. If a file with attempts
    is not found, returns an empty dictionary, assuming no previous attempts.
    This helps in the implementation of the password brute force mechanism
    by allowing you to keep track of the
    the number of failed login attempts for different users.
    """
    try:
        with open(ATTEMPTS_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}


def save_login_attempts(attempts):
    """
    Saves the current status of file login attempts. This allows you to effectively
    track and limit the number of login attempts for users,
    preventing password brute force attacks.
    password brute force attacks. This approach enhances system security,
    by maintaining a history of access attempts.
    """
    with open(ATTEMPTS_FILE, "w", encoding="utf-8") as file:  # Указываем кодировку явно
        json.dump(attempts, file)


def check_and_reset_attempts(username):
    """
    Checks the number of login attempts for a given user and decides whether to block
    the user or reset the attempt counter based on the configuration of maximum
    attempts and block duration. It acts as a deterrent against brute-force attacks,
    enhancing system security by temporarily blocking access upon detecting suspicious
    activity.
    """
    max_attempts = app.config['MAX_LOGIN_ATTEMPTS']
    block_duration = app.config['BLOCK_DURATION_MINUTES']

    attempts = get_login_attempts()
    current_time = datetime.now()

    if username in attempts:
        last_attempt = attempts[username]
        last_attempt_time = datetime.fromisoformat(
            last_attempt["last_attempt"])
        time_since_last_attempt = current_time - last_attempt_time

        if time_since_last_attempt < timedelta(minutes=block_duration):
            if last_attempt["count"] >= max_attempts:
                logger.warning(
                    "Login for user %s is blocked due to too many login attempts", username)
                return True
        else:
            attempts[username] = {"count": 0,
                                  "last_attempt": current_time.isoformat()}
    else:
        attempts[username] = {"count": 0,
                              "last_attempt": current_time.isoformat()}

    save_login_attempts(attempts)
    return False


def increment_failed_attempts(username):
    """
    Increments the count of failed login attempts for a specified user and updates
    the timestamp of the last attempt. This function helps in monitoring and mitigating
    brute-force attack risks by tracking consecutive failed login attempts.
    """
    attempts = get_login_attempts()
    if username in attempts:
        attempts[username]["count"] += 1
        attempts[username]["last_attempt"] = datetime.now().isoformat()
    else:
        attempts[username] = {"count": 1,
                              "last_attempt": datetime.now().isoformat()}
    save_login_attempts(attempts)


storage = FileStorage("login_attempts.json")


def check_user_before_registration(username):
    """
    Checks if a user can proceed with registration based on their current status in the database.
    It verifies if the user exists, if they are allowed to register,
    or if they have already registered.
    Returns a tuple with a boolean indicating the action's outcome and a message for the user.
    """
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT otp_key FROM users WHERE domain_and_username = ?", (username,))
        result = cursor.fetchone()

        if result is None:
            return False, loc.MESSAGES["reg_deny"]
        if result[0] == "1":
            return True, loc.MESSAGES["reg_cont"]
        if result[0] == "0":
            return False, loc.MESSAGES["reg_deny"]
        return False, loc.MESSAGES["reg_already"]


# Function for adding a user to the database after OTP verification
def update_user_after_verification(username, new_secret):
    """
    Updates the user's record in the database with a new OTP secret
    key after successful OTP verification.
    Returns a success message upon updating the record.
    """
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        # Update otp_key only if verification is successful
        cursor.execute(
            "UPDATE users SET otp_key = ? WHERE domain_and_username = ?", (new_secret, username))
        conn.commit()
        return loc.MESSAGES["successful_upgrade"]


def create_qr_code(data):
    """
    Generates a QR code image for the given data and returns it as a byte stream.
    This allows for easy integration and display in web applications or for storage.
    """
    qr_code_img = qrcode.make(data)
    img_io = BytesIO()
    qr_code_img.save(img_io, 'PNG')
    img_io.seek(0)
    return img_io


@app.before_request
def before_request():
    """
    Sets the session as persistent and updates the time of the user's last activity.
    Checks if the time since the user's last activity has elapsed more,
    than the time specified in PERMANENT_SESSION_LIFETIME.
    If so, clears the session and redirects the user to the login page.
    This prevents the use of a session that has been inactive for longer than the allowed time.
    """
    session.permanent = True  # pylint: disable=assigning-non-slot
    session.modified = True  # pylint: disable=assigning-non-slot
    if 'last_activity' in session:
        last_activity = datetime.fromisoformat(session['last_activity'])
        last_activity_utc = last_activity.replace(tzinfo=pytz.utc)
        now_utc = datetime.utcnow().replace(tzinfo=pytz.utc)

        # Difference in seconds between the current time and the time of the last activity
        seconds_since_last_activity = (
            now_utc - last_activity_utc).total_seconds()
        # Session lifetime in seconds
        session_lifetime_seconds = app.config['PERMANENT_SESSION_LIFETIME'].total_seconds(
        )

        if seconds_since_last_activity > session_lifetime_seconds:
            session.clear()
            return redirect(url_for('login'))
    session['last_activity'] = datetime.now().isoformat()
    return None


@app.after_request
def apply_csp(response):
    """
    Applies CSP headers to the response to enhance security.

    Args:
        response: The response object.

    Returns:
        The modified response object with CSP headers.
    """
    return add_csp_header(response)


@app.context_processor
def inject_loc():
    """
    Injects localization data into all templates.

    Returns:
        A dictionary with localization resources for template use.
    """
    return dict(loc=loc)


@reg_blueprint.route('/registration', methods=['GET', 'POST'])
@login_required
def register():
    """
    Handles the registration process, generates a secret for two-factor authentication,
    and renders the registration template with a QR code for the user to scan.
    """
    form = RegistrationForm()
    user_id = session.get('user_id')
    secret = pyotp.random_base32()
    # Save the secret in the session to use it later to generate a QR code
    session['secret'] = secret
    session['otp_uri'] = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user_id, issuer_name=Config.OTP_FIRM_INFO)
    logger.info("Generated secret for user %s", user_id)

    return render_template('registration.html', login=user_id, form=form)


@reg_blueprint.route('/verify', methods=['POST'])
@login_required
def verify():
    """
    Verifies the one-time password (OTP) entered by the user during the two-factor
    authentication process. If the verification is successful, updates the user's
    status and logs them out, returning a success message and a redirect URL.
    Returns an error message if verification fails.
    """
    username = request.form['login']
    secret = session.get('secret')
    otp = request.form['otp']
    totp = pyotp.TOTP(secret)

    if totp.verify(otp, valid_window=1):
        update_user_after_verification(username, secret)
        logger.info("User %s successfully registered", username)
        logout_silent()
        return jsonify({'message': loc.MESSAGES["successful_reg"],
                        'redirect_url': url_for(LOGIN_ROUTE)})

    return jsonify({'message': loc.MESSAGES["unsuccessful_reg"]}), 400


@reg_blueprint.route('/qr-code')
@login_required
def qr_code():
    """
    Generates and sends a QR code image based on the OTP URI stored in the session.
    This QR code is used for setting up two-factor authentication in an authenticator app.
    Returns a 404 error if the OTP URI is not found in the session.
    """
    # Extract data for QR code from session
    otp_uri = session.get('otp_uri')
    if not otp_uri:
        return "Error: Data for QR code not found", 404
    qr_img = create_qr_code(otp_uri)
    return send_file(qr_img, mimetype='image/png')


def radius_authentication(username, password):
    """
    Authenticate a user against the RADIUS server.

    :param username: Username for authentication.
    :param password: Password for authentication.
    :return: Reply packet from the RADIUS server.
    """
    radius_secret_env = Config.OTP_RADIUS_SECRET
    radius_server = 'host.docker.internal'
    radius_secret = bytes(radius_secret_env, 'utf-8')
    radius_port = Config.OTP_RADIUS_PORT
    radius_client = Client(server=radius_server, secret=radius_secret,
                           dict=Dictionary("dictionary"), authport=radius_port, retries=1,
                           timeout=Config.FREE2FA_TIMEOUT+2)

    req = radius_client.CreateAuthPacket(
        code=AccessRequest, User_Name=username, NAS_Identifier="nas_id")
    req["User-Password"] = req.PwCrypt(password)
    reply = radius_client.SendPacket(req)
    return reply


def handle_authentication_result(username, reply):
    """
    Handle the result of the RADIUS authentication.

    :param username: Username of the user.
    :param reply: Reply packet from the RADIUS server.
    :return: Redirect to welcome page or render login template with error.
    """
    if reply.code == AccessAccept:
        logger.info("Successful user authorization %s", username)
        session['username'] = username
        session['authenticated'] = True
        session['user_id'] = username
        return redirect(url_for('reg.welcome'))

    logger.warning("Incorrect login or password %s", username)
    increment_failed_attempts(username)
    return render_template('login.html', form=LoginForm(),
                           error_message=loc.MESSAGES["Incorrect_input"])


def handle_exceptions(error):
    """
    Handle exceptions raised during RADIUS authentication.

    :param error: Exception instance.
    :return: Error message as a string.
    """
    if isinstance(error, pyrad.client.Timeout):
        logger.error("Timeout while connecting to RADIUS server")
        return "RADIUS server error: Timeout exceeded"
    if isinstance(error, socket.error):
        logger.error(
            "Network error while connecting to RADIUS server: %s", error)
        return f"Network error when connecting to the RADIUS server: {error}"
    return "An unknown error occurred"


@reg_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handle login requests. Authenticate users and manage login attempts.
    """
    form = LoginForm()
    log_message = ""  # Prepare a variable for log reporting

    if form.validate_on_submit():
        username = form.username.data

        if check_and_reset_attempts(username):
            logger.info("Too many login attempts")
            return loc.MESSAGES["too_many_tries"]

        if re.match(r'^[\w\.\-\\@]+$', username):
            registration_allowed, message = check_user_before_registration(username)
        else:
            registration_allowed = False
            message = loc.MESSAGES["reg_deny"]
            encoded_username = base64.b64encode(username.encode('UTF-8')).decode('UTF-8')
            log_message = f"Registration not allowed for user with encoded username: {encoded_username}"

        if not registration_allowed:
            increment_failed_attempts(username)
            # Preparing a message for logging, if it has not already been prepared
            if not log_message:
                log_message = f"Registration not allowed for user: {username}"
            logger.info(log_message)  # Output a message to the log
            return render_template('login.html', form=form, error_message=message)

        try:
            reply = radius_authentication(username, form.password.data)
            logger.info("User authenticated successfully")
            return handle_authentication_result(username, reply)
        except (pyrad.client.Timeout, socket.error) as error:
            logger.error(f"Error during authentication: {error}")
            return handle_exceptions(error)

    return render_template('login_form.html', form=form)


@reg_blueprint.route('/logout')
@login_required
def logout():
    """
    Logout the current user and redirect to the login page.

    This function clears the user's session and redirects to the login page,
    effectively logging the user out.
    """
    logout_silent()
    return redirect(url_for(LOGIN_ROUTE))


def logout_silent():
    """
    Clear the user's session without logging messages.

    This helper function silently clears authentication and user ID from the session,
    used primarily during the logout process.
    """
    session.pop('authenticated', None)
    session.pop('user_id', None)


def create_and_save_qr_code(data, path_to_save):
    """
    Creates a QR code from the given data and saves it to a specified path.

    :param data: The data to encode in the QR code.
    :param path_to_save: The file path where the QR code image will be saved.
    """
    # Check if there is a directory for saving. If not, create it.
    directory = os.path.dirname(path_to_save)
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)

    # Creating a QR code
    app_link_qr_code = qrcode.make(data)
    # Saving the QR code to a file
    app_link_qr_code.save(path_to_save)


ANDROID_APP_URL = (
    'https://play.google.com/store/apps/details?id='
    'com.google.android.apps.authenticator2'
)

IOS_APP_URL = (
    'https://apps.apple.com/us/app/google-authenticator/'
    'id388497605'
)


# Save QR codes as files
ANDROID_QR_PATH = 'static/qr_android.png'
IOS_QR_PATH = 'static/qr_ios.png'

create_and_save_qr_code(ANDROID_APP_URL, ANDROID_QR_PATH)
create_and_save_qr_code(IOS_APP_URL, IOS_QR_PATH)


@reg_blueprint.route('/welcome')
@login_required
def welcome():
    """
    Displays the welcome page for authenticated users.

    :return: The rendered template of the welcome page.
    """
    return render_template('welcome.html')


# Add a decorator to each answer
app.after_request(add_csp_header)
app.register_blueprint(reg_blueprint)
