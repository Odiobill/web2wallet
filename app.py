from flask import Flask, redirect, url_for, session, request
from authlib.integrations.flask_client import OAuth
import os
from dotenv import load_dotenv
import logging
import secrets
import base64
import hashlib
from urllib.parse import urlencode
import requests
import json
from filelock import FileLock
from functools import wraps

load_dotenv()

# --- Structured Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# API Keys authentication
API_KEYS = os.getenv("API_KEYS")
if API_KEYS:
    API_KEYS = [key.strip() for key in API_KEYS.split(',')]
else:
    API_KEYS = []


def require_api_key(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not API_KEYS:
            return func(*args, **kwargs)

        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return {"error": "Unauthorized", "message": "Authorization header missing or malformed"}, 401

        provided_key = auth_header.split('Bearer ')[1]
        if provided_key not in API_KEYS:
            return {"error": "Unauthorized", "message": "Invalid API key"}, 401

        return func(*args, **kwargs)
    return wrapper


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

oauth = OAuth(app)

# --- Conditional Provider Registration ---

# Load Google credentials
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI:
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={
            'scope': 'openid email profile',
            'redirect_uri': GOOGLE_REDIRECT_URI,
        }
    )
    logging.info("Google OAuth provider registered.")


# --- Configurable Redirect URLs ---
SUCCESS_REDIRECT_URL = os.getenv("SUCCESS_REDIRECT_URL")
FAILURE_REDIRECT_URL = os.getenv("FAILURE_REDIRECT_URL")
LOGOUT_REDIRECT_URL = os.getenv("LOGOUT_REDIRECT_URL")

# --- NMKR: Configuration and Wallet Storage ---
NMKR_API_KEY = os.getenv("NMKR_API_KEY")
NMKR_CUSTOMER_ID = os.getenv("NMKR_CUSTOMER_ID")
NMKR_ENABLED = NMKR_API_KEY and NMKR_CUSTOMER_ID
WALLET_STORAGE_FILE = os.getenv("WALLET_STORAGE_FILE", "wallets.json")
WALLET_LOCK_FILE = f"{WALLET_STORAGE_FILE}.lock"


if NMKR_ENABLED:
    logging.info("NMKR wallet feature is enabled.")


def get_wallet_associations():
    """Loads wallet associations from the JSON file."""
    if not os.path.exists(WALLET_STORAGE_FILE):
        return {}
    try:
        with open(WALLET_STORAGE_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def save_wallet_association(oauth_user_id, wallet_address):
    """Saves a new wallet association to the JSON file safely using a file lock."""
    lock = FileLock(WALLET_LOCK_FILE)
    with lock:
        associations = get_wallet_associations()
        associations[oauth_user_id] = wallet_address
        with open(WALLET_STORAGE_FILE, 'w') as f:
            json.dump(associations, f, indent=4)


def create_nmkr_wallet(oauth_user_id):
    """Calls the NMKR API to create a new managed wallet."""
    if not NMKR_ENABLED:
        raise Exception("NMKR feature is not enabled.")

    url = f"https://studio-api.nmkr.io/v2/CreateWallet/{NMKR_CUSTOMER_ID}"
    headers = {"Authorization": f"Bearer {NMKR_API_KEY}", "accept": "text/plain"}
    payload = {"walletpassword": oauth_user_id, "enterpriseaddress": False, "walletname": oauth_user_id}

    logging.info(f"Creating NMKR wallet for user {oauth_user_id}")

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()
        return data.get("address"), data.get("seedPhrase")
    except requests.exceptions.HTTPError as e:
        logging.error(f"NMKR API Error for user {oauth_user_id}: {response.text}")
        raise e


# In-memory storage for authentication status
auth_status = {}


@app.route('/')
def index():
    if 'user' in session:
        return f"Hello, {session['user']}! <a href='/logout'>Logout</a>"
    return '''Welcome! Available endpoints:
<ul>
<li>/ : Displays this welcome message and lists available endpoints.</li>
<li>/login/&lt;provider&gt;?auth_id=UUID : Initiates the OAuth login flow for a given provider.</li>
<li>/callback/&lt;provider&gt; : The callback endpoint for the OAuth provider.</li>
<li>/auth/status?auth_id=UUID : Checks the status of an authentication attempt.</li>
<li>/logout : Logs the user out.</li>
</ul>'''


@app.route('/login/<provider>')
def login(provider):
    if provider not in oauth._clients:
        return f"Error: Provider '{provider}' is not configured or enabled.", 404

    auth_id = request.args.get('auth_id')
    if not auth_id:
        return "Error: auth_id is required for login.", 400

    session['auth_id'] = auth_id
    auth_status[auth_id] = {"status": "pending"}

    redirect_uri = url_for('authorize', provider=provider, _external=True)

    if provider == 'google':
        return oauth.google.authorize_redirect(redirect_uri, nonce=auth_id)
    else:
        return "Unknown provider", 404


@app.route('/callback/<provider>')
def authorize(provider):
    auth_id = session.get('auth_id')
    if not auth_id:
        if FAILURE_REDIRECT_URL:
            params = {'provider': provider, 'error': 'session_expired', 'error_message': 'Authentication session expired or invalid.'}
            return redirect(f"{FAILURE_REDIRECT_URL}?{urlencode(params)}")
        return "Authentication session expired or invalid.", 400

    try:
        oauth_user_id = None
        user_info = {}

        if provider == 'google':
            token = oauth.google.authorize_access_token()
            user_info = oauth.google.parse_id_token(token, nonce=session.get('auth_id'))
            oauth_user_id = user_info.get('sub')
            session['user'] = user_info.get('name')
            session['user_email'] = user_info.get('email')
        else:
            return "Unknown provider", 404

        current_status = {"status": "success", "user_info": user_info}

        if NMKR_ENABLED and oauth_user_id:
            namespaced_user_id = f"{provider}:{oauth_user_id}"
            wallet_associations = get_wallet_associations()
            existing_address = wallet_associations.get(namespaced_user_id)

            if existing_address:
                logging.info(f"Found existing wallet for user {namespaced_user_id}.")
                current_status['wallet_address'] = existing_address
            else:
                logging.info(f"No wallet found. Creating new wallet for user {namespaced_user_id}.")
                new_address, new_seed = create_nmkr_wallet(namespaced_user_id)
                if new_address:
                    save_wallet_association(namespaced_user_id, new_address)
                    current_status['wallet_address'] = new_address
                    current_status['wallet_seed'] = new_seed

        auth_status[auth_id] = current_status

        if SUCCESS_REDIRECT_URL:
            params = {
                'auth_id': auth_id, 'provider': provider,
                'name': session.get('user'),
                'email': session.get('user_email')
            }
            filtered_params = {k: v for k, v in params.items() if v is not None}
            return redirect(f"{SUCCESS_REDIRECT_URL}?{urlencode(filtered_params)}")

        return redirect(url_for('index'))

    except Exception as e:
        logging.error(f"Error during {provider} authorization for auth_id {auth_id}: {e}", exc_info=True)
        auth_status[auth_id] = {"status": "error", "message": str(e)}

        if FAILURE_REDIRECT_URL:
            params = {'auth_id': auth_id, 'provider': provider, 'error': 'authorization_failed', 'error_message': str(e)}
            return redirect(f"{FAILURE_REDIRECT_URL}?{urlencode(params)}")

        return "Authorization failed.", 500


@app.route('/auth/status', methods=['GET'])
@require_api_key
def get_auth_status():
    auth_id = request.args.get('auth_id')
    if not auth_id or auth_id not in auth_status:
        return {"status": "error", "message": "Invalid or missing auth_id"}, 400

    return auth_status.get(auth_id, {})


@app.route('/logout')
@require_api_key
def logout():
    """Clears the session and redirects."""
    session.pop('user', None)
    session.pop('user_email', None)
    session.pop('auth_id', None)

    # Redirect to a custom URL if configured, otherwise to the index.
    if LOGOUT_REDIRECT_URL:
        return redirect(LOGOUT_REDIRECT_URL)

    return redirect(url_for('index'))


if __name__ == '__main__':
    port = int(os.getenv("TCP_PORT", 42069))
    app.run(debug=True, port=port)
