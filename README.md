# Frictionless Onboarding: Open-Source Web2 Login to Wallet

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A robust, configurable Flask backend designed to provide seamless authentication and on-the-fly Cardano wallet creation for your application or game. This project handles the complexity of OAuth 2.0 and blockchain interactions, allowing you to focus on your frontend experience.

## Overview

This application serves as a centralized authentication and wallet management service. A client application (like a game) can initiate an authentication flow by opening a browser window to this backend. The user logs in via a supported provider (Google). Upon the first successful login, the backend communicates with [NMKR Studio](https://nmkr.io/) to create a new managed Cardano wallet for that user, securely associating it with their account. On subsequent logins, it simply retrieves the user's existing wallet address.

The client application polls a status endpoint to know when the process is complete and to receive the user's details and wallet information.

## Features

-   **Google Authentication:** Out-of-the-box support for Google using OAuth 2.0.
-   **Dynamic Provider Registration:** Automatically enables only the providers that are fully configured in the `.env` file.
-   **On-the-Fly Wallet Creation:** Integrates with the NMKR Studio API to create a managed Cardano wallet for new users.
-   **Persistent & Safe Wallet Association:** Securely links a user's OAuth identity to their Cardano wallet address using a simple JSON file. File-locking prevents data corruption during simultaneous sign-ups.
-   **Secure by Design:** Seed phrases are never stored on the server. They are provided only once upon wallet creation and passed through directly to the client.
-   **Highly Configurable:**
    -   Set the listening port via an environment variable.
    -   Define custom redirect URLs for your frontend to handle success, failure, and logout events.
    -   Protect sensitive endpoints with a simple API key system.
-   **Production-Ready:** Includes structured logging, best practices for decorators, and guidance for production deployment.

## Getting Started

Follow these instructions to get your own instance of the backend running.

### Prerequisites

-   Python 3.8+
-   `pip` for package installation
-   A text editor to create the `.env` file

### Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd <local-path>
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the required packages:**
    The project now includes a pre-configured `requirements.txt` file. Simply run:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Create and configure your environment file:**
    Create a new file named `.env` in the root of the project directory. Copy the contents from the example below and fill in the values according to the configuration guides.

5.  **Run the application:**
    ```bash
    python app.py
    ```
    The server will start, and you'll see output in your terminal indicating which OAuth providers and features were successfully enabled.

---

## Configuration (`.env` file)

Create a `.env` file in the project's root directory. Use the following template and fill in your own secrets. Lines starting with `#` are optional.

```ini
# --- General Application Settings ---
# A persistent, random secret key for Flask sessions. REQUIRED FOR PRODUCTION.
# If not set, a temporary key is generated, and all logins will be lost on restart.
#SECRET_KEY=your_super_secret_random_string

# A comma-separated list of API keys to protect the /auth/status and /logout endpoints.
# HIGHLY RECOMMENDED FOR PRODUCTION.
#API_KEYS=your_game_api_key1,your_game_api_key2

# The TCP port for the application. Defaults to 42069 if not set.
#TCP_PORT=42069

# --- Custom Redirects (Optional) ---
# The URL to redirect to after a successful login. User/wallet data is added as query parameters.
#SUCCESS_REDIRECT_URL=https://my-game.com/auth-success
# The URL to redirect to after a failed login. Error details are added as query parameters.
#FAILURE_REDIRECT_URL=https://my-game.com/auth-failure
# The URL to redirect to after a user logs out.
#LOGOUT_REDIRECT_URL=https://my-game.com/logged-out

# --- Google OAuth Provider (Optional) ---
#GOOGLE_CLIENT_ID=
#GOOGLE_CLIENT_SECRET=
#GOOGLE_REDIRECT_URI=http://localhost:42069/callback/google

# --- NMKR Studio Wallet Integration (Optional) ---
#NMKR_API_KEY=
#NMKR_CUSTOMER_ID=
# (Optional) The filename for storing wallet associations. Defaults to "wallets.json".
#WALLET_STORAGE_FILE=wallets.json
```

---

## Provider & Service Setup Guides

To get the necessary credentials, you must register your application on each provider's developer portal.

### Google Setup

1.  Go to the [Google Cloud Console](https://console.cloud.google.com/).
2.  Create a new project.
3.  Navigate to **APIs & Services** > **Credentials**.
4.  Click **Create Credentials** > **OAuth client ID**.
5.  Select **Web application** as the application type.
6.  Under **Authorized redirect URIs**, add the URI for your backend. For local testing, this is `http://localhost:42069/callback/google`.
7.  Click **Create**. You will be shown your **Client ID** and **Client Secret**. Copy these into your `.env` file.



### NMKR Studio Setup

1.  Create an account on [NMKR Studio](https://nmkr.io/).
2.  Log in and find your **Customer ID**. It is typically visible in your account or profile settings.
3.  Navigate to the **API Keys** section of the dashboard.
4.  Generate a new API key. Give it a descriptive name.
5.  Copy the generated **API Key** and your **Customer ID** into the `.env` file.

---

## API Endpoints & Flow

This is how your client application (or game) should interact with the backend.

### The Authentication Flow

1.  The client generates a unique ID for the authentication attempt (e.g., a UUID). Let's call it `auth_id`.
2.  The client opens a browser window to `https://your-backend.com/login/<provider>?auth_id=<auth_id>`.
3.  The user authenticates with the provider (Google, etc.) and is redirected back to the backend.
4.  The backend handles the callback, fetches user info, creates/retrieves a wallet (if enabled), and stores the final status.
5.  Meanwhile, the client application starts polling the status endpoint every few seconds: `https://your-backend.com/auth/status?auth_id=<auth_id>`.
6.  The polling continues until the status is no longer `"pending"`.

### Endpoint Details

#### `GET /login/<provider>`

-   **Description:** Initiates the login flow for a specific provider.
-   **Query Parameters:**
    -   `auth_id` (required): A unique ID generated by your client for this specific login attempt.
-   **Action:** Redirects the user's browser to the provider's authentication page.

#### `GET /callback/<provider>`

-   **Description:** The endpoint where the OAuth provider redirects the user after authentication. You should not interact with this directly; it's part of the flow.

#### `GET /auth/status`

-   **Description:** The endpoint your client polls to check the result of a login attempt. Should be protected by an API Key if configured.
-   **Headers:**
    -   `Authorization: Bearer <your_api_key>` (if `API_KEYS` is set).
-   **Query Parameters:**
    -   `auth_id` (required): The same unique ID used to initiate the login.
-   **Responses:**
    -   **Pending:** `{"status": "pending"}`
    -   **Success (First Time Login):**
        ```json
        {
          "status": "success",
          "user_info": { ... },
          "wallet_address": "addr1...",
          "wallet_seed": "word1 word2 word3 ..."
        }
        ```
    -   **Success (Subsequent Login):**
        ```json
        {
          "status": "success",
          "user_info": { ... },
          "wallet_address": "addr1..."
        }
        ```
    -   **Error:** `{"status": "error", "message": "Details about the error"}`

#### `GET /logout`

-   **Description:** Clears the user's session on the backend.
-   **Headers:**
    -   `Authorization: Bearer <your_api_key>` (if `API_KEYS` is set).
-   **Action:** Logs the user out. Redirects to the `LOGOUT_REDIRECT_URL` if set, otherwise redirects to the backend's index page.

---

## Security Considerations

-   **`SECRET_KEY`:** For any production deployment, it is **critical** to set a permanent, cryptographically secure `SECRET_KEY` in your `.env` file. If you don't, all user sessions will be invalidated every time the server restarts.
-   **`API_KEYS`:** If your backend is exposed to the public internet, it is **essential** to set strong, unique `API_KEYS` to protect the `/auth/status` and `/logout` endpoints from unauthorized access to user login information.
-   **Data Storage:** The `auth_status` object is stored in-memory and does not persist through server restarts. The `wallets.json` file is suitable for smaller-scale applications, but for large-scale or high-concurrency environments, consider replacing the file-based storage with a dedicated database solution (e.g., PostgreSQL, MySQL, Redis).
-   **Seed Phrases:** This server is designed to be a "pass-through" for seed phrases. They are returned in the API response **only once** upon wallet creation and are **never stored** on the server. Your client application is responsible for handling the seed phrase securely.

---

## Production Deployment

The built-in Flask development server (`app.run(debug=True)`) is not suitable for production use. It is not designed to be efficient, stable, or secure enough to handle real-world traffic. When deploying this application, use a production-ready WSGI server like **Gunicorn** or **uWSGI**.

**Example with Gunicorn:**

1.  Install Gunicorn: `pip install gunicorn`
2.  Run the app from your project's root directory:
    ```bash
    gunicorn --bind 0.0.0.0:42069 app:app
    ```
3.  For a more robust setup, you would typically run Gunicorn behind a reverse proxy like Nginx.

For detailed deployment instructions including Docker setup, environment variable configuration, and production best practices, please refer to our [Deployment Guide](DEPLOYMENT.md).

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
