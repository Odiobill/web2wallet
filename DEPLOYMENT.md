# Deployment Guide for Web2Wallet

This guide provides detailed instructions for deploying the Web2Wallet application in a production environment.

## Prerequisites

- Docker and Docker Compose installed
- Python 3.9+ (if running without Docker)
- Access to OAuth provider developer dashboards (Google, Discord, Twitter)
- NMKR Studio account (optional, for Cardano wallet creation)

## Quick Start with Docker

1. Clone the repository:
   ```bash
   git clone https://github.com/Odiobill/web2wallet.git
   cd web2wallet
   ```

2. Create a `.env` file with your configuration (see Environment Variables section below)

3. Start the application:
   ```bash
   docker-compose up -d
   ```

4. Access the application at `http://localhost:42069` (or a different port is configured accordingly)

## Environment Variables

The application can be configured using environment variables. You can either set them in a `.env` file or directly in the docker-compose.yml.

### Security Settings

- `API_KEYS`: Comma-separated list of API keys for protecting endpoints

### OAuth Provider Configuration

At least one OAuth provider must be configured:

#### Google OAuth
- `GOOGLE_CLIENT_ID`: Google OAuth client ID
- `GOOGLE_CLIENT_SECRET`: Google OAuth client secret
- `GOOGLE_REDIRECT_URI`: Google OAuth redirect URI (e.g., http://localhost:42069/callback/google)

#### Discord OAuth
- `DISCORD_CLIENT_ID`: Discord OAuth client ID
- `DISCORD_CLIENT_SECRET`: Discord OAuth client secret
- `DISCORD_REDIRECT_URI`: Discord OAuth redirect URI (e.g., http://localhost:42069/callback/discord)

#### X/Twitter OAuth
- `X_CLIENT_ID`: X/Twitter OAuth client ID
- `X_CLIENT_SECRET`: X/Twitter OAuth client secret
- `X_REDIRECT_URI`: X/Twitter OAuth redirect URI (e.g., http://localhost:42069/callback/x)

### Redirect URLs

- `SUCCESS_REDIRECT_URL`: URL to redirect to after successful authentication
- `FAILURE_REDIRECT_URL`: URL to redirect to after failed authentication
- `LOGOUT_REDIRECT_URL`: URL to redirect to after logout

### NMKR Settings (Optional)

For Cardano wallet creation:
- `NMKR_API_KEY`: API key for NMKR Studio
- `NMKR_CUSTOMER_ID`: Customer ID for NMKR Studio
- `WALLET_PASSWORD`: Optional password for created wallets

### File Storage Settings

- `WALLET_STORAGE_FILE`: Path to wallet storage file (default: wallets.json)

## Example .env File

```bash
# Secret key for Flask sessions (required)
SECRET_KEY=your-very-secure-secret-key-here

# API keys for endpoint protection (optional)
API_KEYS=key1,key2,key3

# Google OAuth settings (optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:42069/callback/google

# Discord OAuth settings (optional)
DISCORD_CLIENT_ID=your-discord-client-id
DISCORD_CLIENT_SECRET=your-discord-client-secret
DISCORD_REDIRECT_URI=http://localhost:42069/callback/discord

# X/Twitter OAuth settings (optional)
X_CLIENT_ID=your-x-client-id
X_CLIENT_SECRET=your-x-client-secret
X_REDIRECT_URI=http://localhost:42069/callback/x

# Redirect URLs (optional)
SUCCESS_REDIRECT_URL=https://your-frontend-app.com/login-success
FAILURE_REDIRECT_URL=https://your-frontend-app.com/login-failure
LOGOUT_REDIRECT_URL=https://your-frontend-app.com/logout

# NMKR settings (optional)
NMKR_API_KEY=your-nmkr-api-key
NMKR_CUSTOMER_ID=your-nmkr-customer-id
WALLET_PASSWORD=your-wallet-password
```

## Production Deployment

### Using Gunicorn (without Docker)

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Set up your environment variables

3. Run with Gunicorn:
   ```bash
   gunicorn --bind 0.0.0.0:42069 app:app
   ```

### Behind a Reverse Proxy (Nginx)

For production use, it's recommended to run the application behind a reverse proxy like Nginx:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:42069;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Health Check Endpoint

The application includes a basic health check endpoint at `/` which provides:
- A welcome message when not authenticated
- User information when authenticated
- A list of available endpoints

## Monitoring and Logging

The application uses Python's built-in logging module with INFO level logging. Logs include:
- OAuth provider registration status
- Authentication attempts
- NMKR API calls
- Error conditions

For production deployments, consider:
- Centralized logging with tools like ELK stack or Splunk
- Log rotation to prevent disk space issues
- Alerting on critical errors

## Backup Strategy

The wallet storage file (`wallets.json` by default) contains important user data. Implement a regular backup strategy:
- Daily backups of the wallet storage file
- Store backups in a secure, separate location
- Test restoration procedures regularly

## Security Considerations

1. Always use a strong, random `SECRET_KEY` in production
2. Protect API endpoints with `API_KEYS` if exposed to the public internet
3. Use HTTPS in production (configure in your reverse proxy)
4. Regularly rotate OAuth client secrets
5. Monitor authentication logs for suspicious activity
6. Keep dependencies up to date

## Troubleshooting

### Common Issues

1. **OAuth providers not working**: Check that all required environment variables are set and correct
2. **404 errors on callback URLs**: Verify redirect URIs match those configured in OAuth provider dashboards
3. **Permission errors with wallet storage**: Ensure the application has write permissions to the storage file
4. **NMKR wallet creation failing**: Verify API key and customer ID are correct

### Debugging

Enable debug logging by setting the logging level to DEBUG in the application code:
```python
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
```

## Scaling Considerations

For high-traffic deployments:
- Replace file-based wallet storage with a database (PostgreSQL, MySQL, MongoDB)
- Use Redis for session storage
- Implement load balancing with multiple application instances
- Add rate limiting to prevent abuse
