# SIEM Analyzer Migration Guide

This guide ensures a seamless transition of the **Intelligence Analyzer** to your production server via the tunnel hostname.

## 1. Prerequisites
- Docker & Docker Compose installed on the server.
- Existing Redis instance running on the server (port 6379).
- Tunnel hostname (e.g., Cloudflare Tunnel) pointing to port 8000.

## 2. Configuration Setup
1.  **Environment Variables**: Use the provided `.env.production` as a template.
2.  **External Redis**: In your `.env`, set `REDIS_URL=redis://host.docker.internal:6379/0`.
    - *Note*: We have added `extra_hosts` to the compose file to resolve this automatically.
3.  **Allowed Origins**: Add your tunnel hostname to `ALLOWED_ORIGINS` to prevent CORS issues.

## 3. Automated Database Initialization
- **Zero-Touch Setup**: When you run `docker compose -f docker-compose.prod.yml up -d`, the application will automatically:
    - Connect to the internal Postgres.
    - Create the `siem_analyzer` database if it doesn't exist.
    - Initialize all 11+ security tables immediately.

## 4. GitHub Actions (CI/CD)
To enable automated deployment:
1.  Go to your GitHub Repository -> Settings -> Secrets and variables -> Actions.
2.  Add the following secrets:
    - `DOCKER_USERNAME`: Your DockerHub username.
    - `DOCKER_PASSWORD`: Your DockerHub Personal Access Token.
3.  **Deploy**: Push a version tag (e.g., `git tag v1.0.0 && git push --tags`) to trigger the production build and push.

## 5. Deployment Commands
```bash
# Pull the latest image (once pushed by GitHub Actions)
docker compose -f docker-compose.prod.yml pull

# Start the stack
docker compose -f docker-compose.prod.yml up -d

# Verify health
docker compose -f docker-compose.prod.yml ps
```
