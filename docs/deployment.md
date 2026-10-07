# ScamSentry Deployment Guide

This guide walks you through deploying ScamSentry to production. The recommended architecture uses **Render** for the FastAPI backend and **Vercel** for the Next.js frontend dashboard.

## A. GitHub Repository
1. Push this repository to your own GitHub account.
2. Ensure you do **not** commit your local `.env` file containing any API keys.

## B. Render Backend (FastAPI + ML)
Render natively supports Docker deployments. We have included a `render.yaml` configuration to automate the setup.

1. Connect your Render account to your GitHub repository.
2. Render will automatically detect `render.yaml` and prompt you to create the `scamsentry-api` web service.
3. In the Render Dashboard, navigate to your new service -> **Environment**.
4. Securely add your threat intelligence API keys:
   - `URLHAUS_AUTH_KEY`
   - `GOOGLE_SAFE_BROWSING_API_KEY`
5. Note your deployed Render URL (e.g., `https://scamsentry-api.onrender.com`).

## C. Vercel Frontend (Next.js Dashboard)
Vercel is ideal for hosting the Next.js dashboard.

1. Connect your Vercel account to your GitHub repository.
2. Import the project. In the setup screen, set the **Root Directory** to `frontend/`.
3. Add the following Environment Variable:
   - Name: `NEXT_PUBLIC_API_URL`
   - Value: `https://scamsentry-api.onrender.com` (Your Render URL)
4. Deploy the project and note your deployed Vercel URL (e.g., `https://scamsentry.vercel.app`).

## D. Environment Variables Update (Backend)
Return to your Render Dashboard and update your backend variables to trust the new frontend:
- `FRONTEND_URL`: `https://scamsentry.vercel.app`
- `CORS_PRODUCTION_ORIGINS`: `https://scamsentry.vercel.app`

## E. CORS & Extension Setup
By default, the backend only allows requests from the origins specified in `CORS_PRODUCTION_ORIGINS`.

**Browser Extension:**
When you publish the extension or load it packed into a browser, it will be assigned a unique ID (e.g., `chrome-extension://abcdefghijk...`). To allow the extension to access the API:
1. Append the extension origin to your backend CORS list.
   `CORS_PRODUCTION_ORIGINS=https://scamsentry.vercel.app,chrome-extension://abcdefghijk...`

## F. Extension Production Build
To build the extension pointing to your production API, build it locally with environment variables:

**Linux / Mac:**
```bash
cd extension
API_BASE_URL=https://scamsentry-api.onrender.com DASHBOARD_URL=https://scamsentry.vercel.app node build.js
```

**Windows PowerShell:**
```powershell
cd extension
$env:API_BASE_URL="https://scamsentry-api.onrender.com"
$env:DASHBOARD_URL="https://scamsentry.vercel.app"
node build.js
```

Then zip the `extension/` folder to upload to the Chrome Web Store, or load it unpacked into your browser.

## G. Post-Deployment Smoke Test
1. Visit `https://scamsentry-api.onrender.com/health` to confirm the backend is alive.
2. Visit `https://scamsentry-api.onrender.com/ready` to confirm the ML model and Threat feeds are loaded.
3. Open your deployed Vercel dashboard. Submit a safe URL (`http://example.com`).
4. Click **View Full Analysis** and confirm no errors appear.
5. Use the packed browser extension on a webpage and click "Scan this page". Verify that the analysis works end-to-end.
