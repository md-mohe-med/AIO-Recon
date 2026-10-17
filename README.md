# AIO-Recon (Threat Intel Radar)

A small React + Flask dashboard that bundles a few common OSINT/threat-intel
checks behind one UI: file/URL scanning via VirusTotal, email breach lookups,
and email-to-account OSINT via Holehe.

## Features

- **URL / File scanning** — proxies the VirusTotal v3 API (URL/domain/file
  hash lookups, file upload for scanning) without exposing your API key to
  the browser.
- **Email breach check** — queries XposedOrNot and LeakCheck for an email
  address and shows breach sources/dates (never forwards plaintext
  passwords/hashes to the frontend).
- **Email OSINT** — uses [Holehe](https://github.com/megadose/holehe) to check
  which online services an email address is registered on.

## Stack

- Frontend: React 18 + Vite + Tailwind CSS
- Backend: Flask (Python), proxies third-party APIs and keeps API keys
  server-side

## Setup

### 1. Backend (Python)

```bash
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and fill in your API keys:

```bash
cp .env.example .env
```

```env
VIRUSTOTAL_API_KEY=your_key_here
LEAKCHECK_API_KEY=your_key_here
```

Run the backend:

```bash
python server.py
```

It listens on `127.0.0.1:5000`.

### 2. Frontend (Node)

```bash
npm install
npm run dev
```

Vite proxies `/api` requests to the Flask backend. Open the printed local URL
in your browser.

### Production build

```bash
npm run build
npm run preview
```

## Notes

- Both API keys are optional — the app degrades gracefully (e.g. LeakCheck
  falls back to its public, unauthenticated endpoint; `GET /api/status`
  reports which keys are configured).
- `.env`, `node_modules`, `dist`, and `__pycache__` are gitignored — never
  commit real API keys.
- Built for authorized security research / OSINT use only.
