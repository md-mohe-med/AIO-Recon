# Threat Intelligence, OSINT & AI Phishing Radar

## Overview

A cybersecurity intelligence platform that combines Email OSINT profiling, email/password breach checking, AI-powered phishing image analysis (via Google Gemini Vision API), and heuristic URL/domain risk scanning. The frontend runs client-side as a single HTML file; a lightweight Python Flask backend (`server.py`) bridges the Holehe OSINT library for email account discovery.

The platform is designed for security researchers, IT professionals, and everyday users who need to quickly assess digital threats from one unified dark-themed dashboard.

---

## Tech Stack

| Layer           | Technology                                           |
| --------------- | ---------------------------------------------------- |
| Frontend        | Vanilla HTML + JavaScript (single `code.html`)       |
| Styling         | Tailwind CSS (CDN)                                   |
| Fonts           | Inter + JetBrains Mono (Google Fonts)                |
| Icons           | Material Symbols Outlined (Google Fonts)             |
| AI Engine       | Google Gemini Vision API (client-side calls)          |
| Backend         | Python Flask micro-API (`server.py`) for Holehe OSINT |
| Hosting         | Frontend: any static host · Backend: local or VPS    |

**Architecture:** The frontend (`code.html`) runs entirely in the browser. Most API calls (XposedOrNot, HIBP Pwned Passwords, Gemini Vision) go directly from the client with no intermediary. The one exception is **Holehe** (email account discovery across 120+ sites), which is a Python library and requires a lightweight Flask server (`server.py`) that the frontend calls at `http://localhost:5000`. The Gemini API key is stored in `localStorage` and never touches a server.

---

## Free API Stack

All external APIs used by this platform are **free and require no API key** (except Gemini Vision which needs a free Google API key, VirusTotal which needs a free registered key, and LeakCheck Pro which needs a paid key for full password results).

### 1. XposedOrNot — Email Breach Check

- **What it does:** Checks if an email address has appeared in known data breaches
- **Cost:** Free, no API key needed
- **Endpoint:** `GET https://api.xposedornot.com/v1/check-email/{email}`
- **Response:** JSON with breach list, breach count, data types exposed, and breach dates
- **Called from:** Client-side (`code.html`) — direct fetch, no backend needed
- **Docs:** https://xposedornot.com/

### 2. HIBP Pwned Passwords — Password Breach Check

- **What it does:** Checks if a password has appeared in known data breaches using k-Anonymity (only the first 5 characters of the SHA-1 hash are sent — the full password never leaves the browser)
- **Cost:** Free, no API key needed
- **How it works:**
  1. SHA-1 hash the password in the browser (`crypto.subtle.digest`)
  2. Send only the first 5 hex characters to the API
  3. API returns all hash suffixes that match that prefix
  4. Browser checks locally if the full hash is in the returned list
- **Endpoint:** `GET https://api.pwnedpasswords.com/range/{first5chars}`
- **Response:** Plain text — one hash suffix + count per line (e.g., `0018A45C4D1DEF81644B54AB7F969B88D65:1`)
- **Called from:** Client-side (`code.html`) — direct fetch, no backend needed
- **Docs:** https://haveibeenpwned.com/API/v3#PwnedPasswords

### 3. XposedOrNot Passwords — Password Exposure Check (Alternative)

- **What it does:** Alternative password breach check, also uses k-Anonymity (first 10 chars of SHA-1)
- **Cost:** Free, no API key needed
- **Endpoint:** `GET https://passwords.xposedornot.com/api/v1/pass/anon/{first10chars}`
- **Called from:** Client-side (`code.html`) — direct fetch, no backend needed

### 4. Holehe — Email Account Discovery (OSINT)

- **What it does:** Checks 120+ websites (GitHub, Twitter, Instagram, Spotify, etc.) to see if an email address is registered on them
- **Cost:** Free, open source
- **Type:** Python library (NOT a REST API) — requires a Flask backend to bridge it
- **Install:** `pip3 install holehe`
- **Endpoint (via server.py):** `GET http://localhost:5000/api/holehe?email={email}`
- **Response:** JSON with total sites checked, accounts found count, and per-site results with `exists: true/false`
- **Called from:** Client-side (`code.html`) fetches → Flask `server.py` → Holehe Python library
- **GitHub:** https://github.com/megadose/holehe

### 5. Google Gemini Vision API — AI Phishing Analysis

- **What it does:** Analyzes uploaded images of suspicious emails, SMS, invoices, and login pages for phishing indicators
- **Cost:** Free tier available (requires Google API key — free to create at https://aistudio.google.com/apikey)
- **Models:** `gemini-1.5-flash`, `gemini-2.0-flash`, `gemini-1.5-pro`
- **Endpoint:** `POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent`
- **Called from:** Client-side (`code.html`) — direct fetch, API key stored in `localStorage`
- **Already integrated:** Yes, fully working

### 6. LeakCheck — Email Breach + Leaked Data Lookup

- **What it does:** Checks if an email has appeared in data breaches and returns which breach sources it was found in, what data types were exposed (passwords, hashes, usernames, etc.)
- **Two tiers:**
  - **Public API (free, no key):** Returns breach source names and exposed data categories only — no actual passwords
  - **Pro API v2 (paid, from $9.99/mo):** Returns full breach records including leaked passwords, hashes, and usernames
- **Public API (free):**
  - **Endpoint:** `GET https://leakcheck.io/api/public?check={email}`
  - **Auth:** None
  - **Rate limit:** 1 request/second
  - **Search types:** Email and username only
  - **Response:** Breach source list and data categories (no passwords)
  - **Commercial use:** Free if you add a "Powered by LeakCheck" link
- **Pro API v2 (paid):**
  - **Endpoint:** `GET https://leakcheck.io/api/v2/query/{email}`
  - **Auth:** `X-API-Key` header
  - **Rate limit:** 3 requests/second (upgradable)
  - **Response:** Full breach records with passwords, hashes, usernames
- **Called from:** Client-side (`code.html`) — direct fetch, no backend needed
- **Docs:** https://docs.leakcheck.io/overview
- **Website:** https://leakcheck.io

### 7. VirusTotal — URL/Domain Scanning (Planned)

- **What it does:** Scans URLs and domains against 70+ antivirus engines and blocklists
- **Cost:** Free tier (4 requests/minute, requires free registered API key)
- **Endpoint:** `GET https://www.virustotal.com/api/v3/urls/{id}` (or submit via POST)
- **Called from:** Client-side or via backend proxy (API key needed)
- **Docs:** https://docs.virustotal.com/reference/overview

### Services Evaluated but Not Used

| Service | Why not |
| --- | --- |
| **HIBP Email Breach API** | Paid (~$4.39/mo), replaced by XposedOrNot (free) |
| **emailosint.org** | No public API — web-only tool, can't be called from code |
| **EmailRep.io** | Has free tier but rate-limited and may require API key for production use |

---

## Core Features

### Tab 1: Email OSINT & Digital Identity Profiler

- **Input:** Email address
- **Output:** Linked accounts, usernames, profile pictures, registration history, authentication methods, and an AI-generated profile summary
- **Data Points Displayed:**
  - Accounts found count, first seen / last seen dates
  - Names and usernames across platforms (Etsy, GitHub, Chess.com, etc.)
  - Profile pictures aggregated from discovered accounts
  - Direct profile links
  - Linked account cards with detailed metadata per platform (user IDs, auth methods, country, account type, creation dates, verification status)
  - Registration badges (icon grid of all platforms the email is registered on)
- **API Integration Plan:** Holehe (via `server.py`) for account discovery + XposedOrNot for breach data + LeakCheck Public API for breach sources
- **Current State:** Ships with hardcoded demo data for `kapasoviking@gmail.com`. Custom email searches return dynamically generated placeholder results. APIs not wired up yet — UI shell ready for integration.

### Tab 2: AI Phishing & Scam Image Inspector (Gemini Vision)

- **Input:** Uploaded image (drag & drop, file picker, or Ctrl+V paste) of a suspicious email, SMS, invoice, fake login page, or QR code
- **Output:** Full forensic threat analysis report with verdict, confidence score, red flags, and mitigation steps
- **AI Integration:**
  - Calls Google Gemini Vision API (`gemini-1.5-flash`, `gemini-2.0-flash`, or `gemini-1.5-pro`) with a structured phishing analysis prompt
  - Requests JSON response with: verdict, threat level, confidence score, impersonated brand, attack vector, urgency level, executive summary, red flags, and mitigation steps
  - Falls back to a built-in offline simulator when no API key is configured
- **1-Click Test Specimens:** Four pre-built demo scenarios rendered as canvas-generated images:
  1. PayPal Fake Invoice (Geek Squad $799 scam)
  2. Microsoft 365 Password Expiration (credential harvesting)
  3. DHL Parcel On Hold (fake $1.95 redelivery fee)
  4. Google Security Alert (legitimate / safe — control test)
- **Report Output Includes:**
  - Color-coded verdict banner (red = phishing, green = safe)
  - Threat score out of 100 with confidence percentage
  - Executive threat intelligence summary
  - Metadata grid (impersonated brand, attack vector, urgency level, model engine)
  - Red flags list with individual fraud indicators
  - Defensive mitigation steps
  - Copy JSON / Export dossier actions

### Tab 3: URL & Domain Phishing Scanner

- **Input:** URL or domain
- **Output:** Heuristic risk assessment card with domain age, SSL certificate info, reputation engine verdict, and triage signals
- **API Integration Plan:** VirusTotal API v3 (free tier, requires registered key)
- **Current State:** Ships with static demo results for suspicious domains. API not wired up yet — UI shell ready for integration.

---

## File Structure

```
project/
├── code.html          # The entire frontend application (HTML + CSS + JS in one file)
├── server.py          # Flask backend for Holehe email OSINT (Python)
├── requirements.txt   # Python dependencies (flask, flask-cors, holehe)
├── icon.svg           # Favicon (referenced but not included)
└── PROJECT.md         # This file
```

**Frontend** — everything lives in a single `code.html` file:
- `<head>` — Tailwind CDN config, Google Fonts, custom CSS (scrollbar, grid background, scanline overlay, pulse/glow animations, scan beam laser)
- `<body>` — Three tab sections, API key modal, footer
- `<script>` — All application logic (~500 lines of vanilla JS)

**Backend** — `server.py` is a minimal Flask server:
- Single endpoint: `GET /api/holehe?email={email}`
- CORS enabled for local development
- Runs Holehe async checks and returns JSON results
- Dependencies: `flask`, `flask-cors`, `holehe`

---

## Application State

All runtime state is managed through a single `AppState` object:

```js
AppState = {
  activeTab: 'email-osint',          // Current visible tab
  geminiApiKey: '',                   // From localStorage
  selectedModel: 'gemini-1.5-flash', // Gemini model choice
  currentImageBase64: null,          // Uploaded image data
  currentImageMime: 'image/png',     // MIME type of uploaded image
  currentImageFilename: '',          // Display filename
  lastReport: null                   // Most recent AI analysis result
}
```

Persistent storage uses only `localStorage`:
- `skyday_gemini_key` — Gemini API key
- `skyday_gemini_model` — Selected model name

---

## Gemini API Integration Details

### Configuration Flow
1. User clicks the API key status button in the header
2. Modal opens with key input, model selector, and test connection button
3. Key is saved to `localStorage` — never sent to any intermediary server
4. Status LED in header updates: amber (demo mode) → green (live API connected)

### Vision Analysis Flow
1. Image is loaded as base64 via `FileReader.readAsDataURL()`
2. A structured prompt instructs Gemini to respond with strict JSON containing verdict, scores, flags, and mitigations
3. Request is sent directly to `https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent`
4. Response is parsed and rendered into the forensic report UI
5. On API failure or missing key, the built-in `generateRealisticForensicReport()` simulator produces realistic demo output

### Gemini Request Payload Structure
```json
{
  "contents": [{
    "parts": [
      { "text": "<phishing analysis prompt>" },
      { "inline_data": { "mime_type": "image/png", "data": "<base64>" } }
    ]
  }],
  "generationConfig": {
    "temperature": 0.1,
    "maxOutputTokens": 2048,
    "responseMimeType": "application/json"
  }
}
```

---

## UI/UX Design System

- **Theme:** Dark cybersecurity aesthetic with scanline overlay and dot-grid background
- **Primary Color:** Crimson red (`#ef4444`) with glow shadows for threat indicators
- **Safe Color:** Emerald green (`#10b981`) for verified/safe states
- **Warning Color:** Amber (`#f59e0b`) for demo/unconfigured states
- **Typography:** Inter (UI text) + JetBrains Mono (data, labels, code)
- **Cards:** Dark elevated surfaces (`#141720`) with subtle borders (`#222634`)
- **Animations:** Pulse glow on status LEDs, scan beam laser on image analysis, spinning loader during API calls
- **Layout:** Fixed header with tab navigation, responsive content area, fixed mobile bottom nav bar
- **Scrollbar:** Custom thin dark scrollbar with crimson hover accent

### Color Tokens

| Token             | Hex       | Usage                              |
| ----------------- | --------- | ---------------------------------- |
| `canvas`          | `#0a0b0e` | Page background                    |
| `canvas-elevated` | `#0f1117` | Header, footer, elevated surfaces  |
| `card`            | `#141720` | Card backgrounds                   |
| `card-hover`      | `#1a1e2a` | Card hover state                   |
| `card-subtle`     | `#181b24` | Inner card sections, badges        |
| `border`          | `#222634` | Default borders                    |
| `border-light`    | `#2f3447` | Hover borders                      |
| `crimson`         | `#ef4444` | Primary accent, threats, CTAs      |
| `crimson-glow`    | `#dc2626` | Hover/active state for crimson     |
| `crimson-dark`    | `#261214` | Crimson background tint            |
| `accent`          | `#f43f5e` | Secondary accent                   |
| `neon`            | `#38bdf8` | Info highlights                    |
| `emerald`         | `#10b981` | Safe/verified indicators           |
| `amber`           | `#f59e0b` | Warning/demo states                |

---

## Key JavaScript Functions

| Function                          | Purpose                                                    |
| --------------------------------- | ---------------------------------------------------------- |
| `switchTab(tabId)`                | Toggle between the 3 main tabs, update nav styling         |
| `handleEmailSearch(e)`            | Process email OSINT search, animate progress, update UI    |
| `runGeminiPhishingScan()`         | Orchestrate AI scan — live API or fallback simulator       |
| `callLiveGeminiVisionApi()`       | Direct fetch to Gemini Vision endpoint with base64 image   |
| `generateRealisticForensicReport()` | Offline fallback producing realistic demo forensic data  |
| `renderAiReport(data, engine)`    | Populate the forensic report card from API/sim results     |
| `loadPhishPreset(key)`            | Generate canvas specimen image for 1-click demo samples    |
| `loadBlobIntoPreview(blob, name)` | Read image file into base64 and show in dropzone preview   |
| `handleUrlScan(e)`                | Process URL scan form and display static results           |
| `openApiKeyModal()` / `saveApiKeyModal()` | Manage Gemini API key configuration modal         |
| `testApiKeyConnection()`          | Validate API key by hitting Gemini models listing endpoint |
| `exportCurrentReport()`           | Export combined investigation data as downloadable JSON    |
| `copyForensicAnalysis()`          | Copy last AI report JSON to clipboard                     |
| `setupPasteListener()`            | Listen for Ctrl+V image paste on AI Vision tab             |

---

## Export / Reporting

The platform exports a combined forensic dossier as JSON containing:

```json
{
  "platform": "Cyber Threat Intel & OSINT Platform",
  "timestamp": "2026-10-17T...",
  "emailInvestigation": {
    "target": "user@email.com",
    "accountsFound": "11",
    "firstSeen": "Jan 20, 2022",
    "lastSeen": "Oct 12, 2026"
  },
  "aiPhishingScan": { /* full Gemini analysis object */ }
}
```

---

## What's Wired Up vs. What Needs API Integration

| Feature                          | Status                                         |
| -------------------------------- | ---------------------------------------------- |
| AI Phishing Vision (Gemini)      | ✅ Fully working with live Gemini API           |
| AI Phishing Vision (Offline)     | ✅ Fully working built-in simulator             |
| Gemini API key management        | ✅ Fully working (localStorage)                 |
| Image upload / drag-drop / paste | ✅ Fully working                                |
| 1-Click test specimens           | ✅ Fully working (canvas-generated)             |
| JSON export                      | ✅ Fully working                                |
| Tab navigation + mobile nav      | ✅ Fully working                                |
| Email breach check (XposedOrNot) | 🔲 API ready — needs wiring into `code.html`   |
| Email breach check (LeakCheck)   | 🔲 API ready — needs wiring into `code.html`   |
| Password breach (HIBP Pwned Pw)  | 🔲 API ready — needs wiring into `code.html`   |
| Email OSINT (Holehe via Flask)   | 🔲 Needs `server.py` + wiring into `code.html` |
| URL Scanner (VirusTotal)         | 🔲 API ready — needs wiring into `code.html`   |

---

## Roadmap / Next Steps

### Phase 1: Wire Up Free APIs (No Cost)
- [ ] Integrate XposedOrNot email breach check into Email OSINT tab (client-side fetch)
- [ ] Integrate LeakCheck Public API for breach source lookup (client-side fetch, free, no key)
- [ ] Integrate HIBP Pwned Passwords check into Email OSINT tab (client-side SHA-1 + fetch)
- [ ] Build `server.py` Flask backend for Holehe email account discovery
- [ ] Wire `handleEmailSearch()` to call Holehe backend + XposedOrNot in parallel
- [ ] Integrate VirusTotal free tier into URL Scanner tab

### Phase 2: Feature Enhancements
- [ ] Add real domain WHOIS lookups (domain age, registrar, nameservers)
- [ ] Add DNS/MX record resolution for email validation
- [ ] PDF report generation with branded forensic layout
- [ ] Batch scanning (multiple emails or URLs at once)
- [ ] Rate limit handling and request queuing

### Phase 3: Production Hardening
- [ ] Move Gemini API calls to a backend proxy to protect API keys in production
- [ ] Add user authentication and saved scan history
- [ ] Convert to Next.js or a proper build system (React + Tailwind + API routes)
- [ ] Browser extension for right-click URL/email checking
- [ ] Dark/light theme toggle

---

## Development

### Frontend Only (no Holehe)

No build step required:

```bash
# Just open the file in a browser
open code.html

# Or serve with any static server
npx serve .
python3 -m http.server 8000
```

### Full Stack (with Holehe backend)

```bash
# 1. Install Python dependencies
pip3 install flask flask-cors holehe

# 2. Start the Flask backend
python3 server.py
# → Running on http://localhost:5000

# 3. Open the frontend (in another terminal)
open code.html
# Or serve it:
python3 -m http.server 8000
```

### Deploy

- **Frontend:** Upload `code.html` to any static hosting provider (Vercel, Netlify, GitHub Pages, Cloudflare Pages)
- **Backend:** Deploy `server.py` to a VPS, Railway, Render, or any Python hosting. Update the Holehe endpoint URL in `code.html` to point to the deployed server instead of `localhost:5000`

---

## Notes for Claude Code

- This is a **single-file HTML application** — all markup, styles, and scripts live in `code.html`
- No build tools, no npm, no framework — pure vanilla JS with Tailwind CDN
- Tailwind config is inline via `tailwind.config` in a `<script>` tag
- All colors are defined as custom Tailwind theme extensions, not arbitrary values
- The Gemini API key is stored in `localStorage` and used for direct client-side API calls — there is no backend proxy
- The Email OSINT and URL Scanner tabs currently show hardcoded/simulated data — they are UI shells awaiting real API integration
- The AI Phishing Vision tab is the only feature with real external API connectivity (Gemini)
- When modifying the JS, all state flows through the global `AppState` object
- Image handling uses `FileReader.readAsDataURL()` → base64 for both preview and API submission
- The 1-click test specimens are generated at runtime using HTML Canvas, not static image files
- Mobile navigation is a separate fixed bottom bar — keep it in sync with desktop nav when adding tabs
- **Free API calls (XposedOrNot, HIBP Pwned Passwords, LeakCheck Public) go directly from the browser** — no backend needed for these
- **Holehe requires `server.py`** — it's a Python library, not a REST API, so the Flask server bridges it
- When wiring APIs into `handleEmailSearch()`, call XposedOrNot + LeakCheck + Holehe in parallel (`Promise.all`) for speed
- LeakCheck Public API (`/api/public?check={email}`) is rate-limited to 1 req/sec — add a small delay or queue if batch scanning
- HIBP Pwned Passwords uses SHA-1 k-Anonymity — hash in browser with `crypto.subtle.digest('SHA-1', ...)`, send only first 5 hex chars, match locally