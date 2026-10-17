"""Backend for the Threat Intel Radar.

Keeps the VirusTotal / LeakCheck keys server-side, proxies VirusTotal (no browser CORS),
and bridges the Holehe Python library. Listens on 127.0.0.1:5000; Vite proxies /api to it.
"""
import os
import re
import time
from pathlib import Path

import requests
from flask import Flask, jsonify, request

ROOT = Path(__file__).parent
for line in (ROOT / ".env").read_text().splitlines() if (ROOT / ".env").exists() else []:
    if "=" in line and not line.lstrip().startswith("#"):
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())

VT_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
LC_KEY = os.environ.get("LEAKCHECK_API_KEY", "")
EMAIL_RE = re.compile(r"^[^@\s/?#]+@[^@\s/?#]+\.[^@\s/?#]+$")
VT_ALLOWED = re.compile(r"^(urls(/[A-Za-z0-9_\-=]+)?|analyses/[A-Za-z0-9_\-=]+|domains/[A-Za-z0-9.\-]+|files/[A-Fa-f0-9]{64})$")

app = Flask(__name__)


def http(method, url, **kw):
    """requests wrapper that retries on transient network errors (e.g. flaky DNS)."""
    for attempt in range(3):
        try:
            return requests.request(method, url, **kw)
        except requests.ConnectionError:
            if attempt == 2:
                raise
            time.sleep(1.5)


@app.get("/api/status")
def status():
    return jsonify(virustotal=bool(VT_KEY), leakcheck=bool(LC_KEY))


@app.get("/api/xon")
def xposedornot():
    email = request.args.get("email", "").strip()
    if not EMAIL_RE.match(email):
        return jsonify(error="invalid email"), 400
    try:
        r = http("GET", f"https://api.xposedornot.com/v1/check-email/{email}", timeout=20)
        if r.status_code == 404:
            return jsonify(found=False, breaches=[], details=[])
        if r.status_code != 200:
            return jsonify(error=f"XposedOrNot returned HTTP {r.status_code}"), 502
        names = [b for g in r.json().get("breaches", []) for b in (g if isinstance(g, list) else [g])]
        details = []
        try:
            a = http("GET", "https://api.xposedornot.com/v1/breach-analytics", params={"email": email}, timeout=20)
            if a.status_code == 200:
                details = (a.json().get("ExposedBreaches") or {}).get("breaches_details") or []
        except (requests.RequestException, ValueError):
            pass  # analytics are optional
        return jsonify(found=bool(names), breaches=names, details=details)
    except (requests.RequestException, ValueError):
        return jsonify(error="Could not reach XposedOrNot (network or DNS problem). Try again."), 502


@app.get("/api/leakcheck")
def leakcheck():
    email = request.args.get("email", "").strip()
    if not EMAIL_RE.match(email):
        return jsonify(error="invalid email"), 400
    try:
        if LC_KEY:
            r = http("GET", f"https://leakcheck.io/api/v2/query/{email}",
                             headers={"X-API-Key": LC_KEY, "Accept": "application/json"}, timeout=20)
            data = r.json()
            if data.get("success"):
                # Never forward plaintext passwords/hashes to the browser: expose metadata only.
                rows = []
                for item in data.get("result", []) or []:
                    src = item.get("source") or {}
                    rows.append({
                        "source": src.get("name") if isinstance(src, dict) else str(src),
                        "date": src.get("breach_date") if isinstance(src, dict) else None,
                        "fields": item.get("fields", []),
                        "username": item.get("username"),
                        "name": item.get("name") or item.get("first_name"),
                    })
                return jsonify(tier="pro", success=True, found=data.get("found", len(rows)),
                               quota=data.get("quota"), results=rows)
            if data.get("error") == "Not found":
                return jsonify(tier="pro", success=True, found=0, quota=data.get("quota"), results=[])
            # Key rejected / no active plan: fall through to the free public endpoint.
        r = http("GET", "https://leakcheck.io/api/public", params={"check": email}, timeout=20)
        data = r.json()
        rows = [{"source": s.get("name"), "date": s.get("date"), "fields": []} for s in data.get("sources", [])]
        not_found = data.get("error") == "Not found"
        return jsonify(tier="public", success=bool(data.get("success")) or not_found, found=data.get("found", 0),
                       fields=data.get("fields", []), error=None if not_found else data.get("error"), results=rows)
    except (requests.RequestException, ValueError) as e:
        return jsonify(error="Could not reach LeakCheck (network or DNS problem). Check your connection and try again."), 502


@app.route("/api/vt/<path:subpath>", methods=["GET", "POST"])
def virustotal(subpath):
    if not VT_KEY:
        return jsonify(error="VIRUSTOTAL_API_KEY not configured"), 503
    if not VT_ALLOWED.match(subpath):
        return jsonify(error="path not allowed"), 400
    if request.method == "POST" and subpath != "urls":
        return jsonify(error="method not allowed"), 405
    try:
        r = http(request.method, f"https://www.virustotal.com/api/v3/{subpath}",
                             headers={"x-apikey": VT_KEY, "Accept": "application/json"},
                             data=request.form.to_dict() if request.method == "POST" else None, timeout=30)
        return (r.content, r.status_code, {"Content-Type": "application/json"})
    except requests.RequestException as e:
        return jsonify(error=f"VirusTotal request failed: {e}"), 502


@app.post("/api/vt-upload")
def vt_upload():
    if not VT_KEY:
        return jsonify(error="VIRUSTOTAL_API_KEY not configured"), 503
    f = request.files.get("file")
    if not f:
        return jsonify(error="no file provided"), 400
    try:
        r = requests.post("https://www.virustotal.com/api/v3/files",
                          headers={"x-apikey": VT_KEY, "Accept": "application/json"},
                          files={"file": (f.filename or "sample", f.stream)}, timeout=120)
        return (r.content, r.status_code, {"Content-Type": "application/json"})
    except requests.RequestException as e:
        return jsonify(error=f"VirusTotal upload failed: {e}"), 502


@app.errorhandler(413)
def too_large(_):
    return jsonify(error="File exceeds the 32 MB limit"), 413


@app.get("/api/holehe")
def holehe_lookup():
    email = request.args.get("email", "").strip()
    if not EMAIL_RE.match(email):
        return jsonify(error="invalid email"), 400
    try:
        import httpx
        import trio
        from holehe.core import get_functions, import_submodules
    except ImportError:
        return jsonify(error="holehe is not installed (pip install holehe)"), 503

    modules = import_submodules("holehe.modules")
    websites = get_functions(modules)

    async def run():
        out = []
        limiter = trio.CapacityLimiter(15)  # too many parallel lookups overload flaky DNS and drop results

        async with httpx.AsyncClient(timeout=20, limits=httpx.Limits(max_connections=30)) as client:
            async def one(site):
                async with limiter:
                    try:
                        await site(email, client, out)
                    except Exception:
                        pass

            pending = list(websites)
            for _ in range(3):  # re-run sites that produced no result (timeouts, DNS blips)
                async with trio.open_nursery() as nursery:
                    for site in pending:
                        nursery.start_soon(one, site)
                answered = {r.get("name") for r in out}
                pending = [w for w in pending if w.__name__ not in answered]
                if not pending:
                    break
        return out, [w.__name__ for w in pending]

    try:
        results, failed = trio.run(run)
    except BaseException as e:  # trio raises ExceptionGroup on nursery failures
        if isinstance(e, KeyboardInterrupt):
            raise
        return jsonify(error="Holehe scan failed (network problem?). Try again."), 502
    sites = [{"name": r.get("name"), "domain": r.get("domain"), "exists": bool(r.get("exists")),
              "rate_limit": bool(r.get("rateLimit")),
              "recovery_email": r.get("emailrecovery"), "recovery_phone": r.get("phoneNumber")}
             for r in results]
    sites.sort(key=lambda s: (not s["exists"], s["name"] or ""))
    return jsonify(email=email, checked=len(sites), total=len(websites), failed=failed,
                   found=sum(s["exists"] for s in sites), sites=sites)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
