const EMAIL_RE = /^[^@\s/?#]+@[^@\s/?#]+\.[^@\s/?#]+$/
export const isEmail = (s) => EMAIL_RE.test(s)

async function getJson(url, opts) {
  const res = await fetch(url, opts)
  let body = null
  try { body = await res.json() } catch { /* non-JSON */ }
  return { ok: res.ok, status: res.status, body }
}

// XposedOrNot via the backend (retries network blips, no browser CORS dependency).
export async function checkXposedOrNot(email) {
  const r = await getJson(`/api/xon?email=${encodeURIComponent(email)}`)
  if (!r.ok) throw new Error(r.body?.error || `XposedOrNot proxy HTTP ${r.status}`)
  return r.body
}

export async function checkLeakCheck(email) {
  const r = await getJson(`/api/leakcheck?email=${encodeURIComponent(email)}`)
  if (!r.ok) throw new Error(r.body?.error || `LeakCheck proxy HTTP ${r.status}`)
  if (r.body?.success === false) throw new Error(r.body.error || 'LeakCheck query failed')
  return r.body
}

export async function checkHolehe(email) {
  const r = await getJson(`/api/holehe?email=${encodeURIComponent(email)}`)
  if (!r.ok) throw new Error(r.body?.error || `Holehe backend HTTP ${r.status}`)
  return r.body
}

// HIBP Pwned Passwords: k-anonymity, only the first 5 SHA-1 hex chars leave the browser.
export async function checkPwnedPassword(password) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password))
  const hex = [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase()
  const prefix = hex.slice(0, 5)
  const suffix = hex.slice(5)
  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { 'Add-Padding': 'true' } })
  if (!res.ok) throw new Error(`HIBP returned HTTP ${res.status}`)
  const text = await res.text()
  for (const line of text.split('\n')) {
    const [s, count] = line.trim().split(':')
    if (s === suffix) return { pwned: true, count: parseInt(count, 10) }
  }
  return { pwned: false, count: 0 }
}

// VirusTotal via backend proxy (key stays server-side).
const b64url = (s) => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

export function normalizeUrl(input) {
  const t = input.trim()
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(t) ? t : `http://${t}`
  const u = new URL(withScheme)
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Only http(s) URLs are supported')
  return u
}

export async function scanUrl(rawUrl, onStep = () => {}) {
  const u = normalizeUrl(rawUrl)
  const url = u.href
  const id = b64url(url)
  onStep('Looking up existing VirusTotal report')
  let r = await getJson(`/api/vt/urls/${id}`)
  if (r.status === 404) {
    onStep('Submitting URL for analysis')
    const sub = await getJson('/api/vt/urls', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ url }),
    })
    if (!sub.ok) throw new Error(sub.body?.error?.message || sub.body?.error || `VirusTotal submit HTTP ${sub.status}`)
    const aid = sub.body?.data?.id
    for (let i = 0; i < 8; i++) {
      onStep(`Waiting for engines (${i + 1}/8)`)
      await sleep(3000)
      const a = await getJson(`/api/vt/analyses/${aid}`)
      if (a.body?.data?.attributes?.status === 'completed') break
    }
    r = await getJson(`/api/vt/urls/${id}`)
  }
  if (!r.ok) throw new Error(r.body?.error?.message || r.body?.error || `VirusTotal HTTP ${r.status}`)
  const attrs = r.body.data.attributes

  let domain = null
  try {
    onStep('Fetching domain intelligence')
    const d = await getJson(`/api/vt/domains/${u.hostname}`)
    if (d.ok) domain = d.body.data.attributes
  } catch { /* domain details are optional */ }

  return { url, hostname: u.hostname, attrs, domain }
}

// VirusTotal file scan: hash locally, look up by SHA-256, upload only if the user opts in.
export async function sha256File(file) {
  const buf = await crypto.subtle.digest('SHA-256', await file.arrayBuffer())
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export async function lookupFile(hash) {
  const r = await getJson(`/api/vt/files/${hash}`)
  if (r.status === 404) return null
  if (!r.ok) throw new Error(r.body?.error?.message || r.body?.error || `VirusTotal HTTP ${r.status}`)
  return r.body.data.attributes
}

export async function uploadAndScanFile(file, hash, onStep = () => {}) {
  onStep('Uploading file to VirusTotal')
  const fd = new FormData()
  fd.append('file', file)
  const up = await getJson('/api/vt-upload', { method: 'POST', body: fd })
  if (!up.ok) throw new Error(up.body?.error?.message || up.body?.error || `Upload failed (HTTP ${up.status})`)
  const aid = up.body?.data?.id
  for (let i = 0; i < 12; i++) {
    onStep(`Waiting for engines (${i + 1}/12)`)
    await sleep(5000)
    const a = await getJson(`/api/vt/analyses/${aid}`)
    if (a.body?.data?.attributes?.status === 'completed') break
  }
  const attrs = await lookupFile(hash)
  if (!attrs) throw new Error('Analysis is still running. Try again in a minute.')
  return attrs
}
