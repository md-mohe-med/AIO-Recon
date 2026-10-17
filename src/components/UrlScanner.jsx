import { useState } from 'react'
import { Badge, Card, Copy, Empty, ErrorNote, Hero, SearchConsole, Stat, Td, Th } from './ui.jsx'
import { scanUrl } from '../lib/api.js'

const ageOf = (ts) => {
  if (!ts) return null
  const days = Math.floor((Date.now() / 1000 - ts) / 86400)
  if (days < 1) return 'today'
  if (days < 60) return `${days} days`
  if (days < 730) return `${Math.round(days / 30)} months`
  return `${(days / 365).toFixed(1)} years`
}

function verdict(stats, domainAgeDays) {
  const mal = stats.malicious || 0
  const sus = stats.suspicious || 0
  if (mal >= 3) return { tone: 'bad', label: 'Malicious', score: Math.min(100, 60 + mal * 4) }
  if (mal > 0 || sus > 0) return { tone: 'warn', label: 'Suspicious', score: Math.min(80, 30 + mal * 15 + sus * 10) }
  if (domainAgeDays != null && domainAgeDays < 30) return { tone: 'warn', label: 'New domain', score: 35 }
  return { tone: 'safe', label: 'Clean', score: 0 }
}

export default function UrlScanner({ onResult }) {
  const [url, setUrl] = useState('')
  const [busy, setBusy] = useState(false)
  const [step, setStep] = useState('')
  const [err, setErr] = useState('')
  const [res, setRes] = useState(null)

  const run = async () => {
    if (!url.trim()) return
    setBusy(true); setErr(''); setRes(null); setStep('Starting')
    try {
      const r = await scanUrl(url, setStep)
      setRes(r)
      onResult({ url: r.url, stats: r.attrs.last_analysis_stats, reputation: r.attrs.reputation })
    } catch (e) {
      setErr(e.message?.includes('Invalid URL') ? 'That does not look like a valid URL.' : e.message)
    } finally { setBusy(false) }
  }

  const stats = res?.attrs.last_analysis_stats
  const total = stats ? Object.values(stats).reduce((a, b) => a + b, 0) : 0
  const created = res?.domain?.creation_date
  const ageDays = created ? Math.floor((Date.now() / 1000 - created) / 86400) : null
  const v = stats ? verdict(stats, ageDays) : null
  const flagged = res ? Object.values(res.attrs.last_analysis_results || {}).filter((r) => ['malicious', 'suspicious'].includes(r.category)) : []
  const cats = res ? [...new Set(Object.values(res.attrs.categories || {}))] : []
  const cert = res?.domain?.last_https_certificate

  return (
    <div className="space-y-6">
      <Hero badge="DOMAIN & URL REPUTATION TRIAGE" title="Is This Website Safe?"
        subtitle="Scan a URL against 70+ security engines and review domain age, certificate and categorisation.">
        <div className="w-full max-w-2xl"><SearchConsole icon="language" value={url} onChange={setUrl} onSubmit={run} busy={busy} placeholder="https://example.com" label="Check URL" /></div>
        {busy && <p className="font-mono text-[12px] text-ink-muted">{step}…</p>}
      </Hero>

      {err && <ErrorNote>{err}</ErrorNote>}
      {!res && !busy && !err && <Empty icon="link" title="No URL scanned yet">The URL is submitted to VirusTotal through the local backend. Free tier allows 4 requests per minute.</Empty>}

      {res && v && (
        <>
          <Card
            title={<span className="font-mono text-[13px] break-all">{res.url}</span>}
            right={<Badge tone={v.tone}>{v.label}</Badge>}
          >
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
              <span>Final URL: <Copy text={res.attrs.last_final_url || res.url}>{res.attrs.last_final_url || res.url}</Copy></span>
              {res.attrs.title && <span className="text-ink-muted">Title: {res.attrs.title}</span>}
            </div>
          </Card>

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <Stat label="Malicious" value={`${stats.malicious || 0} / ${total}`} tone={stats.malicious ? 'bad' : 'safe'} />
            <Stat label="Suspicious" value={stats.suspicious || 0} tone={stats.suspicious ? 'warn' : undefined} />
            <Stat label="Harmless" value={stats.harmless || 0} tone="safe" />
            <Stat label="Risk score" value={`${v.score} / 100`} tone={v.tone} />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <Card title="Domain intelligence" meta={res.hostname} className="lg:col-span-1">
              <dl className="space-y-3 text-sm">
                {[
                  ['Domain age', created ? `${ageOf(created)} (registered ${new Date(created * 1000).toISOString().slice(0, 10)})` : 'Unknown'],
                  ['Registrar', res.domain?.registrar || 'Unknown'],
                  ['Reputation', res.domain?.reputation ?? res.attrs.reputation ?? '—'],
                  ['Categories', cats.length ? cats.join(', ') : '—'],
                  ['TLS issuer', cert?.issuer?.O || cert?.issuer?.CN || 'None observed'],
                  ['TLS valid until', cert?.validity?.not_after || '—'],
                ].map(([k, val]) => (
                  <div key={k}><dt className="font-mono text-[11px] uppercase tracking-[0.06em] text-ink-muted">{k}</dt><dd className="mt-0.5 break-words">{val}</dd></div>
                ))}
              </dl>
              {ageDays != null && ageDays < 30 && <div className="mt-4"><Badge tone="warn">Newly registered domain</Badge></div>}
            </Card>

            <Card title="Engine detections" meta={`${flagged.length} flagged`} className="lg:col-span-2">
              {flagged.length === 0 ? (
                <p className="text-sm text-ink-muted">No engine flagged this URL as malicious or suspicious.</p>
              ) : (
                <div className="overflow-x-auto -m-4 max-h-80">
                  <table className="w-full">
                    <thead><tr><Th>Engine</Th><Th>Verdict</Th><Th>Result</Th></tr></thead>
                    <tbody>
                      {flagged.map((f) => (
                        <tr key={f.engine_name} className="hover:bg-card-hover">
                          <Td className="font-medium text-ink">{f.engine_name}</Td>
                          <Td><Badge tone={f.category === 'malicious' ? 'bad' : 'warn'}>{f.category}</Badge></Td>
                          <Td className="font-mono text-[12px]">{f.result}</Td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <p className="mt-4 text-xs text-ink-muted">Last analysed {res.attrs.last_analysis_date ? new Date(res.attrs.last_analysis_date * 1000).toLocaleString() : 'n/a'}.</p>
            </Card>
          </div>
        </>
      )}
    </div>
  )
}
