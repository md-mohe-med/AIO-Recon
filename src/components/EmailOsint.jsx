import { useState } from 'react'
import { Badge, Button, Card, Copy, Empty, ErrorNote, Hero, Icon, SearchConsole, Stat, Td, Th } from './ui.jsx'
import { checkHolehe, checkLeakCheck, checkPwnedPassword, checkXposedOrNot, isEmail } from '../lib/api.js'

const SOURCES = [
  { key: 'xon', label: 'XposedOrNot' },
  { key: 'lc', label: 'LeakCheck' },
  { key: 'holehe', label: 'Holehe' },
]

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

function fmtDate(raw) {
  const m = /^(\d{4})(?:-(\d{2}))?(?:-(\d{2}))?/.exec(String(raw || ''))
  if (!m) return null
  const [, y, mo, d] = m
  if (!mo) return y
  const mon = MONTHS[parseInt(mo, 10) - 1]
  return d ? `${mon} ${parseInt(d, 10)}, ${y}` : `${mon} ${y}`
}

const Field = ({ label, value }) => value ? (
  <div className="min-w-0">
    <span className="text-[10px] text-ink-muted block uppercase">{label}</span>
    <span className="text-xs font-mono font-semibold block truncate text-white">{value}</span>
  </div>
) : null

const Chip = ({ children, tag }) => (
  <span className="px-2.5 py-1 rounded-lg bg-card-subtle border border-line text-xs font-mono text-white flex items-center gap-1.5">
    <span>{children}</span>{tag && <span className="text-[10px] text-ink-muted">{tag}</span>}
  </span>
)

const SummaryBox = ({ icon, title, children }) => (
  <div className="rounded-xl bg-card border border-line p-4 space-y-2.5">
    <div className="flex items-center gap-2 text-xs font-mono text-ink-muted"><Icon name={icon} className="!text-[16px]" /><span>{title}</span></div>
    <div className="flex flex-wrap items-center gap-2">{children}</div>
  </div>
)

function SourceStatus({ state }) {
  return (
    <div className="flex flex-wrap gap-2">
      {SOURCES.map(({ key, label }) => {
        const s = state[key]
        const tone = s === 'loading' ? 'neutral' : s === 'ok' ? 'safe' : s ? 'bad' : 'neutral'
        const text = s === 'loading' ? 'querying' : s === 'ok' ? 'ok' : s ? 'failed' : 'idle'
        return <Badge key={key} tone={tone}>{label} · {text}</Badge>
      })}
    </div>
  )
}

function PasswordCheck() {
  const [pw, setPw] = useState('')
  const [show, setShow] = useState(false)
  const [busy, setBusy] = useState(false)
  const [res, setRes] = useState(null)
  const [err, setErr] = useState('')

  const run = async () => {
    if (!pw) return
    setBusy(true); setErr(''); setRes(null)
    try { setRes(await checkPwnedPassword(pw)) } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }

  return (
    <Card title="Password exposure check" meta="HIBP Pwned Passwords · k-anonymity">
      <p className="text-sm text-ink-muted mb-3">
        The password is hashed (SHA-1) in your browser; only the first 5 hex characters of the hash are sent. The password never leaves this page.
      </p>
      <form onSubmit={(e) => { e.preventDefault(); run() }} className="flex flex-col sm:flex-row gap-2 max-w-2xl">
        <div className="flex-1 flex items-center h-9 bg-card border border-line-strong rounded px-3 gap-2 focus-within:border-brand focus-within:shadow-focus">
          <Icon name="password" className="text-ink-faint" />
          <input
            type={show ? 'text' : 'password'} value={pw} onChange={(e) => setPw(e.target.value)}
            placeholder="Password to check" autoComplete="off"
            className="flex-1 bg-transparent font-mono text-[13px] outline-none placeholder-ink-faint"
          />
          <button type="button" onClick={() => setShow((s) => !s)} className="text-ink-faint hover:text-ink" title="Toggle visibility">
            <Icon name={show ? 'visibility_off' : 'visibility'} />
          </button>
        </div>
        <Button type="submit" disabled={busy || !pw}>Check password</Button>
      </form>
      <div className="mt-3 space-y-2">
        {err && <ErrorNote>{err}</ErrorNote>}
        {res && (res.pwned ? (
          <div className="flex items-center gap-3"><Badge tone="bad">Exposed</Badge>
            <span className="text-sm">Seen <b className="tabular-nums">{res.count.toLocaleString()}</b> times in known breaches. Do not use it.</span></div>
        ) : (
          <div className="flex items-center gap-3"><Badge tone="safe">Not found</Badge>
            <span className="text-sm">No match in the Pwned Passwords corpus. That does not guarantee strength.</span></div>
        ))}
      </div>
    </Card>
  )
}

export default function EmailOsint({ onResult }) {
  const [email, setEmail] = useState('')
  const [busy, setBusy] = useState(false)
  const [target, setTarget] = useState('')
  const [state, setState] = useState({})
  const [errors, setErrors] = useState({})
  const [data, setData] = useState(null)
  const [formErr, setFormErr] = useState('')

  const run = async () => {
    const e = email.trim()
    if (!isEmail(e)) { setFormErr('Enter a valid email address.'); return }
    setFormErr(''); setBusy(true); setTarget(e); setData(null); setErrors({})
    setState({ xon: 'loading', lc: 'loading', holehe: 'loading' })

    const track = (key, p) => p.then(
      (v) => { setState((s) => ({ ...s, [key]: 'ok' })); return v },
      (err) => { setState((s) => ({ ...s, [key]: 'err' })); setErrors((x) => ({ ...x, [key]: err.message })); return null },
    )
    const [xon, lc, holehe] = await Promise.all([
      track('xon', checkXposedOrNot(e)),
      track('lc', checkLeakCheck(e)),
      track('holehe', checkHolehe(e)),
    ])
    const d = { xon, lc, holehe }
    setData(d); setBusy(false)
    onResult({
      target: e,
      xposedOrNot: xon && { breaches: xon.breaches },
      leakCheck: lc && { tier: lc.tier, found: lc.found, sources: lc.results.map((r) => r.source) },
      holehe: holehe && { checked: holehe.checked, accounts: holehe.sites.filter((s) => s.exists).map((s) => s.name) },
    })
  }

  const xonCount = data?.xon?.breaches.length ?? 0
  const lcCount = data?.lc?.results.length ?? 0
  const accounts = data?.holehe?.sites.filter((s) => s.exists) ?? []
  const totalBreach = new Set([...(data?.xon?.breaches || []), ...(data?.lc?.results || []).map((r) => r.source)].filter(Boolean)).size
  const exposed = data && (xonCount > 0 || lcCount > 0)
  const dates = [...(data?.xon?.details || []).map((b) => b.xposed_date), ...(data?.lc?.results || []).map((r) => r.date)]
    .filter((d) => fmtDate(d)).sort()
  const firstSeen = dates.length ? fmtDate(dates[0]) : null
  const lastSeen = dates.length ? fmtDate(dates[dates.length - 1]) : null
  const lcRows = data?.lc?.results || []
  const names = [...new Map(lcRows.filter((r) => r.name).map((r) => [r.name + r.source, r])).values()]
  const usernames = [...new Map(lcRows.filter((r) => r.username).map((r) => [r.username + r.source, r])).values()]

  return (
    <div className="space-y-6">
      <Hero badge="PASSIVE OSINT // BREACH & ACCOUNT DISCOVERY" title="Digital Identity & Exposure Profiler"
        subtitle="Check which breaches an email appears in and which of 120+ services have an account registered to it.">
        <div className="w-full max-w-2xl"><SearchConsole icon="mail" type="email" value={email} onChange={setEmail} onSubmit={run} busy={busy} placeholder="target@email.com" label="Investigate" /></div>
        {formErr && <div className="w-full max-w-2xl text-left"><ErrorNote>{formErr}</ErrorNote></div>}
        {(busy || data) && <SourceStatus state={state} />}
      </Hero>

      {!busy && !data && <Empty icon="travel_explore" title="No investigation yet">Enter an email above. XposedOrNot, LeakCheck and Holehe are queried in parallel.</Empty>}

      {data && (
        <>
          <div className="flex items-center gap-3 flex-wrap">
            <span className="text-sm text-ink-muted">Results for</span>
            <Copy text={target}><span className="font-mono text-sm font-medium">{target}</span></Copy>
            <Badge tone={exposed ? 'bad' : data.xon && data.lc ? 'safe' : data.xon || data.lc ? 'warn' : 'neutral'}>{exposed ? 'Breach exposure' : data.xon && data.lc ? 'No breaches found' : data.xon || data.lc ? 'No breaches found · partial' : 'Inconclusive'}</Badge>
          </div>

          {Object.entries(errors).map(([k, m]) => (
            <ErrorNote key={k}><b>{SOURCES.find((s) => s.key === k).label}:</b> {m}</ErrorNote>
          ))}

          <div className={`grid grid-cols-1 gap-4 ${firstSeen && lastSeen ? 'sm:grid-cols-3' : firstSeen || lastSeen ? 'sm:grid-cols-2' : ''}`}>
            {data.holehe && <Stat label="Accounts found" value={accounts.length} />}
            {firstSeen && <Stat label="First seen" value={firstSeen} />}
            {lastSeen && <Stat label="Last seen" value={lastSeen} />}
          </div>

          {(names.length > 0 || usernames.length > 0 || accounts.length > 0) && (
            <div className="space-y-3">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">Summary</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {names.length > 0 && (
                  <SummaryBox icon="badge" title="Names Found">
                    {names.map((r) => <Chip key={r.name + r.source} tag={r.source}>{r.name}</Chip>)}
                  </SummaryBox>
                )}
                {usernames.length > 0 && (
                  <SummaryBox icon="alternate_email" title="Usernames">
                    {usernames.map((r) => <Chip key={r.username + r.source} tag={r.source}>{r.username}</Chip>)}
                  </SummaryBox>
                )}
                {accounts.length > 0 && (
                  <div className="rounded-xl bg-card border border-line p-4 space-y-2.5">
                    <div className="flex items-center gap-2 text-xs font-mono text-ink-muted"><Icon name="share" className="!text-[16px]" /><span>Profile Links</span></div>
                    <div className="flex flex-col gap-1.5 text-xs font-mono">
                      {accounts.map((a) => (
                        <a key={a.name} href={`https://${a.domain}`} target="_blank" rel="noreferrer noopener" className="text-brand hover:underline">
                          <span className="capitalize">{a.name}</span> <span className="text-ink-muted">({a.domain})</span>
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {data.xon && xonCount > 0 && (
            <Card title="Breaches" meta={`XposedOrNot · ${xonCount}`}>
              <div className="overflow-x-auto -m-4">
                <table className="w-full min-w-[640px]">
                  <thead><tr><Th>Breach</Th><Th>Domain</Th><Th>Date</Th><Th>Data exposed</Th><Th className="text-right">Records</Th></tr></thead>
                  <tbody>
                    {(data.xon.details.length ? data.xon.details : data.xon.breaches.map((b) => ({ breach: b }))).map((b) => (
                      <tr key={b.breach} className="hover:bg-card-hover">
                        <Td className="font-medium text-ink">{b.breach}</Td>
                        <Td className="font-mono text-[12px]">{b.domain || '—'}</Td>
                        <Td className="font-mono text-[12px]">{b.xposed_date || '—'}</Td>
                        <Td className="font-mono text-[11px] text-ink-muted">{b.xposed_data || '—'}</Td>
                        <Td className="text-right tabular-nums">{b.xposed_records ? Number(b.xposed_records).toLocaleString() : '—'}</Td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}

          {data.lc && lcCount > 0 && (
            <Card title="Leak sources" meta={`LeakCheck ${data.lc.tier} · ${lcCount}${data.lc.quota != null ? ` · quota ${data.lc.quota}` : ''}`}>
              <div className="overflow-x-auto -m-4">
                <table className="w-full min-w-[560px]">
                  <thead><tr><Th>Source</Th><Th>Date</Th><Th>Username</Th><Th>Fields leaked</Th></tr></thead>
                  <tbody>
                    {data.lc.results.map((r, i) => (
                      <tr key={i} className="hover:bg-card-hover">
                        <Td className="font-medium text-ink">{r.source || 'Unknown'}</Td>
                        <Td className="font-mono text-[12px]">{r.date || '—'}</Td>
                        <Td className="font-mono text-[12px]">{r.username || '—'}</Td>
                        <Td>
                          <div className="flex flex-wrap gap-1">
                            {(r.fields || []).map((f) => (
                              <span key={f} className={`px-1.5 py-0.5 rounded border font-mono text-[10px] ${/pass|hash/i.test(f) ? 'bg-bad-bg text-bad-ink border-bad-line' : 'bg-line-soft text-ink-muted border-line'}`}>{f}</span>
                            ))}
                          </div>
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {data.lc.tier === 'public' && data.lc.fields?.length > 0 && (
                <p className="mt-4 text-xs text-ink-muted">Public tier: per-source fields are not available. Data types seen across all {data.lc.found?.toLocaleString()} matching records: <span className="font-mono">{data.lc.fields.join(', ')}</span>.</p>
              )}
              <p className="mt-2 text-xs text-ink-muted">Leaked passwords and hashes are intentionally not retrieved or displayed; only the exposed field types.</p>
            </Card>
          )}

          {data.holehe && (
            <div className="space-y-3 pt-2">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-white tracking-wide">Linked accounts</h3>
                  <span className="text-xs font-mono text-ink-muted">{accounts.length} profiles discovered · {data.holehe.checked}/{data.holehe.total} sites answered</span>
                </div>
                <span className="hidden sm:block text-xs font-mono text-ink-muted">Active Recon Grid</span>
              </div>
              {accounts.length === 0 ? (
                <p className="text-sm text-ink-muted">No registrations detected across the sites that answered.</p>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {accounts.map((a) => (
                    <div key={a.name} className="rounded-xl bg-card border border-line p-5 space-y-4 hover:border-line-strong transition-all">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2.5 min-w-0">
                          <div className="w-8 h-8 rounded-lg bg-brand/10 border border-brand/30 flex items-center justify-center text-brand font-extrabold text-sm uppercase shrink-0">{a.name[0]}</div>
                          <div className="min-w-0">
                            <span className="text-xs font-bold text-white capitalize block truncate">{a.name}</span>
                            <span className="text-[11px] font-mono text-ink-muted block truncate">{a.domain}</span>
                          </div>
                        </div>
                        <a href={`https://${a.domain}`} target="_blank" rel="noreferrer noopener" className="text-ink-faint hover:text-white" title="Open site"><Icon name="open_in_new" className="!text-[16px]" /></a>
                      </div>
                      {(a.recovery_email || a.recovery_phone) && (
                        <div className="grid grid-cols-2 gap-3">
                          <Field label="Recovery Email" value={a.recovery_email} />
                          <Field label="Recovery Phone" value={a.recovery_phone} />
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
              {data.holehe.failed?.length > 0 && (
                <p className="text-xs text-warn-ink">{data.holehe.failed.length} sites did not respond after 3 attempts (network or blocking), so results may be incomplete.</p>
              )}
              {data.holehe.sites.some((s) => s.rate_limit) && (
                <p className="text-xs text-ink-muted">Some sites rate-limited the check, so results may be incomplete.</p>
              )}
            </div>
          )}
        </>
      )}

      <PasswordCheck />
    </div>
  )
}
