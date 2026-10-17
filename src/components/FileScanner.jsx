import { useRef, useState } from 'react'
import { Badge, Button, Card, Copy, Empty, ErrorNote, Hero, Icon, Stat, Td, Th } from './ui.jsx'
import { lookupFile, sha256File, uploadAndScanFile } from '../lib/api.js'

const MAX = 32 * 1024 * 1024

const fmtSize = (n) => (n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`)

function verdict(stats) {
  const mal = stats.malicious || 0
  const sus = stats.suspicious || 0
  if (mal >= 3) return { tone: 'bad', label: 'Malicious' }
  if (mal > 0 || sus > 0) return { tone: 'warn', label: 'Suspicious' }
  return { tone: 'safe', label: 'No detections' }
}

export default function FileScanner({ onResult }) {
  const [file, setFile] = useState(null)
  const [hash, setHash] = useState('')
  const [attrs, setAttrs] = useState(null)
  const [unknown, setUnknown] = useState(false)
  const [busy, setBusy] = useState(false)
  const [step, setStep] = useState('')
  const [err, setErr] = useState('')
  const [drag, setDrag] = useState(false)
  const input = useRef(null)

  const reset = () => { setAttrs(null); setUnknown(false); setErr(''); setHash('') }

  const scan = async (f) => {
    if (!f) return
    reset(); setFile(f)
    if (f.size > MAX) { setErr('File is larger than 32 MB (VirusTotal direct-upload limit).'); return }
    setBusy(true); setStep('Computing SHA-256 locally')
    try {
      const h = await sha256File(f)
      setHash(h)
      setStep('Looking up hash on VirusTotal')
      const a = await lookupFile(h)
      if (a) { setAttrs(a); onResult({ name: f.name, sha256: h, stats: a.last_analysis_stats }) } else setUnknown(true)
    } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }

  const upload = async () => {
    setBusy(true); setErr(''); setUnknown(false)
    try {
      const a = await uploadAndScanFile(file, hash, setStep)
      setAttrs(a); onResult({ name: file.name, sha256: hash, stats: a.last_analysis_stats })
    } catch (e) { setErr(e.message); setUnknown(true) } finally { setBusy(false) }
  }

  const stats = attrs?.last_analysis_stats
  const total = stats ? Object.values(stats).reduce((a, b) => a + b, 0) : 0
  const v = stats ? verdict(stats) : null
  const flagged = attrs ? Object.values(attrs.last_analysis_results || {}).filter((r) => ['malicious', 'suspicious'].includes(r.category)) : []
  const label = attrs?.popular_threat_classification?.suggested_threat_label

  return (
    <div className="space-y-6">
      <Hero badge="FILE MALWARE SCAN // VIRUSTOTAL" title="Is This File Dangerous?"
        subtitle="The file is hashed in your browser and only the SHA-256 is looked up. It is uploaded only if the hash is unknown and you choose to." />

      <div
        onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => { e.preventDefault(); setDrag(false); scan(e.dataTransfer.files?.[0]) }}
        className={`bg-card border-2 border-dashed rounded-xl p-8 text-center transition ${drag ? 'border-brand bg-brand/5' : 'border-line-strong'}`}
      >
        <input ref={input} type="file" className="hidden" onChange={(e) => { scan(e.target.files?.[0]); e.target.value = '' }} />
        <button type="button" onClick={() => input.current.click()} disabled={busy} className="space-y-2">
          <Icon name="upload_file" className="!text-[32px] text-brand" />
          <p className="text-sm font-medium text-ink">Click or drag a file here</p>
          <p className="font-mono text-[11px] text-ink-muted">Any file type · up to 32 MB</p>
        </button>
        {file && <p className="mt-3 font-mono text-[12px] text-ink-muted truncate">{file.name} · {fmtSize(file.size)}</p>}
        {busy && <p className="mt-2 font-mono text-[12px] text-brand">{step}…</p>}
      </div>

      {err && <ErrorNote>{err}</ErrorNote>}

      {hash && (
        <div className="flex items-center gap-2 text-sm"><span className="text-ink-muted">SHA-256</span><Copy text={hash}><span className="font-mono text-[12px] break-all">{hash}</span></Copy></div>
      )}

      {unknown && !busy && (
        <Card title="Not known to VirusTotal" right={<Badge tone="neutral">Unscanned</Badge>}>
          <p className="text-sm">No engine has seen this exact file, so there is no verdict yet. Uploading scans it with 70+ engines, but VirusTotal then keeps a copy that other users can access. Do not upload private or sensitive files.</p>
          <div className="mt-4"><Button onClick={upload}><Icon name="cloud_upload" />Upload and scan</Button></div>
        </Card>
      )}

      {!file && !busy && !err && <Empty icon="shield" title="No file scanned yet">Choose a file to check it for malware.</Empty>}

      {attrs && v && (
        <>
          <Card title={attrs.meaningful_name || file?.name} meta={attrs.type_description} right={<Badge tone={v.tone}>{v.label}</Badge>}>
            <div className="flex flex-wrap gap-x-6 gap-y-2 text-sm">
              {label && <span>Threat label: <b className="text-bad-ink">{label}</b></span>}
              <span className="text-ink-muted">Size: {fmtSize(attrs.size)}</span>
              {attrs.first_submission_date && <span className="text-ink-muted">First seen: {new Date(attrs.first_submission_date * 1000).toISOString().slice(0, 10)}</span>}
              {attrs.times_submitted != null && <span className="text-ink-muted">Submitted {attrs.times_submitted}×</span>}
            </div>
          </Card>

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <Stat label="Malicious" value={`${stats.malicious || 0} / ${total}`} tone={stats.malicious ? 'bad' : 'safe'} />
            <Stat label="Suspicious" value={stats.suspicious || 0} tone={stats.suspicious ? 'warn' : undefined} />
            <Stat label="Harmless / undetected" value={(stats.harmless || 0) + (stats.undetected || 0)} tone="safe" />
            <Stat label="Unsupported / timeout" value={(stats['type-unsupported'] || 0) + (stats.timeout || 0)} />
          </div>

          <Card title="Engine detections" meta={`${flagged.length} flagged`}>
            {flagged.length === 0 ? (
              <p className="text-sm text-ink-muted">No engine flagged this file. That lowers the risk but does not prove it is safe.</p>
            ) : (
              <div className="overflow-x-auto -m-4 max-h-96">
                <table className="w-full min-w-[480px]">
                  <thead><tr><Th>Engine</Th><Th>Verdict</Th><Th>Detection</Th></tr></thead>
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
            <p className="mt-4 text-xs text-ink-muted">Last analysed {attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toLocaleString() : 'n/a'} · MD5 <span className="font-mono">{attrs.md5}</span></p>
          </Card>
        </>
      )}
    </div>
  )
}
