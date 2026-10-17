import { useEffect, useState } from 'react'
import EmailOsint from './components/EmailOsint.jsx'
import UrlScanner from './components/UrlScanner.jsx'
import FileScanner from './components/FileScanner.jsx'
import { Icon } from './components/ui.jsx'

const TABS = [
  { id: 'email', label: 'Email OSINT', short: 'OSINT', icon: 'account_box' },
  { id: 'url', label: 'URL Scanner', short: 'URL', icon: 'link' },
  { id: 'file', label: 'File Scanner', short: 'File', icon: 'shield' },
]

export default function App() {
  const [tab, setTab] = useState('email')
  const [backend, setBackend] = useState(null)
  const [dossier, setDossier] = useState({})

  useEffect(() => {
    fetch('/api/status').then((r) => r.json()).then(setBackend).catch(() => setBackend(false))
  }, [])

  const setPart = (k) => (v) => setDossier((d) => ({ ...d, [k]: v }))
  const goTab = (id) => { setTab(id); window.scrollTo({ top: 0, behavior: 'smooth' }) }

  const exportDossier = () => {
    const blob = new Blob([JSON.stringify({ platform: 'Threat Intelligence Radar', timestamp: new Date().toISOString(), ...dossier }, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob); a.download = `dossier_${Date.now()}.json`; a.click()
    URL.revokeObjectURL(a.href)
  }

  return (
    <div className="min-h-screen flex flex-col">
      <header className="fixed top-0 inset-x-0 z-50 bg-canvas-elevated/90 backdrop-blur-md border-b border-line">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
          <button onClick={() => goTab('email')} className="flex items-center gap-3 group text-left">
            <div className="w-10 h-10 rounded-xl bg-card border border-brand/50 p-1 flex items-center justify-center group-hover:shadow-glow-red group-hover:border-brand transition-all shrink-0">
              <img src="/icon.svg" alt="" className="w-full h-full object-contain" />
            </div>
            <div className="flex flex-col">
              <span className="text-sm font-bold tracking-wider text-white uppercase">Threat Intelligence</span>
              <span className="text-[10px] font-mono text-ink-muted tracking-wider uppercase">OSINT &amp; Scan Hub</span>
            </div>
          </button>

          <nav className="hidden md:flex items-center gap-1 bg-card-subtle px-1.5 py-1 rounded-lg border border-line" aria-label="Primary">
            {TABS.map((t) => (
              <button key={t.id} onClick={() => goTab(t.id)} aria-current={tab === t.id ? 'page' : undefined}
                className={`px-3.5 py-1.5 rounded-md text-xs font-medium font-mono transition-all flex items-center gap-1.5 ${tab === t.id ? 'bg-brand text-white shadow-sm' : 'text-gray-300 hover:text-white hover:bg-card'}`}>
                <Icon name={t.icon} className="!text-[16px]" />{t.label}
              </button>
            ))}
          </nav>

          <div className="flex items-center gap-3">
            <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-card-subtle border border-line text-[11px] font-mono">
              <span className={`w-2 h-2 rounded-full ${backend ? 'bg-emerald-500 animate-pulse' : backend === false ? 'bg-brand' : 'bg-amber-400'}`} />
              <span className={`font-semibold ${backend ? 'text-safe-ink' : backend === false ? 'text-bad-ink' : 'text-warn-ink'}`}>
                {backend ? 'BACKEND ONLINE' : backend === false ? 'BACKEND OFFLINE' : 'CHECKING'}
              </span>
            </div>
            <button onClick={exportDossier} title="Export dossier (JSON)" className="p-2 rounded-lg bg-card-subtle hover:bg-card border border-line text-gray-300 hover:text-white transition-all">
              <Icon name="file_download" className="!text-[18px]" />
            </button>
          </div>
        </div>
      </header>

      <div className="md:hidden fixed bottom-0 inset-x-0 z-50 bg-canvas-elevated border-t border-line px-2 py-2 flex items-center justify-around">
        {TABS.map((t) => (
          <button key={t.id} onClick={() => goTab(t.id)} className={`flex flex-col items-center gap-0.5 text-xs font-mono ${tab === t.id ? 'text-brand' : 'text-ink-muted hover:text-white'}`}>
            <Icon name={t.icon} className="!text-[20px]" /><span>{t.short}</span>
          </button>
        ))}
      </div>

      <main className="flex-1 pt-20 pb-20 md:pb-16 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8">
        {backend === false && (
          <div className="mb-4 p-3 rounded-xl border border-warn-line bg-warn-bg text-warn-ink text-sm">
            The Python backend is not reachable. Account discovery (Holehe), LeakCheck, URL and file scanning need it: run <span className="font-mono">python3 server.py</span>.
          </div>
        )}
        <div hidden={tab !== 'email'}><EmailOsint onResult={setPart('emailInvestigation')} /></div>
        <div hidden={tab !== 'url'}><UrlScanner onResult={setPart('urlScan')} /></div>
        <div hidden={tab !== 'file'}><FileScanner onResult={setPart('fileScan')} /></div>
      </main>

      <footer className="hidden md:block w-full bg-canvas-elevated border-t border-line py-6">
        <div className="max-w-7xl mx-auto px-8 flex justify-between text-xs font-mono text-ink-muted">
          <span><span className="text-white font-bold">THREAT INTEL PLATFORM</span> • XposedOrNot · HIBP · LeakCheck · Holehe · VirusTotal</span>
          <span>Authorized use only • <a className="hover:text-white" href="https://leakcheck.io" target="_blank" rel="noreferrer noopener">Powered by LeakCheck</a></span>
        </div>
      </footer>
    </div>
  )
}
