import { useState } from 'react'

export const Icon = ({ name, className = '' }) => (
  <span className={`material-symbols-outlined ${className}`} aria-hidden="true">{name}</span>
)

const TONES = {
  safe: 'text-safe-ink bg-safe-bg border-safe-line',
  warn: 'text-warn-ink bg-warn-bg border-warn-line',
  bad: 'text-bad-ink bg-bad-bg border-bad-line',
  neutral: 'text-ink-muted bg-line-soft border-line',
}
const DOTS = { safe: 'bg-safe-ink', warn: 'bg-warn-ink', bad: 'bg-bad-ink', neutral: 'bg-ink-faint' }

export const Badge = ({ tone = 'neutral', children }) => (
  <span className={`inline-flex items-center gap-1.5 h-6 px-2 rounded-full border font-mono text-[11px] font-semibold uppercase tracking-[0.06em] ${TONES[tone]}`}>
    <span className={`w-1.5 h-1.5 rounded-full ${DOTS[tone]}`} />
    {children}
  </span>
)

export const Card = ({ title, meta, right, children, className = '' }) => (
  <section className={`bg-card border border-line rounded-xl shadow-card ${className}`}>
    {(title || right) && (
      <header className="flex items-center justify-between gap-3 px-4 py-3 border-b border-line">
        <div className="flex items-baseline gap-3 min-w-0">
          <h3 className="text-[15px] font-semibold text-ink truncate">{title}</h3>
          {meta && <span className="font-mono text-[11px] text-ink-muted truncate">{meta}</span>}
        </div>
        {right}
      </header>
    )}
    <div className="p-4">{children}</div>
  </section>
)

export const Stat = ({ label, value, tone }) => (
  <div className="bg-card border border-line rounded-xl shadow-card p-5">
    <div className="font-mono text-xs text-ink-muted">{label}</div>
    <div className={`mt-1 text-2xl font-semibold tabular-nums ${value === 'undefined' ? 'text-ink-faint' : tone === 'bad' ? 'text-bad-ink' : tone === 'safe' ? 'text-safe-ink' : tone === 'warn' ? 'text-warn-ink' : 'text-ink'}`}>{value}</div>
  </div>
)

export const Button = ({ variant = 'primary', className = '', ...p }) => (
  <button
    {...p}
    className={`h-9 px-4 rounded-xl text-sm font-medium inline-flex items-center justify-center gap-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
      variant === 'primary'
        ? 'bg-brand text-white hover:bg-brand-active shadow-glow-red hover:shadow-glow-red-lg'
        : 'bg-card-subtle text-ink-body border border-line hover:bg-card-hover hover:text-white hover:border-line-strong'
    } ${className}`}
  />
)

export function SearchConsole({ icon, type = 'text', value, onChange, placeholder, onSubmit, busy, label = 'Search' }) {
  return (
    <form
      onSubmit={(e) => { e.preventDefault(); onSubmit() }}
      className="flex flex-col sm:flex-row gap-2 w-full max-w-2xl"
    >
      <div className="flex-1 flex items-center h-12 bg-[#181a22] border border-line rounded-xl px-4 gap-2 focus-within:border-brand focus-within:shadow-focus transition">
        <Icon name={icon} className="text-ink-faint" />
        <input
          type={type}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          autoComplete="off"
          spellCheck="false"
          className="flex-1 bg-transparent font-mono text-[13px] text-ink placeholder-ink-faint outline-none"
        />
      </div>
      <Button type="submit" disabled={busy} className="!h-12 !px-6">
        {busy ? <span className="w-4 h-4 rounded-full border-2 border-white/40 border-t-white animate-spin" /> : <Icon name="search" />}
        {label}
        <kbd className="font-mono text-[11px] opacity-80">↵</kbd>
      </Button>
    </form>
  )
}

export function Copy({ text, children }) {
  const [done, setDone] = useState(false)
  return (
    <button
      type="button"
      title="Copy"
      onClick={() => navigator.clipboard.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1200) })}
      className="group inline-flex items-center gap-1 font-mono text-[12px] text-ink hover:text-brand"
    >
      {children}
      <Icon name={done ? 'check' : 'content_copy'} className="!text-[14px] text-ink-faint opacity-0 group-hover:opacity-100" />
    </button>
  )
}

export const ErrorNote = ({ children }) => (
  <div className="flex items-start gap-2 p-3 rounded border border-bad-line bg-bad-bg text-bad-ink text-sm">
    <Icon name="error" className="mt-0.5" />
    <span>{children}</span>
  </div>
)

export const Empty = ({ icon, title, children }) => (
  <div className="bg-card border border-dashed border-line-strong rounded-xl p-10 text-center">
    <Icon name={icon} className="!text-[32px] text-ink-faint" />
    <h3 className="mt-2 text-[15px] font-semibold text-ink">{title}</h3>
    <p className="mt-1 text-sm text-ink-muted max-w-md mx-auto">{children}</p>
  </div>
)

export const Th = ({ children, className = '' }) => (
  <th className={`sticky top-0 bg-card-subtle border-b border-line px-3 py-2 text-left font-mono text-[11px] uppercase tracking-[0.06em] text-ink-muted font-medium ${className}`}>{children}</th>
)
export const Td = ({ children, className = '' }) => (
  <td className={`px-3 h-10 border-b border-line-soft text-sm ${className}`}>{children}</td>
)

export const Hero = ({ badge, title, subtitle, children }) => (
  <div className="relative rounded-2xl bg-gradient-to-b from-card to-canvas-elevated p-6 sm:p-8 border border-line shadow-card overflow-hidden">
    <div className="absolute inset-0 grid-bg opacity-60 pointer-events-none" />
    <div className="absolute -top-24 -right-24 w-80 h-80 rounded-full bg-brand/10 blur-3xl pointer-events-none" />
    <div className="absolute -bottom-24 -left-24 w-80 h-80 rounded-full bg-red-950/20 blur-3xl pointer-events-none" />
    <div className="relative max-w-3xl mx-auto flex flex-col items-center text-center gap-4">
      <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-brand-dark border border-brand/30 text-xs font-mono text-red-300">
        <span className="w-2 h-2 rounded-full bg-brand animate-ping" />{badge}
      </span>
      <h1 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-white tracking-tight">{title}</h1>
      <p className="text-sm text-ink-muted max-w-xl">{subtitle}</p>
      {children}
    </div>
  </div>
)
