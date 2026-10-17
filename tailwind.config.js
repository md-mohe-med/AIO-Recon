/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        canvas: { DEFAULT: '#0a0b0e', elevated: '#0f1117' },
        card: { DEFAULT: '#141720', hover: '#1a1e2a', subtle: '#181b24' },
        ink: { DEFAULT: '#ffffff', body: '#d1d5db', muted: '#9ca3af', faint: '#6b7280' },
        line: { DEFAULT: '#222634', soft: '#181b24', strong: '#2f3447' },
        brand: { DEFAULT: '#ef4444', active: '#dc2626', dark: '#261214', subtle: '#3b1619' },
        safe: { ink: '#34d399', bg: '#06281f', line: '#065f46' },
        warn: { ink: '#fbbf24', bg: '#2a1c06', line: '#92400e' },
        bad: { ink: '#f87171', bg: '#261214', line: '#7f1d1d' },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
      boxShadow: {
        card: '0 4px 20px -2px rgba(0,0,0,0.65)',
        'glow-red': '0 0 25px -4px rgba(239,68,68,0.35)',
        'glow-red-lg': '0 0 45px -8px rgba(239,68,68,0.45)',
        focus: '0 0 0 2px rgba(239,68,68,0.2)',
      },
    },
  },
  plugins: [],
}
