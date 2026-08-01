import type { Config } from 'tailwindcss'

const config: Config = {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        predator: {
          bg: '#0d1014',
          card: '#151a21',
          border: '#2b3440',
          accent: '#8eafff',
          danger: '#ee858d',
          warning: '#e0b875',
          muted: '#8f99a7',
          text: '#f2f4f7',
          glow: 'rgba(142, 175, 255, 0.12)',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'IBM Plex Mono', 'monospace'],
      },
      animation: {
        'blink-soft': 'blink-soft 2.4s steps(2, end) infinite',
      },
      keyframes: {
        'blink-soft': {
          '0%, 48%': { opacity: '1' },
          '49%, 100%': { opacity: '0.3' },
        },
      },
    },
  },
  plugins: [],
}

export default config
