import React, { Component, type ReactNode } from 'react'

interface Props {
  children: ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
}

export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null })
  }

  handleReload = () => {
    window.location.reload()
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          position: 'fixed',
          inset: 0,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 16,
          padding: 32,
          background: '#0a0a0f',
          color: '#fff',
          fontFamily: "'Inter', system-ui, sans-serif",
          textAlign: 'center',
        }}>
          <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
            <circle cx="24" cy="24" r="22" stroke="#ff4444" strokeWidth="2" />
            <line x1="16" y1="16" x2="32" y2="32" stroke="#ff4444" strokeWidth="3" strokeLinecap="round" />
            <line x1="32" y1="16" x2="16" y2="32" stroke="#ff4444" strokeWidth="3" strokeLinecap="round" />
          </svg>
          <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>
            Произошла ошибка
          </h1>
          <p style={{ fontSize: 14, color: 'rgba(255,255,255,0.6)', maxWidth: 400, lineHeight: 1.5, margin: 0 }}>
            {this.state.error?.message || 'Неизвестная ошибка'}
          </p>
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <button
              onClick={this.handleReset}
              style={{
                padding: '8px 20px',
                borderRadius: 8,
                border: '1px solid rgba(255,255,255,0.15)',
                background: 'rgba(255,255,255,0.06)',
                color: '#fff',
                cursor: 'pointer',
                fontSize: 13,
                fontFamily: 'inherit',
              }}
            >
              Попробовать снова
            </button>
            <button
              onClick={this.handleReload}
              style={{
                padding: '8px 20px',
                borderRadius: 8,
                border: 'none',
                background: 'linear-gradient(135deg, #ff4444, #ff6b35)',
                color: '#fff',
                cursor: 'pointer',
                fontSize: 13,
                fontWeight: 600,
                fontFamily: 'inherit',
              }}
            >
              Перезагрузить
            </button>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}
