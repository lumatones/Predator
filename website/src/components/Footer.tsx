export default function Footer() {
  return (
    <footer className="border-t border-predator-border bg-predator-bg/80 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Brand */}
          <div className="md:col-span-2">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-8 h-8 rounded-lg bg-predator-accent/20 flex items-center justify-center">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
              </div>
              <span className="text-lg font-bold">
                <span className="text-predator-accent">Predator</span>
              </span>
            </div>
            <p className="text-predator-muted text-sm leading-relaxed max-w-md">
              Профессиональная платформа античит-проверки для GTA 5 RP серверов.
              Автоматическое обнаружение читов, DMA-устройств и следов очистки ПК.
            </p>
            <div className="flex gap-3 mt-4">
              <a href="https://discord.gg/predator" target="_blank" rel="noopener" className="w-9 h-9 rounded-lg bg-predator-card border border-predator-border flex items-center justify-center text-predator-muted hover:text-predator-accent hover:border-predator-accent/30 transition-all">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.617-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.077.077 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/>
                </svg>
              </a>
              <a href="https://t.me/predator_ac" target="_blank" rel="noopener" className="w-9 h-9 rounded-lg bg-predator-card border border-predator-border flex items-center justify-center text-predator-muted hover:text-predator-accent hover:border-predator-accent/30 transition-all">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M11.944 0A12 12 0 000 12a12 12 0 0012 12 12 12 0 0012-12A12 12 0 0012 0a12 12 0 00-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 01.171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.479.33-.913.492-1.302.48-.428-.013-1.252-.242-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"/>
                </svg>
              </a>
              <a href="https://github.com/lumatones/Predator" target="_blank" rel="noopener" className="w-9 h-9 rounded-lg bg-predator-card border border-predator-border flex items-center justify-center text-predator-muted hover:text-predator-accent hover:border-predator-accent/30 transition-all">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                </svg>
              </a>
            </div>
          </div>

          {/* Links */}
          <div>
            <h3 className="text-sm font-semibold text-predator-text mb-3">Платформа</h3>
            <ul className="space-y-2">
              <li><a href="/players" className="text-sm text-predator-muted hover:text-predator-accent transition-colors">База данных игроков</a></li>
              <li><a href="/news" className="text-sm text-predator-muted hover:text-predator-accent transition-colors">Новости</a></li>
              <li><a href="/login" className="text-sm text-predator-muted hover:text-predator-accent transition-colors">Личный кабинет</a></li>
            </ul>
          </div>
          <div>
            <h3 className="text-sm font-semibold text-predator-text mb-3">Скачать</h3>
            <ul className="space-y-2">
              <li><a href="https://github.com/lumatones/Predator/releases" target="_blank" rel="noopener" className="text-sm text-predator-muted hover:text-predator-accent transition-colors">Последний релиз</a></li>
              <li><a href="https://github.com/lumatones/Predator" target="_blank" rel="noopener" className="text-sm text-predator-muted hover:text-predator-accent transition-colors">GitHub</a></li>
            </ul>
          </div>
        </div>

        <div className="mt-10 pt-6 border-t border-predator-border flex flex-col sm:flex-row items-center justify-between gap-4">
          <p className="text-xs text-predator-muted">© 2026 Predator Anti-Cheat. Все права защищены.</p>
          <p className="text-xs text-predator-muted">v0.4.5 · Windows 10/11 x64</p>
        </div>
      </div>
    </footer>
  )
}
