import { Github, Send } from 'lucide-react'

export default function Footer() {
  return (
    <footer className="border-t border-predator-border bg-predator-bg">
      <div className="mx-auto max-w-6xl px-4 py-12 sm:px-6 lg:px-8">
        <div className="grid gap-10 md:grid-cols-[1.5fr_1fr_1fr]">
          <div>
            <div className="flex items-center gap-3">
              <span className="flex h-7 w-7 items-center justify-center bg-predator-accent text-xs font-bold text-predator-bg">P</span>
              <span className="font-semibold tracking-[-0.03em] text-predator-text">Predator</span>
            </div>
            <p className="mt-4 max-w-sm text-sm leading-6 text-predator-muted">Платформа проверки игроков для серверов GTA 5 RP. Сигналы, контекст и понятные основания для решения.</p>
            <div className="mt-5 flex gap-4">
              <a href="https://discord.gg/predator" target="_blank" rel="noopener noreferrer" aria-label="Predator в Discord" className="text-predator-muted transition-colors hover:text-predator-accent"><span className="text-sm font-medium">Discord</span></a>
              <a href="https://t.me/predator_ac" target="_blank" rel="noopener noreferrer" aria-label="Predator в Telegram" className="text-predator-muted transition-colors hover:text-predator-accent"><Send size={16} /></a>
              <a href="https://github.com/lumatones/Predator" target="_blank" rel="noopener noreferrer" aria-label="Predator на GitHub" className="text-predator-muted transition-colors hover:text-predator-accent"><Github size={16} /></a>
            </div>
          </div>
          <div>
            <h2 className="text-sm font-medium text-predator-text">Платформа</h2>
            <ul className="mt-4 space-y-3 text-sm text-predator-muted">
              <li><a href="/players" className="hover:text-predator-text">Реестр игроков</a></li>
              <li><a href="/news" className="hover:text-predator-text">Обновления</a></li>
              <li><a href="/login" className="hover:text-predator-text">Личный кабинет</a></li>
            </ul>
          </div>
          <div>
            <h2 className="text-sm font-medium text-predator-text">Ресурсы</h2>
            <ul className="mt-4 space-y-3 text-sm text-predator-muted">
              <li><a href="https://github.com/lumatones/Predator/releases" target="_blank" rel="noopener noreferrer" className="hover:text-predator-text">Последний релиз</a></li>
              <li><a href="https://github.com/lumatones/Predator" target="_blank" rel="noopener noreferrer" className="hover:text-predator-text">Исходный код</a></li>
            </ul>
          </div>
        </div>
        <div className="mt-10 flex flex-col justify-between gap-3 border-t border-predator-border pt-5 text-xs text-predator-muted sm:flex-row">
          <span>© 2026 Predator Anti-Cheat</span>
          <span>Windows 10/11 x64 · v0.5.1</span>
        </div>
      </div>
    </footer>
  )
}
