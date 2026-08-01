import { motion } from 'framer-motion'
import { Link } from 'react-router-dom'
import { Shield, Scan, Cpu, Eye, ArrowRight, Users, Server, Zap } from 'lucide-react'

const STATS = [
  { label: 'Игроков проверено', value: '12,847', icon: Users },
  { label: 'Серверов подключено', value: '156', icon: Server },
  { label: 'Читов обнаружено', value: '3,421', icon: Shield },
  { label: 'Точность детекции', value: '98.7%', icon: Zap },
]

const FEATURES = [
  {
    icon: Scan,
    title: '4 режима сканирования',
    desc: 'Полное, быстрое, DMA и детект чистки ПК — от файловой системы до аппаратных устройств',
    color: '#22c55e',
  },
  {
    icon: Cpu,
    title: 'DMA-обнаружение',
    desc: 'Поиск FPGA-устройств, PCIe-карт и драйверов памяти, используемых для читов',
    color: '#8b5cf6',
  },
  {
    icon: Eye,
    title: 'Поведенческий анализ',
    desc: 'Кросс-процессная корреляция, обнаружение инъекций и цепочек атак',
    color: '#f59e0b',
  },
  {
    icon: Shield,
    title: 'Cloud-классификатор',
    desc: 'Crowdsource-верификация, TLSH fuzzy hashing, YARA-правила и ML-скоринг',
    color: '#ef4444',
  },
]

const fadeUp = {
  hidden: { opacity: 0, y: 30 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.1, duration: 0.6, ease: [0.16, 1, 0.3, 1] },
  }),
}

export default function Hero() {
  return (
    <div className="relative overflow-hidden">
      {/* Hero Glow */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[600px] bg-hero-glow pointer-events-none" />

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
          className="text-center max-w-4xl mx-auto"
        >
          {/* Badge */}
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.2 }}
            className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-predator-accent/10 border border-predator-accent/20 text-predator-accent text-xs font-medium mb-8"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-predator-accent animate-pulse" />
            v0.4.5 · NSIS Installer · Автообновление
          </motion.div>

          <h1 className="text-5xl sm:text-6xl lg:text-7xl font-black tracking-tight leading-[1.05] mb-6">
            <span className="text-predator-text">Античит-проверка</span>
            <br />
            <span className="text-predator-accent glow-text">для GTA 5 RP</span>
          </h1>

          <p className="text-lg sm:text-xl text-predator-muted max-w-2xl mx-auto mb-10 leading-relaxed">
            Профессиональная платформа верификации игроков. Автоматическое обнаружение
            читов, DMA-устройств, HWID-спуферов и следов очистки ПК.
          </p>

          {/* CTAs */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link
              to="/players"
              className="group flex items-center gap-2 px-8 py-3.5 rounded-xl bg-predator-accent text-black font-semibold text-sm hover:bg-predator-accent/90 transition-all shadow-lg shadow-predator-accent/20"
            >
              База данных игроков
              <ArrowRight size={16} className="group-hover:translate-x-0.5 transition-transform" />
            </Link>
            <a
              href="https://github.com/lumatones/Predator/releases"
              target="_blank"
              rel="noopener"
              className="flex items-center gap-2 px-8 py-3.5 rounded-xl border border-predator-border text-predator-text font-semibold text-sm hover:border-predator-accent/30 hover:bg-predator-card transition-all"
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
                <polyline points="7 10 12 15 17 10"/>
                <line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
              Скачать приложение
            </a>
          </div>
        </motion.div>

        {/* Stats */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4, duration: 0.8 }}
          className="mt-20 grid grid-cols-2 lg:grid-cols-4 gap-4 max-w-4xl mx-auto"
        >
          {STATS.map((stat, i) => (
            <motion.div
              key={stat.label}
              custom={i}
              variants={fadeUp}
              initial="hidden"
              animate="visible"
              className="glass-card p-5 text-center"
            >
              <stat.icon size={20} className="text-predator-accent mx-auto mb-2" />
              <div className="text-2xl font-bold text-predator-text">{stat.value}</div>
              <div className="text-xs text-predator-muted mt-1">{stat.label}</div>
            </motion.div>
          ))}
        </motion.div>
      </section>

      {/* Features */}
      <section className="relative py-20 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          className="text-center mb-12"
        >
          <h2 className="text-3xl sm:text-4xl font-bold text-predator-text mb-3">Возможности</h2>
          <p className="text-predator-muted max-w-xl mx-auto">Многоуровневая система обнаружения, покрывающая все векторы использования читов</p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {FEATURES.map((feat, i) => (
            <motion.div
              key={feat.title}
              custom={i}
              variants={fadeUp}
              initial="hidden"
              whileInView="visible"
              viewport={{ once: true }}
              className="glass-card-hover p-6 flex gap-4"
            >
              <div
                className="w-11 h-11 rounded-xl flex items-center justify-center shrink-0"
                style={{ background: `${feat.color}15`, color: feat.color }}
              >
                <feat.icon size={20} />
              </div>
              <div>
                <h3 className="font-semibold text-predator-text mb-1">{feat.title}</h3>
                <p className="text-sm text-predator-muted leading-relaxed">{feat.desc}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </section>

      {/* How it works */}
      <section className="relative py-20 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          className="text-center mb-12"
        >
          <h2 className="text-3xl sm:text-4xl font-bold text-predator-text mb-3">Как это работает</h2>
          <p className="text-predator-muted max-w-xl mx-auto">Три шага для верификации игрока на вашем сервере</p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-4xl mx-auto">
          {[
            { step: '01', title: 'Игрок скачивает', desc: 'Устанавливает NSIS-установщик Predator. Автообновление включено по умолчанию.' },
            { step: '02', title: 'Запускает проверку', desc: 'Выбирает режим сканирования. Результаты отправляются на сервер в штатном режиме.' },
            { step: '03', title: 'Сервер получает', desc: 'Администратор видит результат в личном кабинете или через Discord-бота.' },
          ].map((item, i) => (
            <motion.div
              key={item.step}
              custom={i}
              variants={fadeUp}
              initial="hidden"
              whileInView="visible"
              viewport={{ once: true }}
              className="glass-card p-6 text-center relative"
            >
              <div className="text-5xl font-black text-predator-accent/10 mb-2">{item.step}</div>
              <h3 className="font-semibold text-predator-text mb-2">{item.title}</h3>
              <p className="text-sm text-predator-muted leading-relaxed">{item.desc}</p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="relative py-20 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="gradient-border max-w-3xl mx-auto text-center"
        >
          <div className="gradient-border-inner">
            <h2 className="text-2xl sm:text-3xl font-bold text-predator-text mb-3">Начните проверять игроков</h2>
            <p className="text-predator-muted mb-6 max-w-lg mx-auto">
              Зарегистрируйтесь, привяжите Discord-сервер и получите доступ к базе данных проверок
            </p>
            <Link
              to="/login"
              className="inline-flex items-center gap-2 px-8 py-3.5 rounded-xl bg-predator-accent text-black font-semibold text-sm hover:bg-predator-accent/90 transition-all shadow-lg shadow-predator-accent/20"
            >
              Зарегистрироваться
              <ArrowRight size={16} />
            </Link>
          </div>
        </motion.div>
      </section>
    </div>
  )
}
