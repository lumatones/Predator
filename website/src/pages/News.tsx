import { motion } from 'framer-motion'
import { Calendar, Tag, ArrowRight } from 'lucide-react'

const NEWS = [
  {
    id: 1,
    date: '2026-07-31',
    tag: 'Релиз',
    tagColor: '#22c55e',
    title: 'Predator v0.4.5 — NSIS Installer + Автообновление',
    excerpt: 'Полноценная установка через NSIS, дифференциальные обновления через .blockmap, исправленный релизный пайплайн.',
    content: 'Релиз v0.4.5 включает: NSIS-установщик (вместо portable exe), electron-updater для автообновлений, загрузку .blockmap для дифференциальных обновлений, исправленный GitHub Actions workflow.',
  },
  {
    id: 2,
    date: '2026-07-28',
    tag: 'Обновление',
    tagColor: '#8b5cf6',
    title: 'Улучшен UI Dashboard — Glass Morphism v2',
    excerpt: 'Новая визуальная палитра, компактный режим сканирования, тултипы и микроанимации.',
    content: 'Обновлён весь фронтенд: компактный режим для фонового сканирования, улучшенные карточки угроз, модальные окна с деталями файлов, интерактивная карта угроз.',
  },
  {
    id: 3,
    date: '2026-07-25',
    tag: 'Безопасность',
    tagColor: '#ef4444',
    title: 'Новые DMA-детекты — Xilinx FPGA + PCIe',
    excerpt: 'Обнаружение DMA-карт, FPGA-устройств и vulnerable драйверов (BYOVD).',
    content: 'Добавлены: сканирование PCIe config space, обнаружение Xilinx/Altera FPGA, проверка vulnerable драйверов (rtcore, gdrv, iqvw64e), BYOVD-детект через KDMapper/DrvMap.',
  },
  {
    id: 4,
    date: '2026-07-22',
    tag: 'Команда',
    tagColor: '#f59e0b',
    title: 'Cloud-классификатор v2 — Correlation Engine',
    excerpt: 'Мульти-сигнальная классификация с crowdsource-верификацией и adaptive thresholds.',
    content: 'Новый классификатор: 11 сигналов, correlation bonus для слабых индикаторов, crowdsource safe/malicious через уникальные PC, TLSH fuzzy matching, adaptive thresholds для DMA и cleaner нахождений.',
  },
  {
    id: 5,
    date: '2026-07-18',
    tag: 'Обновление',
    tagColor: '#8b5cf6',
    title: 'Поведенческий анализ E17 — Attack Chain Detection',
    excerpt: 'Кросс-процессная корреляция, обнаружение инъекций и CEF-дебага.',
    content: 'Новый модуль behavior-engine: построение дерева процессов, обнаружение пар injector→victim, детект CEF remote debugging, suspicious parent chain, session-level behavioral scoring.',
  },
]

const fadeUp = {
  hidden: { opacity: 0, y: 20 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.08, duration: 0.5, ease: [0.16, 1, 0.3, 1] },
  }),
}

export default function News() {
  return (
    <div className="pt-24 pb-20 px-4 sm:px-6 lg:px-8 max-w-4xl mx-auto">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }}>
        <h1 className="text-3xl sm:text-4xl font-bold text-predator-text mb-2">Новости</h1>
        <p className="text-predator-muted mb-10">Последние обновления платформы Predator Anti-Cheat</p>

        <div className="space-y-5">
          {NEWS.map((item, i) => (
            <motion.article
              key={item.id}
              custom={i}
              variants={fadeUp}
              initial="hidden"
              animate="visible"
              className="glass-card-hover p-6 group cursor-pointer"
            >
              <div className="flex items-center gap-3 mb-3">
                <span
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium"
                  style={{ background: `${item.tagColor}15`, color: item.tagColor }}
                >
                  <Tag size={10} />
                  {item.tag}
                </span>
                <span className="flex items-center gap-1.5 text-xs text-predator-muted">
                  <Calendar size={12} />
                  {item.date}
                </span>
              </div>

              <h2 className="text-lg font-semibold text-predator-text mb-2 group-hover:text-predator-accent transition-colors">
                {item.title}
              </h2>
              <p className="text-sm text-predator-muted leading-relaxed">{item.excerpt}</p>

              <div className="flex items-center gap-1.5 mt-4 text-xs font-medium text-predator-accent opacity-0 group-hover:opacity-100 transition-opacity">
                Подробнее <ArrowRight size={12} />
              </div>
            </motion.article>
          ))}
        </div>
      </motion.div>
    </div>
  )
}
