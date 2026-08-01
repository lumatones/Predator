import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Calendar, Tag, ArrowRight, Loader2, AlertTriangle } from 'lucide-react'
import { fetchNews, fetchNewsArticle, type NewsArticle } from '../api'

const fadeUp = {
  hidden: { opacity: 0, y: 16 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.06, duration: 0.45, ease: [0.16, 1, 0.3, 1] as const },
  }),
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString('ru-RU', { year: 'numeric', month: 'long', day: 'numeric' })
}

export default function News() {
  const [articles, setArticles] = useState<NewsArticle[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [expandedContent, setExpandedContent] = useState<string | null>(null)
  const [contentLoading, setContentLoading] = useState(false)

  const load = () => {
    setLoading(true)
    setError(null)
    fetchNews()
      .then(setArticles)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }

  useEffect(load, [])

  const toggleExpand = async (id: number) => {
    if (expandedId === id) {
      setExpandedId(null)
      setExpandedContent(null)
      return
    }
    setExpandedId(id)
    setExpandedContent(null)
    setContentLoading(true)
    try {
      const article = await fetchNewsArticle(id)
      setExpandedContent(article.content || article.excerpt || '')
    } catch {
      setExpandedContent('Не удалось загрузить полный текст статьи.')
    } finally {
      setContentLoading(false)
    }
  }

  return (
    <div className="mx-auto max-w-5xl px-4 pb-24 pt-32 sm:px-6 lg:px-8 lg:pt-40">
      <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.55 }}>
        <div className="border-b border-predator-border pb-8">
          <p className="data-mono text-[10px] uppercase tracking-[0.14em] text-predator-accent">Predator / заметки к релизам</p>
          <h1 className="mt-4 text-4xl font-semibold tracking-[-0.05em] text-predator-text sm:text-5xl">Обновления системы</h1>
          <p className="mt-4 max-w-2xl text-base leading-7 text-predator-muted">Изменения в ядре проверки, правилах детекции и инструментах для серверных операторов.</p>
        </div>

        {loading ? (
          <div className="mt-8 space-y-6 border-t border-predator-border pt-2" role="status" aria-label="Загрузка обновлений">
            {Array.from({ length: 4 }, (_, index) => <div key={index} className="grid gap-4 border-b border-predator-border py-7 sm:grid-cols-[150px_1fr]"><span className="evidence-skeleton h-3 w-28 rounded-full" /><div className="space-y-3"><span className="evidence-skeleton block h-3 w-20 rounded-full" /><span className="evidence-skeleton block h-6 w-3/4 rounded-full" /><span className="evidence-skeleton block h-3 w-full max-w-xl rounded-full" /></div></div>)}
          </div>
        ) : error ? (
          <div className="evidence-sheet mt-8 p-8 text-center">
            <AlertTriangle size={22} className="mx-auto mb-3 text-predator-danger" />
            <p className="text-sm text-predator-danger">{error}</p>
            <button type="button" onClick={load} className="mt-5 border border-predator-border px-4 py-2 text-sm text-predator-muted transition-colors hover:border-predator-accent hover:text-predator-text">Повторить</button>
          </div>
        ) : articles.length === 0 ? (
          <div className="evidence-state mt-8 p-10 text-center"><Tag size={22} className="mx-auto mb-3 text-predator-muted" aria-hidden="true" /><p className="text-sm text-predator-text">Пока нет опубликованных обновлений.</p><p className="mx-auto mt-2 max-w-sm text-xs leading-5 text-predator-muted">Здесь появятся заметки о новых детектах, релизах и изменениях в системе.</p></div>
        ) : (
          <div className="mt-8 border-t border-predator-border">
            {articles.map((item, index) => (
              <motion.article key={item.id} custom={index} variants={fadeUp} initial="hidden" animate="visible" className="group border-b border-predator-border py-7">
                <button type="button" onClick={() => toggleExpand(item.id)} className="block w-full text-left focus-visible:outline-offset-4">
                  <div className="grid gap-4 sm:grid-cols-[150px_1fr_auto] sm:gap-8">
                    <div className="flex items-start gap-2 text-xs text-predator-muted"><Calendar size={13} className="mt-0.5 shrink-0" />{formatDate(item.created_at)}</div>
                    <div>
                      <div className="mb-3 flex items-center gap-2 text-xs" style={{ color: item.tag_color || '#8da2ff' }}><Tag size={12} />{item.tag || 'Обновление'}</div>
                      <h2 className="text-xl font-semibold tracking-[-0.025em] text-predator-text transition-colors group-hover:text-predator-accent">{item.title}</h2>
                      <p className="mt-3 max-w-2xl text-sm leading-6 text-predator-muted">{item.excerpt}</p>
                    </div>
                    <ArrowRight size={17} className={`mt-1 text-predator-muted transition-transform group-hover:text-predator-accent ${expandedId === item.id ? 'rotate-90' : ''}`} />
                  </div>
                </button>

                {expandedId === item.id && (
                  <div className="mt-6 border-l-2 border-predator-accent pl-5 sm:ml-[182px]">
                    {contentLoading ? <div className="flex items-center gap-2 text-sm text-predator-muted"><Loader2 size={15} className="animate-spin text-predator-accent" /> Загрузка текста...</div> : <p className="max-w-2xl whitespace-pre-line text-sm leading-7 text-predator-text">{expandedContent}</p>}
                  </div>
                )}
              </motion.article>
            ))}
          </div>
        )}
      </motion.div>
    </div>
  )
}
