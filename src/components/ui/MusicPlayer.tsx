/**
 * Predator — Music Player UI
 *
 * Slide-out panel with:
 *   - Search bar (artist/track)
 *   - Search results list
 *   - Now Playing section (cover art, track info, progress bar)
 *   - Queue management
 *   - Volume control
 *
 * Design: Dark sci-fi theme matching Predator's aesthetic.
 * Architecture: Pluggable — swap MusicSource implementations without touching UI.
 */

import React, { useState, useRef, useCallback, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useMusicPlayerContext } from '../../hooks/useMusicPlayer'

interface MusicPlayerProps {
  open: boolean
  onClose: () => void
  accent: string
  light: string
  dark: string
  lang: 'ru' | 'en'
}

const UI: Record<string, Record<string, string>> = {
  ru: {
    title: 'Музыка',
    searchPlaceholder: 'Например: phonk, miyagi, rock...',
    searchBtn: 'Найти',
    noResults: 'Ничего не найдено. Попробуйте другой запрос.',
    searching: 'Ищу...',
    queue: 'Очередь',
    nowPlaying: 'Сейчас играет',
    noTrack: 'Выберите трек',
    prev: 'Назад',
    next: 'Вперёд',
    play: 'Играть',
    pause: 'Пауза',
    clearQueue: 'Очистить',
    shuffle: 'Перемешать',
    repeat: 'Повтор',
    source: 'Источник',
    close: 'Закрыть',
    remove: 'Удалить',
    searchHint: 'Поиск идёт через iTunes Preview, Jamendo и YouTube/Invidious. Если внешние сервисы недоступны, появятся демо-треки.',
  },
  en: {
    title: 'Music',
    searchPlaceholder: 'Try: phonk, rock, ambient...',
    searchBtn: 'Search',
    noResults: 'No results found',
    searching: 'Searching...',
    queue: 'Queue',
    nowPlaying: 'Now Playing',
    noTrack: 'Select a track',
    prev: 'Previous',
    next: 'Next',
    play: 'Play',
    pause: 'Pause',
    clearQueue: 'Clear',
    shuffle: 'Shuffle',
    repeat: 'Repeat',
    source: 'Source',
    close: 'Close',
    remove: 'Remove',
    searchHint: 'Search uses iTunes Preview, Jamendo and YouTube/Invidious. Demo tracks are shown if external services are unavailable.',
  },
}

export const MusicPlayer: React.FC<MusicPlayerProps> = ({
  open, onClose, accent, light, dark, lang,
}) => {
  const t = UI[lang]
  const {
    queue, currentIndex, currentTrack, status, volume,
    shuffled, repeat, currentTime, duration,
    searchResults, searching, error,
    playTrack, togglePlayPause, handleNext, handlePrev,
    handleSeek, handleVolume, handleSearch,
    handleRemoveFromQueue, handleClearQueue,
    setShuffled, setRepeat,
  } = useMusicPlayerContext()

  const searchInputRef = useRef<HTMLInputElement>(null)
  const [searchInput, setSearchInput] = useState('')
  const panelRef = useRef<HTMLDivElement>(null)

  // ── Drag state ──
  const [dragPos, setDragPos] = useState({ x: 0, y: 0 })
  const dragRef = useRef({ startX: 0, startY: 0, startPosX: 0, startPosY: 0, isDragging: false })

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    // Keep the fixed panel stable on narrow screens; mobile uses edge-to-edge sizing.
    if (window.innerWidth <= 600) return

    // Only start drag on the header area
    const target = e.target as HTMLElement
    if (target.closest('.music-close-btn') || target.closest('button')) return
    const d = dragRef.current
    d.startX = e.clientX
    d.startY = e.clientY
    d.startPosX = dragPos.x
    d.startPosY = dragPos.y
    d.isDragging = true
    document.body.style.cursor = 'grabbing'
    document.body.style.userSelect = 'none'
  }, [dragPos])

  useEffect(() => {
    if (!open) {
      setDragPos({ x: 0, y: 0 })
      return
    }
    const handleMouseMove = (e: MouseEvent) => {
      const d = dragRef.current
      if (!d.isDragging) return

      const panel = panelRef.current
      const rect = panel?.getBoundingClientRect()
      const dx = e.clientX - d.startX
      const dy = e.clientY - d.startY

      if (!rect) {
        setDragPos({ x: d.startPosX + dx, y: d.startPosY + dy })
        return
      }

      const minX = 8 - rect.left + d.startPosX
      const maxX = Math.max(minX, window.innerWidth - rect.width - 8 - rect.left + d.startPosX)
      const minY = 8 - rect.top + d.startPosY
      const maxY = Math.max(minY, window.innerHeight - rect.height - 8 - rect.top + d.startPosY)

      setDragPos({
        x: Math.min(maxX, Math.max(minX, d.startPosX + dx)),
        y: Math.min(maxY, Math.max(minY, d.startPosY + dy)),
      })
    }
    const handleMouseUp = () => {
      const d = dragRef.current
      if (!d.isDragging) return
      d.isDragging = false
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('mousemove', handleMouseMove)
    window.addEventListener('mouseup', handleMouseUp)
    window.addEventListener('keydown', handleKeyDown)
    return () => {
      window.removeEventListener('mousemove', handleMouseMove)
      window.removeEventListener('mouseup', handleMouseUp)
      window.removeEventListener('keydown', handleKeyDown)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
  }, [open, onClose])

  const handleSearchSubmit = useCallback((e: React.FormEvent) => {
    e.preventDefault()
    handleSearch(searchInput || 'predator')
  }, [searchInput, handleSearch])

  // Auto-load demo tracks when player opens
  useEffect(() => {
    if (open && !searchResults && !searching) {
      handleSearch('predator')
    }
    // handleSearch is stable (useCallback with []), safe to omit from deps
  }, [open, searchResults, searching])

  const formatTime = (s: number) => {
    const m = Math.floor(s / 60)
    const sec = Math.floor(s % 60)
    return `${m}:${sec.toString().padStart(2, '0')}`
  }

  const progress = duration > 0 ? (currentTime / duration) * 100 : 0

  return (
    <AnimatePresence>
      {open && (
        <>
          {/* Backdrop */}
          <motion.div
            className="music-backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            onClick={onClose}
          />

          {/* Panel */}
          <motion.div
            ref={panelRef}
            className="music-panel"
            style={{
              '--music-accent': accent,
              '--music-light': light,
              '--music-dark': dark,
              '--drag-x': `${dragPos.x}px`,
              '--drag-y': `${dragPos.y}px`,
            } as React.CSSProperties}
            initial={{ opacity: 0, x: 40, scale: 0.97 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 40, scale: 0.97 }}
            transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
          >
            {/* Header — drag handle */}
            <div className="music-header music-header-drag" onMouseDown={handleMouseDown}>
              <div className="music-drag-handle">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.35">
                  <circle cx="9" cy="5" r="1.5" /><circle cx="15" cy="5" r="1.5" />
                  <circle cx="9" cy="12" r="1.5" /><circle cx="15" cy="12" r="1.5" />
                  <circle cx="9" cy="19" r="1.5" /><circle cx="15" cy="19" r="1.5" />
                </svg>
              </div>
              <h3 className="music-title">{t.title}</h3>
              <button className="music-close-btn" onClick={onClose} aria-label={t.close}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>

            {/* Search */}
            <form className="music-search" onSubmit={handleSearchSubmit}>
              <input
                ref={searchInputRef}
                className="music-search-input"
                type="text"
                placeholder={t.searchPlaceholder}
                value={searchInput}
                onChange={e => setSearchInput(e.target.value)}
              />
              <button className="music-search-btn" type="submit" disabled={searching || !searchInput.trim()}>
                {searching ? t.searching : t.searchBtn}
              </button>
            </form>
            <p className="music-search-hint">{t.searchHint}</p>

            {/* Body — scrollable */}
            <div className="music-body">
              {/* Error */}
              {error && (
                <div className="music-error">{error}</div>
              )}

              {/* Search Results */}
              {searchResults && (
                <div className="music-section">
                  <p className="music-section-label">
                    {searchResults.tracks.length > 0
                      ? `${lang === 'ru' ? 'Результаты' : 'Results'} (${searchResults.total})${searchResults.source === 'demo' ? ' · demo' : ''}`
                      : t.noResults}
                  </p>
                  <div className="music-track-list">
                    {searchResults.tracks.map(track => (
                      <motion.button
                        key={track.id}
                        className="music-track-row"
                        onClick={() => playTrack(track)}
                        whileHover={{ background: `rgba(${parseInt(accent.slice(1,3), 16)}, ${parseInt(accent.slice(3,5), 16)}, ${parseInt(accent.slice(5,7), 16)}, 0.08)` }}
                        whileTap={{ scale: 0.98 }}
                      >
                        {track.coverUrl ? (
                          <img className="music-track-cover" src={track.coverUrl} alt="" loading="lazy" />
                        ) : (
                          <div className="music-track-cover music-track-cover--placeholder">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M9 18V5l12-2v13" /><circle cx="6" cy="18" r="3" /><circle cx="18" cy="16" r="3" />
                            </svg>
                          </div>
                        )}
                        <div className="music-track-info">
                          <span className="music-track-title">{track.title}</span>
                          <span className="music-track-artist">{track.artist}</span>
                        </div>
                        <span className="music-track-duration">{formatTime(track.duration)}</span>
                        <span className="music-track-source">{track.source}</span>
                      </motion.button>
                    ))}
                  </div>
                </div>
              )}

              {/* Now Playing */}
              {currentTrack && (
                <div className="music-now-playing">
                  <div className="music-now-playing-cover">
                    {currentTrack.coverUrl ? (
                      <img src={currentTrack.coverUrl} alt="" />
                    ) : (
                      <div className="music-now-playing-cover--placeholder">
                        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                          <path d="M9 18V5l12-2v13" /><circle cx="6" cy="18" r="3" /><circle cx="18" cy="16" r="3" />
                        </svg>
                      </div>
                    )}
                  </div>
                  <div className="music-now-playing-info">
                    <span className="music-now-playing-title">{currentTrack.title}</span>
                    <span className="music-now-playing-artist">{currentTrack.artist}</span>
                    <span className="music-now-playing-source">{currentTrack.source}</span>
                  </div>
                </div>
              )}

              {/* Progress bar */}
              {currentTrack && (
                <div className="music-progress-wrap">
                  <span className="music-time">{formatTime(currentTime)}</span>
                  <div
                    className="music-progress-bar"
                    onClick={(e) => {
                      const rect = e.currentTarget.getBoundingClientRect()
                      const pct = (e.clientX - rect.left) / rect.width
                      handleSeek(pct * duration)
                    }}
                  >
                    <div className="music-progress-fill" style={{ width: `${progress}%` }} />
                    <div className="music-progress-thumb" style={{ left: `${progress}%` }} />
                  </div>
                  <span className="music-time">{formatTime(duration)}</span>
                </div>
              )}

              {/* Controls */}
              {currentTrack && (
                <div className="music-controls">
                  <button
                    className={`music-ctrl-btn${shuffled ? ' active' : ''}`}
                    onClick={() => setShuffled(!shuffled)}
                    title={t.shuffle}
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="16 3 21 3 21 8" /><line x1="4" y1="20" x2="21" y2="3" />
                      <polyline points="21 16 21 21 16 21" /><line x1="15" y1="15" x2="21" y2="21" />
                      <line x1="4" y1="4" x2="9" y2="9" />
                    </svg>
                  </button>
                  <button className="music-ctrl-btn" onClick={handlePrev} title={t.prev}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polygon points="19 20 9 12 19 4 19 20" /><line x1="5" y1="19" x2="5" y2="5" />
                    </svg>
                  </button>
                  <button
                    className="music-ctrl-btn music-ctrl-btn--play"
                    onClick={togglePlayPause}
                    title={status === 'playing' ? t.pause : t.play}
                  >
                    {status === 'playing' ? (
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                        <rect x="6" y="4" width="4" height="16" rx="1" />
                        <rect x="14" y="4" width="4" height="16" rx="1" />
                      </svg>
                    ) : status === 'loading' ? (
                      <div className="music-spinner" />
                    ) : (
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                        <polygon points="5 3 19 12 5 21 5 3" />
                      </svg>
                    )}
                  </button>
                  <button className="music-ctrl-btn" onClick={handleNext} title={t.next}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polygon points="5 4 15 12 5 20 5 4" /><line x1="19" y1="5" x2="19" y2="19" />
                    </svg>
                  </button>
                  <button
                    className={`music-ctrl-btn${repeat ? ' active' : ''}`}
                    onClick={() => setRepeat(!repeat)}
                    title={t.repeat}
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="17 1 21 5 17 9" /><path d="M3 11V9a4 4 0 0 1 4-4h14" />
                      <polyline points="7 23 3 19 7 15" /><path d="M21 13v2a4 4 0 0 1-4 4H3" />
                    </svg>
                  </button>
                </div>
              )}

              {/* Volume */}
              {currentTrack && (
                <div className="music-volume-wrap">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5" />
                    {volume > 0 && <path d="M19.07 4.93a10 10 0 0 1 0 14.14M15.54 8.46a5 5 0 0 1 0 7.07" />}
                  </svg>
                  <input
                    className="music-volume-slider"
                    type="range"
                    min="0"
                    max="1"
                    step="0.05"
                    value={volume}
                    onChange={e => handleVolume(parseFloat(e.target.value))}
                    style={{
                      '--vol-pct': `${volume * 100}%`,
                      '--music-accent': accent,
                    } as React.CSSProperties}
                  />
                </div>
              )}

              {/* Queue */}
              {queue.length > 1 && (
                <div className="music-section">
                  <div className="music-section-header">
                    <p className="music-section-label">{t.queue} ({queue.length})</p>
                    <button className="music-clear-btn" onClick={handleClearQueue}>
                      {t.clearQueue}
                    </button>
                  </div>
                  <div className="music-track-list" role="list" aria-label={t.queue}>
                    {queue.map((track, i) => (
                      <motion.div
                        key={`${track.id}-${i}`}
                        className={`music-track-row${i === currentIndex ? ' active' : ''}`}
                        role="listitem"
                        whileHover={{ background: i === currentIndex
                          ? `rgba(${parseInt(accent.slice(1,3), 16)}, ${parseInt(accent.slice(3,5), 16)}, ${parseInt(accent.slice(5,7), 16)}, 0.2)`
                          : 'rgba(255,255,255,0.03)'
                        }}
                        whileTap={{ scale: 0.98 }}
                      >
                        <button
                          className="music-track-play"
                          onClick={() => playTrack(track, false)}
                          aria-label={`${t.play}: ${track.title}`}
                        >
                          <span className="music-queue-index">
                            {i === currentIndex && status === 'playing'
                              ? <span className="music-eq"><span /><span /><span /></span>
                              : i + 1}
                          </span>
                          <span className="music-track-info">
                            <span className="music-track-title">{track.title}</span>
                            <span className="music-track-artist">{track.artist}</span>
                          </span>
                          <span className="music-track-duration">{formatTime(track.duration)}</span>
                        </button>
                        <button
                          className="music-remove-btn"
                          onClick={() => handleRemoveFromQueue(i)}
                          aria-label={`${t.remove}: ${track.title}`}
                        >
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                          </svg>
                        </button>
                      </motion.div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  )
}
