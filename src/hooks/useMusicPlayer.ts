/**
 * Predator — Music Player Hook
 *
 * Central state management for the music player:
 *   - Queue management (add, remove, reorder, shuffle)
 *   - Playback control (play, pause, skip, seek)
 *   - Volume control
 *   - Search across music sources
 *   - Track preloading and stream URL resolution
 *
 * Uses React Context so MusicPlayer + MiniPlayer share the same state.
 */

import { useState, useCallback, useRef, useEffect, createContext, useContext } from 'react'
import type { MusicTrack, PlayerStatus, SearchResult } from '../types/music'
import { searchAllSources, resolveStreamUrl } from '../services/music-sources'

// ═══════════════════════════════════════════════════
// CONTEXT — shared state between MusicPlayer & MiniPlayer
// ═══════════════════════════════════════════════════

export interface MusicPlayerAPI {
  queue: MusicTrack[]
  currentIndex: number
  currentTrack: MusicTrack | null
  status: PlayerStatus
  volume: number
  shuffled: boolean
  repeat: boolean
  currentTime: number
  duration: number
  searchQuery: string
  searchResults: SearchResult | null
  searching: boolean
  error: string | null
  playTrack: (track: MusicTrack, addToQueue?: boolean) => Promise<void>
  togglePlayPause: () => void
  handleNext: () => void
  handlePrev: () => void
  handleSeek: (time: number) => void
  handleVolume: (v: number) => void
  handleSearch: (query: string) => Promise<void>
  handleRemoveFromQueue: (index: number) => void
  handleClearQueue: () => void
  setShuffled: (v: boolean) => void
  setRepeat: (v: boolean) => void
}

export const MusicPlayerContext = createContext<MusicPlayerAPI | null>(null)

export function useMusicPlayerContext(): MusicPlayerAPI {
  const ctx = useContext(MusicPlayerContext)
  if (!ctx) throw new Error('useMusicPlayerContext must be used within MusicPlayerContext.Provider')
  return ctx
}

// ── Local storage keys ──

const LS_QUEUE = 'predator_music_queue'
const LS_VOLUME = 'predator_music_volume'

function loadQueue(): MusicTrack[] {
  try {
    const raw = localStorage.getItem(LS_QUEUE)
    return raw ? JSON.parse(raw) : []
  } catch { return [] }
}

function saveQueue(queue: MusicTrack[]): void {
  try { localStorage.setItem(LS_QUEUE, JSON.stringify(queue.slice(0, 50))) } catch {}
}

function loadVolume(): number {
  try {
    const raw = localStorage.getItem(LS_VOLUME)
    return raw ? parseFloat(raw) : 0.7
  } catch { return 0.7 }
}

function saveVolume(v: number): void {
  try { localStorage.setItem(LS_VOLUME, String(v)) } catch {}
}

// ── Hook ──

export function useMusicPlayer(): MusicPlayerAPI {
  const audioRef = useRef<HTMLAudioElement | null>(null)
  const [queue, setQueue] = useState<MusicTrack[]>(loadQueue)
  const [currentIndex, setCurrentIndex] = useState(-1)
  const [status, setStatus] = useState<PlayerStatus>('idle')
  const [volume, setVolumeState] = useState(loadVolume)
  const [shuffled, setShuffled] = useState(false)
  const [repeat, setRepeat] = useState(false)
  const [currentTime, setCurrentTime] = useState(0)
  const [duration, setDuration] = useState(0)
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState<SearchResult | null>(null)
  const [searching, setSearching] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Ref for handleNext to avoid stale closure in event listeners
  const handleNextRef = useRef<() => void>(() => {})

  // ── Audio element (one-time creation, no deps) ──

  const getAudio = useCallback((): HTMLAudioElement => {
    if (!audioRef.current) {
      audioRef.current = new Audio()
      audioRef.current.volume = loadVolume()
      audioRef.current.addEventListener('timeupdate', () => {
        setCurrentTime(audioRef.current?.currentTime || 0)
      })
      audioRef.current.addEventListener('durationchange', () => {
        setDuration(audioRef.current?.duration || 0)
      })
      // Use ref to avoid stale closure — handleNextRef always has latest handleNext
      audioRef.current.addEventListener('ended', () => {
        handleNextRef.current()
      })
      audioRef.current.addEventListener('error', () => {
        setError('Ошибка воспроизведения')
        setStatus('idle')
      })
      audioRef.current.addEventListener('playing', () => setStatus('playing'))
      audioRef.current.addEventListener('pause', () => {
        if (audioRef.current && !audioRef.current.ended) setStatus('paused')
      })
      audioRef.current.addEventListener('waiting', () => setStatus('loading'))
    }
    return audioRef.current
  }, [])

  // ── Persist queue ──

  useEffect(() => {
    saveQueue(queue)
  }, [queue])

  // ── Playback ──

  const handleNext = useCallback(() => {
    if (queue.length === 0) return

    let nextIdx: number
    if (shuffled) {
      nextIdx = Math.floor(Math.random() * queue.length)
    } else if (repeat && currentIndex === queue.length - 1) {
      nextIdx = 0
    } else {
      nextIdx = (currentIndex + 1) % queue.length
    }

    setCurrentIndex(nextIdx)
    const track = queue[nextIdx]
    if (!track) return

    // Direct audio playback (inline, to avoid circular deps with playTrack)
    setError(null)
    setStatus('loading')
    const audio = audioRef.current
    if (!audio) return

    const doPlay = async () => {
      let streamUrl = track.streamUrl
      if (!streamUrl) {
        try { streamUrl = await resolveStreamUrl(track) } catch {
          setError(`Не удалось загрузить: ${track.title}`)
          setStatus('idle')
          return
        }
      }
      audio.src = streamUrl
      audio.load()
      try { await audio.play() } catch {}
    }
    doPlay()
  }, [queue, currentIndex, shuffled, repeat])

  // Keep ref in sync
  handleNextRef.current = handleNext

  const playTrack = useCallback(async (track: MusicTrack, addToQueue = true) => {
    setError(null)
    setStatus('loading')

    let streamUrl = track.streamUrl
    if (!streamUrl) {
      try { streamUrl = await resolveStreamUrl(track) } catch {
        setError(`Не удалось загрузить: ${track.title}`)
        setStatus('idle')
        return
      }
    }

    const audio = getAudio()
    audio.src = streamUrl
    audio.load()
    try { await audio.play() } catch {}

    if (addToQueue) {
      setQueue(prev => {
        const idx = prev.findIndex(t => t.id === track.id)
        if (idx >= 0) {
          setCurrentIndex(idx)
          return prev
        }
        const next = [...prev, track]
        setCurrentIndex(next.length - 1)
        return next
      })
    }
  }, [getAudio])

  const togglePlayPause = useCallback(() => {
    const audio = audioRef.current
    if (!audio || !audio.src) return
    if (audio.paused) {
      audio.play().catch(() => setError('Ошибка воспроизведения'))
    } else {
      audio.pause()
    }
  }, [])

  const handlePrev = useCallback(() => {
    if (queue.length === 0 || currentIndex <= 0) return
    const prevIdx = currentIndex - 1
    setCurrentIndex(prevIdx)
    const track = queue[prevIdx]
    if (track) playTrack(track, false)
  }, [queue, currentIndex, playTrack])

  const handleSeek = useCallback((time: number) => {
    const audio = audioRef.current
    if (audio) {
      audio.currentTime = time
      setCurrentTime(time)
    }
  }, [])

  const handleVolume = useCallback((v: number) => {
    const clamped = Math.max(0, Math.min(1, v))
    setVolumeState(clamped)
    saveVolume(clamped)
    if (audioRef.current) audioRef.current.volume = clamped
  }, [])

  const handleRemoveFromQueue = useCallback((index: number) => {
    setQueue(prev => {
      const next = [...prev]
      next.splice(index, 1)
      if (index === currentIndex) {
        audioRef.current?.pause()
        setCurrentIndex(-1)
        setStatus('idle')
      } else if (index < currentIndex) {
        setCurrentIndex(prev => prev - 1)
      }
      return next
    })
  }, [currentIndex])

  const handleClearQueue = useCallback(() => {
    audioRef.current?.pause()
    setQueue([])
    setCurrentIndex(-1)
    setStatus('idle')
  }, [])

  // ── Search ──

  const handleSearch = useCallback(async (query: string) => {
    setSearchQuery(query)
    if (!query.trim()) {
      setSearchResults(null)
      return
    }
    setSearching(true)
    setError(null)
    try {
      const results = await searchAllSources(query, 20)
      setSearchResults(results)
    } catch {
      setError('Поиск временно недоступен')
    } finally {
      setSearching(false)
    }
  }, [])

  // ── Current track ──

  const currentTrack = currentIndex >= 0 && currentIndex < queue.length
    ? queue[currentIndex]
    : null

  return {
    queue, currentIndex, currentTrack, status, volume,
    shuffled, repeat, currentTime, duration,
    searchQuery, searchResults, searching, error,
    playTrack, togglePlayPause, handleNext, handlePrev,
    handleSeek, handleVolume, handleSearch,
    handleRemoveFromQueue, handleClearQueue,
    setShuffled, setRepeat,
  }
}
