/**
 * Predator — Music Sources
 *
 * Pluggable music providers that implement the MusicSource interface.
 */

import type { MusicSource, SearchResult, MusicTrack } from '../types/music'

type JamendoTrack = {
  id: string | number
  name?: string
  artist_name?: string
  album_name?: string
  duration?: number | string
  image?: string
  album_image?: string
  audio?: string
  audiodownload?: string
}

type InvidiousVideo = {
  type?: string
  videoId?: string
  title?: string
  author?: string
  lengthSeconds?: number | string
  videoThumbnails?: { url?: string }[]
}

type InvidiousFormat = {
  type?: string
  url?: string
}

type ITunesTrack = {
  trackId?: string | number
  trackName?: string
  artistName?: string
  collectionName?: string
  trackTimeMillis?: number
  artworkUrl100?: string
  artworkUrl60?: string
  previewUrl?: string
}

const FALLBACK_TRACKS: MusicTrack[] = [
  { id: 'demo:night-drive', title: 'Night Drive', artist: 'Predator Radio', duration: 184, streamUrl: 'https://cdn.pixabay.com/download/audio/2022/10/25/audio_946b1b5b19.mp3?filename=night-detective-123577.mp3', coverUrl: '', source: 'Demo' },
  { id: 'demo:cyber-pulse', title: 'Cyber Pulse', artist: 'Predator Radio', duration: 142, streamUrl: 'https://cdn.pixabay.com/download/audio/2022/03/15/audio_2b1952d6c2.mp3?filename=technology-background-109252.mp3', coverUrl: '', source: 'Demo' },
  { id: 'demo:dark-scan', title: 'Dark Scan', artist: 'Predator Radio', duration: 128, streamUrl: 'https://cdn.pixabay.com/download/audio/2022/01/18/audio_d0c6ff1bab.mp3?filename=electronic-rock-king-around-here-15045.mp3', coverUrl: '', source: 'Demo' },
  { id: 'demo:ambient-alert', title: 'Ambient Alert', artist: 'Predator Radio', duration: 165, streamUrl: 'https://cdn.pixabay.com/download/audio/2022/08/02/audio_884fe92c21.mp3?filename=lifelike-126735.mp3', coverUrl: '', source: 'Demo' },
]

const JAMENDO_CLIENT_ID = '9d0e6e8c'

function withTimeout(ms = 7000): AbortController {
  const controller = new AbortController()
  window.setTimeout(() => controller.abort(), ms)
  return controller
}

const iTunesSource: MusicSource = {
  id: 'itunes',
  name: 'iTunes Preview',

  isAvailable: () => true,

  async search(query: string, limit = 15): Promise<SearchResult> {
    const url = `https://itunes.apple.com/search?term=${encodeURIComponent(query)}&media=music&entity=song&limit=${limit}`
    const controller = withTimeout()
    const res = await fetch(url, { signal: controller.signal })
    if (!res.ok) throw new Error(`iTunes API error: ${res.status}`)

    const data = await res.json() as { resultCount?: number; results?: ITunesTrack[] }
    const results = data.results || []
    const tracks: MusicTrack[] = results.map(r => ({
      id: `itunes:${r.trackId}`,
      title: r.trackName || 'Unknown',
      artist: r.artistName || 'Unknown',
      album: r.collectionName || undefined,
      duration: Math.max(1, Math.round((r.trackTimeMillis || 30000) / 1000)),
      coverUrl: r.artworkUrl100 || r.artworkUrl60 || undefined,
      streamUrl: r.previewUrl || '',
      source: 'iTunes Preview',
    })).filter(t => t.streamUrl)

    return {
      tracks,
      total: data.resultCount || tracks.length,
      source: 'itunes',
      query,
    }
  },
}

const jamendoSource: MusicSource = {
  id: 'jamendo',
  name: 'Jamendo',

  isAvailable: () => true,

  async search(query: string, limit = 15): Promise<SearchResult> {
    const url = `https://api.jamendo.com/v3.0/tracks/?client_id=${JAMENDO_CLIENT_ID}&format=json&search=${encodeURIComponent(query)}&limit=${limit}&include=musicinfo&audioformat=mp31`
    const controller = withTimeout()
    const res = await fetch(url, { signal: controller.signal })
    if (!res.ok) throw new Error(`Jamendo API error: ${res.status}`)

    const data = await res.json() as { results?: JamendoTrack[]; headers?: { results_count?: number } }
    const results = data.results || []

    const tracks: MusicTrack[] = results.map(r => ({
      id: `jamendo:${r.id}`,
      title: r.name || 'Unknown',
      artist: r.artist_name || 'Unknown',
      album: r.album_name || undefined,
      duration: Math.round(Number(r.duration) || 0),
      coverUrl: r.image || r.album_image || undefined,
      streamUrl: r.audio || r.audiodownload || '',
      source: 'Jamendo',
    })).filter(t => t.streamUrl)

    return {
      tracks,
      total: data.headers?.results_count || tracks.length,
      source: 'jamendo',
      query,
    }
  },
}

const INVIDIOUS_INSTANCES = [
  'https://inv.nadeko.net',
  'https://yewtu.be',
  'https://vid.puffyan.us',
  'https://invidious.privacyredirect.com',
]

async function fetchInvidious(path: string): Promise<unknown> {
  const instances = [...INVIDIOUS_INSTANCES].sort(() => Math.random() - 0.5)

  for (const base of instances) {
    try {
      const controller = withTimeout()
      const res = await fetch(`${base}${path}`, {
        signal: controller.signal,
        headers: { Accept: 'application/json' },
      })
      if (res.ok) return await res.json()
    } catch {
      continue
    }
  }

  throw new Error('All Invidious instances unavailable')
}

const invidiousSource: MusicSource = {
  id: 'invidious',
  name: 'YouTube (Invidious)',

  isAvailable: () => true,

  async search(query: string, limit = 15): Promise<SearchResult> {
    const data = await fetchInvidious(`/api/v1/search?q=${encodeURIComponent(query)}&type=video&page=1`)
    const items = Array.isArray(data) ? data as InvidiousVideo[] : []
    const tracks: MusicTrack[] = items
      .filter(i => i.type === 'video' && i.videoId && Number(i.lengthSeconds) > 0)
      .slice(0, limit)
      .map(i => ({
        id: `youtube:${i.videoId}`,
        title: i.title || 'Unknown',
        artist: i.author || 'Unknown',
        album: undefined,
        duration: Number(i.lengthSeconds) || 0,
        coverUrl: i.videoThumbnails?.[2]?.url || i.videoThumbnails?.[0]?.url || undefined,
        streamUrl: '',
        source: 'YouTube',
      }))

    return {
      tracks,
      total: tracks.length,
      source: 'invidious',
      query,
    }
  },

  async getStreamUrl(trackId: string): Promise<string> {
    const videoId = trackId.replace('youtube:', '')
    const data = await fetchInvidious(`/api/v1/videos/${videoId}`) as { adaptiveFormats?: InvidiousFormat[] }
    const adaptiveFormats = data.adaptiveFormats || []
    const audioFormat = adaptiveFormats.find(f => f.type?.startsWith('audio/') && f.url)
    if (audioFormat?.url) return audioFormat.url

    const anyFormat = adaptiveFormats.find(f => f.url)
    if (anyFormat?.url) return anyFormat.url

    throw new Error('Could not resolve stream URL')
  },
}

const fallbackSource: MusicSource = {
  id: 'demo',
  name: 'Demo',
  isAvailable: () => true,
  async search(query: string, limit = 8): Promise<SearchResult> {
    const q = query.trim().toLowerCase()
    const filtered = FALLBACK_TRACKS.filter(track =>
      `${track.title} ${track.artist}`.toLowerCase().includes(q)
    )
    const tracks = (filtered.length > 0 ? filtered : FALLBACK_TRACKS).slice(0, limit)
    return { tracks, total: tracks.length, source: 'demo', query }
  },
}

const _sources: Record<string, MusicSource> = {
  itunes: iTunesSource,
  jamendo: jamendoSource,
  invidious: invidiousSource,
  demo: fallbackSource,
}

export function getAllSources(): MusicSource[] {
  return Object.values(_sources).filter(s => s.isAvailable())
}

export function getSource(id: string): MusicSource | undefined {
  return _sources[id]
}

export function getDefaultSource(): MusicSource {
  return _sources.itunes || _sources.jamendo || _sources.invidious || _sources.demo
}

export async function searchAllSources(
  query: string,
  limit = 20,
): Promise<SearchResult> {
  const sources = getAllSources().filter(s => s.id !== 'demo')
  const remoteLimit = Math.max(4, Math.ceil(limit / Math.max(1, sources.length)))
  const results = await Promise.all(sources.map(s =>
    s.search(query, remoteLimit).catch(() => ({
      tracks: [] as MusicTrack[],
      total: 0,
      source: s.id,
      query,
    }))
  ))

  const remoteTracks = results.flatMap(r => r.tracks)
  const fallback = remoteTracks.length === 0 ? await fallbackSource.search(query, limit) : null
  const allTracks = fallback ? fallback.tracks : remoteTracks

  const seen = new Set<string>()
  const unique = allTracks.filter(t => {
    const key = `${t.title}|${t.artist}`.toLowerCase()
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })

  return {
    tracks: unique.slice(0, limit),
    total: unique.length,
    source: fallback ? 'demo' : 'all',
    query,
  }
}

export async function resolveStreamUrl(track: MusicTrack): Promise<string> {
  if (track.streamUrl) return track.streamUrl

  const rawSource = track.id.includes(':') ? track.id.split(':')[0] : ''
  const sourceMap: Record<string, string> = { youtube: 'invidious' }
  const sourceId = sourceMap[rawSource] || rawSource

  const source = _sources[sourceId]
  if (source?.getStreamUrl) {
    try {
      return await source.getStreamUrl(track.id)
    } catch {
      throw new Error(`Не удалось получить поток для "${track.title}"`)
    }
  }

  throw new Error(`Для "${track.title}" нет ссылки на воспроизведение`)
}
