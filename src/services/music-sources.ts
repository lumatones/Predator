/**
 * Predator — Music Sources
 *
 * Pluggable music providers that implement the MusicSource interface.
 *
 * v1 Sources:
 *   - Jamendo (free API, direct MP3 streams, no auth for basic tier)
 *   - YouTube (via Invidious API — no API key needed)
 *
 * Architecture: Add new sources by implementing the MusicSource interface
 * and registering them in getAllSources().
 */

import type { MusicSource, SearchResult, MusicTrack } from '../types/music'

// ═══════════════════════════════════════════════════
// JAMENDO SOURCE
// ═══════════════════════════════════════════════════
//
// Jamendo is a free music platform with a public API.
// Free tier: 3 requests/second, no authentication needed for basic search.
// Base URL: https://api.jamendo.com/v3.0
//
// To get your own client_id: https://developer.jamendo.com/v3.0 (free registration)

const JAMENDO_CLIENT_ID = '9d0e6e8c' // Public demo client_id

const jamendoSource: MusicSource = {
  id: 'jamendo',
  name: 'Jamendo',

  isAvailable: () => true,

  async search(query: string, limit = 15): Promise<SearchResult> {
    const url = `https://api.jamendo.com/v3.0/tracks/?client_id=${JAMENDO_CLIENT_ID}&format=json&search=${encodeURIComponent(query)}&limit=${limit}&include=musicinfo&groupby=artist_id`

    const res = await fetch(url)
    if (!res.ok) throw new Error(`Jamendo API error: ${res.status}`)

    const data = await res.json()
    const results = data.results || []

    const tracks: MusicTrack[] = results.map((r: any) => ({
      id: `jamendo:${r.id}`,
      title: r.name || 'Unknown',
      artist: r.artist_name || 'Unknown',
      album: r.album_name || undefined,
      duration: Math.round(r.duration || 0),
      coverUrl: r.image || r.album_image || undefined,
      streamUrl: r.audio || '',
      source: 'Jamendo',
    })).filter((t: MusicTrack) => t.streamUrl)

    return {
      tracks,
      total: data.headers?.results_count || tracks.length,
      source: 'jamendo',
      query,
    }
  },
}

// ═══════════════════════════════════════════════════
// INVIDIOUS SOURCE (YouTube without API key)
// ═══════════════════════════════════════════════════
//
// Uses Invidious API (privacy-respecting YouTube frontend).
// Multiple public instances available — picks one at random.
// No API key needed. Returns audio-only streams where available.

const INVIDIOUS_INSTANCES = [
  'https://invidious.slipfox.xyz',
  'https://inv.nadeko.net',
  'https://invidious.privacyredirect.com',
]

async function fetchInvidious(path: string): Promise<any> {
  // Try instances in random order
  const instances = [...INVIDIOUS_INSTANCES].sort(() => Math.random() - 0.5)

  for (const base of instances) {
    try {
      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), 5000)

      const res = await fetch(`${base}${path}`, {
        signal: controller.signal,
        headers: { 'Accept': 'application/json' },
      })
      clearTimeout(timeout)

      if (res.ok) return await res.json()
    } catch {
      // Try next instance
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
    try {
      const data = await fetchInvidious(
        `/api/v1/search?q=${encodeURIComponent(query)}&type=video&page=1`
      )

      const items: any[] = data || []
      const tracks: MusicTrack[] = items
        .filter((i: any) => i.type === 'video' && i.lengthSeconds > 0)
        .slice(0, limit)
        .map((i: any) => ({
          id: `youtube:${i.videoId}`,
          title: i.title || 'Unknown',
          artist: i.author || 'Unknown',
          album: undefined,
          duration: i.lengthSeconds || 0,
          coverUrl: i.videoThumbnails?.[2]?.url || i.videoThumbnails?.[0]?.url || undefined,
          // Invidious provides audio-only streams via /latest_version
          streamUrl: '', // Will be resolved on play
          source: 'YouTube',
        }))

      return {
        tracks,
        total: tracks.length,
        source: 'invidious',
        query,
      }
    } catch {
      // Invidious unavailable — return empty
      return { tracks: [], total: 0, source: 'invidious', query }
    }
  },

  async getStreamUrl(trackId: string): Promise<string> {
    // Extract YouTube video ID from our compound ID
    const videoId = trackId.replace('youtube:', '')

    // Try to get audio-only stream from Invidious
    try {
      const data = await fetchInvidious(`/api/v1/videos/${videoId}`)

      // Look for audio-only format
      const adaptiveFormats = data.adaptiveFormats || []
      const audioFormat = adaptiveFormats.find(
        (f: any) => f.type?.startsWith('audio/') && f.url
      )
      if (audioFormat?.url) return audioFormat.url

      // Fallback: any format with a URL
      const anyFormat = adaptiveFormats.find((f: any) => f.url)
      if (anyFormat?.url) return anyFormat.url
    } catch {
      // stream URL not available
    }

    throw new Error('Could not resolve stream URL')
  },
}

// ═══════════════════════════════════════════════════
// SOURCE REGISTRY
// ═══════════════════════════════════════════════════

const _sources: Record<string, MusicSource> = {
  jamendo: jamendoSource,
  invidious: invidiousSource,
}

/** Get all registered music sources */
export function getAllSources(): MusicSource[] {
  return Object.values(_sources).filter(s => s.isAvailable())
}

/** Get a specific source by ID */
export function getSource(id: string): MusicSource | undefined {
  return _sources[id]
}

/** Get the default source */
export function getDefaultSource(): MusicSource {
  return _sources['jamendo'] || _sources['invidious']
}

/**
 * Search across ALL sources and merge results.
 * Each source is queried independently; results are interleaved.
 */
export async function searchAllSources(
  query: string,
  limit = 20,
): Promise<SearchResult> {
  const sources = getAllSources()
  const promises = sources.map(s =>
    s.search(query, Math.ceil(limit / sources.length)).catch(() => ({
      tracks: [] as MusicTrack[],
      total: 0,
      source: s.id,
      query,
    }))
  )

  const results = await Promise.all(promises)
  const allTracks = results.flatMap(r => r.tracks)

  // Deduplicate by title+artist and limit
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
    source: 'all',
    query,
  }
}

/**
 * Resolve a stream URL for a track.
 *
 * Some sources (like Invidious/YouTube) don't provide the stream URL
 * in search results — it must be resolved when the user clicks play.
 */
export async function resolveStreamUrl(track: MusicTrack): Promise<string> {
  // If we already have a stream URL, use it
  if (track.streamUrl) return track.streamUrl

  // Determine source from compound ID (e.g., 'youtube:abc123' → 'invidious')
  const rawSource = track.id.includes(':') ? track.id.split(':')[0] : ''
  // Map external IDs to our internal source IDs
  const sourceMap: Record<string, string> = { youtube: 'invidious' }
  const sourceId = sourceMap[rawSource] || rawSource

  const source = _sources[sourceId]
  if (source?.getStreamUrl) {
    try {
      return await source.getStreamUrl(track.id)
    } catch {
      throw new Error(`Could not resolve stream for "${track.title}"`)
    }
  }

  throw new Error(`No stream URL available for "${track.title}"`)
}
