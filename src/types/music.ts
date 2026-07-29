/**
 * Predator — Music Player Types
 *
 * Pluggable music source architecture (inspired by Nuclear).
 * Sources implement the MusicSource interface — the player
 * doesn't care where the music comes from.
 */

// ── Track ──

export interface MusicTrack {
  /** Unique ID (source-specific, e.g. Jamendo track ID or YouTube video ID) */
  id: string
  /** Display title */
  title: string
  /** Artist name */
  artist: string
  /** Album name (optional) */
  album?: string
  /** Duration in seconds */
  duration: number
  /** Album art / cover URL */
  coverUrl?: string
  /** Direct audio stream URL */
  streamUrl: string
  /** Source name for display */
  source: string
}

// ── Playlist ──

export interface Playlist {
  id: string
  name: string
  tracks: MusicTrack[]
  createdAt: string
}

// ── Search ──

export interface SearchResult {
  tracks: MusicTrack[]
  total: number
  source: string
  query: string
}

// ── Music Source (pluggable provider) ──

export interface MusicSource {
  /** Unique source ID (e.g. 'jamendo', 'youtube', 'local') */
  id: string
  /** Display name */
  name: string
  /** Search for tracks */
  search(query: string, limit?: number): Promise<SearchResult>
  /** Get stream URL for a track (some sources need this extra step) */
  getStreamUrl?(trackId: string): Promise<string>
  /** Whether this source is currently available */
  isAvailable(): boolean
}

// ── Player State ──

export type PlayerStatus = 'idle' | 'playing' | 'paused' | 'loading'

export interface PlayerState {
  /** Current queue */
  queue: MusicTrack[]
  /** Current track index in queue (-1 = empty) */
  currentIndex: number
  /** Playback status */
  status: PlayerStatus
  /** Volume 0-1 */
  volume: number
  /** Whether shuffled */
  shuffled: boolean
  /** Whether repeating */
  repeat: boolean
  /** Current time in seconds */
  currentTime: number
  /** Duration of current track in seconds */
  duration: number
  /** Search query */
  searchQuery: string
  /** Search results */
  searchResults: SearchResult | null
  /** Whether search is in progress */
  searching: boolean
  /** Active source ID */
  activeSource: string
  /** Error message if any */
  error: string | null
}
