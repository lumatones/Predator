/**
 * Predator Website — typed API client.
 *
 * Calls the backend through the Vite dev proxy (`/api` → `http://localhost:3001`).
 * All endpoints are defined in `server/src/routes/website.ts`.
 */

const BASE = '/api/website'
const TOKEN_KEY = 'predator_website_token'

// ── Types (mirror server/src/routes/website.ts responses) ──

export interface PlayerProfile {
  id: number
  display_name: string
  server_name: string | null
  risk_level: 'clean' | 'low' | 'medium' | 'high'
  total_scans: number
  cheat_traces: number
  last_scan_at: string | null
  created_at: string
}

export interface NewsArticle {
  id: number
  title: string
  excerpt: string | null
  content?: string | null
  tag: string | null
  tag_color: string | null
  created_at: string
}

export interface WebsiteStats {
  totalPlayers: number
  cleanPlayers: number
  flaggedPlayers: number
  totalServers: number
  totalScans: number
}

export interface WebsiteUser {
  id: number
  email: string | null
  display_name: string
  avatar_url: string | null
  subscription: 'free' | 'pro'
  created_at: string
  socials: LinkedSocial[]
  servers: LinkedServer[]
}

export interface LinkedSocial {
  id: number
  provider: 'discord' | 'telegram'
  provider_name: string | null
  avatar_url: string | null
  notify_checks: boolean | number
  notify_results: boolean | number
}

export interface LinkedServer {
  id: number
  user_id: number
  discord_guild_id: string
  guild_name: string
  guild_icon: string | null
  is_active: boolean | number
  checks_this_week: number
  created_at: string
}

export interface CheckRequest {
  id: number
  server_id: number | null
  requester_name: string
  player_name: string
  player_steam_id: string | null
  status: 'pending' | 'scanning' | 'completed' | 'cancelled'
  risk_level: 'clean' | 'low' | 'medium' | 'high' | null
  result_summary: string | null
  guild_name?: string | null
  created_at: string
  completed_at: string | null
}

export interface Notification {
  id: number
  type: string
  title: string
  body: string | null
  is_read: boolean | number
  link: string | null
  created_at: string
}

// ── Token helpers ──

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string | null): void {
  if (token) localStorage.setItem(TOKEN_KEY, token)
  else localStorage.removeItem(TOKEN_KEY)
}

// ── Fetch wrapper ──

interface ApiErrorBody {
  error?: { code?: string; message?: string }
}

export class ApiError extends Error {
  readonly status: number
  readonly code?: string

  constructor(message: string, status: number, code?: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getToken()
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init?.headers || {}),
    },
  })

  let body: T & ApiErrorBody
  try {
    body = await res.json()
  } catch {
    throw new Error(`Сервер вернул ${res.status}`)
  }

  if (!res.ok || body?.error) {
    throw new ApiError(
      body?.error?.message || `Ошибка запроса (${res.status})`,
      res.status,
      body?.error?.code,
    )
  }
  return body
}

// ── Public endpoints ──

export function fetchStats(): Promise<WebsiteStats> {
  return request<WebsiteStats>('/stats')
}

export function fetchPlayers(params?: { search?: string; risk?: string; limit?: number }): Promise<{ players: PlayerProfile[]; total: number }> {
  const qs = new URLSearchParams()
  if (params?.search) qs.set('search', params.search)
  if (params?.risk && params.risk !== 'all') qs.set('risk', params.risk)
  qs.set('limit', String(params?.limit ?? 100))
  return request<{ players: PlayerProfile[]; total: number }>(`/players?${qs.toString()}`)
}

export function fetchNews(): Promise<NewsArticle[]> {
  return request<NewsArticle[]>('/news')
}

export function fetchNewsArticle(id: number): Promise<NewsArticle> {
  return request<NewsArticle>(`/news/${id}`)
}

// ── Auth ──

export interface LoginResponse {
  token: string
  user: Omit<WebsiteUser, 'socials' | 'servers'>
}

export async function login(email: string, password: string): Promise<LoginResponse> {
  const data = await request<LoginResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  })
  setToken(data.token)
  return data
}

export async function register(display_name: string, email: string, password: string): Promise<void> {
  await request<{ userId: number }>('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ email, password, display_name }),
  })
}

export function fetchMe(): Promise<WebsiteUser> {
  return request<WebsiteUser>('/auth/me')
}

// ── Authenticated endpoints ──

export function fetchCheckRequests(): Promise<CheckRequest[]> {
  return request<CheckRequest[]>('/check-requests')
}

export function fetchNotifications(): Promise<Notification[]> {
  return request<Notification[]>('/notifications')
}
