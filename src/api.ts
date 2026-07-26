// ── Config ──

// Priority:
//   1) VITE_API_URL env var (build-time)
//   2) Electron userData config (via initApiConfig)
//   3) localStorage fallback (browser dev)
//   4) http://localhost:3001
//
// Set production URL at build time:
//   VITE_API_URL=http://your-server:3001 npm run build

let _apiBase = 'http://5.164.42.189:3001'

function resolveApiBase(): string {
  if (import.meta.env.VITE_API_URL) return (import.meta.env.VITE_API_URL as string).replace(/\/$/, '')
  try {
    const stored = localStorage.getItem('predator_api_url')
    if (stored) return stored.replace(/\/$/, '')
  } catch { /* localStorage unavailable */ }
  return _apiBase
}

export function getApiBase(): string {
  return _apiBase
}

export function setApiBase(url: string): void {
  _apiBase = url.replace(/\/$/, '')
}

/** Load API URL from Electron config or env. Call once on app start. */
export async function initApiConfig(): Promise<string> {
  const api = window.electronAPI
  if (api?.getApiBase) {
    try {
      const url = await api.getApiBase()
      if (url) {
        setApiBase(url)
        return url
      }
    } catch { /* fallback below */ }
  }
  const resolved = resolveApiBase()
  setApiBase(resolved)
  return resolved
}

// ── Types ──

export interface TokenValidateResponse {
  valid: boolean
  token_id?: number
  error?: string
}

export interface TokenUseResponse {
  valid: boolean
  token_id?: number
  message?: string
  error?: string
}

export interface RequestAccessResponse {
  success: boolean
  request_id?: number
  message?: string
  error?: string
}

export interface RequestStatusResponse {
  id: number
  pc_username: string
  status: 'pending' | 'approved' | 'rejected'
  created_at: string
  error?: string
}

// ── Helpers ──

async function fetchApi<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${getApiBase()}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const data = await res.json()
  if (!res.ok) {
    if (typeof data.valid === 'boolean') return data as T
    throw new Error(data.error || `HTTP ${res.status}`)
  }
  return data as T
}

async function fetchGet<T>(path: string): Promise<T> {
  const res = await fetch(`${getApiBase()}${path}`)
  const data = await res.json()
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
  return data as T
}

// ── Auth API ──

export async function validateToken(token: string): Promise<TokenValidateResponse> {
  return fetchApi<TokenValidateResponse>('/api/auth/token', { token })
}

export async function useToken(token: string, pc_username: string): Promise<TokenUseResponse> {
  return fetchApi<TokenUseResponse>('/api/auth/token/use', { token, pc_username })
}

export async function requestAccess(pc_username: string): Promise<RequestAccessResponse> {
  return fetchApi<RequestAccessResponse>('/api/auth/request', { pc_username })
}

export async function checkRequestStatus(id: number): Promise<RequestStatusResponse> {
  return fetchGet<RequestStatusResponse>(`/api/auth/status/${id}`)
}

// ── Scan Submission API ──

export interface SubmitScanRequest {
  token_id?: number
  pc_username: string
  mode: string
  total_scanned: number
  suspicious_files: number
  high_risk_count: number
  scan_time_ms: number
  results: Array<{ path: string; fileName: string; type: string; risk: string; matches: string[] }>
}

export interface SubmitScanResponse {
  success: boolean
  message: string
}

export async function submitScan(data: SubmitScanRequest): Promise<SubmitScanResponse> {
  return fetchApi<SubmitScanResponse>('/api/auth/submit-scan', data)
}

// ── Cloud Hash Submission API ──

export interface SuspectHash {
  sha256: string
  file_name?: string
  file_size?: number
  risk_score?: number
}

export interface SubmitHashesResponse {
  success: boolean
  inserted: number
  total: number
}

export async function submitHashes(hashes: SuspectHash[], pc_username?: string, token_id?: number): Promise<SubmitHashesResponse> {
  return fetchApi<SubmitHashesResponse>('/api/auth/submit-hashes', {
    hashes,
    pc_username,
    token_id,
  })
}

export interface CloudHash {
  sha256: string
  file_name: string
  file_size: number
  added_at: string
}

export interface FetchHashesResponse {
  count: number
  hashes: CloudHash[]
}

export async function fetchCheatHashes(after?: string): Promise<FetchHashesResponse> {
  const q = after ? `?after=${after}` : ''
  return fetchGet<FetchHashesResponse>(`/api/auth/fetch-hashes${q}`)
}
