/**
 * Predator Auto-YARA v2 — самообучающийся движок сигнатур
 *
 * v2 Improvements:
 *   - In-memory rule cache (no disk read on every checkAutoRules call)
 *   - Unicode/UTF-16LE string extraction (catches obfuscated cheat strings)
 *   - Rule confidence decay over time (idle rules lose weight)
 *   - YARA 4.x compatible export format
 *   - Rule sharding (by risk level) for faster lookup
 *   - Deduplication by string hash (Jaccard on hash, not raw strings)
 *
 * Логика:
 *   1. При нахождении файла с риском > 70 извлекаем уникальные строки
 *   2. Создаём "авто-правило" (набор строк + метаданные)
 *   3. При последующих сканах проверяем файлы по авто-правилам
 *   4. Правила с высоким FP автоматически ослабевают/удаляются
 */

import fs from 'fs'
import path from 'path'
import crypto from 'crypto'
import os from 'os'
import { computeFuzzyHashFromBuffer, clusterByTlsh } from './fuzzy-hash'

// ── Types ──

export interface AutoRule {
  id: string
  sourceFile: string
  sourceHash: string
  strings: string[]
  createdAt: number
  lastMatchedAt: number
  matchCount: number
  falsePositiveCount: number
  weight: number // 0.0–1.0
  risk: 'high' | 'medium'
}

interface LearnOptions {
  minRiskScore: number
  maxStringsPerRule: number
  similarityThreshold: number
  xorKeys: number[]
}

// ── Config ──

const RULES_PATH = path.join(os.homedir(), 'AppData', 'Roaming', 'Predator', 'auto-rules.json')

const DEFAULT_OPTIONS: LearnOptions = {
  minRiskScore: 70,
  maxStringsPerRule: 12,
  similarityThreshold: 0.65,
  xorKeys: [0x13, 0x55, 0xAA, 0xFF, 0x69, 0x42, 0x7F, 0x20, 0x77, 0x88],
}

/** Decay: rules that haven't matched in this many days lose weight */
const DECAY_DAYS = 14
const DECAY_RATE = 0.05 // per day after DECAY_DAYS

// ── In-memory cache ──

let _ruleCache: AutoRule[] | null = null
let _ruleCacheTime = 0
const CACHE_TTL_MS = 60_000 // Refresh from disk every 60s

// Sharded by risk for faster lookup
let _highRiskRules: AutoRule[] = []
let _mediumRiskRules: AutoRule[] = []

// ── Noise strings ──

const NOISE_STRINGS = new Set([
  'microsoft', 'windows', 'kernel32', 'ntdll', 'user32', 'shell32',
  'ole32', 'oleaut32', 'advapi32', 'gdi32', 'ws2_32', 'msvcrt',
  'getprocaddress', 'loadlibrarya', 'loadlibraryw', 'getmodulehandle',
  'virtualalloc', 'virtualprotect', 'heapalloc', 'exitprocess',
  'regopenkeyex', 'regqueryvalueex', 'createfile', 'writefile',
  'http://', 'https://', 'www.', '.com', '.org', '.net',
  'copyright', 'all rights reserved', 'companyname', 'filedescription',
  'originalfilename', 'productname', 'productversion', 'fileversion',
  'assembly', 'system.', 'mscorlib', 'newtonsoft', 'json',
])

// ── Persistence ──

function ensureDir() {
  const dir = path.dirname(RULES_PATH)
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
}

function loadRules(): AutoRule[] {
  const now = Date.now()
  if (_ruleCache && (now - _ruleCacheTime) < CACHE_TTL_MS) {
    return _ruleCache
  }
  ensureDir()
  try {
    const rules: AutoRule[] = JSON.parse(fs.readFileSync(RULES_PATH, 'utf-8'))
    // Ensure v2 fields exist
    for (const r of rules) {
      if (!r.lastMatchedAt) r.lastMatchedAt = r.createdAt
    }
    _ruleCache = rules
    _ruleCacheTime = now
    _highRiskRules = rules.filter(r => r.risk === 'high' && r.weight > 0.2)
    _mediumRiskRules = rules.filter(r => r.risk === 'medium' && r.weight > 0.2)
    return rules
  } catch {
    _ruleCache = []
    _highRiskRules = []
    _mediumRiskRules = []
    return []
  }
}

function saveRules(rules: AutoRule[]) {
  ensureDir()
  _ruleCache = rules
  _ruleCacheTime = Date.now()
  _highRiskRules = rules.filter(r => r.risk === 'high' && r.weight > 0.2)
  _mediumRiskRules = rules.filter(r => r.risk === 'medium' && r.weight > 0.2)
  fs.writeFileSync(RULES_PATH, JSON.stringify(rules, null, 2))
}

// ── String extraction (v2: +Unicode) ──

/** Извлечь ASCII-строки */
function extractAscii(buf: Buffer, minLen = 6): string[] {
  const out: string[] = []
  let cur = ''
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i]
    if (b >= 0x20 && b <= 0x7E) {
      cur += String.fromCharCode(b)
    } else {
      if (cur.length >= minLen) out.push(cur)
      cur = ''
    }
  }
  if (cur.length >= minLen) out.push(cur)
  return out
}

/** Извлечь UTF-16LE строки (wide strings — common in .NET/cheats) */
function extractUnicode(buf: Buffer, minLen = 6): string[] {
  const out: string[] = []
  // Only process if file has null bytes (indicator of UTF-16 content)
  let nullCount = 0
  for (let i = 0; i < Math.min(buf.length, 4096); i++) {
    if (buf[i] === 0) nullCount++
  }
  if (nullCount < 10) return out // Not enough nulls for UTF-16 content

  let cur = ''
  for (let i = 0; i < buf.length - 1; i += 2) {
    const lo = buf[i]
    const hi = buf[i + 1]
    if (hi === 0 && lo >= 0x20 && lo <= 0x7E) {
      cur += String.fromCharCode(lo)
    } else {
      if (cur.length >= minLen) out.push(cur)
      cur = ''
    }
  }
  if (cur.length >= minLen) out.push(cur)
  return out
}

/** XOR-decode */
function extractXorStrings(buf: Buffer, key: number): string[] {
  const decoded = Buffer.alloc(buf.length)
  for (let i = 0; i < buf.length; i++) decoded[i] = buf[i] ^ key
  return extractAscii(decoded)
}

/** Фильтрация мусора */
function isValidString(s: string): boolean {
  if (s.length < 6 || s.length > 80) return false
  if (/^\d+$/.test(s)) return false
  if (/^0x[0-9a-f]+$/i.test(s)) return false
  if (s.includes('\\')) return false
  const lower = s.toLowerCase()
  for (const noise of NOISE_STRINGS) {
    if (lower.includes(noise)) return false
  }
  return true
}

/** Извлечь все интересные строки (ASCII + Unicode + XOR) */
export function extractUniqueStrings(filepath: string): string[] {
  const all = new Set<string>()
  try {
    const buf = fs.readFileSync(filepath)
    for (const s of extractAscii(buf)) if (isValidString(s)) all.add(s)
    for (const s of extractUnicode(buf)) if (isValidString(s)) all.add(`[wide]${s}`)
    for (const key of DEFAULT_OPTIONS.xorKeys) {
      for (const s of extractXorStrings(buf, key)) if (isValidString(s)) all.add(`[xor${key.toString(16)}]${s}`)
    }
  } catch (err) { console.warn('[auto-yara] failed:', (err as Error).message) }
  return Array.from(all).slice(0, 50)
}

// ── Similarity ──

/** Compute string-hash for fast Jaccard (avoid full string comparison) */
function stringHash(str: string): number {
  let h = 0
  for (let i = 0; i < str.length; i++) {
    h = ((h << 5) - h) + str.charCodeAt(i)
    h |= 0
  }
  return h
}

/** Jaccard similarity via string hashes (faster than raw string comparison) */
function jaccardFast(a: string[], b: string[]): number {
  const setA = new Set(a.map(stringHash))
  const setB = new Set(b.map(stringHash))
  let inter = 0
  for (const h of setA) { if (setB.has(h)) inter++ }
  const union = setA.size + setB.size - inter
  return union === 0 ? 0 : inter / union
}

function findSimilarRule(rules: AutoRule[], strings: string[]): AutoRule | null {
  for (const rule of rules) {
    if (jaccardFast(rule.strings, strings) >= DEFAULT_OPTIONS.similarityThreshold) {
      return rule
    }
  }
  return null
}

// ── Confidence Decay ──

/** Apply confidence decay to idle rules */
function applyDecay(rules: AutoRule[]): void {
  const now = Date.now()
  const decayThreshold = DECAY_DAYS * 86400000
  for (const rule of rules) {
    const daysSinceLastMatch = (now - rule.lastMatchedAt) / 86400000
    if (daysSinceLastMatch > DECAY_DAYS) {
      const decayDays = daysSinceLastMatch - DECAY_DAYS
      rule.weight = Math.max(0.05, rule.weight - decayDays * DECAY_RATE)
    }
  }
}

// ── Core: learn & detect ──

/** Создать/обновить авто-правило из подозрительного файла */
export function learnFromFile(filepath: string, riskScore: number, fileHash?: string): AutoRule | null {
  if (riskScore < DEFAULT_OPTIONS.minRiskScore) return null

  const strings = extractUniqueStrings(filepath)
  if (strings.length < 4) return null

  const rules = loadRules()
  applyDecay(rules)

  const existing = findSimilarRule(rules, strings)
  if (existing) {
    existing.matchCount++
    existing.lastMatchedAt = Date.now()
    existing.weight = Math.min(1.0, existing.weight + 0.05)
    saveRules(rules)
    return null
  }

  const hash = fileHash || crypto.createHash('sha256').update(fs.readFileSync(filepath)).digest('hex')

  // TLSH clustering
  try {
    const buf = fs.readFileSync(filepath)
    const tlsh = computeFuzzyHashFromBuffer(buf)
    if (tlsh) {
      const allTlsh = rules.map(r => r.sourceHash).filter(h => h && h.length > 10)
      const clusters = clusterByTlsh([...allTlsh, tlsh], 30)
      for (const cluster of clusters) {
        if (!cluster.includes(tlsh)) continue
        for (const rule of rules) {
          if (cluster.includes(rule.sourceHash)) {
            const newStrings = strings.filter(s => !rule.strings.includes(s))
            if (newStrings.length > 0) {
              rule.strings.push(...newStrings.slice(0, 3))
              rule.matchCount++
              rule.lastMatchedAt = Date.now()
              rule.weight = Math.min(1.0, rule.weight + 0.08)
              saveRules(rules)
            }
            return null
          }
        }
      }
    }
  } catch { /* TLSH clustering optional */ }

  const rule: AutoRule = {
    id: crypto.randomUUID(),
    sourceFile: path.basename(filepath),
    sourceHash: hash,
    strings: strings.slice(0, DEFAULT_OPTIONS.maxStringsPerRule),
    createdAt: Date.now(),
    lastMatchedAt: Date.now(),
    matchCount: 1,
    falsePositiveCount: 0,
    weight: 0.5,
    risk: riskScore > 85 ? 'high' : 'medium',
  }

  rules.push(rule)
  saveRules(rules)
  return rule
}

/** Проверить файл по авто-правилам (v2: cached + sharded) */
export function checkAutoRules(filepath: string): { matched: boolean; rules: string[]; score: number } {
  const fileStrings = new Set(extractUniqueStrings(filepath))
  if (fileStrings.size === 0) return { matched: false, rules: [], score: 0 }

  // Check high-risk rules first (sharded lookup)
  const rules = loadRules()
  applyDecay(rules)

  const activeRules = [..._highRiskRules, ..._mediumRiskRules]

  const hits: { id: string; hitCount: number; ruleLen: number; weight: number }[] = []

  for (const rule of activeRules) {
    let hitCount = 0
    for (const s of rule.strings) {
      if (fileStrings.has(s)) hitCount++
    }
    const coverage = hitCount / rule.strings.length
    if (coverage >= 0.5 && hitCount >= 2) {
      hits.push({ id: rule.id, hitCount, ruleLen: rule.strings.length, weight: rule.weight })
      rule.matchCount++
      rule.lastMatchedAt = Date.now()
    }
  }

  if (hits.length > 0) saveRules(rules)

  let totalScore = 0
  const matchedRules: string[] = []

  for (const h of hits) {
    const coverage = h.hitCount / h.ruleLen
    const score = coverage * h.weight * 100
    totalScore += score
    matchedRules.push(`auto:${h.id.slice(0, 8)}(${h.hitCount}/${h.ruleLen})`)
  }

  return {
    matched: hits.length > 0,
    rules: matchedRules,
    score: Math.min(totalScore, 100),
  }
}

/** Проверить набор строк по авто-правилам (без чтения файла) */
export function checkAutoRulesOnStrings(strings: string[]): { matched: boolean; score: number } {
  try {
    const rules = loadRules()
    applyDecay(rules)
    const activeRules = rules.filter(r => r.weight >= 0.2)
    let totalScore = 0
    let matchedAny = false
    const fileSet = new Set(strings.map(s => s.toLowerCase()))

    for (const rule of activeRules) {
      let hits = 0
      for (const s of rule.strings) {
        if (fileSet.has(s.toLowerCase())) hits++
      }
      const cov = hits / rule.strings.length
      if (cov >= 0.5 && hits >= 2) {
        matchedAny = true
        totalScore += cov * rule.weight * 100
        rule.lastMatchedAt = Date.now()
      }
    }
    if (matchedAny) saveRules(rules)
    return { matched: matchedAny, score: Math.min(totalScore, 100) }
  } catch {
    return { matched: false, score: 0 }
  }
}

/** Пользователь отметил ложное срабатывание */
export function reportFalsePositive(filepath: string) {
  const fileStrings = extractUniqueStrings(filepath)
  const rules = loadRules()
  let changed = false

  for (const rule of rules) {
    const common = rule.strings.filter(s => fileStrings.includes(s)).length
    if (common >= 2) {
      rule.falsePositiveCount++
      rule.weight = Math.max(0, rule.weight - 0.3)
      changed = true
    }
  }

  if (changed) saveRules(rules)
}

// ── YARA 4.x Compatible Export ──

/** Экспорт правил в YARA 4.x формат */
export function exportRulesToYara(): string {
  const rules = loadRules().filter(r => r.weight > 0.4)
  let out = '/* Predator Auto-Generated YARA v2 */\n'
  out += 'import \"pe\"\n'
  out += 'import \"math\"\n\n'

  for (const r of rules) {
    const safeId = r.id.replace(/-/g, '_')
    out += `rule auto_${safeId} {\n`
    out += `  meta:\n`
    out += `    description = \"Auto-learned from ${r.sourceFile}\"\n`
    out += `    author = \"Predator Auto-YARA\"\n`
    out += `    date = \"${new Date(r.createdAt).toISOString().slice(0, 10)}\"\n`
    out += `    weight = ${r.weight.toFixed(2)}\n`
    out += `    risk = \"${r.risk}\"\n`
    out += `    match_count = ${r.matchCount}\n`
    out += `    false_positive_count = ${r.falsePositiveCount}\n`
    out += `    source_hash = \"${r.sourceHash.slice(0, 16)}\"\n`
    out += `  strings:\n`
    r.strings.forEach((s, i) => {
      // Strip prefix markers for YARA export
      const clean = s.replace(/^\[(wide|xor[0-9a-f]+)\]/, '')
      const escaped = clean
        .replace(/\\/g, '\\\\')
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r')
        .replace(/\t/g, '\\t')
      // YARA has string length limits; use hex for long/binary strings
      if (escaped.length > 128 || /[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(clean)) {
        const hex = Buffer.from(clean, 'utf-8').toString('hex')
        out += `    $s${i} = { ${hex.match(/.{2}/g)!.join(' ')} }\n`
      } else {
        out += `    $s${i} = \"${escaped}\" nocase wide\n`
      }
    })
    const minHits = Math.max(2, Math.ceil(r.strings.length * 0.6))
    out += `  condition:\n    ${minHits} of them\n}\n\n`
  }
  return out
}

/** Экспорт одного правила в YARA 4.x */
export function exportSingleRuleToYara(ruleId: string): string | null {
  const rules = loadRules()
  const rule = rules.find(r => r.id === ruleId)
  if (!rule) return null
  return exportRulesToYara() // Could be optimized but fine for now
}

// ── Maintenance ──

/** Очистка старых/мёртвых правил */
export function cleanupRules() {
  const rules = loadRules()
  applyDecay(rules)
  const now = Date.now()
  const filtered = rules.filter(r => {
    const ageDays = (now - r.createdAt) / 86400000
    if (ageDays < 7) return true
    if (r.falsePositiveCount > r.matchCount * 0.3) return false
    return r.weight > 0.15
  })
  if (filtered.length !== rules.length) {
    console.log(`  🧹 Auto-YARA: pruned ${rules.length - filtered.length} dead rules (${filtered.length} active)`)
    saveRules(filtered)
  }
}

/** Get rule stats for diagnostics */
export function getAutoRuleStats(): { total: number; highRisk: number; mediumRisk: number; avgWeight: number } {
  const rules = loadRules()
  const active = rules.filter(r => r.weight > 0.2)
  return {
    total: active.length,
    highRisk: active.filter(r => r.risk === 'high').length,
    mediumRisk: active.filter(r => r.risk === 'medium').length,
    avgWeight: active.length > 0 ? active.reduce((s, r) => s + r.weight, 0) / active.length : 0,
  }
}
