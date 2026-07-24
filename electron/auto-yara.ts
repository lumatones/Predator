/**
 * Predator Auto-YARA — самообучающийся движок сигнатур
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

// ── Types ──────────────────────────────────────

export interface AutoRule {
  id: string
  sourceFile: string
  sourceHash: string
  strings: string[]
  createdAt: number
  matchCount: number
  falsePositiveCount: number
  weight: number // 0.0–1.0, растёт с попаданиями, падает с FP
  risk: 'high' | 'medium'
}

interface LearnOptions {
  minRiskScore: number
  maxStringsPerRule: number
  similarityThreshold: number
  xorKeys: number[]
}

// ── Config ─────────────────────────────────────

const RULES_PATH = path.join(os.homedir(), 'AppData', 'Roaming', 'Predator', 'auto-rules.json')

const DEFAULT_OPTIONS: LearnOptions = {
  minRiskScore: 70,
  maxStringsPerRule: 12,
  similarityThreshold: 0.65,
  xorKeys: [0x13, 0x55, 0xAA, 0xFF, 0x69, 0x42, 0x7F, 0x20, 0x77, 0x88],
}

// Системные/библиотечные строки, которые НЕ интересны
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

// ── Persistence ────────────────────────────────

function ensureDir() {
  const dir = path.dirname(RULES_PATH)
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
}

function loadRules(): AutoRule[] {
  ensureDir()
  try {
    return JSON.parse(fs.readFileSync(RULES_PATH, 'utf-8'))
  } catch {
    return []
  }
}

function saveRules(rules: AutoRule[]) {
  ensureDir()
  fs.writeFileSync(RULES_PATH, JSON.stringify(rules, null, 2))
}

// ── String extraction ──────────────────────────

/** Извлечь ASCII-строки из буфера */
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

/** XOR-decode с популярными ключами и извлечь строки */
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

/** Извлечь все интересные строки из файла (включая XOR) */
export function extractUniqueStrings(filepath: string): string[] {
  const all = new Set<string>()
  try {
    const buf = fs.readFileSync(filepath)
    for (const s of extractAscii(buf)) if (isValidString(s)) all.add(s)
    for (const key of DEFAULT_OPTIONS.xorKeys) {
      for (const s of extractXorStrings(buf, key)) if (isValidString(s)) all.add(`[xor${key.toString(16)}]${s}`)
    }
  } catch { /* skip */ }
  return Array.from(all).slice(0, 50)
}

// ── Similarity ─────────────────────────────────

/** Jaccard similarity двух массивов строк */
function jaccard(a: string[], b: string[]): number {
  const setA = new Set(a)
  const setB = new Set(b)
  const inter = new Set([...setA].filter(x => setB.has(x)))
  const union = new Set([...setA, ...setB])
  return union.size === 0 ? 0 : inter.size / union.size
}

function findSimilarRule(rules: AutoRule[], strings: string[]): AutoRule | null {
  for (const rule of rules) {
    if (jaccard(rule.strings, strings) >= DEFAULT_OPTIONS.similarityThreshold) {
      return rule
    }
  }
  return null
}

// ── Core: learn & detect ───────────────────────

/** Создать авто-правило из подозрительного файла */
export function learnFromFile(filepath: string, riskScore: number, fileHash?: string): AutoRule | null {
  if (riskScore < DEFAULT_OPTIONS.minRiskScore) return null

  const strings = extractUniqueStrings(filepath)
  if (strings.length < 4) return null

  const rules = loadRules()
  const existing = findSimilarRule(rules, strings)
  if (existing) {
    existing.matchCount++
    existing.weight = Math.min(1.0, existing.weight + 0.05)
    saveRules(rules)
    return null
  }

  const hash = fileHash || crypto.createHash('sha256').update(fs.readFileSync(filepath)).digest('hex')

  const rule: AutoRule = {
    id: crypto.randomUUID(),
    sourceFile: path.basename(filepath),
    sourceHash: hash,
    strings: strings.slice(0, DEFAULT_OPTIONS.maxStringsPerRule),
    createdAt: Date.now(),
    matchCount: 1,
    falsePositiveCount: 0,
    weight: 0.5,
    risk: riskScore > 85 ? 'high' : 'medium',
  }

  rules.push(rule)
  saveRules(rules)
  return rule
}

/** Проверить файл по авто-правилам */
export function checkAutoRules(filepath: string): { matched: boolean; rules: string[]; score: number } {
  const rules = loadRules()
  if (rules.length === 0) return { matched: false, rules: [], score: 0 }

  const fileStrings = new Set(extractUniqueStrings(filepath))
  if (fileStrings.size === 0) return { matched: false, rules: [], score: 0 }

  const hits: { id: string; hitCount: number; ruleLen: number; weight: number }[] = []

  for (const rule of rules) {
    if (rule.weight < 0.2) continue

    let hitCount = 0
    for (const s of rule.strings) {
      if (fileStrings.has(s)) hitCount++
    }

    const coverage = hitCount / rule.strings.length
    if (coverage >= 0.5 && hitCount >= 2) {
      hits.push({ id: rule.id, hitCount, ruleLen: rule.strings.length, weight: rule.weight })
      rule.matchCount++
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

/** Пользователь отметил ложное срабатывание — ослабить правила */
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

/** Экспорт правил в YARA-подобный формат */
export function exportRulesToYara(): string {
  const rules = loadRules().filter(r => r.weight > 0.4)
  let out = '/* Predator Auto-Generated YARA */\n\n'
  for (const r of rules) {
    out += `rule auto_${r.id.replace(/-/g, '_')} {\n`
    out += `  meta:\n    description = "Auto-learned from ${r.sourceFile}"\n`
    out += `    weight = ${r.weight.toFixed(2)}\n`
    out += `  strings:\n`
    r.strings.forEach((s, i) => {
      const clean = s.replace(/"/g, '\\"').replace(/\n/g, '\\n')
      out += `    $s${i} = "${clean}"\n`
    })
    out += `  condition:\n    ${Math.max(2, Math.ceil(r.strings.length * 0.6))} of them\n}\n\n`
  }
  return out
}

/** Очистка старых/мёртвых правил */
export function cleanupRules() {
  const rules = loadRules()
  const now = Date.now()
  const filtered = rules.filter(r => {
    const ageDays = (now - r.createdAt) / 86400000
    if (ageDays < 7) return true
    if (r.falsePositiveCount > r.matchCount * 0.3) return false
    return r.weight > 0.15
  })
  if (filtered.length !== rules.length) {
    saveRules(filtered)
  }
}

/** Проверить набор строк по авто-правилам (без чтения файла — для дампа памяти) */
export function checkAutoRulesOnStrings(strings: string[]): { matched: boolean; score: number } {
  try {
    if (!fs.existsSync(RULES_PATH)) return { matched: false, score: 0 }
    const rules = JSON.parse(fs.readFileSync(RULES_PATH, 'utf-8')) as AutoRule[]

    let totalScore = 0
    let matchedAny = false
    const fileSet = new Set(strings.map(s => s.toLowerCase()))

    for (const rule of rules) {
      if ((rule.weight || 0.5) < 0.2) continue
      let hits = 0
      for (const s of rule.strings) {
        if (fileSet.has(s.toLowerCase())) hits++
      }
      const cov = hits / rule.strings.length
      if (cov >= 0.5 && hits >= 2) {
        matchedAny = true
        totalScore += cov * (rule.weight || 0.5) * 100
      }
    }
    return { matched: matchedAny, score: Math.min(totalScore, 100) }
  } catch {
    return { matched: false, score: 0 }
  }
}
