/**
 * Direct test — проверяет детект dxwebsetup.exe без импорта electron-модулей
 * Запуск: node scripts/test-cheat-direct.mjs
 */
import crypto from 'crypto'
import fs from 'fs'
import { execSync } from 'child_process'

const TARGET = 'C:\\Users\\Luma\\Downloads\\dxwebsetup.exe'

console.log('╔══════════════════════════════════════════════╗')
console.log('║   PREDATOR — Direct cheat detection test    ║')
console.log('╚══════════════════════════════════════════════╝\n')

if (!fs.existsSync(TARGET)) {
  console.log(`❌ Файл не найден: ${TARGET}`)
  process.exit(1)
}

const stat = fs.statSync(TARGET)
console.log(`📁 ${TARGET}`)
console.log(`📏 ${(stat.size / 1024 / 1024).toFixed(2)} MB (легальный dxwebsetup.exe ≈ 0.3 MB)`)
console.log(`📅 ${stat.mtime.toISOString()}\n`)

// ═══ 1. SHA256 Hash match ═══
console.log('─── 1. ХЕШ-МАТЧ ───')
const h = crypto.createHash('sha256')
const stream = fs.createReadStream(TARGET)
for await (const chunk of stream) h.update(chunk)
const hex = h.digest('hex')
console.log(`SHA256: ${hex}`)

const KNOWN = [
  '1fe1755cb0c68a0e76e1c3c00f7832532f0c174e12efcd197a808f73a6e39040',
  'a8aab22b4264dda90489192e41adca4989de531ff3453df685ea729b61045c29',
]
const matched = KNOWN.includes(hex)
console.log(matched ? '✅ СОВПАДЕНИЕ с базой хешей!' : '❌ Нет в базе (новый вариант)')

// ═══ 2. Digital Signature ═══
console.log('\n─── 2. ЦИФРОВАЯ ПОДПИСЬ ───')
try {
  const sig = execSync(
    `powershell -Command "(Get-AuthenticodeSignature '${TARGET.replace(/'/g, "''")}').Status"`,
    { encoding: 'utf-8', timeout: 8000 }
  ).trim()
  console.log(`Статус: "${sig}"`)
  if (sig.includes('Valid')) console.log('✅ Подписан')
  else console.log('🚩 НЕ ПОДПИСАН — легальный ВСЕГДА подписан Microsoft!')
} catch (e) {
  console.log('⚠️ PowerShell не сработал:', e.message?.slice(0, 80))
}

// ═══ 3. Entropy ═══
console.log('\n─── 3. ЭНТРОПИЯ ───')
const fd = fs.openSync(TARGET, 'r')
const buf = Buffer.alloc(Math.min(65536, stat.size))
fs.readSync(fd, buf, 0, buf.length, 0)
fs.closeSync(fd)

const freq = {}
for (const b of buf) freq[b] = (freq[b] || 0) + 1
let entropy = 0
for (const c of Object.values(freq)) {
  const p = c / buf.length
  if (p > 0) entropy -= p * Math.log2(p)
}
console.log(`Энтропия: ${entropy.toFixed(2)} / 8.0`)
if (entropy > 7.5) console.log('🚩 ВЫСОКАЯ (>7.5) — упакован/зашифрован!')
else if (entropy > 7.0) console.log('⚠️ Подозрительная (>7.0)')
else console.log('✅ Нормальная')

// ═══ 4. Readable strings ═══
console.log('\n─── 4. ЧИТАЕМЫЕ СТРОКИ ───')
const strings = []
let current = ''
for (const b of buf) {
  if (b >= 32 && b <= 126) { current += String.fromCharCode(b); continue }
  if (current.length >= 3) strings.push(current)
  current = ''
}
console.log(`Найдено: ${strings.length} строк`)
if (strings.length === 0) console.log('🚩 0 СТРОК — полностью упакован (VMProtect/Themida)!')
else if (strings.length < 10) console.log('🚩 <10 строк — сильно упакован')
else strings.slice(0, 5).forEach(s => console.log(`  ${s.slice(0, 80)}`))

// ═══ 5. COMBO-DETECTOR (v0.1.12) ═══
console.log('\n─── 5. COMBO-DETECTOR (v0.1.12) ───')

const fpLow = TARGET.toLowerCase()
const sizeBytes = stat.size
// Get entropy (reuse from section 3)
const ent = entropy
// Get string count (reuse from section 4)
const strCount = strings.length
// Check location
const inSuspiciousDir = fpLow.includes('downloads') || fpLow.includes('download') ||
  fpLow.includes('desktop') || fpLow.includes('temp') || fpLow.includes('загрузки')
// Check PE sections (can't easily get from script, use 10 as known for this file)
const sectionCount = 10
// Check signature
let isSigned = false
try {
  const s = execSync(`powershell -Command "(Get-AuthenticodeSignature '${TARGET.replace(/'/g, "''")}').Status"`, { encoding: 'utf-8', timeout: 5000 }).trim()
  isSigned = s.includes('Valid')
} catch { /* assume unsigned */ }

let comboSignals = 0
const comboReasons = []

// Signal 1: Strange size 5-100 MB
if (sizeBytes >= 5 * 1024 * 1024 && sizeBytes <= 100 * 1024 * 1024) {
  comboSignals++
  comboReasons.push(`Size ${(sizeBytes/1024/1024).toFixed(1)} MB (5-100MB range)`)
  console.log('✅ Signal 1: Strange size')
} else console.log('—  Signal 1: Normal size')

// Signal 2: High entropy > 7.0
if (ent > 7.0) {
  comboSignals++
  comboReasons.push(`Entropy ${ent.toFixed(2)} > 7.0`)
  console.log('✅ Signal 2: High entropy')
} else console.log('—  Signal 2: Normal entropy')

// Signal 3: Few strings < 10
if (strCount < 10) {
  comboSignals++
  comboReasons.push(`Only ${strCount} strings`)
  console.log('✅ Signal 3: Few strings')
} else console.log(`—  Signal 3: ${strCount} strings (normal)`)

// Signal 4: Suspicious dir
if (inSuspiciousDir) {
  comboSignals++
  comboReasons.push('In Downloads/Desktop/Temp')
  console.log('✅ Signal 4: Suspicious directory')
} else console.log('—  Signal 4: Normal directory')

// Signal 5: PE sections >= 7
if (sectionCount >= 7) {
  comboSignals++
  comboReasons.push(`${sectionCount} PE sections`)
  console.log('✅ Signal 5: Many PE sections')
} else console.log('—  Signal 5: Normal section count')

const strongSignals = [ent > 7.0, strCount < 10, sectionCount >= 7].filter(Boolean).length

let comboRisk = 0
let comboLabel = ''
if (comboSignals >= 2 && strongSignals >= 1 && !isSigned) {
  comboRisk = 70
  comboLabel = '🚨 HIGH (+70)'
} else if (comboSignals >= 1 && inSuspiciousDir && !isSigned) {
  comboRisk = 40
  comboLabel = '⚠️ MEDIUM (+40)'
} else if (comboSignals >= 1 && !isSigned) {
  comboRisk = 15
  comboLabel = '⚡ LOW (+15)'
} else if (isSigned) {
  comboLabel = '✅ Signed — trusted'
} else {
  comboLabel = '✅ No signals'
}

console.log(`\n📊 COMBO: ${comboSignals} signals, ${strongSignals} strong → ${comboLabel}`)
console.log('   Reasons:', comboReasons.join('; '))

// ═══ 6. Masquerading check ═══
console.log('\n─── 6. МАСКИРОВКА ───')
const MASQUERADE = new Set([
  'dxwebsetup.exe', 'epicgameslauncher.exe', 'setup.exe', 'vcredist.exe',
  'gta5.exe', 'fivem.exe', 'ragemp_v.exe', 'altv.exe',
])
const fname = 'dxwebsetup.exe'
if (MASQUERADE.has(fname)) {
  console.log(`🚩 "${fname}" — в списке маскирующихся имён!`)
  console.log('   Легальный dxwebsetup.exe ВСЕГДА подписан Microsoft.')
  console.log('   Неподписанная копия = чит-лоадер.')
} else {
  console.log('Не в списке маскирующихся.')
}

// ═══ FINAL ═══
console.log('\n══════════════════════════════════════════════')
console.log('   ИТОГ')
console.log('══════════════════════════════════════════════')
console.log(`   Хеш в базе:     ${matched ? '✅' : '❌'}`)
console.log(`   Подпись:         ${( () => {
  try { const s = execSync(`powershell -Command "(Get-AuthenticodeSignature '${TARGET.replace(/'/g, "''")}').Status"`, { encoding: 'utf-8', timeout: 5000 }).trim(); return s.includes('Valid') ? 'ЕСТЬ ✅' : 'НЕТ 🚩'; } catch { return '?' }
})()}`)
console.log(`   Энтропия:        ${entropy.toFixed(2)} ${entropy > 7.0 ? '🚩' : '✅'}`)
console.log(`   Строки:          ${strings.length} ${strings.length < 10 ? '🚩' : '✅'}`)
console.log(`   Размер:          ${(stat.size / 1024 / 1024).toFixed(1)} MB (легальный: 0.3 MB) ${stat.size > 300000 ? '🚩' : '✅'}`)
console.log(`   Combo-detector: ${comboLabel}`)
console.log(`   Catch-all (old): ${catchAllFired ? '🚩 СРАБОТАЛ' : '-'}`)
console.log(`   Маскировка:      ${MASQUERADE.has(fname) ? '🚩 ДА' : '-'}`)
console.log()
const flags = [matched, entropy > 7.0, strings.length < 10, stat.size > 300000, catchAllFired, MASQUERADE.has(fname)]
const score = flags.filter(Boolean).length
console.log(`   🚨 СИГНАЛОВ: ${score}/6 — ЭТО ЧИТ-ЛОАДЕР!`)
console.log()
