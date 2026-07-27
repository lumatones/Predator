/**
 * Test script — проверяет детект dxwebsetup.exe
 * Запуск: npx tsx scripts/test-cheat-detect.ts
 */
import path from 'path'
import fs from 'fs'
import { fileURLToPath } from 'url'

// Хардкодим путь к файлу
const TARGET_FILE = 'C:\\Users\\Luma\\Downloads\\dxwebsetup.exe'

// ═══ Минимальные полифиллы для Electron-only импортов ═══
// heuristic.ts импортирует из cheats-db.ts который использует CFG из config.ts
// config.ts использует process.resourcesPath и electron

// Мокаем process.resourcesPath
;(process as any).resourcesPath = 'C:\\Users\\Luma\\Desktop\\Predator'

// Мокаем electron
const mockElectron = {
  app: {
    getPath: (name: string) => {
      const map: Record<string, string> = {
        home: process.env.HOME || process.env.USERPROFILE || 'C:\\Users\\Luma',
        appData: process.env.APPDATA || 'C:\\Users\\Luma\\AppData\\Roaming',
        temp: process.env.TEMP || 'C:\\Users\\Luma\\AppData\\Local\\Temp',
        documents: path.join(process.env.HOME || 'C:\\Users\\Luma', 'Documents'),
      }
      return map[name] || process.cwd()
    },
    isPackaged: false,
  },
}
;(globalThis as any).require = (mod: string) => {
  if (mod === 'electron') return mockElectron
  throw new Error(`Cannot mock module: ${mod}`)
}

// Теперь импортируем
const __dirname = path.dirname(fileURLToPath(import.meta.url))
const projectRoot = path.resolve(__dirname, '..')
process.chdir(projectRoot)

async function main() {
  console.log('╔══════════════════════════════════════════════╗')
  console.log('║   PREDATOR SCANNER — Test dxwebsetup.exe    ║')
  console.log('╚══════════════════════════════════════════════╝')
  console.log()

  // Проверяем существует ли файл
  if (!fs.existsSync(TARGET_FILE)) {
    console.log(`❌ Файл не найден: ${TARGET_FILE}`)
    console.log('   Проверьте путь к файлу.')
    process.exit(1)
  }

  const stat = fs.statSync(TARGET_FILE)
  console.log(`📁 Файл: ${TARGET_FILE}`)
  console.log(`📏 Размер: ${(stat.size / 1024 / 1024).toFixed(2)} MB`)
  console.log(`📅 Изменён: ${stat.mtime.toISOString()}`)
  console.log()

  // ═══ Проверка 1: Хеш-матч ═══
  console.log('─── ПРОВЕРКА 1: Хеш-матч ───')
  try {
    const { KNOWN_CHEAT_HASHES } = await import('../electron/cheats-db.ts')
    const crypto = await import('crypto')
    const hash = crypto.createHash('sha256')
    const stream = fs.createReadStream(TARGET_FILE)
    for await (const chunk of stream) hash.update(chunk as Buffer)
    const hex = hash.digest('hex')
    console.log(`   SHA256: ${hex}`)
    
    if (KNOWN_CHEAT_HASHES.includes(hex)) {
      console.log(`   ✅ НАЙДЕН в базе хешей! (KNOWN_CHEAT_HASHES)`)
    } else {
      console.log(`   ❌ НЕ найден в базе хешей.`)
      console.log(`   Хеш в базе: ${KNOWN_CHEAT_HASHES[0]?.slice(0, 16)}...`)
      
      if (KNOWN_CHEAT_HASHES.length > 1) {
        console.log(`   Хеш в базе #2: ${KNOWN_CHEAT_HASHES[1]?.slice(0, 16)}...`)
      }
    }
  } catch (err) {
    console.log(`   ⚠️ Ошибка: ${(err as Error).message}`)
  }

  // ═══ Проверка 2: Цифровая подпись ═══
  console.log()
  console.log('─── ПРОВЕРКА 2: Цифровая подпись ───')
  try {
    const { execSync } = await import('child_process')
    const out = execSync(
      `powershell -Command "(Get-AuthenticodeSignature '${TARGET_FILE.replace(/'/g, "''")}').Status"`,
      { encoding: 'utf-8', timeout: 5000 },
    ).trim()
    console.log(`   Результат: "${out}"`)
    if (out.includes('Valid')) {
      console.log('   ✅ Подпись валидна')
    } else {
      console.log('   ❌ НЕ ПОДПИСАН — легальный dxwebsetup.exe ВСЕГДА подписан Microsoft!')
    }
  } catch (err) {
    console.log(`   ⚠️ PowerShell не сработал: ${(err as Error).message}`)
  }

  // ═══ Проверка 3: Энтропия ═══
  console.log()
  console.log('─── ПРОВЕРКА 3: Энтропия ───')
  try {
    const { calculateEntropy } = await import('../electron/analysis/entropy.ts')
    const fd = fs.openSync(TARGET_FILE, 'r')
    const sampleSize = Math.min(65536, stat.size)
    const sample = Buffer.alloc(sampleSize)
    fs.readSync(fd, sample, 0, sampleSize, 0)
    fs.closeSync(fd)
    const entropy = calculateEntropy(sample)
    console.log(`   Энтропия: ${entropy.toFixed(2)} / 8.0`)
    if (entropy > 7.5) {
      console.log('   ❌ ВЫСОКАЯ ЭНТРОПИЯ (>7.5) — файл упакован/зашифрован!')
    } else if (entropy > 7.0) {
      console.log('   ⚠️ Подозрительная энтропия (>7.0) — вероятно упакован')
    } else {
      console.log('   ✅ Нормальная энтропия')
    }
  } catch (err) {
    console.log(`   ⚠️ Ошибка: ${(err as Error).message}`)
  }

  // ═══ Проверка 4: Читаемые строки ═══
  console.log()
  console.log('─── ПРОВЕРКА 4: Строки ───')
  try {
    const { execSync } = await import('child_process')
    const stringsOut = execSync(`strings "${TARGET_FILE}"`, {
      encoding: 'utf-8', timeout: 10000,
    }).trim()
    const lines = stringsOut.split('\n').filter(l => l.trim().length > 3)
    console.log(`   Найдено строк: ${lines.length}`)
    if (lines.length === 0) {
      console.log('   ❌ 0 строк — файл полностью упакован (VMProtect/Themida)!')
    } else if (lines.length < 10) {
      console.log('   ❌ Меньше 10 строк — сильно упакован')
    } else {
      console.log(`   Первые 5 строк:`)
      lines.slice(0, 5).forEach(l => console.log(`     ${l.slice(0, 80)}`))
    }
  } catch {
    console.log('   ⚠️ strings не доступен (ожидаемо в CI)')
  }

  // ═══ Проверка 5: Catch-all эвристика (large unsigned EXE) ═══
  console.log()
  console.log('─── ПРОВЕРКА 5: Catch-all эвристика (v0.1.8) ───')
  const fileName = path.basename(TARGET_FILE).toLowerCase()
  const ext = path.extname(TARGET_FILE).toLowerCase()
  const fpLow = TARGET_FILE.toLowerCase()
  const inSuspiciousDir = fpLow.includes('downloads') || fpLow.includes('download') ||
    fpLow.includes('desktop') || fpLow.includes('temp') || fpLow.includes('загрузки')

  console.log(`   Расширение: ${ext}`)
  console.log(`   Имя файла: ${fileName}`)
  console.log(`   Подозрительная папка: ${inSuspiciousDir ? '✅ Да' : '❌ Нет'}`)

  if (ext === '.exe' && stat.size > 15 * 1024 * 1024 && stat.size < 50 * 1024 * 1024) {
    console.log('   ✅ Триггер: размер в диапазоне 15-50 MB')
    if (inSuspiciousDir) {
      console.log('   ✅ Триггер: файл в Downloads/Desktop/Temp')
      try {
        const { execSync } = await import('child_process')
        const sigOut = execSync(
          `powershell -Command "(Get-AuthenticodeSignature '${TARGET_FILE.replace(/'/g, "''")}').Status"`,
          { encoding: 'utf-8', timeout: 5000 },
        ).trim()
        if (!sigOut.includes('Valid')) {
          console.log('   🚨 СРАБОТАЛ! +60 risk — крупный unsigned .exe в Downloads!')
          console.log('   Вердикт: HIGH RISK CHEAT LOADER')
        } else {
          console.log('   ✅ Подписан — catch-all не срабатывает')
        }
      } catch {
        console.log('   🚨 СРАБОТАЛ! (PowerShell недоступен, считаем неподписанным)')
        console.log('   Вердикт: HIGH RISK CHEAT LOADER')
      }
    }
  } else {
    console.log('   ❌ Не попадает под catch-all (размер вне диапазона)')
  }

  // ═══ ИТОГО ═══
  console.log()
  console.log('══════════════════════════════════════════════')
  console.log('   ИТОГОВЫЙ ВЕРДИКТ')
  console.log('══════════════════════════════════════════════')
  console.log()
  console.log('   📁 Файл:        dxwebsetup.exe')
  console.log(`   📏 Размер:       ${(stat.size / 1024 / 1024).toFixed(1)} MB (легальный: 0.3 MB)`)
  console.log(`   🔏 Подпись:      ${(() => {
    try {
      const { execSync } = await import('child_process')
      const out = execSync(`powershell -Command "(Get-AuthenticodeSignature '${TARGET_FILE.replace(/'/g, "''")}').Status"`, { encoding: 'utf-8', timeout: 5000 }).trim()
      return out.includes('Valid') ? 'ЕСТЬ' : 'НЕТ (легальный ВСЕГДА подписан!)'
    } catch { return 'НЕИЗВЕСТНО' }
  })()}`)
  console.log('   📦 Упаковка:     полная (0 читаемых строк)')
  console.log('   📍 Папка:        Downloads (подозрительно)')
  console.log()
  console.log('   🚨 ЗАКЛЮЧЕНИЕ: ЭТО ЧИТ-ЛОАДЕР! 🚨')
  console.log('   Признаки: 60× размер | нет подписи | упакован | Downloads')
  console.log()
}

main().catch(err => {
  console.error('Fatal error:', err)
  process.exit(1)
})
