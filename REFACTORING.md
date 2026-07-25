# Refactoring Plan — Predator

## Метрики текущего кода

| Метрика | Значение |
|---------|----------|
| Файлов electron/ | 14 |
| Всего строк electron/ | 6,646 |
| scanner.ts | 2,735 строк (41% всего кода) |
| Использований `any` | 26 (scanner.ts: 9) |
| module-level `const _` (глобальное состояние) | 8 в scanner.ts |
| `require()` CJS-стиль | 2 (`require('http')`) |

---

## 🔴 Priority 1 — scanner.ts (God Object)

### Проблема
`electron/scanner.ts` — 2,735 строк, содержит 41% всего кода electron/. В одном файле:
- Типы (ScanResult, ScanProgress, ScanResponse)
- Утилиты (calculateEntropy, scanStrings)
- Бизнес-логика (8 режимов сканирования)
- IPC handler-ы
- Cloud sync
- Dedup-логика
- Power Shell команды

### Решение: Разделить на модули

```
electron/
├── scanner/
│   ├── index.ts          # Только IPC handlers + dispatch
│   ├── types.ts          # ScanResult, ScanProgress, ScanResponse
│   ├── file-scan.ts      # runFileScan, scanFile, heuristicFileScan
│   ├── process-scan.ts   # scanRunningProcesses, scanRunningProcessesV2
│   ├── game-scan.ts      # getGamePids, scanGameModules, scanGameIntegrity
│   ├── browser-scan.ts   # scanBrowserHistory (перенести из scanner.ts)
│   ├── advanced-scan.ts  # rwx, dvm, behavior, api-hashing integration
│   ├── utils.ts          # calculateEntropy, scanStrings, matchKnownCheat
│   ├── dedup.ts          # _findingDedup, _sigCache, _peHeaderCache
│   └── paths.ts          # _PF, _PF86, _WR, _HOME, PROTECTED_PATHS
```

**Трудоёмкость**: 2-3 часа
**Риск**: Высокий (циклические зависимости между модулями)
**Совет**: Делать после добавления тестов

---

## 🟡 Priority 2 — Глобальное состояние (module-level mutables)

### Проблема
8 module-level переменных в scanner.ts, которые изменяются в рантайме:
- `_sigCache` — кеш подписей (Map<string, boolean>)
- `_findingDedup` — дедупликация (Set<string>)
- `_peHeaderCache` — кеш PE заголовков (Map)
- `_cheatNameCache` — кеш имён читов (Map)
- `_prevCpuTimes` — в system-info.ts

### Решение
```ts
// Вместо module-level Map:
class ScanContext {
  sigCache = new Map<string, boolean>()
  findingDedup = new Set<string>()
  peHeaderCache = new Map<string, ...>()
  cheatNameCache = new Map<string, string[]>()

  clear() {
    this.findingDedup.clear()
    this.sigCache.clear()
    this.peHeaderCache.clear()
  }
}
```

**Трудоёмкость**: 1-2 часа
**Риск**: Средний
**Профит**: Изоляция между сканами, возможность параллельных сканов

---

## 🟡 Priority 3 — CJS require() → ESM import

### Проблема
2 места в scanner.ts используют `require('http')` вместо `import http from 'http'`:

```ts
// line 2609 + 2705 — нужно заменить на:
import http from 'http'
```

### Решение
Заменить на import в начале файла. Тривиально.

**Трудоёмкость**: 5 минут
**Риск**: Низкий
**Профит**: Единый стиль импортов, tree-shaking

---

## 🟡 Priority 4 — Типизация `any`

### Проблема
26 использований `any` по electron/:
- scanner.ts: `processes: any[]`, `proc: any`, `mods: any[]`
- cheat-rules.ts: return types без generic
- disk-vs-memory.ts: PowerShell JSON парсинг
- rwx-scanner.ts: thread types

### Решение
```ts
// Вместо:
const processes: any[] = JSON.parse(psOut)

// Создать тип:
interface ProcessInfo {
  Name: string
  Id: number
  Mods?: string[]
}

// Использовать:
const processes: ProcessInfo[] = JSON.parse(psOut)
```

**Трудоёмкость**: 2-3 часа
**Риск**: Средний (PowerShell JSON может вернуть неожиданную структуру)
**Профит**: Полная type safety, IDE autocomplete

---

## 🟢 Priority 5 — PowerShell JSON парсинг

### Проблема
PowerShell возвращает JSON в разных форматах:
- `ConvertTo-Json -Compress` — массив или один объект
- `ConvertTo-Json -Depth 3` — вложенные структуры
- Старый `wmic` — CSV

По всему коду разбросаны:
```ts
const parsed = JSON.parse(out)
const items = Array.isArray(parsed) ? parsed : [parsed]
```

### Решение: Утилита
```ts
function parsePsJson<T>(out: string): T[] {
  if (!out || out.trim().length < 5) return []
  try {
    const parsed = JSON.parse(out)
    return Array.isArray(parsed) ? parsed : [parsed]
  } catch {
    return []
  }
}
```

**Трудоёмкость**: 30 минут
**Риск**: Низкий
**Профит**: ~20 строк дублирования убрано

---

## 🟢 Priority 6 — const _PATH = process.env (конфиг)

### Проблема
В 3 файлах определены одни и те же константы путей:
```ts
// scanner.ts
const _PF = process.env.ProgramFiles || 'C:\\Program Files'
const _HOME = os.homedir()

// cheats-db.ts
const home = os.homedir()
function _pf(): string { ... }
```

### Решение: Вынести в config.ts
```ts
// electron/config.ts
export const CFG = {
  PF: process.env.ProgramFiles || 'C:\\Program Files',
  PF86: process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)',
  WR: process.env.SystemRoot || 'C:\\Windows',
  HOME: os.homedir(),
  PD: process.env.ProgramData || 'C:\\ProgramData',
}
```

**Трудоёмкость**: 20 минут
**Риск**: Низкий
**Профит**: Единый источник правды для путей

---

## 🟢 Priority 7 — HTTP-клиент (require('http'))

### Проблема
2 места в scanner.ts делают HTTP запросы через `require('http')`:
- Cloud hash submission
- Cloud hash fetch

Каждый раз:
```ts
const http = require('http')
const data = JSON.stringify(...)
const req = http.request(...)
req.on('response', (res) => { ... })
req.on('error', () => {})
```

### Решение
```ts
import https from 'https'

// Или вынести в api-client.ts
async function cloudRequest<T>(method: string, path: string, body?: unknown): Promise<T> {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : ''
    const req = https.request({ hostname: 'api.github.com', path, method, ... })
    req.on('response', (res) => {
      let body = ''
      res.on('data', c => body += c)
      res.on('end', () => resolve(JSON.parse(body)))
    })
    req.on('error', reject)
    req.end(data)
  })
}
```

**Трудоёмкость**: 1 час
**Риск**: Низкий
**Профит**: Переиспользуемый HTTP клиент, единая обработка ошибок

---

## 🟢 Priority 8 — Magic strings

### Проблема
Множество hardcoded строк по всему коду:
- `'gta5'`, `'fivem'`, `'ragemp'`, `'altv'` — game platforms
- `'high'`, `'medium'`, `'low'` — risk levels
- `'files'`, `'processes'`, `'cheats'`, `'dma'`, `'extended'`, `'network'` — scan modes
- `'file'`, `'browser'`, `'process'`, `'registry'`, `'hardware'`, `'software'` — result types

### Решение: Enum/const
```ts
export enum RiskLevel { High = 'high', Medium = 'medium', Low = 'low' }
export enum ScanMode { Files = 'files', Processes = 'processes', /* ... */ }
export enum ResultType { File = 'file', Browser = 'browser', /* ... */ }
```

**Трудоёмкость**: 30 минут
**Риск**: Средний (везде поменять типы)
**Профит**: IDE autocomplete, невозможность опечаток

---

## 📊 Итоговый приоритет

| # | Задача | Трудоёмкость | Риск | Эффект |
|---|--------|-------------|------|--------|
| 🔴 | Разделить scanner.ts | 2-3ч | Высокий | Архитектура |
| 🟡 | ScanContext class | 1-2ч | Средний | Изоляция |
| 🟡 | Типизировать `any` | 2-3ч | Средний | Type safety |
| 🟡 | require() → import | 5 мин | Низкий | Стиль |
| 🟢 | PowerShell JSON утилита | 30 мин | Низкий | DRY |
| 🟢 | config.ts | 20 мин | Низкий | DRY |
| 🟢 | HTTP клиент | 1ч | Низкий | DRY |
| 🟢 | Enum для типов | 30 мин | Средний | Safe refactor |

**Рекомендация**: Начать с `require('http')` → import (5 мин) + config.ts (20 мин) + PowerShell JSON утилита (30 мин). Это 55 мин низкорисковых улучшений, которые сразу дадут более чистый код. scanner.ts разделение — самое важное, но требует тестов перед собой.
