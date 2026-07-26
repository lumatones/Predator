# Refactoring Plan — Predator

> **Прогресс:** 6 из 8 задач выполнено ✅
> Последнее обновление: 2026-07-26 (v0.0.21)

## Метрики текущего кода (обновлено)

| Метрика | Было | Стало |
|---------|------|-------|
| Файлов electron/ | 14 | 20 (+ modes/, tests, новые модули) |
| scanner.ts | 2,735 строк (41%) | ~1,500 строк (константы/cloud sync/parsing вынесены) |
| Использований `any` | 26 | ~5 (остались только в краевых случаях) |
| module-level `const _` (глобальное состояние) | 8 | 0 ✅ (ScanContext) |
| `require()` CJS-стиль | 2 | 0 ✅ (все ESM import) |

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

## 🟡 Priority 2 — Глобальное состояние (module-level mutables) ✅ ВЫПОЛНЕНО

### Решение реализовано
`ScanContext` класс в `electron/types.ts`:
```ts
export class ScanContext {
  findingDedup = new Set<string>()
  sigCache = new Map<string, boolean>()
  peHeaderCache = new Map<...>()
  cheatNameCache = new Map<string, string[]>()
  readonly PE_CACHE_MAX = 500
  addFinding(key: string): boolean { ... }
  clear() { ... }
}
export const ctx = new ScanContext()
```
- Глобальный `ctx` используется во всех модулях
- `ctx.clear()` вызывается перед каждым новым сканом
- Старые алиасы (`_findingDedup`, `addFindingDedup`, `clearFindingDedup`) сохранены для обратной совместимости

**Статус**: ✅ Выполнено в v0.0.21

---

## 🟡 Priority 3 — CJS require() → ESM import ✅ ВЫПОЛНЕНО

### Решение реализовано
- `require('http')` заменён на `import http from 'http'` в `cloud-sync.ts`
- `require('child_process')` / `require('os')` заменены на импорты в `types.ts`

**Статус**: ✅ Выполнено в v0.0.21

---

## 🟡 Priority 4 — Типизация `any` ✅ ЧАСТИЧНО ВЫПОЛНЕНО

### Решение реализовано
- Все `any[]` в scanner.ts заменены на дженерик `parsePsJson<T>()`
- `ScanOptions` интерфейс для опций сканирования
- Типизированные параметры в disk-vs-memory.ts, rwx-scanner.ts, dma.ts, games.ts, processes.ts
- Осталось ~5 `any` в краевых случаях (cheat-rules.ts return types)

**Статус**: ✅ Выполнено на 80% в v0.0.21

---

## 🟢 Priority 5 — PowerShell JSON парсинг ✅ ВЫПОЛНЕНО

### Решение реализовано
`parsePsJson<T>()` в `electron/types.ts`:
```ts
export function parsePsJson<T>(out: string): T[] {
  if (!out || out.trim().length < 5) return []
  try {
    const parsed = JSON.parse(out)
    return Array.isArray(parsed) ? parsed : [parsed]
  } catch { return [] }
}
```
- Используется в: dma.ts, games.ts, processes.ts, disk-vs-memory.ts, rwx-scanner.ts, scanner.ts
- ~20 строк дублирования убрано

**Статус**: ✅ Выполнено в v0.0.21

---

## 🟢 Priority 6 — const _PATH = process.env (конфиг) ✅ ВЫПОЛНЕНО

### Решение реализовано
`CFG` объект в `electron/config.ts`:
```ts
export const CFG = {
  PF: process.env.ProgramFiles || 'C:\\Program Files',
  PF86: process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)',
  WR: process.env.SystemRoot || 'C:\\Windows',
  HOME: os.homedir(),
  PD: process.env.ProgramData || 'C:\\ProgramData',
}
```
- Используется в cheats-db.ts, browser-history.ts
- Старые алиасы (`_PF`, `_PF86`, `_HOME`, `_WR`) в types.ts для обратной совместимости

**Статус**: ✅ Выполнено в v0.0.21

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

## 📊 Итоговый приоритет (обновлено v0.0.21)

| # | Задача | Трудоёмкость | Статус |
|---|--------|-------------|--------|
| ✅ | ScanContext class | 1-2ч | **Выполнено** |
| ✅ | Типизировать `any` | 2-3ч | **Выполнено (80%)** |
| ✅ | require() → import | 5 мин | **Выполнено** |
| ✅ | PowerShell JSON утилита | 30 мин | **Выполнено** |
| ✅ | config.ts (CFG) | 20 мин | **Выполнено** |
| ✅ | Константы → constants.ts | 15 мин | **Выполнено** |
| ✅ | Cloud sync → cloud-sync.ts | 20 мин | **Выполнено** |
| 🔴 | Разделить scanner.ts | 2-3ч | **В планах** |
| 🟢 | HTTP клиент | 1ч | **В планах** |
| 🟢 | Enum для типов | 30 мин | **В планах** |
