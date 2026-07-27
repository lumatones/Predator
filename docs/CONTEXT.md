# Predator — Domain Context (Предметный словарь)

> **Назначение**: Единый глоссарий предметной области для AI-агентов и разработчиков.
> Называй вещи своими именами: не «компонент», а модуль; не «сервис», а IPC handler.

---

## 🦅 Core Concepts

| Термин | Определение | Пример |
|--------|------------|--------|
| **Scan** (Скан) | Полный цикл проверки ПК — от запуска до возврата результатов | `start-scan` IPC handler |
| **ScanMode** | Вариант сканирования: `full`, `quick`, `dma`, `cleaner` | `registerScanHandlers()` dispatch |
| **ScanResult** | Одна находка: файл, процесс, запись реестра | `{ path, fileName, type, risk, matches }` |
| **ScanPipeline** | Цепочка пост-скановых side-эффектов | SessionRecorder → ShadowSubmitter → ... → ResultUploader |
| **ScanContext (`ctx`)** | Изолированное состояние между сканами (кеши, dedup) | `ctx.findingDedup`, `ctx.sigCache` |
| **Finding** | Единица обнаружения — то же что ScanResult | `addFindingDedup(key)` |
| **Risk Level** | Уровень опасности: `high`, `medium`, `low` | `riskScoreToLevel(85) → 'high'` |
| **Heuristic** | Эвристический анализ — оценка файла/процесса без точного совпадения | `heuristicFileScan(filePath)` |
| **Signature** | Точное совпадение: хеш, имя процесса, бинарная строка | `KNOWN_CHEAT_HASHES`, `KNOWN_BINARY_SIGNATURES` |
| **Signature Registry** | Единый источник всех сигнатур (данные, не логика) | `signature-registry.ts` |
| **CheatCategory** | Категория угрозы: injector, debugger, hook, driver, ... | `SUSPICIOUS_CATEGORIES.injector` |

## 🎮 Game Platforms

| Термин | Полное название | Идентификатор |
|--------|----------------|---------------|
| **FiveM** | Модификация GTA 5 для ролевых серверов | `fivem` |
| **RAGE MP** | Мультиплеерная платформа GTA 5 (CEF-based) | `rage` |
| **ALT:V** | Альтернативный мультиплеер GTA 5 (JS/.NET) | `altv` |
| **GTA 5** | Grand Theft Auto V (Rockstar) | `gta5` |

## 🔍 Detection Layers

| Слой | Что делает | Где живёт |
|------|-----------|----------|
| **Process Scan** | tasklist + PowerShell модульный анализ | `modes/processes.ts` |
| **Heuristic File Scan** | Энтропия, YARA, PE-заголовки, подписи | `heuristic.ts` |
| **Masquerading Detection** | Файлы/процессы под видом легитимных | `checkMasqueradingExecutable()`, `scanMasqueradingProcesses()` |
| **Behavioral Analysis** | Поведенческие паттерны (память, self-spawning) | `behavior-profile.ts`, `scanMasqueradingProcesses()` |
| **Memory Analysis** | MiniDump, RWX-регионы, disk-vs-memory | `memory-dump.ts`, `rwx-scanner.ts`, `disk-vs-memory.ts` |
| **DMA Detection** | PCI-устройства, FPGA, FTDI-чипы | `modes/dma.ts` |
| **Browser History** | SQLite парсинг истории (6 браузеров) | `browser-history.ts`, `modes/browser.ts` |
| **Registry Scan** | Run/RunOnce, Services, Winlogon | `modes/registry.ts` |
| **Network Scan** | netstat, DNS-кеш, hosts | `modes/network.ts` |
| **Forensic Scan** | Prefetch, Amcache, BAM, UserAssist | `forensic-traces.ts` |
| **Anti-Forensic Scan** | Очистка логов, tampering | `anti-forensic.ts` |
| **ETW/AMSI Detection** | Обход Windows защит | `etw-amsi-patch.ts`, `etw-provider.ts` |

## 🗄️ Database Modules

| Термин | Определение |
|--------|------------|
| **cheats-db** | База известных читов: названия процессов, файлы, хеши, бинарные сигнатуры |
| **safe-files-db** | База безопасных файлов (комьюнити-whitelist) |
| **auto-yara** | Самообучающиеся YARA-правила (извлечение строк из high-risk файлов) |
| **cloud-sync** | Синхронизация хешей читов с бэкенда (WebSocket + HTTP fallback) |
| **persistent-profile** | Накопительный скоринг между сессиями |

## 🏗️ Architecture Terms

| Термин | Определение |
|--------|------------|
| **IPC Handler** | Обработчик Electron IPC (main ↔ renderer) | 
| **Preload** | contextBridge API между main и renderer |
| **Main Process** | Node.js процесс Electron |
| **Renderer Process** | React-фронтенд в Chromium |
| **Seam** | Граница между модулями, через которую можно тестировать |
| **Locality** | Принцип: связанный код живёт рядом, несвязанный — разделён |
| **Shallow Module** | Модуль, чей интерфейс почти такой же сложный как реализация |
| **Deep Module** | Модуль, чей интерфейс прост, а реализация сложна |

## 🔐 Security Terms

| Термин | Определение |
|--------|------------|
| **Token** | 32-символьный hex-токен доступа |
| **Token Lifecycle** | generate → validate → use (activate) → submit-scan |
| **JWT** | JSON Web Token для админ-панели |
| **Shadow Rules** | Сигнатуры в тихом режиме (телеметрия без флагов) |
| **BYOVD** | Bring Your Own Vulnerable Driver — загрузка уязвимого драйвера |
| **VMProtect** | Коммерческий упаковщик/протектор |
| **Barys** | Семейство маскирующихся вредоносных загрузчиков |

## 📊 Scoring & Risk

| Термин | Определение |
|--------|------------|
| **Risk Score** | Числовая оценка (0-100+), накапливается сигналами |
| **Entropy** | Энтропия Шеннона (0-8) — мера случайности/сжатия данных |
| **PE Headers** | Portable Executable заголовки (.exe/.dll) |
| **Section Entropy** | Энтропия отдельных PE-секций |
| **Digital Signature** | Цифровая подпись (Authenticode) |
| **TLSH** | Trend Micro Locality Sensitive Hash — fuzzy-хеш |
| **API Hashing** | Техника сокрытия вызовов WinAPI через хеширование имён |
