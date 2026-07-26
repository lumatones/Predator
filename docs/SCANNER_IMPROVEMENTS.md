# 🔬 Predator Scanner — План улучшений v1.0

> **Дата:** 26.07.2026 | **Основано на:** полном аудите кода + исследовании 2025-2026

---

## 📊 Текущее состояние: scorecard

| Слой | Технология | Оценка | Комментарий |
|------|-----------|--------|-------------|
| **Сигнатуры** | 250+ имён читов, хеши SHA256, бинарные паттерны | ⭐⭐⭐⭐ | Хорошая база, но только точные совпадения |
| **Эвристика** | Энтропия Шеннона, PE-заголовки, YARA, категории | ⭐⭐⭐⭐ | Сильный движок, 13 YARA-правил |
| **Процессы** | tasklist + PowerShell DLL-модули | ⭐⭐⭐ | Зависит от PowerShell (можно отключить) |
| **Маскировка** | Проверка имён системных процессов + цифровые подписи | ⭐⭐⭐⭐ | Умная логика с 7 шагами проверки |
| **Игры** | FiveM/RAGE/ALT:V whitelist + module scanning | ⭐⭐⭐⭐⭐ | Платформенные whitelist'ы — отлично |
| **Реестр** | Run/RunOnce/Services/Winlogon + Prefetch | ⭐⭐⭐ | Базовое покрытие |
| **Сеть** | DNS cache, hosts, netstat, порты | ⭐⭐⭐ | Хорошо, но нет анализа трафика |
| **DMA** | PCI-устройства, драйверы, FTDI, задачи | ⭐⭐⭐ | Нет firmware fingerprinting |
| **Продвинутое** | AMSI/ETW, Behavior, RWX, Disk-vs-Memory | ⭐⭐⭐⭐⭐ | 4 мощных модуля |
| **Auto-YARA** | Самообучение, Jaccard, коррекция FP | ⭐⭐⭐ | Базовая реализация |
| **Облако** | HTTP sync каждые 5 мин, submit hashes | ⭐⭐ | Polling, нет real-time |

---

## 🎯 Топ-7 улучшений (по приоритету)

### 1. 🔥 Fuzzy Hashing (TLSH) — ловим варианты читов

**Проблема:** Читеры меняют 1 байт → новый SHA256 → обходят базу.  
**Решение:** Fuzzy-хеширование (TLSH или ssdeep) — похожие файлы получают близкие хеши.

**Как работает:**
```
Файл A: cheat_loader_v1.exe → SHA256: aaa...111 → TLSH: T1A2B3C4...
Файл B: cheat_loader_v2.exe → SHA256: bbb...222 → TLSH: T1A2B3D4... (distance = 15)
                                                      ↑ другой SHA256, но TLSH близок!
```

**Реализация:**
- Установить `npm install tlsh-js` (чистый JS, не требует node-gyp)
- В `electron/heuristic.ts`: вычислять TLSH для .exe/.dll > 100KB
- Сравнивать distance с облачной базой TLSH-хешей (порог: < 30 = вариант)
- При submit — отправлять и SHA256, и TLSH на сервер

**Сложность:** 🟢 Лёгкая (1-2 часа)  
**Влияние:** 🔴 Огромное (полиморфные читы)  
**Риск FP:** 🟢 Низкий (порог distance настраивается)

---

### 2. 🌐 Real-Time Cloud Sync (WebSocket) — мгновенные обновления

**Проблема:** 5-минутный интервал polling = окно для игры с непроверенными сигнатурами.  
**Решение:** WebSocket (Socket.IO) — сервер пушит новые сигнатуры мгновенно.

**Как работает:**
```
Клиент (Predator.exe)                   Сервер (API)
    │                                       │
    ├─ WS connect ──────────────────────────┤
    │                                       │
    │◄── event: "hash-update" ──────────────┤ (админ подтвердил новый хеш)
    │◄── event: "rule-update" ──────────────┤ (новая YARA-сигнатура)
    │◄── event: "emergency-ban" ────────────┤ (critical threat)
    │                                       │
    ├─ mergeCheatHashes(newHashes) ───┐      │
    ├─ evaluateYara(newRules) ────────┤      │
    └─ (мгновенно активно) ───────────┘      │
```

**Реализация:**
- Сервер уже имеет Socket.IO! Добавить события: `hash-update`, `rule-update`
- `electron/cloud-sync.ts`: заменить `setInterval` на `socket.on('hash-update', ...)`
- Fallback: сохранить HTTP-polling на случай обрыва WS
- Добавить индикатор в UI: "🟢 Cloud Sync Active"

**Сложность:** 🟡 Средняя (3-4 часа)  
**Влияние:** 🟡 Большое (zero-day response)  
**Риск FP:** 🟢 Нулевой (те же сигнатуры, быстрее доставка)

---

### 3. 🧬 Shadow-Mode Rule Deployment — безопасные новые правила

**Проблема:** Новые YARA-правила и эвристики могут давать false positives на легитимном софте.  
**Решение:** "Теневой режим" — правило silently собирает телеметрию, но не банит.

**Как работает:**
```
Правило: "new_cheat_variant" { shadow: true }

Сканирование:
  Файл подходит под правило?
    ├─ shadow: true → silently отправить метаданные на сервер (НЕ флаг как угрозу)
    └─ shadow: false → обычный флаг

Сервер:
  Собрал 1000+ срабатываний от разных пользователей
  → 0% совпадений с легитимными файлами
  → Промоутить правило: shadow: true → shadow: false (активно)
```

**Реализация:**
- `electron/types.ts`: добавить `shadow?: boolean` в `CheatCategory` и YARA-сигнатуры
- `electron/scanner.ts`: shadow-правила → `ctx.shadowFindings.push(...)` вместо `results.push(...)`
- Отправлять `shadowFindings` на сервер отдельным эндпоинтом
- Серверная админка: страница "Shadow Rules" с кнопкой "Promote to Active"

**Сложность:** 🟡 Средняя (3-4 часа)  
**Влияние:** 🟡 Большое (безопасный rollout)  
**Риск FP:** 🟢 Устраняет FP (!)

---

### 4. 📈 Cross-Session Persistent Scoring — ловим "тихих" читеров

**Проблема:** Читер с "умным" софтом получает medium-risk (40 баллов) 5 раз подряд, но каждый скан независим — система не видит паттерн.  
**Решение:** Локальная БД (SQLite) + кумулятивный risk score.

**Как работает:**
```
День 1: disk-vs-memory → 3 suspicious modules → riskScore: 40
День 2: RWX scan → 2 anomalies → riskScore: 35
День 3: behavior profile → suspicious parent process → riskScore: 45
День 4: heuristic → packed file → riskScore: 30
День 5: disk-vs-memory → 2 suspicious modules → riskScore: 40

Кумулятивный профиль:
  avgRisk: 38 | consistency: HIGH (>80% scans flagged) | trend: STABLE
  → Эскалация: "Persistent Anomaly — escalate to HIGH risk"
```

**Реализация:**
- `electron/persistent-profile.ts`: новый модуль
- Использовать `better-sqlite3` (синхронный SQLite для Electron)
- Таблица: `sessions (id, date, mode, riskScore, topFindings JSON, cumulativeScore)`
- При старте скана: загружать историю, вычислять `consistency` и `trend`
- Если consistency > 70% за последние 7 дней → добавлять "+25 cumulative risk" ко всем находкам

**Сложность:** 🟡 Средняя (3-4 часа)  
**Влияние:** 🟡 Большое (умные читеры)  
**Риск FP:** 🟡 Средний (нужен тюнинг порогов)

---

### 5. 🔍 ETW Integration — kernel-level visibility без драйвера

**Проблема:** Читы патчат PowerShell, отключают AMSI — мы теряем видимость.  
**Решение:** Event Tracing for Windows (ETW) — прямой доступ к событиям ядра без кастомного драйвера.

**Что даёт ETW:**
- `Microsoft-Windows-Kernel-Process`: создание потоков, загрузка DLL (раньше PowerShell)
- `Microsoft-Windows-Threat-Intelligence`: подозрительные memory allocation (Remote Thread, APC)
- Не требует подписи драйвера — работает из userspace с SeSystemProfilePrivilege

**Как это дополнит сканер:**
```
Текущий подход:
  PowerShell → Get-Process → (медленно, можно отключить)

ETW подход:
  Подписываемся на Kernel-Process события
  → Реальное время: каждое создание потока, загрузка DLL — instantly
  → Чит не может скрыться (ETW работает на уровне ядра)
  → Нет зависимости от PowerShell
```

**Реализация:**
- `electron/etw-provider.ts`: новый модуль
- Использовать `krabsetw` (Node.js ETW library, требует node-gyp)
- Альтернатива: PowerShell `Register-WmiEvent` для `Win32_ProcessStartTrace`
- На старте: запустить ETW-сессию с фильтром по game-процессам
- События → stream → анализ в реальном времени

**Сложность:** 🔴 Высокая (6-8 часов, node-gyp)  
**Влияние:** 🔴 Огромное (kernel-level видимость)  
**Риск FP:** 🟢 Низкий (ETW — достоверный источник)

---

### 6. 🧪 Auto-YARA v2 — кластеризация + валидация

**Проблема:** Текущий Auto-YARA создаёт правила из ОДНОГО файла. Варианты того же чита создают дубликаты правил.  
**Решение:** Кластеризация файлов по TLSH перед генерацией правил.

**Как работает:**
```
Auto-YARA v1 (сейчас):
  Файл A (risk 85) → извлечь строки → создать правило A
  Файл B (risk 82) → извлечь строки → создать правило B
  Проблема: A и B — варианты одного чита, но правила разные

Auto-YARA v2:
  Файл A (risk 85) → TLSH: T1A2B3...
  Файл B (risk 82) → TLSH: T1A2B5... (distance 12 — вариант!)
  Файл C (risk 78) → TLSH: T1A2C1... (distance 18 — вариант!)
  → Кластер: {A, B, C}
  → Извлечь ОБЩИЕ строки из всего кластера
  → Создать ОДНО правило, покрывающее все 3 варианта
  → Отправить на сервер как "shadow"
  → После валидации: активное правило
```

**Реализация:**
- `electron/auto-yara.ts`: добавить `clusterFindings(tlshHashes)` 
- Группировать по distance < 30
- Для каждого кластера: Jaccard similarity между всеми парами → найти общие строки
- Генерировать правило из общих строк + отправлять как shadow
- Сервер: endpoint для приёма shadow-правил + админ-интерфейс для promote

**Сложность:** 🟡 Средняя (3-4 часа)  
**Влияние:** 🟡 Большое (лучшие правила)  
**Риск FP:** 🟢 Низкий (shadow-mode + кластеризация)

---

### 7. 🛡️ DMA Firmware Fingerprinting — глубже PCI-сканирования

**Проблема:** Читеры меняют Vendor ID (VEN) и Device ID (DEV) в FPGA-прошивке — мы не видим "Xilinx" → пропускаем.  
**Решение:** Дамп конфигурационного пространства PCIe + анализ таймингов.

**Как работает:**
```
Текущий DMA-скан:
  wmic path Win32_PnPEntity → ищем "Xilinx", "FTDI" по имени
  Проблема: читер перепрошил FPGA → имя изменилось на "Standard PCI-to-PCI Bridge"

DMA Fingerprinting:
  1. Дамп PCI config space (256 bytes) через Win32_PnPEntity
  2. Анализ полей: Vendor ID, Device ID, Subsystem ID, Class Code, BARs
  3. Проверка на "Generic" или "Standard" классы с нестандартными BAR
  4. Тайминг-анализ: скорость ответа PCIe устройства (FPGA отвечает быстрее)
  5. Бенчмарк: latency test через чтение BAR0 в цикле
```

**Реализация:**
- `electron/modes/dma.ts`: расширить `scanDmaDevices()`
- Использовать PowerShell/WMIC для дампа PCI config space
- Добавить эвристику: "Generic Bridge" + большой BAR → suspicious
- Тайминг-тест через Node.js `perf_hooks` + PowerShell запросы

**Сложность:** 🔴 Высокая (5-7 часов, низкоуровневый доступ)  
**Влияние:** 🟡 Большое (DMA-читы)  
**Риск FP:** 🟡 Средний (нужен тюнинг)

---

## 📊 Сводная таблица

| # | Улучшение | Сложность | Влияние | FP риск | Часы |
|---|-----------|----------|---------|---------|------|
| 1 | **Fuzzy Hashing (TLSH)** | 🟢 | 🔴 | 🟢 | 1-2ч |
| 2 | **Real-Time Cloud Sync (WS)** | 🟡 | 🟡 | 🟢 | 3-4ч |
| 3 | **Shadow-Mode Rules** | 🟡 | 🟡 | 🟢 | 3-4ч |
| 4 | **Persistent Scoring** | 🟡 | 🟡 | 🟡 | 3-4ч |
| 5 | **ETW Integration** | 🔴 | 🔴 | 🟢 | 6-8ч |
| 6 | **Auto-YARA v2** | 🟡 | 🟡 | 🟢 | 3-4ч |
| 7 | **DMA Fingerprinting** | 🔴 | 🟡 | 🟡 | 5-7ч |

---

## 🗺️ Рекомендуемый порядок реализации

```
Неделя 1: #1 Fuzzy Hashing (быстрый win) + #3 Shadow-Mode (безопасность)
Неделя 2: #2 Real-Time Cloud Sync (инфраструктура) + #4 Persistent Scoring
Неделя 3: #6 Auto-YARA v2 (качество правил)
Неделя 4-5: #5 ETW Integration (kernel visibility)
По готовности: #7 DMA Fingerprinting
```

---

## 🔧 Быстрые wins (можно сделать прямо сейчас)

Помимо 7 основных улучшений, есть микро-оптимизации:

1. **Параллельные фазы сканирования**
   - Фазы 3-5 могут работать параллельно (реестр + prefetch + сеть не зависят друг от друга)
   - `Promise.all([scanRegistryDeepV2(), scanPrefetchV2(), scanNetstatV2()])`
   - Сократит время full scan на 30-40%

2. **Инкрементальный file scan**
   - Кешировать mtime файлов между сканами
   - Повторно сканировать только изменённые файлы
   - Сократит время повторного full scan на 80%+

3. **Cheat-scan-only режим для файлов**
   - Сейчас heuristicFileScan запускается для ВСЕХ .exe/.dll/.asi
   - Добавить быстрый pre-filter: проверить имя файла по cheat-DB → если match → heuristic
   - Сократит CPU на 60% для чистых систем

4. **Локальный кеш сигнатур**
   - Сохранять `KNOWN_CHEAT_HASHES` в localStorage/файл
   - При старте: загружать из кеша → мгновенно готов
   - Обновлять из облака в фоне

---

## 📁 Новые файлы для реализации

```
electron/
├── fuzzy-hash.ts          # TLSH computation + comparison
├── persistent-profile.ts  # Cross-session scoring with SQLite
├── etw-provider.ts        # ETW session management
├── shadow-rules.ts        # Shadow-mode rule evaluation
└── dma-fingerprint.ts     # PCI config space analysis
```

---

> **Вывод:** Система сканирования уже сильная. 7 улучшений превратят её из «хорошей» в «лучшую в своём классе». Начинаем с Fuzzy Hashing — максимальный эффект за минимальное время.
