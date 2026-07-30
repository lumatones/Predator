# Kudu Analysis - что мы узнали и что добавили в Predator

> Анализ проекта [AdventDevInc/kudu](https://github.com/AdventDevInc/kudu) · 2026-07-30

---

## Что такое Kudu

Kudu — бесплатный open-source чистильщик системы (аналог CCleaner) + антивирусный сканер. Electron-приложение (как Predator). 1800+ звёзд на GitHub.

### Возможности Kudu

- Системный чистильщик (temp, логи, кеши, crash dumps)
- Чистильщик браузеров (18 браузеров)
- Чистильщик игр (Steam, Epic, EA, Ubisoft, Riot, Rockstar...)
- Чистильщик реестра
- Менеджер автозагрузки
- Деблоатер Windows
- Дисковый анализатор
- Privacy Shield (30+ настроек Windows)
- **Malware Scanner** (сигнатуры + эвристика + YARA + Defender)
- Secure Delete (перезапись случайными данными)

---

## ЧТО KUDU ЧИСТИТ — полный список целей

### Системные следы (system.json)

| Категория | Конкретные пути |
|-----------|----------------|
| Temp файлы | `%LOCALAPPDATA%/Temp`, `%WINDIR%/Temp`, ServiceProfiles Temp |
| Логи | `Windows/Logs`, `Panther`, `winevt/Logs`, `debug`, `tracing` |
| Логи брандмауэра | `System32/LogFiles/Firewall` |
| WMI трассировка | `System32/LogFiles/WMI` |
| HTTP ошибки | `System32/LogFiles/HTTPERR` |
| Надёжность | `ProgramData/Microsoft/RAC/PublishedData` |
| Поиск Windows | `ProgramData/Microsoft/Search/.../GatherLogs` |
| Диагностика ETL | `ProgramData/Microsoft/Diagnosis/ETLLogs` |
| Энергоэффективность | `ProgramData/Microsoft/Windows/Power Efficiency Diagnostics` |
| **Windows Update** | `SoftwareDistribution/Download`, `DeliveryOptimization` |
| **Prefetch** | `Windows/Prefetch` |
| **Thumbnail/Icon cache** | `%LOCALAPPDATA%/Microsoft/Windows/Explorer` |
| **Шейдерный кеш DirectX** | `%LOCALAPPDATA%/D3DSCache` |
| **Internet кеш** | `%LOCALAPPDATA%/Microsoft/Windows/INetCache` |
| RDP кеш | `%LOCALAPPDATA%/Microsoft/Terminal Server Client/Cache` |
| **Отчёты об ошибках** | `%LOCALAPPDATA%/Microsoft/Windows/WER`, `ProgramData/.../WER` |
| **Crash Dumps** | `%LOCALAPPDATA%/CrashDumps`, `Windows/Minidump`, `LiveKernelReports` |
| **Defender следы** | `ProgramData/.../Windows Defender/Scans/History`, `Support`, `MetaStore` |
| Сертификаты | `CryptnetUrlCache` (LocalService + NetworkService + System) |
| **Memory Dump** | `Windows/MEMORY.DMP` |
| .NET Usage Logs | `%LOCALAPPDATA%/Microsoft/CLR_v4.0/UsageLogs` |
| Windows.old | `C:/Windows.old` |

### Браузеры (18 штук!)

**Chromium-семейство (13):** Chrome, Edge, Brave, Opera, Opera GX, Vivaldi, Arc, Chromium, Thorium, Supermium, Helium, Cromite, CatsXP

**Firefox-семейство (5):** Firefox, LibreWolf, Waterfox, Floorp, Zen

**Что чистит:** Cache, Code Cache, GPU Cache, Service Worker Cache, WebGPU/Graphite Shader Cache, Extension Cache, Skia Shader Cache, PNaCl Translation Cache

### Игровые лаунчеры (17!)

Steam, Epic Games, EA App, Ubisoft Connect, GOG Galaxy, Battle.net, Riot Games, Xbox App, Rockstar Games, itch.io, Minecraft, Roblox, Valorant, Fortnite, Amazon Games, Overwolf/CurseForge

---

## КАК KUDU СКАНИРУЕТ НА ВИРУСЫ

### 8 фаз сканирования

```
init → discovering → signatures → heuristics → scripts → system → persistence → defender → complete
```

### Методы детекции

1. **YARA** — 1400+ правил через `@litko/yara-x`. Облачная загрузка правил. Массовая компиляция (~2 сек на 1400 файлов). Фолбек: покадровая валидация.

2. **Эвристика имён файлов** — ищет системные .exe (svchost.exe, csrss.exe, lsass.exe, winlogon.exe, explorer.exe...) ВНЕ `System32/SysWOW64`. High severity.

3. **PE-анализ** — MZ/PE заголовки, RWX-секции, энтропия секций > 7.0, несоответствие virtual/raw размеров.

4. **Double extension** — `invoice.pdf.exe`, `photo.jpg.scr` и т.д. Более 30 bait-расширений.

5. **Suspicious API imports** — сканирует PE-файлы на:
   - Process injection: `CreateRemoteThread`, `VirtualAllocEx`, `WriteProcessMemory`, `QueueUserAPC`, `SetWindowsHookEx`
   - Credential access: `MiniDumpWriteDump`, `LsaRetrievePrivateData`
   - Keylogging: `GetAsyncKeyState`, `GetClipboardData`
   - Defense evasion: `AmsiScanBuffer`, `EtwEventWrite`

6. **Hosts file** — проверяет редиректы защищённых доменов (google.com, microsoft.com, github.com...) на подозрительные IP.

7. **Defender** — Windows Defender через `MpCmdRun.exe`.

8. **Allowlist** — SHA256-вейтлист для false positive.

### Сканируемые расширения (Windows)

`.exe .dll .sys .drv .scr .bat .cmd .com .pif .ocx .vbs .vbe .js .jse .wsh .wsf .ps1 .msi .jar .hta .cpl .inf .reg .lnk`

---

## ЧТО МЫ ДОБАВИЛИ В PREDATOR

### 1. Kudu-специфичные детекты (pc-cleaner-detection.ts)

- **Kudu executable detection** — поиск `kudu.exe`, `Kudu Setup*.exe` в системе
- **Kudu deletion log** — `%APPDATA%/kudu/deletion-log.jsonl` (Kudu пишет лог всего что удалил)
- **Kudu app data** — `%APPDATA%/kudu/` директория
- **Kudu quarantine** — `quarantine-manifest.json`
- **Расширенный список чистящихся путей** — теперь включаем пути, которые Kudu чистит, но CCleaner не трогает:
  - `CryptnetUrlCache` (сертификаты)
  - `D3DSCache` (DirectX шейдеры)
  - Defender scan history + MetaStore
  - Delivery Optimization
  - .NET Usage Logs
  - RDP Bitmap Cache

### 2. Double extension detection (heuristic.ts)

Новая эвристика `checkDoubleExtension()` — файлы типа `invoice.pdf.exe`:
- 30+ bait-расширений (.pdf, .doc, .jpg, .zip...)
- 10+ исполняемых расширений (.exe, .scr, .bat, .ps1...)
- Автоматически high risk

### 3. Расширенный список браузеров (browser-history.ts)

Добавлены браузеры которые Kudu чистит, но Predator не проверял:
- Thorium, Supermium, Helium, Cromite, CatsXP, Arc (Chromium-семейство)
- LibreWolf, Waterfox, Floorp, Zen (Firefox-семейство)

### 4. Новые сигнатуры

Добавлены в signature-registry.ts:
- Kudu как известный чистильщик (наравне с CCleaner, BleachBit)
- Kudu-специфичные пути в PROTECTED_PATHS
