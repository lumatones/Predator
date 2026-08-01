import type { ScanResult, ScanResponse, ScanMode } from '../types/electron'

// ── IconEraser ──

export const IconEraser = ({ size = 24, color = '#fff' }: { size?: number; color?: string }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M20 20H7L3 16c-.8-.8-.8-2 0-2.8L14.6 1.6c.8-.8 2-.8 2.8 0L21 5.2c.8.8.8 2 0 2.8L12 17" />
    <line x1="6" y1="20" x2="10" y2="20" />
    <line x1="18" y1="8" x2="14" y2="12" />
  </svg>
)

// ── Tabs ──

export interface TabConfig {
  id: ScanMode
  icon: string
  label: string
  desc: string
  color: string
}

export const TABS: TabConfig[] = [
  { id: 'full',     icon: 'Shield',     label: 'tabFull',     desc: 'tabFullDesc',     color: '#22c55e' },
  { id: 'quick',    icon: 'Crosshair',  label: 'tabQuick',    desc: 'tabQuickDesc',    color: '#F59E0B' },
  { id: 'dma',      icon: 'USB',        label: 'tabDma',      desc: 'tabDmaDesc',      color: '#8B5CF6' },
  { id: 'cleaner',  icon: 'Eraser',     label: 'tabCleaner',  desc: 'tabCleanerDesc',  color: '#EF4444' },
]

// ── Translations ──

export const T: Record<string, Record<string, string>> = {
  ru: {
    title: 'Сканирование системы',
    startBtn: 'Начать проверку',
    scanning: 'Сканирование...',
    analyzing: 'Анализ результатов...',
    done: 'Проверка завершена',
    found: 'Найдено',
    high: 'Высокий', medium: 'Средний', low: 'Низкий',
    risk: 'Риск',
    noThreats: 'Подозрительных элементов не обнаружено',
    threatsFound: 'обнаружено',
    filesScanned: 'просканировано',
    time: 'Время', sec: 'сек',
    clear: 'Очистить',
    file: 'Файл', matches: 'Совпадения', path: 'Путь',
    scanAgain: 'Проверить снова',
    browser: 'История браузера',
    tabFull: 'Полное сканирование', tabFullDesc: 'Все модули: файлы, процессы, реестр, сеть, DMA, браузер, эвристика',
    tabQuick: 'Быстрая проверка', tabQuickDesc: 'Процессы, Prefetch, реестр и история браузера — без обхода диска',
    tabDma: 'DMA-устройства', tabDmaDesc: 'Обнаружение DMA-карт и FPGA-устройств',
    tabCleaner: 'Детект чистки ПК', tabCleanerDesc: 'Следы очистки системы, USN-журнал, таймстомпинг, ShellBags, HWID',
    riskHigh: 'Высокий риск', riskMedium: 'Средний риск', riskLow: 'Низкий риск',
    processRunning: 'Запущен', processRecent: 'Недавние', processPrefetch: 'Prefetch', processMem: 'Память',
    cheatFiles: 'Файлы', cheatBrowser: 'История', cheatRegistry: 'Реестр',
    dmaPci: 'PCI-устройства', dmaSoftware: 'ПО', dmaDriver: 'Драйверы', dmaRegistry: 'Реестр',
    typeFile: 'Файл', typeBrowser: 'Браузер', typeProcess: 'Процесс', typeRegistry: 'Реестр',
    typeHardware: 'Оборудование', typeSoftware: 'ПО',
    typeSystem: 'Система',
    noData: 'Нет данных для отображения',
    dmaDetected: 'Обнаружено DMA-устройств',
    cheatsFound: 'Найдено следов читов',
    processesFound: 'Подозрительных процессов',
    cheatFilesUnit: 'файлов', cheatProcUnit: 'процессов', cheatRegUnit: 'реестр',
    cheatBrowserUnit: 'браузер', cheatHwUnit: 'устройств', cheatOtherUnit: 'другое',
    cheatConfidence: 'уверенность',
    cheatOtherActivity: 'Другая подозрительная активность',
    devicesTitle: 'Подключенные устройства',
    devicesSafe: 'Обычные устройства',
    devicesSuspicious: '⚠ Подозрительные устройства',
    devicesHistory: '⏳ История DMA',
    devicesPhone: 'Телефон', devicesFlash: 'Флешка', devicesDma: 'DMA',
    devicesUnknown: 'Неизвестно',
    groupCritical: 'Критический риск', groupHigh: 'Высокий риск', groupMedium: 'Средний риск', groupLow: 'Низкий риск',
    showAll: 'Показать все', collapse: 'Свернуть',
    groupHidden: 'ещё скрыто',
    searchPlaceholder: 'Поиск по имени, пути или совпадениям...',
    searchNoResults: 'Ничего не найдено',
    exportReport: 'Экспорт',
    exportHtml: 'HTML отчёт',
    exportJson: 'JSON отчёт',
    scanError: 'Ошибка сканирования',
    scanErrorHint: 'Попробуйте другой режим или перезапустите приложение',
    scanInconclusive: 'Проверка завершена не полностью',
    scanInconclusiveHint: 'Некоторые модули не смогли получить данные. Результат нельзя считать подтверждённо чистым.',
    backBtn: 'Назад',
    binaryTriage: 'Хардкор-разбор бинарника',
    binaryTriageHint: 'PE / TLS / API / packing — без запуска файла',
    binaryTriageError: 'Не удалось выполнить статический разбор',
  },
  en: {
    title: 'System Scan',
    startBtn: 'Start Scan',
    scanning: 'Scanning...',
    analyzing: 'Analyzing results...',
    done: 'Scan complete',
    found: 'Found',
    high: 'High', medium: 'Medium', low: 'Low',
    risk: 'Risk',
    noThreats: 'No suspicious items detected',
    threatsFound: 'found',
    filesScanned: 'scanned',
    time: 'Time', sec: 'sec',
    clear: 'Clear',
    file: 'File', matches: 'Matches', path: 'Path',
    scanAgain: 'Scan Again',
    browser: 'Browser History',
    tabFull: 'Full Scan', tabFullDesc: 'All modules: files, processes, registry, network, DMA, browser, heuristics',
    tabQuick: 'Quick Check', tabQuickDesc: 'Processes, Prefetch, registry & browser history — no disk walk',
    tabDma: 'DMA Devices', tabDmaDesc: 'Detect DMA cards & FPGA devices',
    tabCleaner: 'PC Cleaner Detection', tabCleanerDesc: 'System cleaning traces, USN journal, timestomping, ShellBags, HWID changes',
    riskHigh: 'High risk', riskMedium: 'Medium risk', riskLow: 'Low risk',
    processRunning: 'Running', processRecent: 'Recent', processPrefetch: 'Prefetch', processMem: 'Memory',
    cheatFiles: 'Files', cheatBrowser: 'History', cheatRegistry: 'Registry',
    dmaPci: 'PCI devices', dmaSoftware: 'Software', dmaDriver: 'Drivers', dmaRegistry: 'Registry',
    typeFile: 'File', typeBrowser: 'Browser', typeProcess: 'Process', typeRegistry: 'Registry',
    typeHardware: 'Hardware', typeSoftware: 'Software',
    typeSystem: 'System',
    noData: 'No data to display',
    dmaDetected: 'DMA devices detected',
    cheatsFound: 'Cheat traces found',
    processesFound: 'Suspicious processes',
    cheatFilesUnit: 'files', cheatProcUnit: 'processes', cheatRegUnit: 'registry',
    cheatBrowserUnit: 'browser', cheatHwUnit: 'hardware', cheatOtherUnit: 'other',
    cheatConfidence: 'confidence',
    cheatOtherActivity: 'Other suspicious activity',
    devicesTitle: 'Connected Devices',
    devicesSafe: 'Normal Devices',
    devicesSuspicious: '⚠ Suspicious Devices',
    devicesHistory: '⏳ DMA History',
    devicesPhone: 'Phone', devicesFlash: 'Flash Drive', devicesDma: 'DMA',
    devicesUnknown: 'Unknown',
    groupCritical: 'Critical risk', groupHigh: 'High risk', groupMedium: 'Medium risk', groupLow: 'Low risk',
    showAll: 'Show all', collapse: 'Collapse',
    groupHidden: 'more hidden',
    searchPlaceholder: 'Search by name, path or matches...',
    searchNoResults: 'Nothing found',
    exportReport: 'Export',
    exportHtml: 'HTML Report',
    exportJson: 'JSON Report',
    exportCopied: 'Copied!',
    scanError: 'Scan error',
    scanErrorHint: 'Try another scan mode or restart the app',
    scanInconclusive: 'Scan completed with gaps',
    scanInconclusiveHint: 'Some modules could not collect data. This result is not confirmed clean.',
    backBtn: 'Back',
    binaryTriage: 'Hardcore binary triage',
    binaryTriageHint: 'PE / TLS / API / packing — file is not executed',
    binaryTriageError: 'Static triage failed',
  },
}

// ── Per-tab cache ──

export interface TabCacheEntry {
  results: ScanResult[]
  summary: ScanResponse['summary']
}

export const tabCache = new Map<ScanMode, TabCacheEntry>()

// ── Mock data ──

export function generateMockData(mode: ScanMode): { results: ScanResult[]; summary: ScanResponse['summary'] } {
  const now = '2026-08-01T10:00:00.000Z'

  const mockSets: Record<ScanMode, { results: ScanResult[]; scanned: number }> = {
    full: {
      results: [
        { path: 'process:Cheat Engine (PID: 4821)', fileName: 'Cheat Engine', type: 'process', risk: 'high', matches: ['process:cheat engine', 'suspicious debugger', 'module:CreateRemoteThread (injector)'], size: 0, modifiedAt: now },
        { path: '~/Downloads/cheat_loader.js', fileName: '[Score:95] cheat_loader.js', type: 'file', risk: 'high', matches: ['Name → [injector]: DLL injector', 'Extension .js: JavaScript', 'Signatures [menu]: ImGui'], size: 15234, modifiedAt: now },
        { path: '~/Desktop/menu.dll', fileName: '[Score:87] menu.dll', type: 'file', risk: 'high', matches: ['High entropy (7.82)', 'Name → [menu]: Game menu'], size: 245760, modifiedAt: now },
        { path: '~/AppData/Local/FiveM/mods/', fileName: '[Score:80] eulen.asi', type: 'file', risk: 'high', matches: ['Extension .asi: ASI mod GTA', 'No digital signature'], size: 320512, modifiedAt: now },
        { path: 'PCI Bus', fileName: 'Xilinx FPGA Device', type: 'hardware', risk: 'high', matches: ['pci:Xilinx (VEN_10ee)', 'FPGA device detected'], size: 0, modifiedAt: now },
        { path: 'HKCU\\\\...\\\\Run', fileName: 'Registry [injector]: inject', type: 'registry', risk: 'high', matches: ['registry-deep:inject', 'risk:CRITICAL'], size: 0, modifiedAt: now },
        { path: 'C:\\\\Windows\\\\Prefetch\\\\DMA_TOOL.EXE-*.pf', fileName: 'Prefetch [dma]: DMA_TOOL.EXE', type: 'file', risk: 'high', matches: ['prefetch:dma', 'last-run:2026-07-20'], size: 0, modifiedAt: now },
        { path: 'Browser History', fileName: 'Chrome History', type: 'browser', risk: 'medium', matches: ['browser:nightfall', 'browser:dma', 'browser:injector'], size: 4096, modifiedAt: now },
      ],
      scanned: 2487,
    },
    quick: {
      results: [
        { path: 'process:Cheat Engine (PID: 4821)', fileName: 'Cheat Engine', type: 'process', risk: 'high', matches: ['process:cheat engine', 'suspicious debugger'], size: 0, modifiedAt: now },
        { path: 'C:\\\\Windows\\\\Prefetch\\\\DMA_TOOL.EXE-*.pf', fileName: 'Prefetch [dma]: DMA_TOOL.EXE', type: 'file', risk: 'high', matches: ['prefetch:dma', 'last-run:2026-07-20'], size: 0, modifiedAt: now },
        { path: 'HKCU\\\\...\\\\Run', fileName: 'Registry [injector]: inject', type: 'registry', risk: 'high', matches: ['registry-deep:inject', 'risk:CRITICAL'], size: 0, modifiedAt: now },
        { path: 'Browser History', fileName: 'Chrome History', type: 'browser', risk: 'medium', matches: ['browser:nightfall', 'browser:dma'], size: 4096, modifiedAt: now },
      ],
      scanned: 45,
    },
    dma: {
      results: [
        { path: 'PCI Bus', fileName: 'Xilinx FPGA Device', type: 'hardware', risk: 'high', matches: ['pci:Xilinx (VEN_10ee)', 'FPGA device detected'], size: 0, modifiedAt: now },
        { path: '~/Downloads/pcileech/', fileName: 'pcileech.exe', type: 'software', risk: 'high', matches: ['dma-software:pcileech.exe', 'DMA memory tool'], size: 0, modifiedAt: now },
        { path: 'System32/drivers/', fileName: 'leeched.sys', type: 'software', risk: 'high', matches: ['dma-driver:leeched.sys', 'DMA kernel driver'], size: 0, modifiedAt: now },
      ],
      scanned: 8,
    },
    cleaner: {
      results: [
        { path: 'C:\\\\$Extend\\\\$UsnJrnl', fileName: '🚨 USN Journal Deleted — Evidence Destruction', type: 'system', risk: 'high', matches: ['usn-journal:deleted', 'All file change history destroyed'], size: 0, modifiedAt: now },
        { path: 'C:\\\\Windows\\\\Prefetch\\\\SDELETE.EXE-*.pf', fileName: '🚨 Secure Deletion Tool: SDELETE', type: 'file', risk: 'high', matches: ['prefetch:sdelete', 'Secure file wiping detected'], size: 0, modifiedAt: now },
        { path: 'HKCU\\\\Software\\\\...\\\\Shell\\\\BagMRU', fileName: '🚨 ShellBags Registry Keys Wiped', type: 'registry', risk: 'high', matches: ['shellbags:missing', 'Folder browsing history wiped'], size: 0, modifiedAt: now },
        { path: 'C:\\\\Users\\\\...\\\\Downloads', fileName: '🚨 Timestomping Detected', type: 'system', risk: 'high', matches: ['timestomp:5+ files', 'File timestamps manipulated'], size: 0, modifiedAt: now },
      ],
      scanned: 42,
    },
  }

  const data = mockSets[mode]
  return {
    results: data.results,
    summary: {
      totalScanned: data.scanned,
      suspiciousFiles: data.results.length,
      highRiskCount: data.results.filter(r => r.risk === 'high').length,
      scanTimeMs: 1800 + data.results.length * 100,
    },
  }
}
