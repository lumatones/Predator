import type { ScanResult } from '../types/electron'
import type { Lang } from '../types'

export type FindingKind = 'dma' | 'process' | 'registry' | 'browser' | 'cleaner' | 'file' | 'software' | 'system'

export interface FindingEvidence {
  source: string
  weight: number
  confidence: number
  label: string
  detail: string
}

export interface FindingExplanation {
  kind: FindingKind
  title: string
  description: string
  whyDangerous: string
  recommendation: string
  confidenceNote: string
  indicators: string[]
  evidence: FindingEvidence[]
}

export const TYPE_LABELS: Record<Lang, Record<string, string>> = {
  ru: {
    file: 'Файл',
    browser: 'История браузера',
    process: 'Процесс',
    registry: 'Реестр',
    hardware: 'Оборудование',
    software: 'Программа или драйвер',
    system: 'Системный след',
  },
  en: {
    file: 'File',
    browser: 'Browser history',
    process: 'Process',
    registry: 'Registry',
    hardware: 'Hardware',
    software: 'Software or driver',
    system: 'System trace',
  },
}

export function normalizeFindingText(finding: Pick<ScanResult, 'fileName' | 'path' | 'matches'>): string {
  return `${finding.fileName} ${finding.path} ${finding.matches.join(' ')}`.toLowerCase()
}

export function getFindingKind(finding: Pick<ScanResult, 'type' | 'fileName' | 'path' | 'matches'>): FindingKind {
  const haystack = normalizeFindingText(finding)
  if (finding.type === 'hardware' || /dma|fpga|xilinx|pcileech|pci|thunderbolt|usb/.test(haystack)) return 'dma'
  if (/usn|journal|sdelete|shellbags|timestomp|clean|wipe|deleted|evidence/.test(haystack)) return 'cleaner'
  if (finding.type === 'process' || /process|pid|remote thread|createremotethread|debugger|cheat engine/.test(haystack)) return 'process'
  if (finding.type === 'registry' || /registry|hkcu|hklm|runonce|winlogon|service/.test(haystack)) return 'registry'
  if (finding.type === 'browser' || /browser|history|download|site|url/.test(haystack)) return 'browser'
  if (finding.type === 'software' || /driver|\.sys|service|tool|software/.test(haystack)) return 'software'
  if (finding.type === 'system') return 'system'
  return 'file'
}

function addUnique(target: string[], value: string): void {
  if (!target.includes(value)) target.push(value)
}

function extractIndicators(finding: Pick<ScanResult, 'matches' | 'fileName' | 'path'>): string[] {
  const haystack = normalizeFindingText(finding)
  const indicators: string[] = []

  if (/entropy|packed|vmprotect|themida|upx|obfuscat/.test(haystack)) addUnique(indicators, 'Высокая энтропия или упаковка: файл может быть сжат, зашифрован или намеренно скрыт от анализа.')
  if (/inject|remote thread|createremotethread|dll/.test(haystack)) addUnique(indicators, 'Признаки инжекта: код может внедряться в другой процесс игры или лаунчера.')
  if (/unsigned|not signed|no digital signature|signature/.test(haystack)) addUnique(indicators, 'Проблема с цифровой подписью: доверенный издатель не подтверждён.')
  if (/yara|signature|pattern|match/.test(haystack)) addUnique(indicators, 'Сработали сигнатуры: найдено совпадение с известными шаблонами читов или обходов.')
  if (/prefetch|last-run/.test(haystack)) addUnique(indicators, 'Prefetch показывает, что похожая программа запускалась на этом ПК.')
  if (/browser|history|download/.test(haystack)) addUnique(indicators, 'В истории браузера есть запросы или страницы, связанные с читами, DMA или инжекторами.')
  if (/registry|run|service|winlogon/.test(haystack)) addUnique(indicators, 'След в реестре может указывать на автозапуск или закрепление в системе.')
  if (/dma|fpga|pci|pcileech|xilinx/.test(haystack)) addUnique(indicators, 'DMA/FPGA-индикатор: устройство или ПО может читать память напрямую, обходя обычную защиту.')
  if (/usn|journal|sdelete|shellbags|timestomp|wipe|deleted/.test(haystack)) addUnique(indicators, 'Признаки чистки следов: удаление журналов, ShellBags или изменение времени файлов мешает проверке истории действий.')

  finding.matches.slice(0, 4).forEach(match => {
    if (indicators.length < 6) addUnique(indicators, `Сырой индикатор сканера: ${match}`)
  })

  return indicators.slice(0, 6)
}

function buildEvidence(finding: ScanResult): FindingEvidence[] {
  const haystack = normalizeFindingText(finding)
  const evidence: FindingEvidence[] = []
  const push = (source: string, weight: number, confidence: number, label: string, detail: string) => {
    evidence.push({ source, weight, confidence, label, detail })
  }

  if (/signature|yara|pattern|hash|tlsh/.test(haystack)) push('signature', 0.9, 85, 'Сигнатурное совпадение', 'Найдено совпадение с известным правилом, хешем или бинарным шаблоном.')
  if (/entropy|packed|obfuscat|vmprotect|themida|upx/.test(haystack)) push('heuristic', 0.55, 65, 'Эвристика упаковки', 'Файл похож на упакованный или обфусцированный бинарник.')
  if (/prefetch|last-run/.test(haystack)) push('forensic', 0.75, 80, 'След запуска', 'Системные артефакты указывают, что похожая программа запускалась.')
  if (/registry|run|service|winlogon/.test(haystack)) push('registry', 0.65, 70, 'След в реестре', 'Запись может быть связана с автозапуском или закреплением.')
  if (/dma|fpga|pci|pcileech|xilinx/.test(haystack)) push('dma', 0.95, 90, 'DMA-индикатор', 'Найден признак устройства или утилиты прямого доступа к памяти.')
  if (/browser|history|download/.test(haystack)) push('browser', 0.35, 45, 'Контекст браузера', 'История браузера усиливает контекст, но сама по себе не доказывает запуск.')
  if (/usn|journal|sdelete|shellbags|timestomp|wipe|deleted/.test(haystack)) push('anti-forensic', 0.8, 82, 'Антифорензика', 'Найдены признаки сокрытия или удаления следов активности.')

  if (evidence.length === 0) {
    const baseConfidence = finding.risk === 'high' ? 70 : finding.risk === 'medium' ? 50 : 30
    push(finding.type, finding.risk === 'high' ? 0.7 : finding.risk === 'medium' ? 0.45 : 0.2, baseConfidence, 'Общий индикатор', 'Сработали совпадения сканера, требующие ручной проверки.')
  }

  return evidence
}

export function buildFindingExplanation(finding: ScanResult, lang: Lang = 'ru'): FindingExplanation {
  const kind = getFindingKind(finding)
  const riskText = finding.risk === 'high' ? 'высокий' : finding.risk === 'medium' ? 'средний' : 'низкий'

  const ruBase: Record<FindingKind, Omit<FindingExplanation, 'kind' | 'confidenceNote' | 'indicators' | 'evidence'>> = {
    dma: {
      title: 'Возможный DMA/FPGA след',
      description: 'Сканер увидел устройство, драйвер или программу, которые похожи на инструменты прямого доступа к памяти. Такие решения используют PCI/USB/FPGA-оборудование или DMA-утилиты для чтения памяти игры вне обычного процесса.',
      whyDangerous: 'DMA может обходить стандартные проверки античита: чит работает не как обычная программа в Windows, а через внешнее устройство или низкоуровневый драйвер.',
      recommendation: 'Проверьте, что это устройство действительно нужно. Если речь про неизвестную плату, драйвер или pcileech-подобную утилиту, отключите устройство, удалите ПО и повторите Scan.',
    },
    process: {
      title: 'Подозрительный процесс',
      description: 'Во время Scan найден запущенный процесс с признаками чита, отладчика, инжектора или инструмента вмешательства в память игры.',
      whyDangerous: 'Такие процессы могут читать или менять память GTA/FiveM/RAGE MP/ALT:V, внедрять DLL, создавать удалённые потоки и маскироваться под легальные программы.',
      recommendation: 'Закройте процесс, проверьте путь запуска и удалите программу, если она не является доверенной. Затем перезапустите игру и повторите Scan.',
    },
    registry: {
      title: 'Подозрительная запись в реестре',
      description: 'Найдена запись реестра, похожая на след автозапуска, закрепления в системе, драйвера или настройки, связанной с читом/обходом.',
      whyDangerous: 'Реестр часто используют для автозагрузки, скрытого запуска компонентов, восстановления после перезагрузки и хранения следов ранее установленного ПО.',
      recommendation: 'Не удаляйте ключ вслепую. Проверьте путь и название программы. Если запись связана с неизвестным читом, удалите её после резервной копии.',
    },
    browser: {
      title: 'След в истории браузера',
      description: 'Сканер нашёл в истории браузера запросы, сайты или загрузки, связанные с читами, DMA, инжекторами или обходами античита.',
      whyDangerous: 'Сам по себе сайт не доказывает запуск чита, но это важный контекст: он показывает, что пользователь искал или скачивал подозрительное ПО.',
      recommendation: 'Сверьте домен, дату и контекст. Если рядом есть скачанные файлы или Prefetch-запуск, такой след усиливает общий Risk Score.',
    },
    cleaner: {
      title: 'Признаки чистки следов',
      description: 'Обнаружены действия, похожие на удаление истории системы: очистка USN-журнала, Prefetch, ShellBags, безопасное удаление файлов или изменение временных меток.',
      whyDangerous: 'Такая активность не всегда является читом, но часто используется после запуска запрещённого ПО, чтобы скрыть факт запуска и удаления файлов.',
      recommendation: 'Проверьте, когда выполнялась чистка и каким инструментом. Если пользователь не может объяснить причину, учитывайте это как серьёзный дополнительный сигнал.',
    },
    file: {
      title: 'Подозрительный файл',
      description: 'Файл совпал с одним или несколькими признаками читов: название, расширение, сигнатура, высокая энтропия, отсутствие подписи или похожие бинарные шаблоны.',
      whyDangerous: 'Файлы читов часто маскируются под обычные DLL/ASI/EXE/JS, упаковываются и загружаются в игровой процесс или клиентские папки GTA RP.',
      recommendation: 'Проверьте происхождение файла. Если он находится в папках игры, загрузок или AppData и не является доверенным модом, переместите его в карантин или удалите.',
    },
    software: {
      title: 'Подозрительное ПО или драйвер',
      description: 'Найдена программа, драйвер или служебный компонент, который похож на инструмент инжекта, DMA, спуфинга, отладки или обхода античита.',
      whyDangerous: 'Драйверы и сервисные утилиты имеют больше прав, чем обычные приложения, поэтому могут скрывать процессы, читать память или менять системные идентификаторы.',
      recommendation: 'Проверьте издателя и назначение. Неизвестные драйверы и сервисы лучше удалить, затем перезагрузить ПК и повторить Scan.',
    },
    system: {
      title: 'Подозрительный системный след',
      description: 'Сканер обнаружил системный индикатор, который не относится к одному файлу: изменение журналов, памяти, сетевых признаков, служб или поведения системы.',
      whyDangerous: 'Такие следы важны в совокупности: они могут показывать подготовку, запуск или сокрытие запрещённого ПО.',
      recommendation: 'Оцените этот пункт вместе с остальными Finding. Если есть несколько независимых сигналов, риск следует считать выше.',
    },
  }

  if (lang === 'en') {
    return {
      kind,
      title: ruBase[kind].title,
      description: ruBase[kind].description,
      whyDangerous: ruBase[kind].whyDangerous,
      recommendation: ruBase[kind].recommendation,
      confidenceNote: `Risk assessment: ${riskText}. It is based on the matches below and becomes more reliable when several independent indicators point to the same activity.`,
      indicators: extractIndicators(finding),
      evidence: buildEvidence(finding),
    }
  }

  return {
    kind,
    ...ruBase[kind],
    confidenceNote: `Оценка риска: ${riskText}. Она строится по совпадениям ниже и становится точнее, когда несколько независимых индикаторов указывают на одно и то же.`,
    indicators: extractIndicators(finding),
    evidence: buildEvidence(finding),
  }
}
