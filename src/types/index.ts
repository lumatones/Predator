export type AppPhase =
  | 'loading'
  | 'onboarding-welcome' | 'onboarding-lang'
  | 'onboarding-theme' | 'onboarding-auth' | 'onboarding-demo'
  | 'requesting-access'
  | 'main' | 'checker' | 'dashboard'

export type ThemeId = 'predator' | 'ocean' | 'stealth' | 'nebula'

export interface ThemeColors {
  accent: string; light: string; dark: string
  bg: string; card: string; name: string
}

export type Lang = 'ru' | 'en'

export interface UpdateModalState {
  show: boolean
  version: string
  state: 'available' | 'downloading' | 'done' | 'error'
  percent: number
  speed: string
  size: string
  errorMsg: string
}

export const THEMES: Record<ThemeId, ThemeColors> = {
  predator: { accent: '#ff4d5a', light: '#ff8a5b', dark: '#b91c1c', bg: '#0a0202', card: '#140a0a', name: 'Predator Red' },
  ocean:    { accent: '#7dd3fc', light: '#60a5fa', dark: '#1d4ed8', bg: '#02020a', card: '#0a0d16', name: 'Ocean Blue' },
  stealth:  { accent: '#a1a1aa', light: '#e4e4e7', dark: '#3f3f46', bg: '#050505', card: '#101010', name: 'Stealth Black' },
  nebula:   { accent: '#c084fc', light: '#f0abfc', dark: '#7c3aed', bg: '#060210', card: '#0f0a1a', name: 'Nebula Purple' },
}

// Demo scan findings — separate from T to avoid string|string[] type widening
export const DEMO_FINDINGS: Record<Lang, string[]> = {
  ru: ['Nightfall.dll — Чит-меню (CRITICAL)', 'kdmapper.exe — Загрузчик драйвера (HIGH)', 'injector.dll — DLL-инжектор (HIGH)', 'suspicious_registry — Автозагрузка (MEDIUM)', 'dma_fpga — DMA-устройство (CRITICAL)'],
  en: ['Nightfall.dll — Cheat menu (CRITICAL)', 'kdmapper.exe — Driver loader (HIGH)', 'injector.dll — DLL injector (HIGH)', 'suspicious_registry — Auto-run (MEDIUM)', 'dma_fpga — DMA device (CRITICAL)'],
}

export const T: Record<Lang, Record<string, string>> = {
  ru: {
    title: 'Система проверки безопасности',
    close: 'Закрыть', updateAvailable: 'Доступно обновление', download: 'Скачать',
    downloading: 'Загрузка обновления...', downloaded: 'Обновление готово!',
    installRestart: 'Установить и перезапустить',
    ready: 'Система готова', startCheck: 'Начать проверку', dashboard: 'Мониторинг', continue: 'Продолжить',
    // Onboarding v2
    welcomeTitle: 'Добро пожаловать в Predator',
    welcomeDesc: 'Античит-сканер для GTA 5 RP. Мы проверим ваш ПК на наличие читов, инжекторов и подозрительного ПО.',
    welcomeStart: 'Начать настройку',
    langTitle: 'Выберите язык', langDesc: 'Язык интерфейса приложения',
    langRu: 'Русский', langEn: 'English', next: 'Далее',
    themeTitle: 'Выберите тему', themeDesc: 'Оформление приложения',
    authTitle: 'Авторизация', authDesc: 'Введите токен доступа, полученный от администратора',
    authPlaceholder: 'XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX',
    authError: 'Токен должен содержать 32 символа',
    authBtn: 'Подтвердить', authAlt: 'Запросить доступ через сайт',
    tokenLabel: 'Токен доступа',
    requestSent: 'Запрос отправлен!', requestPending: 'Ожидание подтверждения администратором...',
    requestApproved: 'Запрос одобрен!', requestRejected: 'Запрос отклонён',
    requestId: 'ID запроса', requesting: 'Отправка запроса...', cancel: 'Отмена',
    // Demo scan
    demoTitle: 'Демо-сканирование', demoDesc: 'Посмотрите, как Predator находит угрозы на примере симуляции',
    demoStart: 'Запустить демо-скан', demoScanning: 'Сканирование...',
    demoDone: 'Демо завершено!', demoDoneDesc: 'Predator обнаружил бы эти угрозы при реальном сканировании. Это демонстрация — ваш ПК не проверялся.',
    demoEnterApp: 'Войти в приложение',
  },
  en: {
    title: 'Security Check System',
    close: 'Close', updateAvailable: 'Update Available', download: 'Download',
    downloading: 'Downloading update...', downloaded: 'Update Ready!',
    installRestart: 'Install & Restart',
    ready: 'System Ready', startCheck: 'Start Check', dashboard: 'Dashboard', continue: 'Continue',
    // Onboarding v2
    welcomeTitle: 'Welcome to Predator',
    welcomeDesc: 'Anti-cheat scanner for GTA 5 RP. We check your PC for cheats, injectors, and suspicious software.',
    welcomeStart: 'Start Setup',
    langTitle: 'Choose Language', langDesc: 'Application interface language',
    langRu: 'Русский', langEn: 'English', next: 'Next',
    themeTitle: 'Choose Theme', themeDesc: 'Application appearance',
    authTitle: 'Authorization', authDesc: 'Enter the access token from your administrator',
    authPlaceholder: 'XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX',
    authError: 'Token must contain 32 characters',
    authBtn: 'Confirm', authAlt: 'Request access via website',
    tokenLabel: 'Access Token',
    requestSent: 'Request sent!', requestPending: 'Waiting for admin approval...',
    requestApproved: 'Request approved!', requestRejected: 'Request rejected',
    requestId: 'Request ID', requesting: 'Sending request...', cancel: 'Cancel',
    // Demo scan
    demoTitle: 'Demo Scan', demoDesc: 'See how Predator detects threats with a simulated scan',
    demoStart: 'Start Demo Scan', demoScanning: 'Scanning...',
    demoDone: 'Demo Complete!', demoDoneDesc: 'Predator would have detected these threats in a real scan. This is a demonstration — your PC was not scanned.',
    demoEnterApp: 'Enter Application',
  },
}
