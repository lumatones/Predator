#!/usr/bin/env node
/**
 * Predator — AI Model Router (npm run ai:route)
 *
 * Routes engineering tasks to the best model of the trio:
 *   GLM 5.2, DeepSeek V4 Pro / Flash, GPT 5.6 Luna.
 *
 * Usage:
 *   npm run ai:route -- --task "refactor risk-scorer.ts" --files electron/risk-scorer.ts
 *   npm run ai:route -- --task "generate YARA rules" --mode cost
 *   npm run ai:route -- --task "debug scan hang" --files electron/scan-pipeline.ts --json
 *   npm run ai:route -- --list
 *
 * Config: scripts/ai-router/config.json (models, task types, path rules, thresholds)
 * Modes:  balanced (default) | cost (bias to cheap) | quality (bias to strong)
 */

import { parseArgs } from 'node:util'
import { readFileSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const CONFIG_PATH = join(ROOT, 'scripts', 'ai-router', 'config.json')

const MODES = ['balanced', 'cost', 'quality']
const QUALITY_TIERS = ['glm-5.2', 'deepseek-v4-pro']
const MULTI_FILE_MODELS = ['glm-5.2', 'deepseek-v4-pro', 'deepseek-v4-flash']
const PRIORITY = ['security', 'long-context', 'refactor', 'debug', 'generate', 'boilerplate', 'triage']
const FALLBACK_INPUT_TOKENS = 20_000

// ── Config & CLI ───────────────────────────────────────────

function loadConfig() {
  return JSON.parse(readFileSync(CONFIG_PATH, 'utf8'))
}

function parseCli() {
  const { values } = parseArgs({
    options: {
      task: { type: 'string', short: 't' },
      files: { type: 'string', short: 'f', multiple: true },
      mode: { type: 'string', short: 'm', default: 'balanced' },
      json: { type: 'boolean' },
      list: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
    allowPositionals: false,
  })
  return values
}

function normalizeFiles(values) {
  return (values.files ?? [])
    .flatMap((entry) => entry.split(','))
    .map((entry) => entry.trim())
    .filter(Boolean)
}

// ── Classification ─────────────────────────────────────────

function globToRegExp(glob) {
  const source = glob
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000')
    .replace(/\*/g, '[^/]*')
    .replace(/\u0000/g, '.*')
  return new RegExp(`^${source}$`)
}

function matchFile(file, glob) {
  const normalized = file.replace(/\\/g, '/')
  const regex = globToRegExp(glob)
  return regex.test(normalized) || regex.test(normalized.split('/').pop() ?? '')
}

function collectPathHits(files, pathRules) {
  const hits = new Map()
  for (const rule of pathRules) {
    const matched = files.filter((file) => matchFile(file, rule.glob))
    if (matched.length === 0) continue
    if (!hits.has(rule.model)) hits.set(rule.model, [])
    hits.get(rule.model).push({ rule, files: matched })
  }
  return hits
}

function classifyTask(text, taskTypes) {
  const lower = text.toLowerCase()
  let best = { type: 'general', hits: 0 }
  for (const type of PRIORITY) {
    const hits = taskTypes[type].keywords.filter((keyword) => lower.includes(keyword.toLowerCase())).length
    if (hits > best.hits) best = { type, hits }
  }
  return best
}

// ── Scoring ────────────────────────────────────────────────

function estimateTokens(files) {
  let bytes = 0
  for (const file of files) {
    try {
      bytes += statSync(file).size
    } catch {
      /* ignore missing files */
    }
  }
  return Math.round(bytes / 4)
}

function cheapestInput(models) {
  return Math.min(...Object.values(models).map((model) => model.inputPerMTokens))
}

function estimateCost(model, inputTokens) {
  const outputTokens = Math.round(inputTokens * 0.25)
  const inputCost = (inputTokens / 1_000_000) * model.inputPerMTokens
  const outputCost = (outputTokens / 1_000_000) * model.outputPerMTokens
  return { inputTokens, outputTokens, total: inputCost + outputCost }
}

function scoreModel(key, model, task, context, mode) {
  const base = model.scores[task.type] ?? model.scores.general ?? 60
  const adjustments = []
  let delta = 0

  const pathHits = context.pathHits.get(key)
  if (pathHits && pathHits.length > 0) {
    delta += 15
    adjustments.push(`путь:${pathHits[0].rule.reason}`)
  }
  if (context.multiFile && MULTI_FILE_MODELS.includes(key)) {
    delta += 10
    adjustments.push('multi-file')
  }
  if (context.longContext && MULTI_FILE_MODELS.includes(key)) {
    delta += 10
    adjustments.push('long-context')
  }
  if (context.longContext && key === 'gpt-5.6-luna') {
    delta -= 8
    adjustments.push('luna: застревает на глубокой навигации')
  }
  if (task.type === 'security' && key === 'deepseek-v4-pro') {
    delta -= 10
    adjustments.push('deepseek: угадывает вместо «не знаю»')
  }

  let total = base + delta
  if (mode === 'cost') {
    total = total * Math.pow(context.cheapestInput / model.inputPerMTokens, 0.25)
  } else if (mode === 'quality' && QUALITY_TIERS.includes(key)) {
    total += 6
  }

  return { key, base, delta, total: Math.round(total), adjustments }
}

// ── Output ─────────────────────────────────────────────────

function formatTokens(count) {
  if (count >= 1_000_000) return `${(count / 1_000_000).toFixed(1)}M`
  if (count >= 1_000) return `${Math.round(count / 1_000)}K`
  return String(count)
}

function formatMoney(value) {
  return `$${value.toFixed(2)}`
}

function defaultModelFor(type, models) {
  return Object.entries(models).reduce(
    (best, [key, model]) => {
      const score = model.scores[type] ?? model.scores.general ?? 0
      return score > best.score ? { key, score } : best
    },
    { key: '—', score: -1 },
  ).key
}

function renderDecision(values, task, files, tokens, scores, winner, winnerModel, cost, longContext) {
  const mode = values.mode
  const type = task.type === 'general' ? 'общая задача' : task.type
  console.log('')
  console.log(`┌─ Задача: ${values.task}`)
  console.log(`├─ Тип:     ${type}${task.hits > 0 ? ` (совпадений: ${task.hits})` : ''} | Режим: ${mode}`)
  console.log(`├─ Файлы:   ${files.length === 0 ? '—' : files.join(', ')}`)
  console.log(`└─ Контекст: ~${formatTokens(tokens)} токенов${longContext ? ' → long-context' : ''}`)
  console.log('')
  console.log('  Модель                Баз   Δ       Итог')
  console.log('  ──────────────────────────────────────────')
  for (const score of scores) {
    const marker = score.key === winner.key ? ' ←' : ''
    console.log(`  ${score.key.padEnd(21)} ${String(score.base).padStart(3)} ${String(score.delta).padStart(4)} ${String(score.total).padStart(5)}${marker}`)
  }
  console.log('')
  console.log(`  ✅ Рекомендация: ${winnerModel.name}`)
  if (winner.adjustments.length > 0) {
    console.log(`     Причины: ${winner.adjustments.join('; ')}`)
  }
  for (const strength of winnerModel.strengths.slice(0, 3)) {
    console.log(`     • ${strength}`)
  }
  console.log('')
  console.log(`  ▶ Runner: ${winnerModel.runner}`)
  console.log(`  💰 Стоимость (оценка): вход ~${formatTokens(cost.inputTokens)} → ${formatMoney(cost.total)}`)
  console.log('')
}

function renderCostTable(costs, tokens) {
  console.log(`  Альтернативы по цене (вход ~${formatTokens(tokens)} ток.):`)
  console.log('  ───────────────────────────────────────────────────────')
  console.log(`  ${'Модель'.padEnd(24)} ${'Вход (ток)'.padStart(10)} ${'Выход (ток)'.padStart(11)} ${'Стоимость ($)'.padStart(13)}`)
  for (const entry of costs) {
    console.log(`  ${entry.key.padEnd(24)} ${formatTokens(entry.inputTokens).padStart(10)} ${formatTokens(entry.outputTokens).padStart(11)} ${formatMoney(entry.total).padStart(13)}`)
  }
  console.log('')
}

function renderJson(payload) {
  console.log(JSON.stringify(payload, null, 2))
}

function renderList(config) {
  console.log('  Модели:')
  for (const [key, model] of Object.entries(config.models)) {
    console.log(`  • ${key} — ${model.name} (${model.provider}) — ${formatMoney(model.inputPerMTokens)}/${formatMoney(model.outputPerMTokens)} за 1M, контекст ${formatTokens(model.contextWindow)}`)
  }
  console.log('')
  console.log('  Типы задач и модель по умолчанию:')
  for (const [type, rule] of Object.entries(config.taskTypes)) {
    console.log(`  • ${type.padEnd(12)} → ${defaultModelFor(type, config.models)}  (${rule.description})`)
  }
  console.log('')
  console.log('  Path-правила:')
  for (const rule of config.pathRules) {
    console.log(`  • ${rule.glob.padEnd(38)} → ${rule.model}`)
  }
  console.log('')
  console.log(`  Пороги: multi-file ≥ ${config.thresholds.multiFileCount}, long-context ≥ ${formatTokens(config.thresholds.longContextTokens)} токенов`)
}

function renderHelp() {
  console.log(`
Predator — AI Model Router

Распределяет инженерные задачи между GLM 5.2, DeepSeek V4 Pro/Flash и GPT 5.6 Luna.

Использование:
  npm run ai:route -- --task "<описание задачи>" [--files <пути>] [--mode <mode>] [--json]
  npm run ai:route -- --list        # показать конфигурацию
  npm run ai:route -- --help        # эта справка

Опции:
  -t, --task    Описание задачи на русском или английском
  -f, --files   Затронутые файлы — повторяйте флаг или разделяйте запятыми: -f a.ts -f b.ts / -f a.ts,b.ts
  -m, --mode    balanced | cost | quality  (по умолчанию: balanced)
  --json        Вывод в JSON (для скриптов/CI)
  --list        Список моделей, типов задач и path-правил

Примеры:
  npm run ai:route -- --task "рефактор risk-scorer.ts" --files electron/risk-scorer.ts
  npm run ai:route -- --task "generate YARA rules" --mode cost
  npm run ai:route -- --task "debug scan hang" --files electron/scan-pipeline.ts,electron/risk-scorer.ts --json
  npm run ai:route -- --task "audit self-protect" -f electron/self-protect.ts -f electron/anti-tamper.ts
`)
}

// ── Main ───────────────────────────────────────────────────

function main() {
  const values = parseCli()
  if (values.help) return renderHelp()

  const config = loadConfig()
  if (values.list) return renderList(config)

  if (!values.task) {
    console.error('Укажите --task "описание задачи". Смотрите --help.')
    process.exitCode = 1
    return
  }
  if (!MODES.includes(values.mode)) {
    console.error(`Неизвестный режим "${values.mode}". Допустимые: ${MODES.join(', ')}.`)
    process.exitCode = 1
    return
  }

  const files = normalizeFiles(values)
  const task = classifyTask(values.task, config.taskTypes)
  const tokens = files.length === 0 ? FALLBACK_INPUT_TOKENS : Math.max(estimateTokens(files), 1)
  const pathHits = collectPathHits(files, config.pathRules)
  const context = {
    pathHits,
    multiFile: files.length >= config.thresholds.multiFileCount,
    longContext: tokens >= config.thresholds.longContextTokens || task.type === 'long-context',
    cheapestInput: cheapestInput(config.models),
  }

  const scores = Object.entries(config.models)
    .map(([key, model]) => scoreModel(key, model, task, context, values.mode))
    .sort((a, b) => b.total - a.total)
  const winner = scores[0]
  const winnerModel = config.models[winner.key]
  const cost = estimateCost(winnerModel, tokens)

  const costs = scores.slice(0, 3).map((score) => {
    const c = estimateCost(config.models[score.key], tokens)
    return { key: score.key, name: config.models[score.key].name, ...c }
  })

  if (values.json) {
    return renderJson({
      task: values.task,
      type: task.type,
      mode: values.mode,
      files,
      tokens,
      longContext: context.longContext,
      scores,
      recommendation: { key: winner.key, name: winnerModel.name, runner: winnerModel.runner, cost: estimateCost(winnerModel, tokens) },
      costs,
    })
  }

  renderDecision(values, task, files, tokens, scores, winner, winnerModel, cost, context.longContext)
  renderCostTable(costs, tokens)
}

main()
