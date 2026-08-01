#!/usr/bin/env node
/* eslint-disable @typescript-eslint/no-require-imports */
/**
 * Predator — Subproject self-containment check
 *
 * Guards CI against "works on my machine" failures caused by root node_modules
 * hoisting (see the v0.5.0 CI incident: server was missing `vitest` in its
 * devDependencies, and website had no tsconfig.json so `tsc` walked up to the
 * root config and typechecked the wrong tree).
 *
 * For each subproject (server, website, admin):
 *   1. its own tsconfig.json must exist — otherwise `tsc` picks up the root
 *      config and typechecks `../src/*` against the wrong node_modules;
 *   2. every bare-module import in its source must be declared in its own
 *      package.json (dependencies + devDependencies + peerDependencies) —
 *      because CI installs each subproject in isolation via `npm ci`, and
 *      nothing may resolve from the root.
 *
 * Run: node scripts/check-subprojects.js
 * Exit code 1 on any failure.
 */

'use strict'

const fs = require('fs')
const path = require('path')
const { builtinModules } = require('module')

const ROOT = path.join(__dirname, '..')
const SUBPROJECTS = ['server', 'website', 'admin']

// Node built-ins (both prefixed and plain forms)
const BUILTINS = new Set([
  ...builtinModules,
  ...builtinModules.map((m) => m.replace(/^node:/, '')),
])

let failed = false
function fail(msg) {
  failed = true
  console.error(`  ✗ ${msg}`)
}

// ── Collect source files (skip deps/build output) ──────────
function collectFiles(dir, out = []) {
  let entries
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true })
  } catch {
    return out
  }
  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue
    if (entry.name === 'dist' || entry.name === 'release' || entry.name === 'out' || entry.name === 'build') continue
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) collectFiles(full, out)
    else if (/\.(ts|tsx|mts|cts|mjs|cjs)$/.test(entry.name)) out.push(full)
  }
  return out
}

// ── Extract bare module specifiers from source ─────────────
function extractImports(source) {
  const specs = new Set()
  // import x from 'y'; import {x} from 'y'; import type {x} from 'y'
  // export {x} from 'y'; export * from 'y'; import 'y'; import('y')
  const re = /(?:^|\n)\s*(?:import|export)\b[^'"]*?\bfrom\s+['"]([^'"]+)['"]|^\s*import\s+['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]\s*\)/gm
  let m
  while ((m = re.exec(source)) !== null) {
    const spec = m[1] || m[2] || m[3]
    if (spec && !spec.startsWith('.')) specs.add(spec)
  }
  // CommonJS require('x') — e.g. in config helpers and .cjs files
  const req = /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g
  while ((m = req.exec(source)) !== null) {
    if (!m[1].startsWith('.')) specs.add(m[1])
  }
  // triple-slash type references (e.g. /// <reference types="vite/client" />)
  const tsl = /\/\/\/\s*<reference\s+types\s*=\s*['"]([^'"]+)['"]/g
  while ((m = tsl.exec(source)) !== null) specs.add(m[1])
  return [...specs]
}

// Strip a subpath to the owning package name ('react-dom/client' → 'react-dom')
function basePackage(spec) {
  const [first, second] = spec.split('/')
  return first.startsWith('@') ? `${first}/${second}` : first
}

// ── Per-subproject checks ──────────────────────────────────
function checkSubproject(name) {
  const dir = path.join(ROOT, name)
  console.log(`\n[${name}]`)

  // 1. tsconfig.json
  if (!fs.existsSync(path.join(dir, 'tsconfig.json'))) {
    fail(`${name}/tsconfig.json отсутствует — tsc подхватит корневой конфиг`)
  } else {
    console.log('  ✓ tsconfig.json')
  }

  // 2. Declared dependencies
  const pkgPath = path.join(dir, 'package.json')
  if (!fs.existsSync(pkgPath)) {
    fail(`${name}/package.json отсутствует`)
    return
  }
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
  const declared = new Set([
    ...Object.keys(pkg.dependencies || {}),
    ...Object.keys(pkg.devDependencies || {}),
    ...Object.keys(pkg.peerDependencies || {}),
  ])

  const missing = new Map() // packageName -> [file...]
  const files = collectFiles(dir)
  for (const file of files) {
    const source = fs.readFileSync(file, 'utf8')
    for (const spec of extractImports(source)) {
      if (BUILTINS.has(spec)) continue
      const base = basePackage(spec)
      if (declared.has(base)) continue
      if (!missing.has(base)) missing.set(base, [])
      missing.get(base).push(path.relative(ROOT, file))
    }
  }

  if (missing.size === 0) {
    console.log(`  ✓ все импорты объявлены (${files.length} файлов проверено)`)
  } else {
    for (const [base, fileList] of missing) {
      fail(`${name}: импорт '${base}' не объявлен в package.json`)
      for (const f of fileList.slice(0, 5)) console.error(`      ${f}`)
    }
  }
}

// ── Main ───────────────────────────────────────────────────
console.log('🔍 Проверка самодостаточности подпроектов (tsconfig + объявленные импорты)...')
for (const sub of SUBPROJECTS) checkSubproject(sub)

console.log('')
if (failed) {
  console.error('❌ Обнаружены подпроекты, зависящие от корневого node_modules.')
  process.exit(1)
}
console.log('✅ Все подпроекты самодостаточны.')
