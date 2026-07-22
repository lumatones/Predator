const envResult = require('dotenv').config()

const express = require('express')
const cors = require('cors')
const path = require('path')

const { testConnection } = require('./config/database')
const authRoutes = require('./routes/auth')
const adminRoutes = require('./routes/admin')

const app = express()
// PORT из .env имеет приоритет над системной переменной окружения
const PORT = (envResult.parsed && envResult.parsed.PORT) || process.env.PORT || 3001

// ── Middleware ─────────────────────────────────

app.use(cors())
app.use(express.json())

// ── Routes ────────────────────────────────────

app.use('/api/auth', authRoutes)
app.use('/api/admin', adminRoutes)

// ── Health check ──────────────────────────────

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0', timestamp: new Date().toISOString() })
})

// ── Start ─────────────────────────────────────

async function start() {
  console.log('\n  🦅 Predator API Server\n')

  const dbOk = await testConnection()
  if (!dbOk) {
    console.log('\n  ⚠️  Запуск без БД. API будет работать,\n'
      + '  но эндпоинты с БД будут возвращать ошибки.\n'
      + '  Запустите WAMP и выполните: npm run db:init\n')
  }

  app.listen(PORT, () => {
    console.log(`  ✓ Server: http://localhost:${PORT}\n`)
    console.log('  ── Endpoints ──')
    console.log(`  POST /api/auth/token         Проверить токен`)
    console.log(`  POST /api/auth/request       Запросить доступ`)
    console.log(`  GET  /api/auth/status/:id    Статус запроса`)
    console.log(`  GET  /api/health             Health check`)
    console.log(`  ── Admin (требуется JWT) ────`)
    console.log(`  POST /api/admin/login        Вход админа`)
    console.log(`  GET  /api/admin/pending      Ожидающие запросы`)
    console.log(`  POST /api/admin/approve/:id  Одобрить`)
    console.log(`  POST /api/admin/reject/:id   Отклонить`)
    console.log(`  POST /api/admin/tokens/generate  Создать токены`)
    console.log(`  GET  /api/admin/tokens       Список токенов`)
    console.log(`  POST /api/admin/tokens/revoke/:id  Отозвать токен\n`)
  })
}

start().catch(console.error)
