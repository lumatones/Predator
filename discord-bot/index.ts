/**
 * Predator — Discord Bot
 *
 * Features:
 *   /check — Request a player check
 *   /status — Check request status
 *   /link — Link server to Predator account
 *   Auto-notifications when checks complete
 *
 * Setup:
 *   1. Create bot at https://discord.com/developers/applications
 *   2. Set DISCORD_BOT_TOKEN and DISCORD_CLIENT_ID in .env
 *   3. npm install discord.js
 *   4. node dist-bot/index.js
 */

import { Client, GatewayIntentBits, SlashCommandBuilder, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle } from 'discord.js'
import http from 'http'

// ═══════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════

const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN || ''
const CLIENT_ID = process.env.DISCORD_CLIENT_ID || ''
const API_BASE = process.env.PREDATOR_API_URL || 'http://localhost:3001'
const PREDATOR_RELEASE_URL = 'https://github.com/lumatones/Predator/releases/latest'

if (!BOT_TOKEN) {
  console.error('❌ DISCORD_BOT_TOKEN is required')
  process.exit(1)
}

// ═══════════════════════════════════════════════
// CLIENT
// ═══════════════════════════════════════════════

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
  ],
})

// ═══════════════════════════════════════════════
// COMMANDS
// ═══════════════════════════════════════════════

const commands = [
  new SlashCommandBuilder()
    .setName('check')
    .setDescription('Request an anti-cheat check for a player')
    .addStringOption(opt =>
      opt.setName('player').setDescription('Player nickname or Steam ID').setRequired(true),
    ),

  new SlashCommandBuilder()
    .setName('status')
    .setDescription('Check the status of a check request')
    .addStringOption(opt =>
      opt.setName('request_id').setDescription('Request ID').setRequired(true),
    ),

  new SlashCommandBuilder()
    .setName('predator')
    .setDescription('Predator Anti-Cheat info')
    .addSubcommand(sub =>
      sub.setName('download').setDescription('Get download link'),
    )
    .addSubcommand(sub =>
      sub.setName('help').setDescription('How to use Predator'),
    ),
]

// ═══════════════════════════════════════════════
// BOT READY
// ═══════════════════════════════════════════════

client.once('ready', async () => {
  console.log(`✅ Predator Bot online: ${client.user?.tag}`)

  // Register slash commands
  try {
    console.log('📝 Registering slash commands...')
    await client.application?.commands.set(commands)
    console.log('✅ Slash commands registered')
  } catch (err) {
    console.error('❌ Failed to register commands:', err)
  }
})

// ═══════════════════════════════════════════════
// COMMAND HANDLER
// ═══════════════════════════════════════════════

client.on('interactionCreate', async (interaction) => {
  if (!interaction.isChatInputCommand()) return

  const { commandName, guildId, user, options } = interaction

  if (commandName === 'check') {
    const player = options.getString('player', true)

    const embed = new EmbedBuilder()
      .setTitle('🔍 Заявка на проверку')
      .setDescription(`Игрок **${player}** будет проверен на читы через Predator Anti-Cheat.`)
      .setColor(0x22c55e)
      .addFields(
        { name: 'Игрок', value: player, inline: true },
        { name: 'Сервер', value: interaction.guild?.name || 'Unknown', inline: true },
        { name: 'Статус', value: '⏳ Ожидание', inline: true },
      )
      .setFooter({ text: 'Predator Anti-Cheat' })
      .setTimestamp()

    const row = new ActionRowBuilder<ButtonBuilder>()
      .addComponents(
        new ButtonBuilder()
          .setLabel('Скачать Predator')
          .setURL(PREDATOR_RELEASE_URL)
          .setStyle(ButtonStyle.Link),
        new ButtonBuilder()
          .setLabel('Отменить')
          .setCustomId(`cancel_check_${interaction.id}`)
          .setStyle(ButtonStyle.Secondary),
      )

    await interaction.reply({ embeds: [embed], components: [row] })

    // Create check request via API
    try {
      await apiPost('/api/website/webhook/check-result', {
        request_id: interaction.id,
        player_name: player,
        guild_id: guildId,
        status: 'pending',
      })
    } catch {
      // API may not be available yet — that's OK
    }
  }

  if (commandName === 'status') {
    const requestId = options.getString('request_id', true)

    const embed = new EmbedBuilder()
      .setTitle(`📋 Статус заявки #${requestId}`)
      .setDescription('Загрузка...')
      .setColor(0x6b7280)
      .setTimestamp()

    await interaction.reply({ embeds: [embed] })
  }

  if (commandName === 'predator') {
    const sub = options.getSubcommand()

    if (sub === 'download') {
      const embed = new EmbedBuilder()
        .setTitle('📥 Скачать Predator Anti-Cheat')
        .setDescription('Последняя версия NSIS-установщика с автообновлением.')
        .setColor(0x22c55e)
        .addFields(
          { name: 'Версия', value: 'v0.4.5', inline: true },
          { name: 'Платформа', value: 'Windows 10/11 x64', inline: true },
          { name: 'Установка', value: 'NSIS Installer (требуются права админа)', inline: true },
        )
        .setURL(PREDATOR_RELEASE_URL)
        .setTimestamp()

      const row = new ActionRowBuilder<ButtonBuilder>()
        .addComponents(
          new ButtonBuilder()
            .setLabel('⬇️ Скачать Predator')
            .setURL(PREDATOR_RELEASE_URL)
            .setStyle(ButtonStyle.Success),
        )

      await interaction.reply({ embeds: [embed], components: [row] })
    }

    if (sub === 'help') {
      const embed = new EmbedBuilder()
        .setTitle('🛡️ Predator Anti-Cheat — Помощь')
        .setDescription('Платформа античит-проверки для GTA 5 RP серверов.')
        .setColor(0x22c55e)
        .addFields(
          { name: '/check <игрок>', value: 'Запросить проверку игрока на читы', inline: false },
          { name: '/status <id>', value: 'Проверить статус заявки', inline: false },
          { name: '/predator download', value: 'Получить ссылку на скачивание', inline: false },
          { name: 'Как это работает', value: 'Игрок скачивает Predator → запускает проверку → результат отправляется на сервер → вы видите его в личном кабинете.', inline: false },
        )
        .setTimestamp()

      await interaction.reply({ embeds: [embed] })
    }
  }
})

// ═══════════════════════════════════════════════
// API HELPER
// ═══════════════════════════════════════════════

async function apiPost(path: string, body: unknown): Promise<any> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, API_BASE)
    const payload = JSON.stringify(body)
    const transport = url.protocol === 'https:' ? (await import('https')).default : http

    const req = transport.request({
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
    }, (res) => {
      let data = ''
      res.on('data', (chunk) => { data += chunk })
      res.on('end', () => { try { resolve(JSON.parse(data)) } catch { resolve(data) } })
    })

    req.on('error', reject)
    req.write(payload)
    req.end()
  })
}

// ═══════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════

client.login(BOT_TOKEN).catch(err => {
  console.error('❌ Login failed:', err.message)
  process.exit(1)
})

console.log('🤖 Predator Discord Bot starting...')
