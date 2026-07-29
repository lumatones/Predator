/**
 * Predator — Network Threat Intelligence (E15)
 *
 * Detects:
 *   - System-level proxy settings (registry, env vars, WinHTTP)
 *   - VPN adapters (TAP-Windows, WireGuard, OpenVPN, Cloudflare WARP)
 *   - Known cheat C2 server connections (blacklist)
 *   - Suspicious firewall rules (cheat-related exceptions)
 */

import { execSync } from 'child_process'
import { type ScanResult, addFindingDedup } from '../types'

// ═══════════════════════════════════════════════════
// C2 SERVER BLACKLIST — known cheat command & control
// ═══════════════════════════════════════════════════

const C2_DOMAINS: string[] = [
  'nightfall.to', 'nightfall.gg', 'nightfall.app',
  'vanish.gg', 'vanishcheats.com',
  'unicore.gg', 'unicorecheats.com',
  'oxcheats.com', '0xcheats.net',
  'leetcheats.se', 'leetcheats.ru',
  'cherax.dev', 'cherax.gg',
  'stand.gg', 'stand.sh',
  'phantomoverlay.io', 'phantomoverlay.net',
  'aimware.net', 'aimware.se',
  'neverlose.cc', 'neverlose.gg',
  'gamesense.pub', 'gamesense.gg',
  'iniuria.us', 'iniuria.xyz',
  'onetap.gg', 'onetap.com',
  'novoline.wtf', 'novoline.gg',
  'skeet.cc', 'skeet.gg',
  'primordial.gg', 'primordial.dev',
  'lithium.rip', 'lithium.wtf',
  'memesense.gg', 'memesense.xyz',
  'airflow.wtf', 'airflow.gg',
  'pandora.gg', 'pandora.wtf',
  'interium.ooo', 'interium.gg',
  'ezfrags.xyz', 'ezfrags.wtf',
  'infinity.wtf', 'infinity.gg',
  'epicgames.cheat', 'cheater.fun',
  'fugashack.ru', 'fugashack.cc',
  'cheatmod.net', 'cheatmod.ru',
  'xone.cc', 'xone.gg',
]

const C2_IP_RANGES: RegExp[] = [
  // Common cheat hosting/VPS providers
  /^45\.(14[0-9]|15[0-5])\./, // DDoS-Guard / cheat hosting
  /^193\.(56\.|70\.).*/,       // OVH (French hosting — popular for cheat panels)
  /^185\.(200\.|240\.).*/,     // Various bulletproof hosting
  /^5\.(182\.|183\.).*/,       // BuyVM / FranTech (bulletproof)
]

// ═══════════════════════════════════════════════════
// VPN ADAPTER NAMES
// ═══════════════════════════════════════════════════

const VPN_ADAPTER_PATTERNS: RegExp[] = [
  /tap-windows/i,         // OpenVPN TAP adapter
  /tun-safe/i,             // OpenVPN TUN
  /wireguard/i,           // WireGuard
  /wintun/i,              // WireGuard TUN (Windows)
  /cloudflare warp/i,     // Cloudflare WARP
  /nordlynx/i,            // NordVPN (NordLynx = WireGuard)
  /mullvad/i,             // Mullvad VPN
  /proton.?vpn/i,         // ProtonVPN
  /expressvpn/i,          // ExpressVPN
  /surfshark/i,           // Surfshark
  /pia-?/i,               // Private Internet Access
  /windscribe/i,          // Windscribe
  /vpn\s*unlimited/i,     // VPN Unlimited
  /hide\.?me/i,           // Hide.me
  /cyberghost/i,          // CyberGhost
  /softether/i,           // SoftEther VPN
  /zero.?tier/i,          // ZeroTier (virtual network — used for DMA)
  /hamachi/i,             // LogMeIn Hamachi (virtual LAN tunnel)
  /radmin\s*vpn/i,        // Radmin VPN
  /game.?ranger/i,        // GameRanger (VPN-like tunneling)
]

// ═══════════════════════════════════════════════════
// SYSTEM PROXY DETECTION
// ═══════════════════════════════════════════════════

/**
 * Detect system-wide proxy settings that could be routing
 * game traffic through a MITM proxy for packet manipulation.
 */
export function scanSystemProxy(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    // Check Internet Explorer proxy settings (used by WinHTTP and many games)
    const psCmd = `
$ErrorActionPreference = 'SilentlyContinue'
$key = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'
$proxyEnable = (Get-ItemProperty -Path $key -Name ProxyEnable -ErrorAction SilentlyContinue).ProxyEnable
$proxyServer = (Get-ItemProperty -Path $key -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer
$proxyOverride = (Get-ItemProperty -Path $key -Name ProxyOverride -ErrorAction SilentlyContinue).ProxyOverride
@{
  Enabled = if ($proxyEnable) { $proxyEnable } else { 0 }
  Server = if ($proxyServer) { $proxyServer } else { '' }
  Override = if ($proxyOverride) { $proxyOverride } else { '' }
} | ConvertTo-Json -Compress
`
    const out = execSync(`powershell -NoProfile -Command "${psCmd.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 5000, windowsHide: true,
    }).trim()

    if (out && out.length > 5) {
      const proxy = JSON.parse(out)
      if (proxy.Enabled && proxy.Enabled !== 0 && proxy.Server) {
        if (addFindingDedup('proxy-system')) {
          results.push({
            path: 'Network: System Proxy',
            fileName: `🌐 System Proxy: ${proxy.Server}`,
            type: 'software',
            risk: 'medium',
            matches: [
              `System-wide proxy enabled: ${proxy.Server}`,
              proxy.Override ? `Bypass list: ${proxy.Override}` : '',
              '⚠ Proxy can intercept/modify game traffic (MITM)',
              'Cheat tools often use local proxies for packet manipulation',
            ].filter(Boolean),
            size: 0,
            modifiedAt: new Date().toISOString(),
          })
        }
      }
    }
  } catch (err) { console.warn('[network-intel] proxy check failed:', (err as Error).message) }

  // Check environment variables for proxy
  const envProxy = process.env.HTTP_PROXY || process.env.HTTPS_PROXY || process.env.ALL_PROXY
  if (envProxy && addFindingDedup('proxy-env')) {
    results.push({
      path: 'Network: Environment Proxy',
      fileName: `🌐 Env Proxy: ${envProxy}`,
      type: 'software',
      risk: 'medium',
      matches: [
        `HTTP_PROXY/HTTPS_PROXY set: ${envProxy}`,
        '⚠ Environment-based proxy can route game traffic',
        'Common in development environments — verify if intentional',
      ],
      size: 0,
      modifiedAt: new Date().toISOString(),
    })
  }

  return results
}

// ═══════════════════════════════════════════════════
// VPN ADAPTER DETECTION
// ═══════════════════════════════════════════════════

/**
 * Detect VPN virtual network adapters.
 * Cheaters use VPNs to evade IP bans, and some DMA setups
 * use ZeroTier/Hamachi for remote DMA access.
 */
export function scanVpnAdapters(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const psCmd = `
Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, Status | ConvertTo-Json -Compress
`
    const out = execSync(`powershell -NoProfile -Command "${psCmd}"`, {
      encoding: 'utf-8', timeout: 8000, windowsHide: true,
    }).trim()

    if (!out || out.length < 5) return results

    const adapters = JSON.parse(out)
    const items = Array.isArray(adapters) ? adapters : [adapters]

    for (const adapter of items) {
      const name = (adapter.Name || '').toLowerCase()
      const desc = (adapter.InterfaceDescription || '').toLowerCase()
      const combined = name + ' ' + desc

      for (const pattern of VPN_ADAPTER_PATTERNS) {
        if (pattern.test(combined)) {
          if (addFindingDedup(`vpn:${adapter.Name}`)) {
            results.push({
              path: 'Network: VPN Adapter',
              fileName: `🔒 VPN Adapter: ${adapter.Name}`,
              type: 'software',
              risk: 'medium',
              matches: [
                `VPN virtual adapter detected: ${adapter.InterfaceDescription || adapter.Name}`,
                `Status: ${adapter.Status || 'Unknown'}`,
                '⚠ VPNs can be used to evade IP bans',
                adapter.Name.toLowerCase().includes('zerotier') || adapter.Name.toLowerCase().includes('hamachi')
                  ? '⚠ ZeroTier/Hamachi used for remote DMA access — high risk'
                  : '',
              ].filter(Boolean),
              size: 0,
              modifiedAt: new Date().toISOString(),
            })
          }
          break
        }
      }
    }
  } catch (err) { console.warn('[network-intel] VPN check failed:', (err as Error).message) }

  return results
}

// ═══════════════════════════════════════════════════
// C2 CONNECTION DETECTION
// ═══════════════════════════════════════════════════

/**
 * Check active connections against known cheat C2 server blacklist.
 */
export function scanC2Connections(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    // Get netstat with process info
    const out = execSync(`netstat -ano`, { encoding: 'utf-8', timeout: 5000 })
    if (!out.trim()) return results

    const lines = out.split('\n')
    const foreignAddrs = new Set<string>()

    for (const line of lines) {
      const parts = line.trim().split(/\s+/)
      if (parts.length < 5) continue
      const foreignAddr = parts[2]
      // Extract IP
      const ipMatch = foreignAddr.match(/(\d+\.\d+\.\d+\.\d+)/)
      if (!ipMatch) continue
      foreignAddrs.add(ipMatch[1])
    }

    // Check each foreign IP against C2 blacklist
    for (const ip of foreignAddrs) {
      for (const range of C2_IP_RANGES) {
        if (range.test(ip) && addFindingDedup(`c2-ip:${ip}`)) {
          results.push({
            path: 'Network: C2 Connection',
            fileName: `⚠ Suspicious Connection: ${ip}`,
            type: 'software',
            risk: 'high',
            matches: [
              `Active connection to IP in cheat hosting range: ${ip}`,
              '⚠ This IP range is associated with cheat C2 servers',
              'Connection is ESTABLISHED — active communication',
            ],
            size: 0,
            modifiedAt: new Date().toISOString(),
          })
        }
      }
    }

    // Check DNS cache for C2 domains
    try {
      const dnsOut = execSync('ipconfig /displaydns', { encoding: 'utf-8', timeout: 5000 })
      const dnsLower = dnsOut.toLowerCase()
      for (const domain of C2_DOMAINS) {
        if (dnsLower.includes(domain) && addFindingDedup(`c2-dns:${domain}`)) {
          results.push({
            path: 'DNS Cache',
            fileName: `⚠ C2 Domain in DNS: ${domain}`,
            type: 'software',
            risk: 'high',
            matches: [
              `DNS cache contains known cheat C2 domain: ${domain}`,
              '⚠ This domain is a known cheat provider/panel',
              'Domain was resolved — active or recent connection',
            ],
            size: 0,
            modifiedAt: new Date().toISOString(),
          })
        }
      }
    } catch { /* DNS optional */ }
  } catch (err) { console.warn('[network-intel] C2 check failed:', (err as Error).message) }

  return results
}

// ═══════════════════════════════════════════════════
// FIREWALL RULE ANALYSIS
// ═══════════════════════════════════════════════════

/**
 * Check Windows Firewall rules for cheat-related exceptions.
 * Cheats often add firewall rules to allow their C2 traffic.
 */
export function scanFirewallRules(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const SUS_NAMES = ['cheat', 'hack', 'inject', 'bypass', 'menu', 'spoof',
      'nightfall', 'vanish', 'unicore', 'aimware', 'onetap', 'gamesense',
      'neverlose', 'skeet', 'novoline', 'cherax', 'stand']

    const psCmd = `
Get-NetFirewallRule -Direction Outbound -Enabled True -Action Allow -ErrorAction SilentlyContinue |
  Where-Object { ${SUS_NAMES.map(n => `$_.DisplayName -match '${n}'`).join(' -or ')} } |
  Select-Object -First 15 DisplayName, Direction, Action, Enabled |
  ConvertTo-Json -Compress
`
    const out = execSync(`powershell -NoProfile -Command "${psCmd.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 8000, windowsHide: true,
    }).trim()

    if (!out || out.length < 5) return results

    const rules = JSON.parse(out)
    const items = Array.isArray(rules) ? rules : [rules]

    for (const rule of items) {
      if (!rule?.DisplayName) continue
      if (addFindingDedup(`fw:${rule.DisplayName}`)) {
        results.push({
          path: 'Network: Firewall Rules',
          fileName: `🔥 Suspicious Firewall Rule: ${rule.DisplayName}`,
          type: 'software',
          risk: 'high',
          matches: [
            `Outbound firewall rule matches cheat keyword`,
            `Rule: ${rule.DisplayName}`,
            `Direction: ${rule.Direction}, Action: ${rule.Action}`,
            '⚠ Cheats add firewall exceptions for C2 communication',
          ],
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch (err) { console.warn('[network-intel] firewall check failed:', (err as Error).message) }

  return results
}

// ═══════════════════════════════════════════════════
// ORCHESTRATOR
// ═══════════════════════════════════════════════════

/**
 * Run all network intelligence scans.
 */
export function runNetworkIntel(): ScanResult[] {
  const results: ScanResult[] = []

  results.push(...scanSystemProxy())
  results.push(...scanVpnAdapters())
  results.push(...scanC2Connections())
  results.push(...scanFirewallRules())

  return results
}
