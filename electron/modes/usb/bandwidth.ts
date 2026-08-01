/**
 * Predator — USB Bandwidth Monitoring (Active DMA Detection)
 *
 * Extracted from usb-devices.ts. Three-tier approach to detect active
 * DMA cards by measuring USB throughput.
 *
 * DMA cards (FT601 bridge) generate 150-400 MB/s sustained USB traffic.
 * Normal USB devices max out at 20-50 MB/s for flash drives, 5-40 MB/s for phones.
 */

import { execPowerShell } from '../../utils/exec'
import type { UsbDeviceInfo } from './descriptors'
import { DMA_VENDORS } from './descriptors'
import { PHONE_VENDORS, FLASH_DRIVE_VENDORS, USB_HUB_VENDORS } from './classification'
import { type ScanResult, addFindingDedup } from '../../types'

// ═══════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════

export interface BandwidthSample {
  instance: string
  bytesPerSec: number
  counterName: string
}

// ═══════════════════════════════════════════════════
// TIER 1: Real-time USB perf counters
// ═══════════════════════════════════════════════════

/**
 * Tier 1: Sample USB bulk transfer throughput via Get-Counter.
 * Takes two samples 3 seconds apart in ONE PowerShell process.
 * Calculates bytes/sec delta.
 */
export function sampleUsbBandwidthViaPerfCounter(): BandwidthSample[] {
  const results: BandwidthSample[] = []

  try {
    const combinedScript = `
$ErrorActionPreference = 'SilentlyContinue'

# Check availability
$sets = Get-Counter -ListSet '*USB*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSetName
if (-not ($sets -match 'USB')) { Write-Host 'UNAVAILABLE'; exit }

# Sample 1
$sample1 = Get-Counter -Counter '\\USB(*)\\Bulk Bytes/Sec' -ErrorAction SilentlyContinue
if (-not $sample1) { Write-Host 'NO_COUNTERS'; exit }
$sample1.CounterSamples | ForEach-Object {
  @{ Instance = $_.InstanceName; Value = $_.CookedValue } | ConvertTo-Json -Compress
}
Write-Host '---SAMPLE1_END---'

# Wait 3 seconds within same process
Start-Sleep -Seconds 3

# Sample 2
$sample2 = Get-Counter -Counter '\\USB(*)\\Bulk Bytes/Sec' -ErrorAction SilentlyContinue
if (-not $sample2) { Write-Host 'NO_COUNTERS_2'; exit }
$sample2.CounterSamples | ForEach-Object {
  @{ Instance = $_.InstanceName; Value = $_.CookedValue } | ConvertTo-Json -Compress
}
Write-Host '---SAMPLE2_END---'
`
    const out = (execPowerShell(combinedScript, { timeout: 12000, collapseLines: 'semicolons' }) || '').trim()

    if (!out || out.includes('UNAVAILABLE') || out.includes('NO_COUNTERS')) return results

    const sections = out.split('---SAMPLE1_END---')
    if (sections.length < 2) return results
    const sample1Block = sections[0] || ''
    const sample2Block = sections[1]?.split('---SAMPLE2_END---')[0] || ''

    const parseSamples = (block: string): Map<string, number> => {
      const map = new Map<string, number>()
      for (const line of block.split('\n').filter(l => l.trim() && !l.includes('---'))) {
        try {
          const obj = JSON.parse(line)
          const instance = (obj.Instance || '').trim().toLowerCase()
          const value = parseFloat(obj.Value) || 0
          if (instance) map.set(instance, value)
        } catch (err) { console.warn('[bandwidth] failed:', (err as Error).message) }
      }
      return map
    }

    const sample1Map = parseSamples(sample1Block)
    const sample2Map = parseSamples(sample2Block)

    for (const [instance, value1] of sample1Map) {
      const value2 = sample2Map.get(instance)
      if (!value2 || value2 <= value1) continue

      const bytesPerSec = (value2 - value1) / 3
      if (bytesPerSec > 10_000_000) {
        results.push({ instance, bytesPerSec, counterName: 'USB Bulk Bytes/Sec' })
      }
    }
  } catch { /* Tier 1 optional */ }

  return results
}

// ═══════════════════════════════════════════════════
// TIER 2: WMI polling fallback
// ═══════════════════════════════════════════════════

/**
 * Tier 2: WMI-based USB bandwidth polling.
 * Tries multiple WMI class names that may expose USB throughput.
 */
export function sampleUsbBandwidthViaWmi(): BandwidthSample[] {
  const results: BandwidthSample[] = []

  try {
    const wmiScript = `
$ErrorActionPreference = 'SilentlyContinue'

$classes = @(
  'Win32_PerfFormattedData_USB',
  'Win32_PerfFormattedData_USBHub_USBHub'
)

$found = $false
foreach ($cls in $classes) {
  try {
    $before = Get-CimInstance -ClassName $cls -ErrorAction SilentlyContinue
    if (-not $before) { continue }
    Start-Sleep -Seconds 3
    $after = Get-CimInstance -ClassName $cls -ErrorAction SilentlyContinue
    if (-not $after) { continue }
    
    $beforeHash = @{}
    foreach ($b in $before) {
      $key = if ($b.InstanceName) { $b.InstanceName } else { $b.Name }
      $beforeHash[$key] = $b
    }
    foreach ($a in $after) {
      $key = if ($a.InstanceName) { $a.InstanceName } else { $a.Name }
      $b = $beforeHash[$key]
      if (-not $b) { continue }
      $bytesAfter = 0
      $bytesBefore = 0
      foreach ($prop in @('BytesTotalPersec', 'BytesPersec', 'BytesReceivedPersec', 'BytesSentPersec', 'CurrentBandwidth')) {
        try { $bytesAfter = $a.$prop -as [double]; $bytesBefore = $b.$prop -as [double] } catch {}
        if ($bytesAfter -gt 0) { break }
      }
      $bytesDelta = $bytesAfter - $bytesBefore
      if ($bytesDelta -gt 10000000) {
        @{ Instance = $key; BytesPerSec = $bytesDelta; Class = $cls } | ConvertTo-Json -Compress
        $found = $true
      }
    }
    if ($found) { break }
  } catch {}
}
`
    const out = (execPowerShell(wmiScript, { timeout: 15000, collapseLines: 'semicolons' }) || '').trim()

    if (!out || out.length < 5) return results

    for (const line of out.split('\n').filter(l => l.trim())) {
      try {
        const obj = JSON.parse(line)
        const instance = (obj.Instance || '').trim().toLowerCase()
        const bytesPerSec = parseFloat(obj.BytesPerSec) || 0
        const className = obj.Class || 'WMI'
        if (instance && bytesPerSec > 10_000_000) {
          results.push({ instance, bytesPerSec, counterName: `WMI ${className}` })
        }
      } catch (err) { console.warn('[bandwidth] failed:', (err as Error).message) }
    }
  } catch { /* Tier 2 optional */ }

  return results
}

// ═══════════════════════════════════════════════════
// TIER 3: Speed class heuristic
// ═══════════════════════════════════════════════════

/**
 * Tier 3: Heuristic — check USB device speed class.
 * FTDI FT601 is USB 3.0 SuperSpeed (5 Gbps).
 * Normal UART adapters are USB 2.0 High-Speed (480 Mbps max = 60 MB/s).
 * BATCHED: all devices checked in ONE PowerShell invocation.
 */
export function checkUsbSpeedClassHeuristic(presentDevices: UsbDeviceInfo[]): BandwidthSample[] {
  const results: BandwidthSample[] = []

  const targets = presentDevices.filter(dev => {
    if (!dev.vid) return false
    const isDmaVendor = !!DMA_VENDORS[dev.vid]
    const isUnknown = !PHONE_VENDORS[dev.vid] && !FLASH_DRIVE_VENDORS[dev.vid] && !USB_HUB_VENDORS[dev.vid]
    return isDmaVendor || isUnknown
  })

  if (targets.length === 0) return results

  try {
    const deviceList = targets.map(d => `@('${d.instanceId.replace(/'/g, "''")}','${d.vid.toUpperCase()}','${d.pid.toUpperCase()}')`).join(',')
    const batchedScript = `
$ErrorActionPreference = 'SilentlyContinue'
$targets = @(${deviceList})
foreach ($t in $targets) {
  $instanceId = $t[0]
  $vid = $t[1]
  $pid = $t[2]
  
  $dev = Get-PnpDevice -InstanceId $instanceId -ErrorAction SilentlyContinue
  if (-not $dev) { continue }

  $usbDev = Get-CimInstance -Query "SELECT * FROM Win32_USBHub WHERE DeviceID LIKE '%' + $vid + '%' + $pid + '%'" -ErrorAction SilentlyContinue
  if ($usbDev) {
    @{ InstanceId = $instanceId; Speed = $usbDev.Name; Rate = 5000 } | ConvertTo-Json -Compress
    continue
  }

  $matches = Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USB' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match $vid }
  if ($matches) {
    $child = ($matches | Select-Object -First 1).PSChildName
    if ($child) {
      $regPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USB\\' + $child
      if (Test-Path $regPath) {
        $props = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
        $speed = $props.Speed -as [int]
        if ($speed -gt 1000) {
          @{ InstanceId = $instanceId; Speed = 'SuperSpeed'; Rate = $speed } | ConvertTo-Json -Compress
        }
      }
    }
  }
}
`
    const out = (execPowerShell(batchedScript, { timeout: 15000, collapseLines: 'semicolons' }) || '').trim()

    if (!out || out.length < 5) return results

    for (const line of out.split('\n').filter(l => l.trim())) {
      try {
        const speedInfo = JSON.parse(line)
        if (speedInfo.Rate >= 4800 && speedInfo.InstanceId) {
          results.push({
            instance: speedInfo.InstanceId.toLowerCase(),
            bytesPerSec: 100_000_000,
            counterName: `USB Speed Class: ${speedInfo.Speed || 'SuperSpeed'} (${speedInfo.Rate} Mbps)`,
          })
        }
      } catch (err) { console.warn('[bandwidth] failed:', (err as Error).message) }
    }
  } catch { /* speed check optional */ }

  return results
}

// ═══════════════════════════════════════════════════
// ORCHESTRATION
// ═══════════════════════════════════════════════════

/**
 * Main USB bandwidth monitoring: combines all three tiers.
 */
export function monitorUsbBandwidth(): BandwidthSample[] {
  const tier1 = sampleUsbBandwidthViaPerfCounter()
  if (tier1.length > 0) return tier1

  const tier2 = sampleUsbBandwidthViaWmi()
  if (tier2.length > 0) return tier2

  return []
}

/**
 * Cross-reference bandwidth data with device classification.
 * Returns ScanResult[] for active DMA cards detected via USB traffic.
 */
export function detectActiveDmaByBandwidth(
  bandwidthData: BandwidthSample[],
  speedHeuristicData: BandwidthSample[],
  presentDevices: UsbDeviceInfo[],
): ScanResult[] {
  const results: ScanResult[] = []

  const deviceByInstance = new Map<string, UsbDeviceInfo>()
  for (const dev of presentDevices) {
    deviceByInstance.set(dev.instanceId.toLowerCase(), dev)
    if (dev.vid) deviceByInstance.set(`vid:${dev.vid}`, dev)
  }

  const allSamples = [...bandwidthData, ...speedHeuristicData]

  for (const sample of allSamples) {
    const matchingDev = deviceByInstance.get(sample.instance) ||
      findDeviceByPartialInstance(presentDevices, sample.instance)

    if (!matchingDev) continue

    const { vid, pid, friendlyName, deviceClass } = matchingDev

    // ── False positive filters ──
    if (FLASH_DRIVE_VENDORS[vid] && vid !== '0403') continue
    const isMassStorage = (
      deviceClass === 'SCSIAdapter' ||
      deviceClass === 'DiskDrive' ||
      friendlyName.toLowerCase().includes('ssd') ||
      friendlyName.toLowerCase().includes('portable') ||
      friendlyName.toLowerCase().includes('external') ||
      friendlyName.toLowerCase().includes('mass storage') ||
      friendlyName.toLowerCase().includes('pssd')
    )
    if (isMassStorage && vid !== '0403') continue
    if (PHONE_VENDORS[vid]) {
      const isPhone = friendlyName.toLowerCase().includes('phone') ||
        friendlyName.toLowerCase().includes('mobile') ||
        friendlyName.toLowerCase().includes('adb') ||
        friendlyName.toLowerCase().includes('mtp') ||
        friendlyName.toLowerCase().includes('android') ||
        friendlyName.toLowerCase().includes('galaxy') ||
        deviceClass === 'WPD'
      if (isPhone) continue
      if (isMassStorage) continue
    }
    if (USB_HUB_VENDORS[vid]) continue
    if (deviceClass === 'Image' || deviceClass === 'Camera' ||
        friendlyName.toLowerCase().includes('webcam') ||
        friendlyName.toLowerCase().includes('oculus') ||
        friendlyName.toLowerCase().includes('vive')) continue
    if (deviceClass === 'Net' || deviceClass === 'Bluetooth') continue

    const bytesPerSecMB = sample.bytesPerSec / 1_000_000
    const isTier3Heuristic = sample.counterName.includes('Speed Class')

    let shouldFlag = false
    let risk: 'high' | 'medium' = 'medium'
    let confidence = ''

    if (isTier3Heuristic) {
      if (DMA_VENDORS[vid]) {
        shouldFlag = true; risk = 'high'
        confidence = 'USB 3.0 SuperSpeed (5 Gbps) on DMA-vendor device — DMA card indicator'
      } else {
        shouldFlag = true; risk = 'medium'
        confidence = 'USB 3.0 SuperSpeed on unknown device — investigate'
      }
    } else if (bytesPerSecMB >= 150) {
      shouldFlag = true; risk = 'high'
      confidence = `Extreme USB throughput: ${bytesPerSecMB.toFixed(0)} MB/s`
    } else if (bytesPerSecMB >= 80 && DMA_VENDORS[vid]) {
      shouldFlag = true; risk = 'high'
      confidence = `High USB throughput on DMA vendor device: ${bytesPerSecMB.toFixed(0)} MB/s`
    } else if (bytesPerSecMB >= 60 && vid === '0403') {
      shouldFlag = true; risk = 'high'
      confidence = `FTDI device at ${bytesPerSecMB.toFixed(0)} MB/s — normal UART max 3 MB/s, this is FT601 DMA bridge`
    } else if (bytesPerSecMB >= 50 && !PHONE_VENDORS[vid] && !FLASH_DRIVE_VENDORS[vid]) {
      shouldFlag = true; risk = 'medium'
      confidence = `Elevated USB throughput on unknown device: ${bytesPerSecMB.toFixed(0)} MB/s`
    }

    if (shouldFlag && addFindingDedup(`usb-bw:${vid}:${pid}`)) {
      const vendorName = DMA_VENDORS[vid] || `VID_${vid}`
      const icon = DMA_VENDORS[vid] ? '⚠️' : '🔍'
      const deviceName = friendlyName || `USB Device (${vendorName})`

      results.push({
        path: 'Hardware: USB Bandwidth Monitor',
        fileName: `${icon} ACTIVE DMA Traffic: ${deviceName} — ${bytesPerSecMB.toFixed(0)} MB/s`,
        type: 'hardware',
        risk,
        matches: [
          `USB Bandwidth: ${bytesPerSecMB.toFixed(0)} MB/s sustained`,
          `Device: ${vendorName}`,
          `VID: ${vid.toUpperCase()} PID: ${pid.toUpperCase()}`,
          '',
          confidence,
          DMA_VENDORS[vid]
            ? `⚠ DMA cards generate 150-400 MB/s via FT601 bridge`
            : `⚠ Normal USB devices max at 20-50 MB/s (flash drives) or 5-40 MB/s (phones)`,
          DMA_VENDORS[vid]
            ? `⚠ Legitimate FTDI UART adapters max at 3 MB/s — ${bytesPerSecMB.toFixed(0)} MB/s is impossible without FT601`
            : '',
          `Source: ${sample.counterName}`,
          `⚠ This indicates an ACTIVE DMA card reading game memory RIGHT NOW`,
        ].filter(Boolean),
        size: Math.round(sample.bytesPerSec),
        modifiedAt: new Date().toISOString(),
      })
    }
  }

  return results
}

/** Helper: find device by partial instance ID match */
function findDeviceByPartialInstance(devices: UsbDeviceInfo[], instance: string): UsbDeviceInfo | undefined {
  const instanceLower = instance.toLowerCase()
  for (const dev of devices) {
    if (!dev.vid) continue
    if (instanceLower.includes(`vid_${dev.vid}`) || instanceLower.includes(`ven_${dev.vid}`)) return dev
    if (dev.pid && (instanceLower.includes(`pid_${dev.pid}`) || instanceLower.includes(`dev_${dev.pid}`))) return dev
  }
  return undefined
}
