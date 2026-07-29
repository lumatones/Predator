/**
 * Predator — USB/PCI Device Scanner (Orchestrator)
 *
 * Coordinates device enumeration, classification, driver signature
 * verification, setupapi log scanning, and bandwidth monitoring.
 *
 * Modular structure:
 *   usb/descriptors.ts  — enumeration + USB descriptor reading
 *   usb/classification.ts — classifyDevice + driver signatures
 *   usb/bandwidth.ts     — bandwidth monitoring (active DMA detection)
 */

import * as fs from 'fs'
import * as path from 'path'
import { _WR, type ScanResult, addFindingDedup } from '../types'

// ── Descriptors & enumeration ──
import {
  enumeratePresentDevices,
  enumerateDeviceHistory,
  DMA_VENDORS,
  type UsbDeviceInfo,
  type DeviceReport,
} from './usb/descriptors'

// ── Classification ──
import {
  classifyDevice,
  checkDriverSignature,
  DMA_DRIVER_FILES,
  type DeviceSummary,
} from './usb/classification'

// ── Bandwidth monitoring ──
import {
  monitorUsbBandwidth,
  checkUsbSpeedClassHeuristic,
  detectActiveDmaByBandwidth,
} from './usb/bandwidth'

// ── Anomaly detection (E16) ──
import { runUsbAnomalyScan } from './usb/anomaly'

// ═══════════════════════════════════════════════════
// DMA DRIVER SIGNATURE SCAN
// ═══════════════════════════════════════════════════

/**
 * Find FTDI/FPGA/DMA driver files on the system and check their signatures.
 * Returns ScanResult[] with findings.
 */
export function scanDmaDriverSignatures(): ScanResult[] {
  const results: ScanResult[] = []

  // 1. Check system32/drivers for known DMA-related .sys files
  const driversDir = path.join(_WR, 'System32', 'drivers')
  if (fs.existsSync(driversDir)) {
    try {
      for (const file of fs.readdirSync(driversDir)) {
        const lower = file.toLowerCase()
        const isDmaDriver = DMA_DRIVER_FILES.some(f => lower === f.toLowerCase()) ||
          lower.includes('ftd') || lower.includes('ft6') ||
          lower.includes('leech') || lower.includes('vmm') ||
          lower.includes('xilinx') || lower.includes('fpga')

        if (!isDmaDriver) continue

        const fullPath = path.join(driversDir, file)
        const sigResult = checkDriverSignature(fullPath)
        if (!sigResult) continue

        if (!sigResult.isValid || sigResult.isSelfSigned) {
          if (addFindingDedup(`dmasig:${file}`)) {
            results.push({
              path: `Hardware: DMA Driver Signature`,
              fileName: `🔐 DMA Driver: ${file} — ${sigResult.isValid ? 'SELF-SIGNED' : 'UNSIGNED'}`,
              type: 'hardware',
              risk: 'high',
              matches: [
                `Driver: ${file}`,
                ...sigResult.details,
                `⚠ Legitimate FTDI/FPGA drivers are ALWAYS Microsoft or FTDI signed`,
                `⚠ Unsigned or self-signed DMA driver = cheat card indicator`,
              ],
              size: 0,
              modifiedAt: new Date().toISOString(),
            })
          }
        } else if (sigResult.isValid && !sigResult.isMicrosoft && !sigResult.isFtdi) {
          if (addFindingDedup(`dmasig:${file}`)) {
            results.push({
              path: `Hardware: DMA Driver Signature`,
              fileName: `⚠ DMA Driver: ${file} (signed by ${sigResult.signer.slice(0, 40)})`,
              type: 'hardware',
              risk: 'medium',
              matches: [
                `Driver: ${file}`,
                ...sigResult.details,
                `Third-party signature — not Microsoft/FTDI`,
              ],
              size: 0,
              modifiedAt: new Date().toISOString(),
            })
          }
        }
      }
    } catch { /* driver scan optional */ }
  }

  // 2. Check System32 for PCILeech DLLs
  const system32Dir = path.join(_WR, 'System32')
  if (fs.existsSync(system32Dir)) {
    try {
      for (const file of fs.readdirSync(system32Dir)) {
        const lower = file.toLowerCase()
        if (!DMA_DRIVER_FILES.some(f => lower === f.toLowerCase())) continue

        const fullPath = path.join(system32Dir, file)
        const sigResult = checkDriverSignature(fullPath)
        if (!sigResult?.isValid) {
          if (addFindingDedup(`dmasig-sys32:${file}`)) {
            results.push({
              path: `Hardware: DMA Driver Signature`,
              fileName: `🔐 PCILeech Component: ${file} — UNSIGNED ⚠`,
              type: 'hardware',
              risk: 'high',
              matches: [
                `File: ${fullPath}`,
                ...(sigResult?.details || ['Driver signature check failed']),
                `⚠ PCILeech components in System32 = DMA cheat infrastructure`,
              ],
              size: 0,
              modifiedAt: new Date().toISOString(),
            })
          }
        }
      }
    } catch { /* system32 scan optional */ }
  }

  return results
}

// ═══════════════════════════════════════════════════
// MAIN SCAN FUNCTIONS
// ═══════════════════════════════════════════════════

/**
 * Scan for connected USB/PCI devices and classify them.
 * Returns a complete device report.
 */
export function scanUsbDevices(): DeviceReport {
  const presentDevices = enumeratePresentDevices()
  const { devices: historyDevices, installDates } = enumerateDeviceHistory()
  return buildDeviceReport(presentDevices, historyDevices, installDates)
}

/**
 * Convert DeviceReport to ScanResult[] for integration with existing scanner.
 */
export function deviceReportToScanResults(report: DeviceReport): ScanResult[] {
  const results: ScanResult[] = []

  for (const dev of report.connectedSuspicious) {
    if (addFindingDedup(`usb-dma:${dev.vid}:${dev.pid}`)) {
      results.push({
        path: `Hardware: DMA/FPGA`,
        fileName: `⚠ ${dev.icon} DMA Device: ${dev.vendor}`,
        type: 'hardware',
        risk: 'high',
        matches: dev.details,
        size: 0,
        modifiedAt: new Date().toISOString(),
      })
    }
  }

  for (const dev of report.dmaHistory) {
    if (addFindingDedup(`usb-dmahist:${dev.vid}`)) {
      results.push({
        path: `Hardware: DMA History`,
        fileName: `⏳ ⚠ DMA History: ${dev.vendor} (was connected)`,
        type: 'hardware',
        risk: 'high',
        matches: dev.details,
        size: 0,
        modifiedAt: dev.lastSeen || new Date().toISOString(),
      })
    }
  }

  for (const dev of report.connectedSafe) {
    if (addFindingDedup(`usb-safe:${dev.vid}:${dev.pid}`)) {
      results.push({
        path: `Hardware: Connected Devices`,
        fileName: `${dev.icon} ${dev.name}`,
        type: 'hardware',
        risk: 'low',
        matches: dev.details,
        size: 0,
        modifiedAt: new Date().toISOString(),
      })
    }
  }

  return results
}

// ═══════════════════════════════════════════════════
// SETUPAPI LOG SCAN
// ═══════════════════════════════════════════════════

/**
 * Scan setupapi.dev.log for DMA-related driver installations.
 * This reveals EXACT timestamps when DMA cards were installed.
 */
export function scanSetupApiLog(): ScanResult[] {
  const results: ScanResult[] = []
  const logPath = path.join(_WR, 'INF', 'setupapi.dev.log')

  if (!fs.existsSync(logPath)) return results

  try {
    const dmaKeywords = ['ven_10ee', 'ven_1172', 'ven_1204', 'ven_dada', 'vid_0403', 'vid_104c',
      'xilinx', 'altera', 'fpga', 'ftdi', 'pcileech', 'ftd3xx', 'leechcore']

    const stat = fs.statSync(logPath)
    const readSize = Math.min(stat.size, 1_000_000)
    const buf = Buffer.alloc(readSize)
    const fd = fs.openSync(logPath, 'r')
    fs.readSync(fd, buf, 0, readSize, stat.size - readSize)
    fs.closeSync(fd)
    const content = buf.toString('utf-8').toLowerCase()
    const lines = content.split('\n')

    const foundEntries: string[] = []

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      for (const kw of dmaKeywords) {
        if (line.includes(kw)) {
          let timestamp = ''
          for (let j = Math.max(0, i - 5); j <= i; j++) {
            const tsMatch = lines[j]?.match(/(\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2})/)
            if (tsMatch) { timestamp = tsMatch[1]; break }
          }
          foundEntries.push(`${timestamp ? `[${timestamp}] ` : ''}${line.slice(0, 200).trim()}`)
          break
        }
      }
    }

    if (foundEntries.length > 0 && addFindingDedup('setupapi-dma')) {
      results.push({
        path: 'Hardware: SetupAPI Log',
        fileName: `📋 DMA Driver Installation History (${foundEntries.length} entries)`,
        type: 'hardware',
        risk: 'high',
        matches: [
          `Found ${foundEntries.length} DMA-related entries in setupapi.dev.log`,
          'This log records ALL driver installations on this PC',
          ...foundEntries.slice(0, 5).map(e => `setupapi: ${e}`),
        ],
        size: 0,
        modifiedAt: new Date().toISOString(),
      })
    }
  } catch { /* setupapi log optional */ }

  return results
}

// ═══════════════════════════════════════════════════
// FULL SCAN ORCHESTRATOR
// ═══════════════════════════════════════════════════

/**
 * Run the full USB/hardware device scan.
 * Combines device inventory + history + setupapi log scan + bandwidth monitoring.
 */
export function runFullUsbDeviceScan(): ScanResult[] {
  const results: ScanResult[] = []

  const presentDevices = enumeratePresentDevices()
  const { devices: historyDevices, installDates } = enumerateDeviceHistory()

  const deviceReport = buildDeviceReport(presentDevices, historyDevices, installDates)
  results.push(...deviceReportToScanResults(deviceReport))
  results.push(...scanSetupApiLog())
  results.push(...scanDmaDriverSignatures())

  // E16: USB anomaly detection — VID/PID spoofing + PCIe scan
  results.push(...runUsbAnomalyScan(presentDevices))

  // ── USB Bandwidth Monitoring: detect ACTIVE DMA cards ──
  const hasDmaVendorDevices = presentDevices.some(d => DMA_VENDORS[d.vid])
  if (hasDmaVendorDevices && presentDevices.length > 0) {
    try {
      const bandwidthData = monitorUsbBandwidth()
      const speedHeuristicData = checkUsbSpeedClassHeuristic(presentDevices)

      if (bandwidthData.length > 0 || speedHeuristicData.length > 0) {
        const dmaFindings = detectActiveDmaByBandwidth(bandwidthData, speedHeuristicData, presentDevices)
        results.push(...dmaFindings)
      }
    } catch { /* bandwidth monitoring optional */ }
  }

  return results
}

/** Internal: build DeviceReport from pre-enumerated devices (avoids double enumeration) */
function buildDeviceReport(
  presentDevices: UsbDeviceInfo[],
  historyDevices: UsbDeviceInfo[],
  installDates: Map<string, string>,
): DeviceReport {
  const connectedSafe: DeviceSummary[] = []
  const connectedSuspicious: DeviceSummary[] = []
  const dmaHistory: DeviceSummary[] = []
  const seenVids = new Set<string>()
  const presentIds = new Set(presentDevices.map(d => d.instanceId.toLowerCase()))

  for (const dev of presentDevices) {
    if (seenVids.has(`${dev.vid}_${dev.pid}`)) continue
    seenVids.add(`${dev.vid}_${dev.pid}`)
    const classification = classifyDevice(dev)
    if (classification.type === 'dma_fpga') {
      connectedSuspicious.push(classification)
    } else if (classification.type === 'hub') {
      continue
    } else {
      connectedSafe.push(classification)
    }
  }

  for (const dev of historyDevices) {
    if (!dev.vid || !DMA_VENDORS[dev.vid]) continue
    if (presentIds.has(dev.instanceId.toLowerCase())) continue
    if (seenVids.has(`${dev.vid}_history`)) continue
    seenVids.add(`${dev.vid}_history`)
    const lastSeen = installDates.get(dev.vid) || 'unknown date'
    dmaHistory.push({
      type: 'dma_fpga', icon: '⏳',
      name: dev.friendlyName || `DMA Device (VID_${dev.vid})`,
      vendor: DMA_VENDORS[dev.vid], vid: dev.vid, pid: dev.pid,
      risk: 'high', isPresent: false,
      details: [
        `⚠ DMA/FPGA card was previously connected to this PC`,
        `Vendor: ${DMA_VENDORS[dev.vid]}`,
        `Last seen: ${lastSeen}`,
        `⚠ Device is NOT currently connected — may have been removed before scan`,
      ],
      lastSeen,
    })
  }

  const totalDevices = connectedSafe.length + connectedSuspicious.length + dmaHistory.length
  let summary = ''
  if (connectedSuspicious.length > 0) {
    summary = `⚠ DETECTED: ${connectedSuspicious.map(d => d.vendor).join(', ')}`
  } else if (dmaHistory.length > 0) {
    summary = `⚠ HISTORY: DMA device previously connected (${dmaHistory.map(d => d.vendor).join(', ')})`
  } else {
    summary = `✅ No suspicious devices (${connectedSafe.length} safe devices)`
  }

  return { connectedSafe, connectedSuspicious, dmaHistory, summary, totalDevices }
}
