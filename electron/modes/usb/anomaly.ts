/**
 * Predator — USB Anomaly Detection (E16)
 *
 * Detects:
 *   - VID/PID spoofing (device claims to be phone but behaves like DMA)
 *   - USB descriptor anomalies (mismatched class codes, impossible combos)
 *   - PCIe configuration space scan (FPGA/DMA cards at PCI level)
 *   - Cloned/spoofed USB serial numbers
 */

import { execSync } from 'child_process'
import { type ScanResult, addFindingDedup } from '../../types'
import { DMA_VENDORS, type UsbDeviceInfo } from './descriptors'

// ═══════════════════════════════════════════════════
// VID/PID SPOOFING DETECTION
// ═══════════════════════════════════════════════════

/**
 * Known legitimate VID→device type mapping.
 * If a device has a phone VID but claims to be a USB controller,
 * it's likely spoofed.
 */
const VID_DEVICE_ROLE: Record<string, string> = {
  '04e8': 'phone/tablet', // Samsung
  '18d1': 'phone/tablet', // Google
  '05ac': 'phone/tablet', // Apple
  '2717': 'phone/tablet', // Xiaomi
  '0951': 'flash_drive',  // Kingston
  '0781': 'flash_drive',  // SanDisk
  '0403': 'serial/dma_fpga', // FTDI
  '10ee': 'fpga',         // Xilinx
  '1172': 'fpga',         // Altera
  '8086': 'chipset',      // Intel
  '1022': 'chipset',      // AMD
  '10de': 'gpu',          // NVIDIA
  '1002': 'gpu',          // AMD/ATI
}

/**
 * Detect VID/PID spoofing: device claims one identity but
 * its behavior/USB descriptors contradict it.
 */
export function detectVidPidSpoofing(devices: UsbDeviceInfo[]): ScanResult[] {
  const results: ScanResult[] = []

  for (const dev of devices) {
    const expectedRole = VID_DEVICE_ROLE[dev.vid]
    if (!expectedRole) continue

    const lowerName = (dev.friendlyName || '').toLowerCase()

    // Samsung VID (04e8) but device claims to be a USB serial controller → spoofed
    if (expectedRole === 'phone/tablet') {
      const isController = (
        lowerName.includes('serial') ||
        lowerName.includes('uart') ||
        lowerName.includes('jtag') ||
        lowerName.includes('debug') ||
        lowerName.includes('ftdi') ||
        lowerName.includes('fpga') ||
        lowerName.includes('controller')
      )
      if (isController && addFindingDedup(`spoof-vid:${dev.vid}:${dev.pid}`)) {
        results.push({
          path: 'Hardware: VID Spoof',
          fileName: `🕵️ VID Spoof: ${dev.friendlyName || dev.vid}`,
          type: 'hardware',
          risk: 'high',
          matches: [
            `Device VID ${dev.vid.toUpperCase()} = ${VID_DEVICE_ROLE[dev.vid]}, but claims to be a controller`,
            `⚠ VID/PID SPOOFING DETECTED — device hiding its true identity`,
            `Expected: ${expectedRole}, Actual name: ${dev.friendlyName}`,
            dev.isPresent ? '⚠ Device is CURRENTLY CONNECTED' : '',
            `DMA/FPGA cheat cards often spoof phone VIDs to bypass detection`,
          ].filter(Boolean),
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }

    // Flash drive VID but claims to be a DMA controller → spoofed
    if (expectedRole === 'flash_drive') {
      const isDma = (
        lowerName.includes('dma') ||
        lowerName.includes('fpga') ||
        lowerName.includes('leech') ||
        lowerName.includes('xilinx')
      )
      if (isDma && addFindingDedup(`spoof-flash:${dev.vid}:${dev.pid}`)) {
        results.push({
          path: 'Hardware: VID Spoof',
          fileName: `🕵️ VID Spoof: ${dev.friendlyName || dev.vid}`,
          type: 'hardware',
          risk: 'high',
          matches: [
            `Flash drive VID (${VID_DEVICE_ROLE[dev.vid]}) but device describes itself as DMA`,
            `⚠ Likely spoofed VID/PID — DMA card hiding as flash drive`,
            dev.isPresent ? '⚠ Device is CURRENTLY CONNECTED' : '',
          ].filter(Boolean),
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  }

  return results
}

// ═══════════════════════════════════════════════════
// SERIAL NUMBER ANOMALY DETECTION
// ═══════════════════════════════════════════════════

/**
 * Known spoofed/cloned USB serial numbers.
 * Cheat firmware often uses hardcoded or generic serial numbers.
 */
const SPOOFED_SERIALS = new Set([
  '00000000', '12345678', '00000001', 'default',
  'ABCDEF01', 'DEADBEEF', 'FFFFFFFF',
  '0123456789AB', '000000000000',
])

/**
 * Detect USB devices with suspiciously generic serial numbers.
 */
export function detectClonedSerials(devices: UsbDeviceInfo[]): ScanResult[] {
  const results: ScanResult[] = []
  const seenSerials = new Map<string, UsbDeviceInfo[]>()

  for (const dev of devices) {
    const serial = (dev.descriptors?.serialNumber || '').trim()
    if (!serial) continue

    // Check for known spoofed serials
    const normalizedSerial = serial.replace(/[-:\s]/g, '').toUpperCase()
    if (SPOOFED_SERIALS.has(normalizedSerial)) {
      // Only flag if it's a suspicious device (not just any device)
      if (DMA_VENDORS[dev.vid] || normalizedSerial.length < 8) {
        if (addFindingDedup(`serial-spoof:${dev.vid}:${serial}`)) {
          results.push({
            path: 'Hardware: Spoofed Serial',
            fileName: `🕵️ Spoofed Serial: ${dev.friendlyName || dev.vid}`,
            type: 'hardware',
            risk: 'high',
            matches: [
              `Device has generic/spoofed serial number: "${serial}"`,
              `VID: ${dev.vid.toUpperCase()} PID: ${dev.pid.toUpperCase()}`,
              `⚠ Legitimate devices have unique serial numbers`,
              dev.isPresent ? '⚠ Device is CURRENTLY CONNECTED' : '',
            ].filter(Boolean),
            size: 0,
            modifiedAt: new Date().toISOString(),
          })
        }
      }
    }

    // Track for duplicate detection
    if (!seenSerials.has(serial)) {
      seenSerials.set(serial, [])
    }
    seenSerials.get(serial)!.push(dev)
  }

  // Detect duplicate serial numbers (cloned devices)
  for (const [serial, devs] of seenSerials) {
    if (devs.length >= 2 && DMA_VENDORS[devs[0].vid]) {
      if (addFindingDedup(`serial-dup:${serial}`)) {
        const names = devs.map(d => d.friendlyName || d.vid).join(', ')
        results.push({
          path: 'Hardware: Cloned Serial',
          fileName: `🕵️ Duplicate Serial: ${devs.length} devices`,
          type: 'hardware',
          risk: 'high',
          matches: [
            `${devs.length} devices share the same serial: "${serial}"`,
            `Devices: ${names}`,
            `⚠ Cloned serial numbers = spoofed/counterfeit hardware`,
            `⚠ DMA cheat cards often clone serials to avoid detection`,
          ],
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  }

  return results
}

// ═══════════════════════════════════════════════════
// PCIe CONFIGURATION SPACE SCAN
// ═══════════════════════════════════════════════════

/**
 * PCIe vendor IDs associated with FPGA/DMA cheat cards.
 */
const PCIE_FPGA_VENDORS: Record<string, string> = {
  '10EE': 'Xilinx (FPGA)',
  '1172': 'Altera/Intel (FPGA)',
  '1204': 'Altera (FPGA)',
  'DADA': 'FTDI (FPGA controller)',
  '1FC0': 'Reflex CES (FPGA)',
}

/**
 * Scan PCIe bus for FPGA/DMA devices using devcon or PowerShell.
 * This catches DMA cards even if they spoof USB descriptors.
 */
export function scanPcieConfigSpace(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    // Use PowerShell to enumerate PCI devices via WMI
    const psCmd = `
Get-WmiObject Win32_PnPEntity |
  Where-Object { $_.PNPClass -eq 'System' -or $_.PNPClass -eq 'PCI' -or $_.PNPDeviceID -like 'PCI\\\\*' } |
  Select-Object Name, DeviceID, PNPDeviceID, Status |
  Where-Object { $_.Name -match 'xilinx|altera|fpga|leech|dma|pcie' -or $_.PNPDeviceID -match 'VEN_10EE|VEN_1172|VEN_1204|VEN_DADA|VEN_1FC0' } |
  ConvertTo-Json -Compress
`
    const out = execSync(`powershell -NoProfile -Command "${psCmd.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 10000, windowsHide: true,
    }).trim()

    if (!out || out.length < 5) return results

    const devices = JSON.parse(out)
    const items = Array.isArray(devices) ? devices : [devices]

    for (const dev of items) {
      if (!dev?.PNPDeviceID) continue

      // Extract vendor ID from PNPDeviceID (e.g., PCI\\VEN_10EE&DEV_...)
      const venMatch = dev.PNPDeviceID?.match(/VEN_([0-9A-F]{4})/i)
      const venId = venMatch ? venMatch[1].toUpperCase() : ''
      const vendorName = PCIE_FPGA_VENDORS[venId]

      if (vendorName && addFindingDedup(`pcie-fpga:${venId}`)) {
        results.push({
          path: 'Hardware: PCIe FPGA',
          fileName: `⚠ PCIe FPGA Device: ${dev.Name || vendorName}`,
          type: 'hardware',
          risk: 'high',
          matches: [
            `FPGA device detected on PCIe bus: ${dev.Name || 'Unknown device'}`,
            `Vendor: ${vendorName} (VEN_${venId})`,
            `Device ID: ${dev.PNPDeviceID}`,
            dev.Status ? `Status: ${dev.Status}` : '',
            '⚠ PCIe FPGA = DMA cheat card (reads game memory via PCIe DMA)',
            '⚠ This is the most definitive DMA cheat indicator',
          ].filter(Boolean),
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch (err) { console.warn('[usb-anomaly] PCIe scan failed:', (err as Error).message) }

  // Also check for PCIe devices via devcon if available
  try {
    const devconOut = execSync('devcon find PCI\\* 2>nul', { encoding: 'utf-8', timeout: 5000 })
    const lower = devconOut.toLowerCase()
    for (const [venId, name] of Object.entries(PCIE_FPGA_VENDORS)) {
      if (lower.includes(`ven_${venId.toLowerCase()}`) && addFindingDedup(`pcie-devcon:${venId}`)) {
        results.push({
          path: 'Hardware: PCIe FPGA (devcon)',
          fileName: `⚠ PCIe FPGA: ${name} (VEN_${venId})`,
          type: 'hardware',
          risk: 'high',
          matches: [
            `FPGA device found via devcon: ${name}`,
            `VEN_${venId.toUpperCase()} — known FPGA/DMA vendor`,
            '⚠ PCIe enumeration confirms hardware-level DMA capability',
          ],
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch { /* devcon not available — skip */ }

  return results
}

// ═══════════════════════════════════════════════════
// ORCHESTRATOR
// ═══════════════════════════════════════════════════

/**
 * Run all USB/hardware anomaly detection scans.
 */
export function runUsbAnomalyScan(devices: UsbDeviceInfo[]): ScanResult[] {
  const results: ScanResult[] = []

  results.push(...detectVidPidSpoofing(devices))
  results.push(...detectClonedSerials(devices))
  results.push(...scanPcieConfigSpace())

  return results
}
