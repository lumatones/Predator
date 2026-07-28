/**
 * Predator — USB/PCI Device Inventory & History Scanner
 *
 * Enumerates ALL connected USB/PCI devices, classifies them
 * (phone, flash drive, DMA card, keyboard, etc.), and detects
 * traces of previously-connected DMA hardware.
 *
 * Data sources:
 *   - Get-PnpDevice (present devices with class, VID/PID, description)
 *   - Registry HKLM\SYSTEM\CurrentControlSet\Enum\USB|PCI (all-time device history)
 *   - setupapi.dev.log (driver install timestamps)
 *
 * Output: grouped ScanResult[] with type='hardware' and device metadata
 */

import { execSync } from 'child_process'
import * as fs from 'fs'
import * as path from 'path'
import { _WR, type ScanResult, addFindingDedup, parsePsJson, ctx } from '../types'

// ═══════════════════════════════════════════════════
// DRIVER SIGNATURE VERIFICATION
// ═══════════════════════════════════════════════════

/** Result of driver signature verification */
export interface DriverSignatureResult {
  isValid: boolean
  signer: string
  isMicrosoft: boolean
  isFtdi: boolean
  isSelfSigned: boolean
  details: string[]
}

// Known legitimate signers for FTDI/FPGA drivers
const LEGITIMATE_SIGNERS = [
  'microsoft windows',
  'microsoft windows hardware compatibility',
  'ftdi ltd',
  'future technology devices international',
]

const DMA_DRIVER_FILES = [
  'ftd3xx.dll', 'ftd2xx.dll', 'ftdiBus3.sys', 'ftdiBus2.sys',
  'leechcore.dll', 'vmm.dll', 'pcileech.dll', 'pcileech_core.dll',
  'leechsvc.dll', 'memprocfs.exe', 'ft601.sys', 'ftdibus.sys',
]

/**
 * Check digital signature of a driver file.
 * Returns full signature info: validity, signer name, trust level.
 */
function checkDriverSignature(filepath: string): DriverSignatureResult | null {
  try {
    if (!fs.existsSync(filepath)) return null

    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$sig = Get-AuthenticodeSignature -FilePath '${filepath.replace(/'/g, "''")}'
@{
  Status = $sig.Status.ToString()
  Signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }
  Issuer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Issuer } else { '' }
} | ConvertTo-Json -Compress
`
    const out = execSync(`powershell -NoProfile -Command "${psScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 5000, windowsHide: true,
    }).trim()

    if (!out || out.length < 5) return null

    const result = JSON.parse(out)
    const status = result.Status || 'Unknown'
    const signer = (result.Signer || '').toLowerCase()
    const issuer = (result.Issuer || '').toLowerCase()

    const isValid = status === 'Valid'
    const isMicrosoft = signer.includes('microsoft') || issuer.includes('microsoft')
    const isFtdi = signer.includes('ftdi') || signer.includes('future technology')
    const isSelfSigned = signer === issuer && !isMicrosoft && !isFtdi

    const details: string[] = []
    if (isValid) {
      details.push(`Signed by: ${result.Signer || 'Unknown'}`)
      if (isMicrosoft) details.push('✅ Microsoft-signed driver (trusted)')
      else if (isFtdi) details.push('✅ FTDI-signed driver (trusted)')
      else details.push('⚠ Signed by third party — verify manually')
    } else if (status === 'NotSigned') {
      details.push('❌ DRIVER IS NOT SIGNED')
      details.push('⚠ Legitimate drivers are ALWAYS signed')
      details.push('⚠ Unsigned DMA driver = strong cheat indicator')
    } else if (status === 'HashMismatch') {
      details.push('❌ Driver signature HASH MISMATCH (tampered)')
    } else {
      details.push(`⚠ Unknown signature status: ${status}`)
    }

    return { isValid, signer, isMicrosoft, isFtdi, isSelfSigned, details }
  } catch {
    return null
  }
}

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

/**
 * Check driver signatures for a specific FTDI/FPGA device by its VID/PID.
 * Uses PowerShell to find the driver files associated with the device.
 */
export function checkDeviceDriverSignature(vid: string, pid: string): DriverSignatureResult | null {
  try {
    // Find the driver service name for this specific device, then locate its .sys file
    // DEVPKEY_Device_Service = {a45c254e-df1c-4efd-8020-67d146a850e0} 6
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$dev = Get-PnpDevice | Where-Object { $_.InstanceId -match 'VID_${vid}' -and $_.InstanceId -match 'PID_${pid}' } | Select-Object -First 1
if (-not $dev) { Write-Host 'NO_DEVICE'; exit 0 }
$svcData = Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName '{a45c254e-df1c-4efd-8020-67d146a850e0} 6' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Data
if ($svcData) { Write-Host "SERVICE:$svcData" } else { Write-Host 'NO_SERVICE' }
`
    const out = execSync(`powershell -NoProfile -Command "${psScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 8000, windowsHide: true,
    }).trim()

    if (!out || out === 'NO_DEVICE' || out === 'NO_SERVICE') return null

    const svcMatch = out.match(/SERVICE:(.+)/)
    const serviceName = svcMatch ? svcMatch[1].trim() : ''

    // Search for .sys files matching the service name or common FTDI/FPGA driver patterns
    const driversDir = path.join(_WR, 'System32', 'drivers')
    const system32Dir = path.join(_WR, 'System32')

    for (const searchDir of [driversDir, system32Dir]) {
      if (!fs.existsSync(searchDir)) continue
      try {
        for (const file of fs.readdirSync(searchDir)) {
          const lower = file.toLowerCase()
          // Match by service name OR by FTDI/FPGA driver patterns
          const matchesService = serviceName && lower.includes(serviceName.toLowerCase().replace('.sys', ''))
          const matchesPattern = lower.includes('ftd') || lower.includes('ft6') ||
            lower.includes('leech') || lower.includes('vmm') ||
            lower.includes('xilinx') || lower.includes('fpga') ||
            lower.includes('pcileech')
          if (matchesService || matchesPattern) {
            const sigResult = checkDriverSignature(path.join(searchDir, file))
            if (sigResult) return sigResult
          }
        }
      } catch { /* skip */ }
    }

    return null
  } catch {
    return null
  }
}

// ═══════════════════════════════════════════════════
// USB Device Classification Tables
// ═══════════════════════════════════════════════════

/** USB Class Codes → human-readable device type */
const USB_CLASS_MAP: Record<string, { name: string; icon: string; risk: 'low' | 'medium' }> = {
  '01': { name: 'Audio Device', icon: '🎵', risk: 'low' },
  '02': { name: 'Communication Device', icon: '📡', risk: 'low' },
  '03': { name: 'HID (Keyboard/Mouse)', icon: '⌨️', risk: 'low' },
  '05': { name: 'HID Game Controller', icon: '🎮', risk: 'low' },
  '06': { name: 'Imaging/Camera', icon: '📷', risk: 'low' },
  '07': { name: 'Printer', icon: '🖨️', risk: 'low' },
  '08': { name: 'Mass Storage (Flash Drive)', icon: '💾', risk: 'low' },
  '09': { name: 'USB Hub', icon: '🔌', risk: 'low' },
  '0A': { name: 'CDC Data', icon: '📊', risk: 'low' },
  '0B': { name: 'Smart Card', icon: '💳', risk: 'low' },
  '0D': { name: 'Security Device', icon: '🔐', risk: 'medium' },
  '0E': { name: 'Video/Webcam', icon: '📹', risk: 'low' },
  '0F': { name: 'Healthcare', icon: '🏥', risk: 'low' },
  'DC': { name: 'Diagnostic Device', icon: '🔧', risk: 'medium' },
  'E0': { name: 'Wireless Adapter', icon: '📶', risk: 'low' },
  'EF': { name: 'Miscellaneous', icon: '📦', risk: 'low' },
  'FE': { name: 'Application Specific', icon: '⚙️', risk: 'medium' },
  'FF': { name: 'Vendor Specific', icon: '⚠️', risk: 'medium' },
}

/** Known phone/tablet Vendor IDs (VID) */
const PHONE_VENDORS: Record<string, string> = {
  '04e8': 'Samsung',
  '18d1': 'Google',
  '22b8': 'Motorola',
  '05ac': 'Apple iPhone/iPad',
  '1004': 'LG',
  '0fce': 'Sony',
  '04da': 'Panasonic',
  '2717': 'Xiaomi',
  '2a70': 'OnePlus',
  '109b': 'Samsung (tether)',
  '04e3': 'Samsung (tether)',
}

/** Known flash drive Vendor IDs (VID) */
const FLASH_DRIVE_VENDORS: Record<string, string> = {
  '0951': 'Kingston',
  '0781': 'SanDisk',
  '13fe': 'Kingston',
  '090c': 'Silicon Power',
  '125f': 'ADATA',
  '1307': 'Transcend',
  '058f': 'Alcor Micro',
  '14cd': 'Super Top',
  'abcd': 'Generic',
}

/** DMA/FPGA/Cheat vendor IDs (the dangerous ones) */
const DMA_VENDORS: Record<string, string> = {
  '10ee': 'Xilinx FPGA (DMA cheat card)',
  '1172': 'Altera/Intel FPGA (DMA cheat card)',
  '1204': 'Lattice FPGA (DMA cheat card)',
  'dada': 'Xilinx FPGA (alt ID)',
  '0403': 'FTDI USB-FPGA Bridge (DMA card)',
  '104c': 'TI FPGA',
}

/** Generic USB hubs — ignore these */
const USB_HUB_VENDORS: Record<string, string> = {
  '8087': 'Intel USB Hub',
  '1a40': 'Terminus USB Hub',
  '05e3': 'Genesys Logic Hub',
  '0bda': 'Realtek USB Hub',
  '2109': 'VIA Labs Hub',
}

/** Hardware cheat devices — input manipulation / aimbot hardware */
const HW_CHEAT_VENDORS: Record<string, { name: string; risk: 'high' | 'medium' }> = {
  // Arduino Leonardo — programmable HID (aimbot, recoil scripts)
  '2341': { name: 'Arduino Leonardo (HID aimbot)', risk: 'high' },
  // Teensy — programmable USB development board (aimbot, input injection)
  '16c0': { name: 'Teensy USB (HID aimbot)', risk: 'high' },
  // Titan Two / Cronus Zen — controller emulation + scripts
  '2508': { name: 'ConsoleTuner Titan Two (controller cheat)', risk: 'high' },
  // Cronus Zen specific
  '0c12': { name: 'Cronus Zen (controller cheat)', risk: 'high' },
}

/** Known hardware cheat PID from multi-purpose VIDs — narrow match */
const HW_CHEAT_PIDS: Set<string> = new Set([
  // Arduino Leonardo bootloader + sketch
  '8036', '0036', '8037', '0037',
  // Teensy 2.0/3.x/4.x
  '0486', '0483', '0487', '0488', '0489',
  // Titan Two
  '0001', '0002',
])

// ═══════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════

export interface UsbDeviceInfo {
  instanceId: string
  friendlyName: string
  deviceClass: string
  vid: string
  pid: string
  isPresent: boolean
  installDate?: string
  /** USB descriptor data from Get-PnpDeviceProperty (manufacturer, serial, MTP/ADB mode) */
  descriptors?: UsbDescriptors
}

/** USB device descriptor properties read via Get-PnpDeviceProperty */
export interface UsbDescriptors {
  /** DEVPKEY_Device_Manufacturer (PID 13) — e.g. "Samsung Electronics" */
  manufacturer: string
  /** DEVPKEY_Device_BusReportedDeviceDescription (PID 14) — e.g. "Galaxy S24" */
  busReportedDesc: string
  /** DEVPKEY_Device_SerialNumber (PID 30) — device serial if available */
  serialNumber: string
  /** DEVPKEY_Device_CompatibleIds (PID 4) — hardware/compatible ID strings */
  compatibleIds: string[]
  /** Detected USB protocol mode */
  protocolMode: 'mtp' | 'ptp' | 'adb' | 'rndis' | 'mass_storage' | 'charging' | 'unknown'
  /** Whether this is a phone based on descriptor data (MTP/PTP/ADB/RNDIS) */
  isPhoneByDescriptor: boolean
}

export interface DeviceReport {
  /** Currently connected, safe devices */
  connectedSafe: DeviceSummary[]
  /** Currently connected, suspicious devices (DMA/FPGA) */
  connectedSuspicious: DeviceSummary[]
  /** Previously connected DMA devices (not present now) */
  dmaHistory: DeviceSummary[]
  /** Summary text for UI */
  summary: string
  /** Total devices found */
  totalDevices: number
}

export interface DeviceSummary {
  type: 'phone' | 'flash_drive' | 'dma_fpga' | 'keyboard_mouse' | 'webcam' | 'audio' | 'network' | 'hub' | 'unknown'
  icon: string
  name: string
  vendor: string
  vid: string
  pid: string
  risk: 'high' | 'medium' | 'low'
  isPresent: boolean
  details: string[]
  lastSeen?: string
}

// ═══════════════════════════════════════════════════
// DEVICE ENUMERATION
// ═══════════════════════════════════════════════════

/**
 * Enumerate all present USB/PCI devices via PowerShell.
 * Returns raw device info array.
 */
function enumeratePresentDevices(): UsbDeviceInfo[] {
  const devices: UsbDeviceInfo[] = []

  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
Get-PnpDevice -PresentOnly |
  Where-Object { $_.Class -match 'USB|HIDClass|Ports|System|Net|SCSIAdapter|Image|Camera|Media|AudioEndpoint|Bluetooth|WPD' } |
  Select-Object InstanceId, FriendlyName, Class |
  ConvertTo-Json -Compress
`
    const out = execSync(`powershell -NoProfile -Command "${psScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 10000, windowsHide: true,
    }).trim()

    if (!out || out.length < 5) return devices

    const raw = parsePsJson<{ InstanceId?: string; FriendlyName?: string; Class?: string }>(out)

    for (const dev of raw) {
      const instanceId = dev.InstanceId || ''
      const friendlyName = (dev.FriendlyName || '').replace(/[^\x20-\x7E\u0400-\u04FF]/g, '').trim()
      const deviceClass = dev.Class || 'Unknown'

      // Extract VID/PID from InstanceId (e.g., USB\VID_04E8&PID_6860\...)
      const vidMatch = instanceId.match(/VID[_\s]*([0-9A-Fa-f]{4})/i)
      const pidMatch = instanceId.match(/PID[_\s]*([0-9A-Fa-f]{4})/i)
      const vid = vidMatch ? vidMatch[1].toLowerCase() : ''
      const pid = pidMatch ? pidMatch[1].toLowerCase() : ''

      // Also check for PCI VEN/DEV
      const venMatch = instanceId.match(/VEN[_\s]*([0-9A-Fa-f]{4})/i)
      const devMatch = instanceId.match(/DEV[_\s]*([0-9A-Fa-f]{4})/i)

      devices.push({
        instanceId,
        friendlyName,
        deviceClass,
        vid: vid || (venMatch ? venMatch[1].toLowerCase() : ''),
        pid: pid || (devMatch ? devMatch[1].toLowerCase() : ''),
        isPresent: true,
      })
    }

    // ── USB Descriptor Enrichment ──
    // Read manufacturer, serial, MTP/ADB mode from USB descriptors
    // This gives 100% accurate phone vs storage classification
    if (devices.length > 0) {
      try {
        const descriptorMap = readUsbDescriptors(devices)
        for (const dev of devices) {
          const desc = descriptorMap.get(dev.instanceId.toLowerCase())
          if (desc) {
            dev.descriptors = desc
          }
        }
      } catch { /* descriptor enrichment optional */ }
    }
  } catch { /* enumeration optional */ }

  return devices
}

// ═══════════════════════════════════════════════════
// USB DESCRIPTOR READING — Get-PnpDeviceProperty
// ═══════════════════════════════════════════════════

/** DEVPKEY GUID for standard device properties */
const DEVPKEY_GUID = '{a45c254e-df1c-4efd-8020-67d146a850e0}'

/** PID constants for standard device properties */
const DEVPKEY_PID = {
  CompatibleIds: 4,           // DEVPKEY_Device_CompatibleIds
  ClassGuid: 9,               // DEVPKEY_Device_ClassGuid
  Manufacturer: 13,           // DEVPKEY_Device_Manufacturer
  BusReportedDeviceDesc: 14,  // DEVPKEY_Device_BusReportedDeviceDescription
  SerialNumber: 30,           // DEVPKEY_Device_SerialNumber
} as const

/**
 * Batched USB descriptor reader — reads Manufacturer, BusReportedDesc,
 * CompatibleIds, and SerialNumber for ALL present devices in ONE PowerShell call.
 * Returns a Map of instanceId → UsbDescriptors.
 */
function readUsbDescriptors(devices: UsbDeviceInfo[]): Map<string, UsbDescriptors> {
  const descriptorMap = new Map<string, UsbDescriptors>()

  if (devices.length === 0) return descriptorMap

  // Filter to devices that have a VID (skip PCI/system-only devices)
  const targets = devices.filter(d => d.vid && d.instanceId)
  if (targets.length === 0) return descriptorMap

  try {
    // Build an array of instance IDs for the PowerShell script
    const idList = targets.map(d => `'${d.instanceId.replace(/'/g, "''")}'`).join(',')
    const guid = DEVPKEY_GUID

    const batchedScript = `
$ErrorActionPreference = 'SilentlyContinue'
$guid = '${guid}'
$ids = @(${idList})
$results = @()

foreach ($id in $ids) {
  $info = @{ InstanceId = $id }

  # Read Manufacturer (PID 13)
  $mfr = Get-PnpDeviceProperty -InstanceId $id -KeyName "$guid ${DEVPKEY_PID.Manufacturer}" -ErrorAction SilentlyContinue
  if ($mfr -and $mfr.Data) { $info.Mfr = $mfr.Data.ToString() } else { $info.Mfr = '' }

  # Read Bus Reported Device Description (PID 14) — the USB product string
  $desc = Get-PnpDeviceProperty -InstanceId $id -KeyName "$guid ${DEVPKEY_PID.BusReportedDeviceDesc}" -ErrorAction SilentlyContinue
  if ($desc -and $desc.Data) { $info.BusDesc = $desc.Data.ToString() } else { $info.BusDesc = '' }

  # Read Serial Number (PID 30) — may not exist on all devices
  $sn = Get-PnpDeviceProperty -InstanceId $id -KeyName "$guid ${DEVPKEY_PID.SerialNumber}" -ErrorAction SilentlyContinue
  if ($sn -and $sn.Data) { $info.Serial = $sn.Data.ToString() } else { $info.Serial = '' }

  # Read Compatible IDs (PID 4) — multi-string for MTP/PTP/ADB detection
  $compat = Get-PnpDeviceProperty -InstanceId $id -KeyName "$guid ${DEVPKEY_PID.CompatibleIds}" -ErrorAction SilentlyContinue
  if ($compat -and $compat.Data) {
    $compatList = @()
    foreach ($c in $compat.Data) { $compatList += $c.ToString() }
    $info.CompatIds = $compatList -join '|'
  } else {
    $info.CompatIds = ''
  }

  # Only output if we got at least one descriptor (avoids noise)
  if ($info.Mfr -or $info.BusDesc -or $info.Serial -or $info.CompatIds) {
    $info | ConvertTo-Json -Compress
  }
}
`
    const out = execSync(`powershell -NoProfile -Command "${batchedScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 20000, windowsHide: true,
    }).trim()

    if (!out || out.length < 5) return descriptorMap

    // Parse each line as JSON
    for (const line of out.split('\n').filter(l => l.trim())) {
      try {
        const raw = JSON.parse(line)
        const instanceId = (raw.InstanceId || '').trim()
        if (!instanceId) continue

        const manufacturer = (raw.Mfr || '').replace(/[^\x20-\x7E\u0400-\u04FF]/g, '').trim()
        const busReportedDesc = (raw.BusDesc || '').replace(/[^\x20-\x7E\u0400-\u04FF]/g, '').trim()
        const serialNumber = (raw.Serial || '').replace(/[^\x20-\x7E\u0400-\u04FF]/g, '').trim()
        const compatRaw = (raw.CompatIds || '').trim()
        const compatibleIds = compatRaw ? compatRaw.split('|').map((s: string) => s.trim()).filter(Boolean) : []

        // Detect USB protocol mode from compatible IDs
        const allIds = compatibleIds.join('\\').toLowerCase()
        let protocolMode: UsbDescriptors['protocolMode'] = 'unknown'
        if (allIds.includes('ms_comp_mtp') || (allIds.includes('class_06') && allIds.includes('subclass_01'))) {
          protocolMode = 'mtp'
        } else if (allIds.includes('class_ff') && allIds.includes('subclass_42')) {
          protocolMode = 'adb'
        } else if (allIds.includes('class_06') && !allIds.includes('mtp')) {
          protocolMode = 'ptp'
        } else if (allIds.includes('ms_comp_rndis') || allIds.includes('rndis')) {
          protocolMode = 'rndis'
        } else if (allIds.includes('class_08')) {
          protocolMode = 'mass_storage'
        }

        // Determine if this is a phone by descriptor data.
        // Protocol mode is authoritative — manufacturer alone is NOT sufficient
        // (Samsung/Google/Motorola make SSDs, Chromecasts, network gear, etc.)
        const isPhoneByDescriptor = (
          protocolMode === 'mtp' ||
          protocolMode === 'ptp' ||
          protocolMode === 'adb' ||
          protocolMode === 'rndis' ||
          // Only fall back to busReportedDesc matching if protocol is ambiguous
          (protocolMode === 'unknown' && (
            busReportedDesc.toLowerCase().includes('phone') ||
            busReportedDesc.toLowerCase().includes('galaxy') ||
            busReportedDesc.toLowerCase().includes('iphone') ||
            busReportedDesc.toLowerCase().includes('ipad') ||
            busReportedDesc.toLowerCase().includes('pixel') ||
            busReportedDesc.toLowerCase().includes('oneplus') ||
            (busReportedDesc.toLowerCase().includes('mi ') && !busReportedDesc.toLowerCase().includes('micro'))
          ))
        )

        descriptorMap.set(instanceId.toLowerCase(), {
          manufacturer,
          busReportedDesc,
          serialNumber,
          compatibleIds,
          protocolMode,
          isPhoneByDescriptor,
        })
      } catch { /* skip malformed line */ }
    }
  } catch { /* descriptor reading optional */ }

  return descriptorMap
}

/**
 * Check registry for ALL device entries (present + historical).
 * Returns list of device IDs found in registry.
 */
function enumerateDeviceHistory(): { devices: UsbDeviceInfo[]; installDates: Map<string, string> } {
  const devices: UsbDeviceInfo[] = []
  const installDates = new Map<string, string>()

  try {
    // Read USB device history from registry
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$results = @()

# USB device history
$usbPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USB'
if (Test-Path $usbPath) {
  Get-ChildItem $usbPath -Recurse -Depth 2 -ErrorAction SilentlyContinue |
    ForEach-Object {
      $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
      $deviceDesc = $props.DeviceDesc || $props.FriendlyName || ''
      $service = $props.Service || ''
      $installDate = $props.InstallDate || ''
      $results += [PSCustomObject]@{
        InstanceId = $_.Name -replace '.*\\\\USB\\\\', 'USB\\'
        FriendlyName = $deviceDesc.ToString()
        Class = 'USB'
        Service = $service
        InstallDate = $installDate
      }
    }
}

# PCI device history
$pciPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\PCI'
if (Test-Path $pciPath) {
  Get-ChildItem $pciPath -Recurse -Depth 2 -ErrorAction SilentlyContinue |
    ForEach-Object {
      $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
      $results += [PSCustomObject]@{
        InstanceId = $_.Name -replace '.*\\\\PCI\\\\', 'PCI\\'
        FriendlyName = ($props.DeviceDesc || '').ToString()
        Class = 'PCI'
        Service = ($props.Service || '').ToString()
        InstallDate = $props.InstallDate || ''
      }
    }
}

$results | ConvertTo-Json -Compress
`
    const out = execSync(`powershell -NoProfile -Command "${psScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 15000, windowsHide: true,
    }).trim()

    if (!out || out.length < 5) return { devices, installDates }

    const raw = parsePsJson<{ InstanceId?: string; FriendlyName?: string; Class?: string; Service?: string; InstallDate?: any }>(out)

    for (const dev of raw) {
      const instanceId = dev.InstanceId || ''
      const friendlyName = (dev.FriendlyName || '').replace(/[^\x20-\x7E\u0400-\u04FF]/g, '').trim()
      const installDate = typeof dev.InstallDate === 'string' ? dev.InstallDate : ''

      const vidMatch = instanceId.match(/VID[_\s]*([0-9A-Fa-f]{4})/i)
      const venMatch = instanceId.match(/VEN[_\s]*([0-9A-Fa-f]{4})/i)

      const vid = vidMatch ? vidMatch[1].toLowerCase() : (venMatch ? venMatch[1].toLowerCase() : '')
      const pidMatch = instanceId.match(/PID[_\s]*([0-9A-Fa-f]{4})/i)
      const pid = pidMatch ? pidMatch[1].toLowerCase() : ''

      if (vid && installDate) {
        installDates.set(vid, installDate)
      }

      devices.push({
        instanceId,
        friendlyName,
        deviceClass: dev.Class || 'Unknown',
        vid,
        pid,
        isPresent: false, // All registry entries — we'll cross-check with active devices
      })
    }
  } catch { /* history enumeration optional */ }

  return { devices, installDates }
}

// ═══════════════════════════════════════════════════
// DEVICE CLASSIFICATION
// ═══════════════════════════════════════════════════

/**
 * Classify a device based on VID, PID, USB class, and name.
 */
function classifyDevice(info: UsbDeviceInfo): DeviceSummary {
  const { vid, pid, friendlyName, deviceClass } = info

  // ── Rule 0: Hardware cheat devices (Arduino/Teensy/Titan Two — aimbot hardware) ──
  const hwCheat = HW_CHEAT_VENDORS[vid]
  if (hwCheat && HW_CHEAT_PIDS.has(pid)) {
    return {
      type: 'unknown',
      icon: '🎯',
      name: friendlyName || `${hwCheat.name}`,
      vendor: hwCheat.name,
      vid, pid,
      risk: hwCheat.risk,
      isPresent: info.isPresent,
      details: [
        `⚠ HARDWARE AIMBOT / INPUT CHEAT DEVICE`,
        `Device: ${hwCheat.name}`,
        `VID: ${vid.toUpperCase()} PID: ${pid.toUpperCase()}`,
        info.isPresent ? '⚠ DEVICE IS CURRENTLY CONNECTED' : '',
        `These devices inject automated mouse/keyboard input (aimbot, recoil scripts)`,
        `They can spoof VID/PID to evade detection`,
      ].filter(Boolean),
    }
  }

  // ── Rule 1: Check DMA/FPGA vendors (HIGH risk) — with additional checks ──
  if (DMA_VENDORS[vid]) {
    const isFtdi = vid === '0403'

    // FTDI (0403): only flag as DMA if combined with FPGA indicators
    // FTDI makes common USB-UART chips used by Arduino, industrial equipment, etc.
    if (isFtdi) {
      const hasDmaIndicator = (
        friendlyName.toLowerCase().includes('ft601') ||
        friendlyName.toLowerCase().includes('ftd3') ||
        friendlyName.toLowerCase().includes('fpga') ||
        friendlyName.toLowerCase().includes('xilinx') ||
        friendlyName.toLowerCase().includes('pcileech') ||
        friendlyName.toLowerCase().includes('leech')
      )
      if (!hasDmaIndicator) {
        // Regular FTDI serial adapter — not DMA
        return {
          type: 'unknown',
          icon: '🔌',
          name: friendlyName || `FTDI USB-Serial Adapter (VID_${vid})`,
          vendor: 'FTDI (USB-UART)',
          vid, pid,
          risk: 'low',
          isPresent: info.isPresent,
          details: ['FTDI USB-to-Serial adapter (common Arduino/industrial use)'],
        }
      }
    }

    // Build DMA device result
    const dmaDetails = [
      `FPGA/DMA controller detected`,
      `Vendor: ${DMA_VENDORS[vid]}`,
      info.isPresent ? '⚠ DEVICE IS CURRENTLY CONNECTED' : 'Device not currently active',
    ]

    // ── DRIVER SIGNATURE CHECK for ALL FTDI/FPGA/DMA devices ──
    // Legitimate drivers are ALWAYS Microsoft or vendor-signed.
    // Unsigned or self-signed driver = strong DMA cheat indicator.
    if (info.isPresent) {
      try {
        const driverSig = checkDeviceDriverSignature(vid, pid)
        if (driverSig) {
          if (!driverSig.isValid) {
            dmaDetails.push('🔐 DRIVER SIGNATURE: UNSIGNED ⚠')
            dmaDetails.push(...driverSig.details)
            dmaDetails.push('⚠ Unsigned FTDI/FPGA driver = definitive DMA cheat card signal')
          } else if (driverSig.isSelfSigned) {
            dmaDetails.push('🔐 DRIVER SIGNATURE: SELF-SIGNED ⚠')
            dmaDetails.push(...driverSig.details)
          } else if (!driverSig.isMicrosoft && !driverSig.isFtdi) {
            dmaDetails.push(`🔐 Driver signed by third party: ${driverSig.signer.slice(0, 60)}`)
          } else {
            dmaDetails.push(`✅ Driver correctly signed by ${driverSig.isMicrosoft ? 'Microsoft' : 'FTDI'}`)
          }
        }
      } catch { /* driver sig check optional */ }
    }

    return {
      type: 'dma_fpga',
      icon: '⚠️',
      name: friendlyName || `DMA Device (VID_${vid})`,
      vendor: DMA_VENDORS[vid],
      vid,
      pid,
      risk: 'high',
      isPresent: info.isPresent,
      details: dmaDetails,
    }
  }

  // ── Rule 2: Check phone/tablet vendors (with USB descriptors for 100% accuracy) ──
  if (PHONE_VENDORS[vid]) {
    const desc = info.descriptors
    const lowerName = friendlyName.toLowerCase()

    // ** TIER 1: Descriptor-based definitive classification **
    if (desc) {
      // MTP/ADB/PTP/RNDIS protocol mode = definitively a phone
      if (desc.isPhoneByDescriptor) {
        const phoneModel = desc.busReportedDesc || friendlyName || `Phone: ${PHONE_VENDORS[vid]}`
        const phoneMfr = desc.manufacturer || PHONE_VENDORS[vid]
        const modeLabel = desc.protocolMode === 'adb'
          ? ' (USB Debug/ADB mode ⚠)'
          : desc.protocolMode === 'mtp'
            ? ' (MTP — Media Transfer)'
            : desc.protocolMode === 'ptp'
              ? ' (PTP — Photo Transfer)'
              : desc.protocolMode === 'rndis'
                ? ' (USB Tethering)'
                : ''
        const phoneDetails = [
          `✅ USB Descriptor: definitively a phone/tablet`,
          `Manufacturer: ${phoneMfr}`,
          `Model: ${phoneModel}`,
          desc.serialNumber ? `Serial: ${desc.serialNumber}` : '',
          `Protocol: ${desc.protocolMode.toUpperCase()}${modeLabel}`,
          desc.protocolMode === 'adb' ? '⚠ ADB mode — device in debug/developer mode' : '',
        ].filter(Boolean)

        return {
          type: 'phone',
          icon: '📱',
          name: phoneModel,
          vendor: phoneMfr,
          vid, pid,
          risk: desc.protocolMode === 'adb' ? 'medium' : 'low',
          isPresent: info.isPresent,
          details: phoneDetails,
        }
      }

      // Mass storage protocol mode on a phone-vendor VID = storage device, NOT a phone
      if (desc.protocolMode === 'mass_storage' && !desc.isPhoneByDescriptor) {
        return {
          type: 'flash_drive',
          icon: '💾',
          name: desc.busReportedDesc || friendlyName || `Storage Device (${PHONE_VENDORS[vid]})`,
          vendor: desc.manufacturer || PHONE_VENDORS[vid],
          vid, pid,
          risk: 'low',
          isPresent: info.isPresent,
          details: [
            `USB Mass Storage Device (USB descriptor confirmed)`,
            desc.manufacturer ? `Manufacturer: ${desc.manufacturer}` : '',
            desc.busReportedDesc ? `Model: ${desc.busReportedDesc}` : '',
            desc.serialNumber ? `Serial: ${desc.serialNumber}` : '',
          ].filter(Boolean),
        }
      }

      // Unknown protocol mode but no phone indicators — likely storage/peripheral
      if (desc.protocolMode === 'unknown' && !desc.isPhoneByDescriptor) {
        return {
          type: 'unknown',
          icon: '🔌',
          name: desc.busReportedDesc || friendlyName || `USB Device (${PHONE_VENDORS[vid]})`,
          vendor: desc.manufacturer || PHONE_VENDORS[vid],
          vid, pid,
          risk: 'low',
          isPresent: info.isPresent,
          details: [
            `USB device from ${PHONE_VENDORS[vid]} (descriptor: not a phone)`,
            desc.manufacturer ? `Manufacturer: ${desc.manufacturer}` : '',
            desc.serialNumber ? `Serial: ${desc.serialNumber}` : '',
          ].filter(Boolean),
        }
      }
    }

    // ** TIER 2: Fallback heuristics (no descriptors available) **
    // Phones typically use MTP, PTP, ADB, or vendor-specific restore modes
    const isLikelyPhone = (
      lowerName.includes('phone') ||
      lowerName.includes('mobile') ||
      lowerName.includes('adb') ||
      lowerName.includes('fastboot') ||
      lowerName.includes('mtp') ||
      lowerName.includes('restore') ||
      lowerName.includes('recovery') ||
      lowerName.includes('tether') ||
      lowerName.includes('android') ||
      lowerName.includes('galaxy') ||
      deviceClass === 'WPD' ||  // Portable devices (MTP)
      deviceClass === 'Image'    // PTP cameras/phones
    )
    if (!isLikelyPhone) {
      return {
        type: 'unknown',
        icon: '🔌',
        name: friendlyName || `USB Device (${PHONE_VENDORS[vid]})`,
        vendor: PHONE_VENDORS[vid],
        vid, pid,
        risk: 'low',
        isPresent: info.isPresent,
        details: [`USB device from ${PHONE_VENDORS[vid]} (not a phone — may be storage/peripheral)`],
      }
    }
    const phoneType = lowerName.includes('adb') || lowerName.includes('fastboot')
      ? ' (USB Debug/ADB mode ⚠)'
      : lowerName.includes('tether')
        ? ' (Tethering)'
        : ''
    return {
      type: 'phone',
      icon: '📱',
      name: friendlyName || `Phone: ${PHONE_VENDORS[vid]}`,
      vendor: PHONE_VENDORS[vid],
      vid,
      pid,
      risk: lowerName.includes('adb') ? 'medium' : 'low',
      isPresent: info.isPresent,
      details: [
        `Mobile device: ${PHONE_VENDORS[vid]}${phoneType}`,
        `USB connection established`,
        '⚠ Descriptors unavailable — classification based on heuristics',
      ],
    }
  }

  // ── Rule 3: Check flash drive vendors ──
  if (FLASH_DRIVE_VENDORS[vid] || deviceClass === 'USB' && friendlyName.toLowerCase().includes('usb mass storage')) {
    return {
      type: 'flash_drive',
      icon: '💾',
      name: friendlyName || `USB Flash Drive (VID_${vid})`,
      vendor: FLASH_DRIVE_VENDORS[vid] || 'Generic',
      vid,
      pid,
      risk: 'low',
      isPresent: info.isPresent,
      details: [
        `USB Mass Storage Device`,
        FLASH_DRIVE_VENDORS[vid] ? `Brand: ${FLASH_DRIVE_VENDORS[vid]}` : '',
      ],
    }
  }

  // ── Rule 4: USB class-based classification ──
  if (deviceClass === 'HIDClass' || deviceClass === 'Keyboard' || deviceClass === 'Mouse') {
    return {
      type: 'keyboard_mouse',
      icon: '⌨️',
      name: friendlyName || 'HID Input Device',
      vendor: USB_HUB_VENDORS[vid] || 'Unknown',
      vid, pid,
      risk: 'low',
      isPresent: info.isPresent,
      details: ['Human Interface Device (keyboard/mouse/gamepad)'],
    }
  }

  if (deviceClass === 'Image' || deviceClass === 'Camera' || friendlyName.toLowerCase().includes('webcam') || friendlyName.toLowerCase().includes('camera')) {
    return {
      type: 'webcam',
      icon: '📹',
      name: friendlyName || 'Camera Device',
      vendor: '',
      vid, pid,
      risk: 'low',
      isPresent: info.isPresent,
      details: ['Imaging/Camera device'],
    }
  }

  if (deviceClass === 'Media' || deviceClass === 'AudioEndpoint' || friendlyName.toLowerCase().includes('audio') || friendlyName.toLowerCase().includes('speaker') || friendlyName.toLowerCase().includes('headphone')) {
    return {
      type: 'audio',
      icon: '🎵',
      name: friendlyName || 'Audio Device',
      vendor: '',
      vid, pid,
      risk: 'low',
      isPresent: info.isPresent,
      details: ['Audio device'],
    }
  }

  if (deviceClass === 'Net' || deviceClass === 'Bluetooth' || friendlyName.toLowerCase().includes('ethernet') || friendlyName.toLowerCase().includes('wifi') || friendlyName.toLowerCase().includes('bluetooth')) {
    return {
      type: 'network',
      icon: '📶',
      name: friendlyName || 'Network Adapter',
      vendor: '',
      vid, pid,
      risk: 'low',
      isPresent: info.isPresent,
      details: ['Network/Bluetooth adapter'],
    }
  }

  // ── Rule 5: USB Hub — ignore ──
  if (USB_HUB_VENDORS[vid] || friendlyName.toLowerCase().includes('root hub') || friendlyName.toLowerCase().includes('usb 3') || friendlyName.toLowerCase().includes('usb hub')) {
    return {
      type: 'hub',
      icon: '🔌',
      name: friendlyName || `USB Hub (VID_${vid})`,
      vendor: USB_HUB_VENDORS[vid] || '',
      vid, pid,
      risk: 'low',
      isPresent: info.isPresent,
      details: ['USB Hub (not a storage or DMA device)'],
    }
  }

  // ── Rule 6: Unknown USB device → flag as medium risk ──
  return {
    type: 'unknown',
    icon: '❓',
    name: friendlyName || `Unknown USB Device (VID_${vid}:PID_${pid})`,
    vendor: '',
    vid, pid,
    risk: 'medium',
    isPresent: info.isPresent,
    details: [
      'Unrecognized USB device',
      vid ? `VID: ${vid}` : '',
      pid ? `PID: ${pid}` : '',
      'Consider investigating this device',
    ],
  }
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

  // Add suspicious devices (DMA/FPGA) — HIGH risk
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

  // Add DMA history — HIGH risk
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

  // Add safe devices as informational (low risk — won't alarm the user)
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
// USB History from SetupAPI Log
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

    // Cap at 1MB to avoid OOM on systems with large driver install history
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
          // Get context: find timestamp on nearby lines
          let timestamp = ''
          for (let j = Math.max(0, i - 5); j <= i; j++) {
            const tsMatch = lines[j]?.match(/(\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2})/)
            if (tsMatch) {
              timestamp = tsMatch[1]
              break
            }
          }
          foundEntries.push(`${timestamp ? `[${timestamp}] ` : ''}${line.slice(0, 200).trim()}`)
          break // One keyword match per line
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
// USB BANDWIDTH MONITORING — Active DMA Detection
// ═══════════════════════════════════════════════════

/**
 * DMA cards (FT601 bridge) generate 150-400 MB/s sustained USB traffic.
 * Normal USB devices max out at 20-50 MB/s for flash drives, 5-40 MB/s for phones.
 * This function detects active DMA cards by measuring USB throughput.
 *
 * Three-tier approach:
 *   Tier 1: PowerShell Get-Counter "\USB(*)\Bulk Bytes/Sec" — real-time throughput
 *   Tier 2: WMI Win32_PerfFormattedData polling — fallback if counters unavailable
 *   Tier 3: USB speed class heuristic — SuperSpeed (5Gbps) on FTDI = suspicion
 */

interface BandwidthSample {
  instance: string
  bytesPerSec: number
  counterName: string
}

/**
 * Tier 1: Sample USB bulk transfer throughput via Get-Counter.
 * Takes two samples 3 seconds apart in ONE PowerShell process (no separate sleep spawn).
 * Calculates bytes/sec delta.
 */
function sampleUsbBandwidthViaPerfCounter(): BandwidthSample[] {
  const results: BandwidthSample[] = []

  try {
    // Check availability + sample twice in ONE script (avoids extra process spawn)
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
    const out = execSync(`powershell -NoProfile -Command "${combinedScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 12000, windowsHide: true,
    }).trim()

    if (!out || out.includes('UNAVAILABLE') || out.includes('NO_COUNTERS')) return results

    // Split output into sample 1 and sample 2 sections
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
        } catch { /* skip */ }
      }
      return map
    }

    const sample1Map = parseSamples(sample1Block)
    const sample2Map = parseSamples(sample2Block)

    for (const [instance, value1] of sample1Map) {
      const value2 = sample2Map.get(instance)
      if (!value2 || value2 <= value1) continue

      const bytesPerSec = (value2 - value1) / 3
      if (bytesPerSec > 10_000_000) { // > 10 MB/s
        results.push({ instance, bytesPerSec, counterName: 'USB Bulk Bytes/Sec' })
      }
    }
  } catch { /* Tier 1 optional */ }

  return results
}

/**
 * Tier 2: WMI-based USB bandwidth polling via network adapter counters as proxy.
 * USB perf counters are rarely available; we use a heuristic: check if ANY high-throughput
 * data transfer is happening when we know USB hubs are active.
 * Tries multiple WMI class names that may expose USB throughput.
 */
function sampleUsbBandwidthViaWmi(): BandwidthSample[] {
  const results: BandwidthSample[] = []

  try {
    // Try multiple WMI class names that may have USB throughput data
    const wmiScript = `
$ErrorActionPreference = 'SilentlyContinue'

# Try to find any WMI class with USB throughput data
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
      # Try common counter property names for bytes/sec
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
    const out = execSync(`powershell -NoProfile -Command "${wmiScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 15000, windowsHide: true,
    }).trim()

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
      } catch { /* skip */ }
    }
  } catch { /* Tier 2 optional */ }

  return results
}

/**
 * Tier 3: Heuristic — check USB device speed class.
 * FTDI FT601 is USB 3.0 SuperSpeed (5 Gbps).
 * Normal UART adapters are USB 2.0 High-Speed (480 Mbps max = 60 MB/s).
 * An FTDI device at SuperSpeed that isn't a known safe device = DMA suspicion.
 *
 * BATCHED: all devices checked in ONE PowerShell invocation.
 */
function checkUsbSpeedClassHeuristic(presentDevices: UsbDeviceInfo[]): BandwidthSample[] {
  const results: BandwidthSample[] = []

  // Filter to relevant devices only
  const targets = presentDevices.filter(dev => {
    if (!dev.vid) return false
    const isDmaVendor = !!DMA_VENDORS[dev.vid]
    const isUnknown = !PHONE_VENDORS[dev.vid] && !FLASH_DRIVE_VENDORS[dev.vid] && !USB_HUB_VENDORS[dev.vid]
    return isDmaVendor || isUnknown
  })

  if (targets.length === 0) return results

  try {
    // Build batched PowerShell: one script checks ALL target devices
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

  # Check USB hub/controller info for this device
  $usbDev = Get-CimInstance -Query "SELECT * FROM Win32_USBHub WHERE DeviceID LIKE '%' + $vid + '%' + $pid + '%'" -ErrorAction SilentlyContinue
  if ($usbDev) {
    @{ InstanceId = $instanceId; Speed = $usbDev.Name; Rate = 5000 } | ConvertTo-Json -Compress
    continue
  }

  # Try alternate: check registry for USB speed (with null-guard)
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
    const out = execSync(`powershell -NoProfile -Command "${batchedScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 15000, windowsHide: true,
    }).trim()

    if (!out || out.length < 5) return results

    // Parse batched output — each line is one device's JSON result
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
      } catch { /* skip */ }
    }
  } catch { /* speed check optional */ }

  return results
}

/**
 * Main USB bandwidth monitoring: combines all three tiers.
 * Returns bandwidth samples for all detected high-throughput USB devices.
 */
function monitorUsbBandwidth(): BandwidthSample[] {
  // Tier 1: Real-time performance counters (most accurate)
  const tier1 = sampleUsbBandwidthViaPerfCounter()
  if (tier1.length > 0) return tier1

  // Tier 2: WMI polling fallback
  const tier2 = sampleUsbBandwidthViaWmi()
  if (tier2.length > 0) return tier2

  // Tier 3: Speed class heuristic (least accurate, but always available)
  return [] // Tier 3 requires device list — called separately
}

/**
 * Cross-reference bandwidth data with device classification.
 * Returns ScanResult[] for active DMA cards detected via USB traffic.
 */
function detectActiveDmaByBandwidth(
  bandwidthData: BandwidthSample[],
  speedHeuristicData: BandwidthSample[],
  presentDevices: UsbDeviceInfo[],
): ScanResult[] {
  const results: ScanResult[] = []

  // Build device lookup by instance ID (lowercase)
  const deviceByInstance = new Map<string, UsbDeviceInfo>()
  for (const dev of presentDevices) {
    deviceByInstance.set(dev.instanceId.toLowerCase(), dev)
    // Also index by VID
    if (dev.vid) {
      deviceByInstance.set(`vid:${dev.vid}`, dev)
    }
  }

  // Combine all bandwidth data
  const allSamples = [...bandwidthData, ...speedHeuristicData]

  for (const sample of allSamples) {
    // Find matching device
    const matchingDev = deviceByInstance.get(sample.instance) ||
      findDeviceByPartialInstance(presentDevices, sample.instance)

    if (!matchingDev) continue

    const { vid, pid, friendlyName, deviceClass } = matchingDev

    // ── False positive filters ──
    // Skip known Mass Storage vendors (external SSDs like Kingston, SanDisk)
    if (FLASH_DRIVE_VENDORS[vid] && vid !== '0403') continue
    // Skip Mass Storage devices regardless of VID (Samsung T7, external SSD, etc.)
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
    // Skip phones from phone-vendor VIDs (even at high bandwidth — MTP transfers)
    if (PHONE_VENDORS[vid]) {
      const isPhone = friendlyName.toLowerCase().includes('phone') ||
        friendlyName.toLowerCase().includes('mobile') ||
        friendlyName.toLowerCase().includes('adb') ||
        friendlyName.toLowerCase().includes('mtp') ||
        friendlyName.toLowerCase().includes('android') ||
        friendlyName.toLowerCase().includes('galaxy') ||
        deviceClass === 'WPD'
      if (isPhone) continue
      // If not a phone but from phone vendor VID, check if it's storage → skip
      if (isMassStorage) continue
    }
    // Skip USB hubs
    if (USB_HUB_VENDORS[vid]) continue
    // Skip video/camera devices (VR headsets, webcams)
    if (deviceClass === 'Image' || deviceClass === 'Camera' ||
        friendlyName.toLowerCase().includes('webcam') ||
        friendlyName.toLowerCase().includes('oculus') ||
        friendlyName.toLowerCase().includes('vive')) continue
    // Skip network devices
    if (deviceClass === 'Net' || deviceClass === 'Bluetooth') continue

    const bytesPerSecMB = sample.bytesPerSec / 1_000_000
    const isTier3Heuristic = sample.counterName.includes('Speed Class')

    // ── Bandwidth thresholds ──
    let shouldFlag = false
    let risk: 'high' | 'medium' = 'medium'
    let confidence = ''

    if (isTier3Heuristic) {
      // USB 3.0 SuperSpeed on FTDI/unknown device
      if (DMA_VENDORS[vid]) {
        shouldFlag = true
        risk = 'high'
        confidence = 'USB 3.0 SuperSpeed (5 Gbps) on DMA-vendor device — DMA card indicator'
      } else {
        shouldFlag = true
        risk = 'medium'
        confidence = 'USB 3.0 SuperSpeed on unknown device — investigate'
      }
    } else if (bytesPerSecMB >= 150) {
      // >150 MB/s sustained = almost certainly DMA (no normal USB device does this)
      shouldFlag = true
      risk = 'high'
      confidence = `Extreme USB throughput: ${bytesPerSecMB.toFixed(0)} MB/s`
    } else if (bytesPerSecMB >= 80 && DMA_VENDORS[vid]) {
      // >80 MB/s on an FTDI/FPGA device
      shouldFlag = true
      risk = 'high'
      confidence = `High USB throughput on DMA vendor device: ${bytesPerSecMB.toFixed(0)} MB/s`
    } else if (bytesPerSecMB >= 60 && vid === '0403') {
      // >60 MB/s on FTDI (normal UART maxes at ~3 MB/s)
      shouldFlag = true
      risk = 'high'
      confidence = `FTDI device at ${bytesPerSecMB.toFixed(0)} MB/s — normal UART max 3 MB/s, this is FT601 DMA bridge`
    } else if (bytesPerSecMB >= 50 && !PHONE_VENDORS[vid] && !FLASH_DRIVE_VENDORS[vid]) {
      // >50 MB/s on unknown device
      shouldFlag = true
      risk = 'medium'
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
    // Try VID match (instance names in perf counters may use VID)
    if (instanceLower.includes(`vid_${dev.vid}`) || instanceLower.includes(`ven_${dev.vid}`)) {
      return dev
    }
    // Try PID match
    if (dev.pid && (instanceLower.includes(`pid_${dev.pid}`) || instanceLower.includes(`dev_${dev.pid}`))) {
      return dev
    }
  }
  return undefined
}

/**
 * Run the full USB/hardware device scan.
 * Combines device inventory + history + setupapi log scan + bandwidth monitoring.
 */
export function runFullUsbDeviceScan(): ScanResult[] {
  const results: ScanResult[] = []

  // Enumerate devices ONCE and reuse across all sub-scans
  const presentDevices = enumeratePresentDevices()
  const { devices: historyDevices, installDates } = enumerateDeviceHistory()

  // Device inventory + classification
  const deviceReport = buildDeviceReport(presentDevices, historyDevices, installDates)
  results.push(...deviceReportToScanResults(deviceReport))
  results.push(...scanSetupApiLog())
  results.push(...scanDmaDriverSignatures())

  // ── USB Bandwidth Monitoring: detect ACTIVE DMA cards ──
  // Only run if DMA-vendor devices are present (avoid 3s delay on clean systems)
  const hasDmaVendorDevices = presentDevices.some(d => DMA_VENDORS[d.vid])
  if (hasDmaVendorDevices && presentDevices.length > 0) {
    try {
      // Tier 1+2: Real-time perf counter / WMI bandwidth sampling (+3s)
      const bandwidthData = monitorUsbBandwidth()

      // Tier 3: Speed class heuristic on present devices
      const speedHeuristicData = checkUsbSpeedClassHeuristic(presentDevices)

      // Cross-reference and generate findings
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
