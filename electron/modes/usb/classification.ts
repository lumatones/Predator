/**
 * Predator — USB Device Classification + Driver Signature Verification
 *
 * Extracted from usb-devices.ts. Classifies USB/PCI devices by VID, PID,
 * USB class code, and name into safe/suspicious categories.
 * Also verifies driver digital signatures for DMA/FPGA devices.
 */

import { execSync } from 'child_process'
import * as fs from 'fs'
import * as path from 'path'
import { _WR } from '../../types'
import type { UsbDeviceInfo, UsbDescriptors } from './descriptors'
import { DMA_VENDORS } from './descriptors'

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

export const DMA_DRIVER_FILES = [
  'ftd3xx.dll', 'ftd2xx.dll', 'ftdiBus3.sys', 'ftdiBus2.sys',
  'leechcore.dll', 'vmm.dll', 'pcileech.dll', 'pcileech_core.dll',
  'leechsvc.dll', 'memprocfs.exe', 'ft601.sys', 'ftdibus.sys',
]

/**
 * Check digital signature of a driver file.
 * Returns full signature info: validity, signer name, trust level.
 */
export function checkDriverSignature(filepath: string): DriverSignatureResult | null {
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
 * Check driver signatures for a specific FTDI/FPGA device by its VID/PID.
 * Uses PowerShell to find the driver files associated with the device.
 */
export function checkDeviceDriverSignature(vid: string, pid: string): DriverSignatureResult | null {
  try {
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

    const driversDir = path.join(_WR, 'System32', 'drivers')
    const system32Dir = path.join(_WR, 'System32')

    for (const searchDir of [driversDir, system32Dir]) {
      if (!fs.existsSync(searchDir)) continue
      try {
        for (const file of fs.readdirSync(searchDir)) {
          const lower = file.toLowerCase()
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
      } catch (err) { console.warn('[classification] failed:', (err as Error).message) }
    }

    return null
  } catch {
    return null
  }
}

// ═══════════════════════════════════════════════════
// USB Device Classification Tables
// ═══════════════════════════════════════════════════

/** Known phone/tablet Vendor IDs (VID) */
export const PHONE_VENDORS: Record<string, string> = {
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
export const FLASH_DRIVE_VENDORS: Record<string, string> = {
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

/** Generic USB hubs — ignore these */
export const USB_HUB_VENDORS: Record<string, string> = {
  '8087': 'Intel USB Hub',
  '1a40': 'Terminus USB Hub',
  '05e3': 'Genesys Logic Hub',
  '0bda': 'Realtek USB Hub',
  '2109': 'VIA Labs Hub',
}

/** Hardware cheat devices — input manipulation / aimbot hardware */
const HW_CHEAT_VENDORS: Record<string, { name: string; risk: 'high' | 'medium' }> = {
  '2341': { name: 'Arduino Leonardo (HID aimbot)', risk: 'high' },
  '16c0': { name: 'Teensy USB (HID aimbot)', risk: 'high' },
  '2508': { name: 'ConsoleTuner Titan Two (controller cheat)', risk: 'high' },
  '0c12': { name: 'Cronus Zen (controller cheat)', risk: 'high' },
}

/** Known hardware cheat PID from multi-purpose VIDs — narrow match */
const HW_CHEAT_PIDS: Set<string> = new Set([
  '8036', '0036', '8037', '0037',
  '0486', '0483', '0487', '0488', '0489',
  '0001', '0002',
])

// ═══════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════

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
// CLASSIFICATION ENGINE
// ═══════════════════════════════════════════════════

/**
 * Classify a device based on VID, PID, USB class, and name.
 */
export function classifyDevice(info: UsbDeviceInfo): DeviceSummary {
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

  // ── Rule 1: Check DMA/FPGA vendors (HIGH risk) ──
  if (DMA_VENDORS[vid]) {
    const isFtdi = vid === '0403'
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
        return {
          type: 'unknown', icon: '🔌',
          name: friendlyName || `FTDI USB-Serial Adapter (VID_${vid})`,
          vendor: 'FTDI (USB-UART)', vid, pid,
          risk: 'low', isPresent: info.isPresent,
          details: ['FTDI USB-to-Serial adapter (common Arduino/industrial use)'],
        }
      }
    }

    const dmaDetails = [
      `FPGA/DMA controller detected`,
      `Vendor: ${DMA_VENDORS[vid]}`,
      info.isPresent ? '⚠ DEVICE IS CURRENTLY CONNECTED' : 'Device not currently active',
    ]

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
      type: 'dma_fpga', icon: '⚠️',
      name: friendlyName || `DMA Device (VID_${vid})`,
      vendor: DMA_VENDORS[vid], vid, pid,
      risk: 'high', isPresent: info.isPresent,
      details: dmaDetails,
    }
  }

  // ── Rule 2: Check phone/tablet vendors ──
  if (PHONE_VENDORS[vid]) {
    const desc = info.descriptors
    const lowerName = friendlyName.toLowerCase()

    if (desc) {
      if (desc.isPhoneByDescriptor) {
        const phoneModel = desc.busReportedDesc || friendlyName || `Phone: ${PHONE_VENDORS[vid]}`
        const phoneMfr = desc.manufacturer || PHONE_VENDORS[vid]
        const modeLabel = desc.protocolMode === 'adb' ? ' (USB Debug/ADB mode ⚠)'
          : desc.protocolMode === 'mtp' ? ' (MTP — Media Transfer)'
          : desc.protocolMode === 'ptp' ? ' (PTP — Photo Transfer)'
          : desc.protocolMode === 'rndis' ? ' (USB Tethering)' : ''
        return {
          type: 'phone', icon: '📱', name: phoneModel, vendor: phoneMfr, vid, pid,
          risk: desc.protocolMode === 'adb' ? 'medium' : 'low', isPresent: info.isPresent,
          details: [
            `✅ USB Descriptor: definitively a phone/tablet`,
            `Manufacturer: ${phoneMfr}`, `Model: ${phoneModel}`,
            desc.serialNumber ? `Serial: ${desc.serialNumber}` : '',
            `Protocol: ${desc.protocolMode.toUpperCase()}${modeLabel}`,
            desc.protocolMode === 'adb' ? '⚠ ADB mode — device in debug/developer mode' : '',
          ].filter(Boolean),
        }
      }
      if (desc.protocolMode === 'mass_storage' && !desc.isPhoneByDescriptor) {
        return {
          type: 'flash_drive', icon: '💾',
          name: desc.busReportedDesc || friendlyName || `Storage Device (${PHONE_VENDORS[vid]})`,
          vendor: desc.manufacturer || PHONE_VENDORS[vid], vid, pid,
          risk: 'low', isPresent: info.isPresent,
          details: [
            `USB Mass Storage Device (USB descriptor confirmed)`,
            desc.manufacturer ? `Manufacturer: ${desc.manufacturer}` : '',
            desc.busReportedDesc ? `Model: ${desc.busReportedDesc}` : '',
            desc.serialNumber ? `Serial: ${desc.serialNumber}` : '',
          ].filter(Boolean),
        }
      }
      if (desc.protocolMode === 'unknown' && !desc.isPhoneByDescriptor) {
        return {
          type: 'unknown', icon: '🔌',
          name: desc.busReportedDesc || friendlyName || `USB Device (${PHONE_VENDORS[vid]})`,
          vendor: desc.manufacturer || PHONE_VENDORS[vid], vid, pid,
          risk: 'low', isPresent: info.isPresent,
          details: [
            `USB device from ${PHONE_VENDORS[vid]} (descriptor: not a phone)`,
            desc.manufacturer ? `Manufacturer: ${desc.manufacturer}` : '',
            desc.serialNumber ? `Serial: ${desc.serialNumber}` : '',
          ].filter(Boolean),
        }
      }
    }

    const isLikelyPhone = (
      lowerName.includes('phone') || lowerName.includes('mobile') ||
      lowerName.includes('adb') || lowerName.includes('fastboot') ||
      lowerName.includes('mtp') || lowerName.includes('restore') ||
      lowerName.includes('recovery') || lowerName.includes('tether') ||
      lowerName.includes('android') || lowerName.includes('galaxy') ||
      deviceClass === 'WPD' || deviceClass === 'Image'
    )
    if (!isLikelyPhone) {
      return {
        type: 'unknown', icon: '🔌',
        name: friendlyName || `USB Device (${PHONE_VENDORS[vid]})`,
        vendor: PHONE_VENDORS[vid], vid, pid,
        risk: 'low', isPresent: info.isPresent,
        details: [`USB device from ${PHONE_VENDORS[vid]} (not a phone — may be storage/peripheral)`],
      }
    }
    const phoneType = lowerName.includes('adb') || lowerName.includes('fastboot')
      ? ' (USB Debug/ADB mode ⚠)' : lowerName.includes('tether') ? ' (Tethering)' : ''
    return {
      type: 'phone', icon: '📱',
      name: friendlyName || `Phone: ${PHONE_VENDORS[vid]}`,
      vendor: PHONE_VENDORS[vid], vid, pid,
      risk: lowerName.includes('adb') ? 'medium' : 'low', isPresent: info.isPresent,
      details: [
        `Mobile device: ${PHONE_VENDORS[vid]}${phoneType}`,
        `USB connection established`,
        '⚠ Descriptors unavailable — classification based on heuristics',
      ],
    }
  }

  // ── Rule 3: Check flash drive vendors ──
  if (FLASH_DRIVE_VENDORS[vid] || (deviceClass === 'USB' && friendlyName.toLowerCase().includes('usb mass storage'))) {
    return {
      type: 'flash_drive', icon: '💾',
      name: friendlyName || `USB Flash Drive (VID_${vid})`,
      vendor: FLASH_DRIVE_VENDORS[vid] || 'Generic', vid, pid,
      risk: 'low', isPresent: info.isPresent,
      details: [`USB Mass Storage Device`, FLASH_DRIVE_VENDORS[vid] ? `Brand: ${FLASH_DRIVE_VENDORS[vid]}` : ''],
    }
  }

  // ── Rule 4: USB class-based classification ──
  if (deviceClass === 'HIDClass' || deviceClass === 'Keyboard' || deviceClass === 'Mouse') {
    return {
      type: 'keyboard_mouse', icon: '⌨️',
      name: friendlyName || 'HID Input Device',
      vendor: USB_HUB_VENDORS[vid] || 'Unknown', vid, pid,
      risk: 'low', isPresent: info.isPresent,
      details: ['Human Interface Device (keyboard/mouse/gamepad)'],
    }
  }
  if (deviceClass === 'Image' || deviceClass === 'Camera' || friendlyName.toLowerCase().includes('webcam') || friendlyName.toLowerCase().includes('camera')) {
    return { type: 'webcam', icon: '📹', name: friendlyName || 'Camera Device', vendor: '', vid, pid, risk: 'low', isPresent: info.isPresent, details: ['Imaging/Camera device'] }
  }
  if (deviceClass === 'Media' || deviceClass === 'AudioEndpoint' || friendlyName.toLowerCase().includes('audio') || friendlyName.toLowerCase().includes('speaker') || friendlyName.toLowerCase().includes('headphone')) {
    return { type: 'audio', icon: '🎵', name: friendlyName || 'Audio Device', vendor: '', vid, pid, risk: 'low', isPresent: info.isPresent, details: ['Audio device'] }
  }
  if (deviceClass === 'Net' || deviceClass === 'Bluetooth' || friendlyName.toLowerCase().includes('ethernet') || friendlyName.toLowerCase().includes('wifi') || friendlyName.toLowerCase().includes('bluetooth')) {
    return { type: 'network', icon: '📶', name: friendlyName || 'Network Adapter', vendor: '', vid, pid, risk: 'low', isPresent: info.isPresent, details: ['Network/Bluetooth adapter'] }
  }

  // ── Rule 5: USB Hub — ignore ──
  if (USB_HUB_VENDORS[vid] || friendlyName.toLowerCase().includes('root hub') || friendlyName.toLowerCase().includes('usb 3') || friendlyName.toLowerCase().includes('usb hub')) {
    return { type: 'hub', icon: '🔌', name: friendlyName || `USB Hub (VID_${vid})`, vendor: USB_HUB_VENDORS[vid] || '', vid, pid, risk: 'low', isPresent: info.isPresent, details: ['USB Hub (not a storage or DMA device)'] }
  }

  // ── Rule 6: Unknown USB device → flag as medium risk ──
  return {
    type: 'unknown', icon: '❓',
    name: friendlyName || `Unknown USB Device (VID_${vid}:PID_${pid})`,
    vendor: '', vid, pid, risk: 'medium', isPresent: info.isPresent,
    details: ['Unrecognized USB device', vid ? `VID: ${vid}` : '', pid ? `PID: ${pid}` : '', 'Consider investigating this device'],
  }
}
