/**
 * Predator — USB Descriptor Reading
 *
 * Extracted from usb-devices.ts. Reads USB device descriptors via
 * Get-PnpDeviceProperty (batched PowerShell), enumerates present
 * and historical devices.
 */

import { execPowerShell } from '../../utils/exec'
import { parsePsJson } from '../../types'

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
  descriptors?: UsbDescriptors
}

export interface UsbDescriptors {
  manufacturer: string
  busReportedDesc: string
  serialNumber: string
  compatibleIds: string[]
  protocolMode: 'mtp' | 'ptp' | 'adb' | 'rndis' | 'mass_storage' | 'charging' | 'unknown'
  isPhoneByDescriptor: boolean
}

export interface DeviceReport {
  connectedSafe: import('./classification').DeviceSummary[]
  connectedSuspicious: import('./classification').DeviceSummary[]
  dmaHistory: import('./classification').DeviceSummary[]
  summary: string
  totalDevices: number
}

// ═══════════════════════════════════════════════════
// DMA/FPGA VENDORS — shared with classification
// ═══════════════════════════════════════════════════

export const DMA_VENDORS: Record<string, string> = {
  '10ee': 'Xilinx FPGA (DMA cheat card)',
  '1172': 'Altera/Intel FPGA (DMA cheat card)',
  '1204': 'Lattice FPGA (DMA cheat card)',
  'dada': 'Xilinx FPGA (alt ID)',
  '0403': 'FTDI USB-FPGA Bridge (DMA card)',
  '104c': 'TI FPGA',
}

// ═══════════════════════════════════════════════════
// USB DESCRIPTOR READING
// ═══════════════════════════════════════════════════

const DEVPKEY_GUID = '{a45c254e-df1c-4efd-8020-67d146a850e0}'

const DEVPKEY_PID = {
  CompatibleIds: 4,
  ClassGuid: 9,
  Manufacturer: 13,
  BusReportedDeviceDesc: 14,
  SerialNumber: 30,
} as const

export function readUsbDescriptors(devices: UsbDeviceInfo[]): Map<string, UsbDescriptors> {
  const descriptorMap = new Map<string, UsbDescriptors>()
  if (devices.length === 0) return descriptorMap

  const targets = devices.filter(d => d.vid && d.instanceId)
  if (targets.length === 0) return descriptorMap

  try {
    const idList = targets.map(d => `'${d.instanceId.replace(/'/g, "''")}'`).join(',')
    const guid = DEVPKEY_GUID

    const batchedScript = `
$ErrorActionPreference = 'SilentlyContinue'
$guid = '${guid}'
$ids = @(${idList})
$results = @()

foreach ($id in $ids) {
  $info = @{ InstanceId = $id }

  $mfr = Get-PnpDeviceProperty -InstanceId $id -KeyName "$guid ${DEVPKEY_PID.Manufacturer}" -ErrorAction SilentlyContinue
  if ($mfr -and $mfr.Data) { $info.Mfr = $mfr.Data.ToString() } else { $info.Mfr = '' }

  $desc = Get-PnpDeviceProperty -InstanceId $id -KeyName "$guid ${DEVPKEY_PID.BusReportedDeviceDesc}" -ErrorAction SilentlyContinue
  if ($desc -and $desc.Data) { $info.BusDesc = $desc.Data.ToString() } else { $info.BusDesc = '' }

  $sn = Get-PnpDeviceProperty -InstanceId $id -KeyName "$guid ${DEVPKEY_PID.SerialNumber}" -ErrorAction SilentlyContinue
  if ($sn -and $sn.Data) { $info.Serial = $sn.Data.ToString() } else { $info.Serial = '' }

  $compat = Get-PnpDeviceProperty -InstanceId $id -KeyName "$guid ${DEVPKEY_PID.CompatibleIds}" -ErrorAction SilentlyContinue
  if ($compat -and $compat.Data) {
    $compatList = @()
    foreach ($c in $compat.Data) { $compatList += $c.ToString() }
    $info.CompatIds = $compatList -join '|'
  } else { $info.CompatIds = '' }

  if ($info.Mfr -or $info.BusDesc -or $info.Serial -or $info.CompatIds) {
    $info | ConvertTo-Json -Compress
  }
}
`
    const out = (execPowerShell(batchedScript, { timeout: 20000, collapseLines: 'semicolons' }) || '').trim()

    if (!out || out.length < 5) return descriptorMap

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

        const isPhoneByDescriptor = (
          protocolMode === 'mtp' || protocolMode === 'ptp' ||
          protocolMode === 'adb' || protocolMode === 'rndis' ||
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
          manufacturer, busReportedDesc, serialNumber, compatibleIds,
          protocolMode, isPhoneByDescriptor,
        })
      } catch { /* skip malformed line */ }
    }
  } catch { /* descriptor reading optional */ }

  return descriptorMap
}

// ═══════════════════════════════════════════════════
// DEVICE ENUMERATION
// ═══════════════════════════════════════════════════

export function enumeratePresentDevices(): UsbDeviceInfo[] {
  const devices: UsbDeviceInfo[] = []

  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
Get-PnpDevice -PresentOnly |
  Where-Object { $_.Class -match 'USB|HIDClass|Ports|System|Net|SCSIAdapter|Image|Camera|Media|AudioEndpoint|Bluetooth|WPD' } |
  Select-Object InstanceId, FriendlyName, Class |
  ConvertTo-Json -Compress
`
    const out = (execPowerShell(psScript, { timeout: 10000 }) || '').trim()

    if (!out || out.length < 5) return devices

    const raw = parsePsJson<{ InstanceId?: string; FriendlyName?: string; Class?: string }>(out)

    for (const dev of raw) {
      const instanceId = dev.InstanceId || ''
      const friendlyName = (dev.FriendlyName || '').replace(/[^\x20-\x7E\u0400-\u04FF]/g, '').trim()
      const deviceClass = dev.Class || 'Unknown'

      const vidMatch = instanceId.match(/VID[_\s]*([0-9A-Fa-f]{4})/i)
      const pidMatch = instanceId.match(/PID[_\s]*([0-9A-Fa-f]{4})/i)
      const venMatch = instanceId.match(/VEN[_\s]*([0-9A-Fa-f]{4})/i)
      const devMatch = instanceId.match(/DEV[_\s]*([0-9A-Fa-f]{4})/i)

      devices.push({
        instanceId, friendlyName, deviceClass,
        vid: vidMatch ? vidMatch[1].toLowerCase() : (venMatch ? venMatch[1].toLowerCase() : ''),
        pid: pidMatch ? pidMatch[1].toLowerCase() : (devMatch ? devMatch[1].toLowerCase() : ''),
        isPresent: true,
      })
    }

    if (devices.length > 0) {
      try {
        const descriptorMap = readUsbDescriptors(devices)
        for (const dev of devices) {
          const desc = descriptorMap.get(dev.instanceId.toLowerCase())
          if (desc) dev.descriptors = desc
        }
      } catch { /* descriptor enrichment optional */ }
    }
  } catch { /* enumeration optional */ }

  return devices
}

export function enumerateDeviceHistory(): { devices: UsbDeviceInfo[]; installDates: Map<string, string> } {
  const devices: UsbDeviceInfo[] = []
  const installDates = new Map<string, string>()

  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$results = @()

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
    const out = (execPowerShell(psScript, { timeout: 15000 }) || '').trim()

    if (!out || out.length < 5) return { devices, installDates }

    const raw = parsePsJson<{ InstanceId?: string; FriendlyName?: string; Class?: string; Service?: string; InstallDate?: unknown }>(out)

    for (const dev of raw) {
      const instanceId = dev.InstanceId || ''
      const friendlyName = (dev.FriendlyName || '').replace(/[^\x20-\x7E\u0400-\u04FF]/g, '').trim()
      const installDate = typeof dev.InstallDate === 'string' ? dev.InstallDate : ''

      const vidMatch = instanceId.match(/VID[_\s]*([0-9A-Fa-f]{4})/i)
      const venMatch = instanceId.match(/VEN[_\s]*([0-9A-Fa-f]{4})/i)
      const vid = vidMatch ? vidMatch[1].toLowerCase() : (venMatch ? venMatch[1].toLowerCase() : '')
      const pidMatch = instanceId.match(/PID[_\s]*([0-9A-Fa-f]{4})/i)
      const pid = pidMatch ? pidMatch[1].toLowerCase() : ''

      if (vid && installDate) installDates.set(vid, installDate)

      devices.push({ instanceId, friendlyName, deviceClass: dev.Class || 'Unknown', vid, pid, isPresent: false })
    }
  } catch { /* history enumeration optional */ }

  return { devices, installDates }
}
