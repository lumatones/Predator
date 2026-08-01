export type TriageSeverity = 'critical' | 'high' | 'medium' | 'low'
export type TriageVerdict = 'high-risk' | 'suspicious' | 'inconclusive' | 'low-risk'

export interface TriageSection {
  name: string
  virtualAddress: number
  virtualSize: number
  rawOffset: number
  rawSize: number
  entropy: number | null
  executable: boolean
  writable: boolean
  rawBacked: boolean
}

export interface TriageImport {
  dll: string
  name?: string
  ordinal?: number
  risk: TriageSeverity
  reason?: string
}

export interface TriageDirectory {
  name: string
  rva: number
  size: number
  mapped: boolean
}

export interface TriageIndicator {
  id: string
  severity: TriageSeverity
  title: string
  explanation: string
  confidence: number
}

export interface BinaryTriageReport {
  staticOnly: true
  file: {
    path: string
    fileName: string
    size: number
    sha256: string
    extension: string
    signed: boolean
    signatureStatus: 'valid' | 'unsigned' | 'unknown'
  }
  pe: {
    valid: boolean
    architecture: 'x86' | 'x64' | 'unknown'
    machine: string
    subsystem: string
    imageBase: string
    entryPointRva: string
    entryPointSection?: string
    sectionCount: number
    sections: TriageSection[]
    directories: TriageDirectory[]
    imports: TriageImport[]
    tls: {
      present: boolean
      callbackCount: number
      physicalCallbackCount: number
    }
    manifest?: string
    requestedExecutionLevel?: string
  }
  indicators: TriageIndicator[]
  score: number
  verdict: TriageVerdict
  limitations: string[]
}
