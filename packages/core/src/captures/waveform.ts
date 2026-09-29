/**
 * Bitpeek Ultra - Normalized Hardware Waveform Captures & Importers
 *
 * Implements Section 14 (CAP-01, AC049):
 * - Normalized waveform model (channels, timebase, transitions)
 * - CSV edge/sample importer
 * - Bounded Value Change Dump (VCD) digital trace parser
 */

export interface DigitalTransition {
  timestamp: number // in seconds
  value: 0 | 1
}

export interface DigitalChannel {
  name: string
  id: string
  transitions: DigitalTransition[]
}

export interface WaveformCapture {
  captureId: string
  timebaseUnit: string // e.g. "1ns", "1us", "1s"
  timebaseScale: number // multiplier to convert ticks to seconds
  channels: Map<string, DigitalChannel>
  duration: number
  totalTransitions: number
}

/**
 * Parses a CSV waveform file.
 * Format:
 * time_s,CLK,MOSI,MISO,CS
 * 0.000000,0,0,1,1
 * 0.000001,1,1,0,0
 */
export function parseCsvWaveform(csvText: string, captureId = 'csv_capture'): WaveformCapture {
  const lines = csvText.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0 && !l.startsWith('#'))
  if (lines.length < 2) {
    throw new Error('CSV capture requires at least header and one data row')
  }

  const header = lines[0]!.split(',').map((c) => c.trim())
  const timeIdx = header.findIndex((h) => h.toLowerCase().includes('time') || h.toLowerCase() === 't')
  if (timeIdx < 0) {
    throw new Error('CSV capture missing "time" column in header')
  }

  const channels = new Map<string, DigitalChannel>()
  for (let i = 0; i < header.length; i++) {
    if (i !== timeIdx) {
      const name = header[i]!
      channels.set(name, {
        name,
        id: name.toLowerCase(),
        transitions: [],
      })
    }
  }

  let totalTransitions = 0
  let maxTime = 0
  const lastValues = new Map<string, number>()

  for (let r = 1; r < lines.length; r++) {
    const row = lines[r]!.split(',').map((c) => c.trim())
    if (row.length < header.length) continue

    const t = parseFloat(row[timeIdx]!)
    if (isNaN(t)) continue
    if (t > maxTime) maxTime = t

    for (let c = 0; c < header.length; c++) {
      if (c === timeIdx) continue
      const name = header[c]!
      const rawVal = parseInt(row[c]!, 10)
      const val: 0 | 1 = rawVal !== 0 ? 1 : 0
      const last = lastValues.get(name)

      if (last === undefined || last !== val) {
        channels.get(name)!.transitions.push({ timestamp: t, value: val })
        lastValues.set(name, val)
        totalTransitions++
      }
    }
  }

  return {
    captureId,
    timebaseUnit: '1s',
    timebaseScale: 1.0,
    channels,
    duration: maxTime,
    totalTransitions,
  }
}

/**
 * Parses a standard IEEE 1364 VCD (Value Change Dump) file.
 */
export function parseVcdWaveform(vcdText: string, captureId = 'vcd_capture'): WaveformCapture {
  const lines = vcdText.split(/\r?\n/)
  const channels = new Map<string, DigitalChannel>()
  const idToName = new Map<string, string>()

  let timeScale = 1e-9 // default 1ns
  let timebaseUnit = '1ns'
  let inHeader = true
  let currentTimestamp = 0
  let totalTransitions = 0

  for (const line of lines) {
    const trimmed = line.trim()
    if (trimmed.length === 0) continue

    if (inHeader) {
      if (trimmed.startsWith('$timescale')) {
        const match = trimmed.match(/\$timescale\s+([0-9]+)\s*([a-zA-Z]+)/)
        if (match) {
          const num = parseInt(match[1]!, 10)
          const unit = match[2]!.toLowerCase()
          timebaseUnit = `${num}${unit}`
          const multiplier = unit === 'fs' ? 1e-15 : unit === 'ps' ? 1e-12 : unit === 'ns' ? 1e-9 : unit === 'us' ? 1e-6 : unit === 'ms' ? 1e-3 : 1
          timeScale = num * multiplier
        }
      } else if (trimmed.startsWith('$var')) {
        // $var wire 1 ! clk $end
        const parts = trimmed.split(/\s+/)
        if (parts.length >= 5) {
          const id = parts[3]!
          const name = parts[4]!
          idToName.set(id, name)
          channels.set(name, {
            name,
            id,
            transitions: [],
          })
        }
      } else if (trimmed.startsWith('$enddefinitions')) {
        inHeader = false
      }
      continue
    }

    // Value change section
    if (trimmed.startsWith('#')) {
      const ticks = parseInt(trimmed.substring(1), 10)
      if (!isNaN(ticks)) {
        currentTimestamp = ticks * timeScale
      }
    } else {
      // 0! or 1! or b0 !
      const valChar = trimmed[0]
      if (valChar === '0' || valChar === '1') {
        const id = trimmed.substring(1).trim()
        const name = idToName.get(id)
        if (name && channels.has(name)) {
          const val: 0 | 1 = valChar === '1' ? 1 : 0
          channels.get(name)!.transitions.push({
            timestamp: currentTimestamp,
            value: val,
          })
          totalTransitions++
        }
      }
    }
  }

  return {
    captureId,
    timebaseUnit,
    timebaseScale: timeScale,
    channels,
    duration: currentTimestamp,
    totalTransitions,
  }
}
