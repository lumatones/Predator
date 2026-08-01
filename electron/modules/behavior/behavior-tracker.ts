import type { BehaviorEvent, BehaviorSnapshot, ProcessSnapshot } from './models'

export interface BehaviorTrackerOptions {
  readonly maxSubjects?: number
  readonly maxEventsPerSubject?: number
}

const DEFAULT_MAX_SUBJECTS = 2_000
const DEFAULT_MAX_EVENTS_PER_SUBJECT = 128

/**
 * Stores only normalized behavior metadata. It intentionally does not accept
 * paths, filenames, hashes or memory bytes.
 */
export class BehaviorTracker {
  private readonly snapshots = new Map<string, ProcessSnapshot>()
  private readonly histories = new Map<string, BehaviorEvent[]>()
  private readonly maxSubjects: number
  private readonly maxEventsPerSubject: number

  constructor(options: BehaviorTrackerOptions = {}) {
    this.maxSubjects = options.maxSubjects ?? DEFAULT_MAX_SUBJECTS
    this.maxEventsPerSubject = options.maxEventsPerSubject ?? DEFAULT_MAX_EVENTS_PER_SUBJECT

    if (!Number.isInteger(this.maxSubjects) || this.maxSubjects < 1) {
      throw new RangeError('Behavior tracker maxSubjects must be a positive integer')
    }
    if (!Number.isInteger(this.maxEventsPerSubject) || this.maxEventsPerSubject < 1) {
      throw new RangeError('Behavior tracker maxEventsPerSubject must be a positive integer')
    }
  }

  record(snapshot: BehaviorSnapshot): void {
    for (const process of snapshot.processes) this.recordProcess(process)
    for (const event of snapshot.events) this.recordEvent(event)
    this.trimSubjects()
  }

  recordProcess(process: ProcessSnapshot): void {
    this.snapshots.set(process.stableId, process)
    if (!this.histories.has(process.stableId)) this.histories.set(process.stableId, [])
  }

  recordEvent(event: BehaviorEvent): void {
    const history = this.histories.get(event.sourceId) ?? []
    if (!this.histories.has(event.sourceId)) this.histories.set(event.sourceId, history)

    const last = history[history.length - 1]
    if (last?.eventId === event.eventId) return

    history.push(event)
    if (history.length > this.maxEventsPerSubject) {
      history.splice(0, history.length - this.maxEventsPerSubject)
    }
  }

  getSnapshot(subjectId: string): ProcessSnapshot | undefined {
    return this.snapshots.get(subjectId)
  }

  getHistory(subjectId: string): readonly BehaviorEvent[] {
    return [...(this.histories.get(subjectId) ?? [])]
  }

  getSubjectIds(): readonly string[] {
    return [...this.snapshots.keys()]
  }

  clear(): void {
    this.snapshots.clear()
    this.histories.clear()
  }

  private trimSubjects(): void {
    if (this.snapshots.size <= this.maxSubjects) return

    const subjects = [...this.snapshots.values()]
      .sort((left, right) => left.observedAt - right.observedAt)
      .slice(0, this.snapshots.size - this.maxSubjects)

    for (const subject of subjects) {
      this.snapshots.delete(subject.stableId)
      this.histories.delete(subject.stableId)
    }
  }
}
