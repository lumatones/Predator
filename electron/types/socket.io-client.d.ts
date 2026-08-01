declare module 'socket.io-client' {
  interface HashUpdate {
    hashes?: string[]
    tlsh?: string[]
  }

  interface RuleUpdate {
    rules?: unknown[]
  }

  interface Socket {
    on(event: 'connect' | 'disconnect', callback: () => void): void
    on(event: 'hash-update', callback: (data: HashUpdate) => void): void
    on(event: 'rule-update', callback: (data: RuleUpdate) => void): void
    on(event: string, callback: (data: unknown) => void): void
    emit(event: string, ...args: unknown[]): void
    disconnect(): void
  }
  export function io(url: string, opts?: Record<string, unknown>): Socket
}
