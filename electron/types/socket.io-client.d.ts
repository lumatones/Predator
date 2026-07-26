declare module 'socket.io-client' {
  interface Socket {
    on(event: string, callback: (data: any) => void): void
    emit(event: string, ...args: any[]): void
    disconnect(): void
  }
  export function io(url: string, opts?: Record<string, unknown>): Socket
}
