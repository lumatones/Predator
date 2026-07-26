declare module 'tlsh' {
  const tlsh: {
    hash(data: Buffer | Uint8Array): string
    diff(hash1: string, hash2: string): number
  }
  export default tlsh
}
