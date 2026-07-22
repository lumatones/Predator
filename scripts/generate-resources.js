/**
 * Resource Generator for Predator Installer
 * Generates BMP images for NSIS customization and proper PNG icon
 * Pure Node.js — uses built-in zlib for PNG compression
 */

const fs = require('fs')
const path = require('path')
const zlib = require('zlib')

const RESOURCES_DIR = path.join(__dirname, '..', 'resources')

if (!fs.existsSync(RESOURCES_DIR)) {
  fs.mkdirSync(RESOURCES_DIR, { recursive: true })
}

/* ── BMP Generator ────────────────────────────── */

function generateBMP(width, height, isSidebar = true) {
  const rowSize = Math.ceil((width * 3) / 4) * 4
  const pixelDataSize = rowSize * height
  const fileSize = 54 + pixelDataSize
  const buf = Buffer.alloc(fileSize)

  buf.write('BM', 0)
  buf.writeUInt32LE(fileSize, 2)
  buf.writeUInt32LE(54, 10)
  buf.writeUInt32LE(40, 14)
  buf.writeInt32LE(width, 18)
  buf.writeInt32LE(height, 22)
  buf.writeUInt16LE(1, 26)
  buf.writeUInt16LE(24, 28)
  buf.writeUInt32LE(0, 34)
  buf.writeUInt32LE(pixelDataSize, 38)

  const d = [18, 18, 26]
  const m = [26, 26, 38]
  const a = [68, 107, 255]   // BGR
  const r = [68, 68, 255]    // BGR

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const o = 54 + y * rowSize + x * 3
      let cr, cg, cb

      if (isSidebar) {
        const p = y / height
        if (x < 4) {
          const mix = Math.max(0, 1 - (4 - x) / 4)
          cr = Math.round(mix * a[2] + (1 - mix) * r[2])
          cg = Math.round(mix * a[1] + (1 - mix) * r[1])
          cb = Math.round(mix * a[0] + (1 - mix) * r[0])
        } else if (x < width - 20) {
          cr = Math.round(d[0] * (1 - p * 0.3))
          cg = Math.round(m[1] * (1 - p * 0.2))
          cb = Math.round(m[2] * (1 - p * 0.1))
        } else {
          const ef = (x - (width - 20)) / 20
          cr = Math.round(a[2] * ef * 0.3 + d[0] * (1 - ef * 0.3))
          cg = Math.round(a[1] * ef * 0.3 + m[1] * (1 - ef * 0.3))
          cb = Math.round(a[0] * ef * 0.3 + m[2] * (1 - ef * 0.3))
        }
      } else {
        const p = x / width
        if (y < 2 || y > height - 3) {
          cr = Math.round(a[2] * (1 - p * 0.5))
          cg = Math.round(a[1] * (1 - p * 0.5))
          cb = Math.round(a[0] * (1 - p * 0.5))
        } else {
          cr = Math.round(d[0] + (r[2] - d[0]) * p * 0.15)
          cg = Math.round(m[1] + (a[1] - m[1]) * p * 0.2)
          cb = Math.round(m[2] + (a[0] - m[2]) * p * 0.15)
        }
      }

      buf.writeUInt8(Math.min(255, Math.max(0, cb)), o)
      buf.writeUInt8(Math.min(255, Math.max(0, cg)), o + 1)
      buf.writeUInt8(Math.min(255, Math.max(0, cr)), o + 2)
    }
  }

  return buf
}

/* ── ICO Generator (pure Node.js) ───────────────── */

function generateICO(size) {
  // Reuse the same pixel data as PNG but in BGRA format for ICO
  const rawRowSize = size * 4 // BGRA
  const xorSize = rawRowSize * size
  const andRowBytes = Math.ceil(size / 8)
  const andRowPadded = Math.ceil(andRowBytes / 4) * 4
  const andSize = andRowPadded * size

  // Build XOR mask (BGRA pixel data, bottom-up)
  const xorMask = Buffer.alloc(xorSize)

  for (let y = 0; y < size; y++) {
    const srcY = y  // top-down for our generation
    for (let x = 0; x < size; x++) {
      const cx = x - size / 2
      const cy = srcY - size / 2
      const dist = Math.sqrt(cx * cx + cy * cy)
      const radius = size * 0.42

      // Bottom-up: ICO stores pixels bottom-up
      const dstY = (size - 1 - y)
      const o = (dstY * rawRowSize) + (x * 4)

      if (dist <= radius) {
        const fade = 1 - dist / radius
        let r = 24 + Math.round(fade * 60)
        let g = 12 + Math.round(fade * 20)
        let b = 18 + Math.round(fade * 30)

        if (cy > 0) {
          r += Math.round(fade * 80 * (cy / (size / 2)))
          g -= Math.round(fade * 10)
        }
        if (dist < radius * 0.4) {
          r += Math.round(fade * 60)
          g += Math.round(fade * 30)
        }
        if (Math.abs(cx) < size * 0.06 && cy > -size * 0.08 && cy < size * 0.15) {
          r = 255; g = 80; b = 50
        }
        if (dist > radius * 0.88) {
          const bfade = (dist - radius * 0.88) / (radius * 0.12)
          r = Math.round(r + (255 - r) * bfade * 0.3)
          g = Math.round(g - g * bfade * 0.2)
          b = Math.round(b - b * bfade * 0.2)
        }

        xorMask[o] = b        // Blue
        xorMask[o + 1] = g    // Green
        xorMask[o + 2] = r    // Red
        xorMask[o + 3] = 255  // Alpha
      }
    }
  }

  // AND mask (all zeros since we use alpha)
  const andMask = Buffer.alloc(andSize)

  // BITMAPINFOHEADER (40 bytes)
  const bih = Buffer.alloc(40)
  bih.writeUInt32LE(40, 0)     // biSize
  bih.writeInt32LE(size, 4)    // biWidth
  bih.writeInt32LE(size * 2, 8) // biHeight = height * 2 (XOR + AND masks combined)
  bih.writeUInt16LE(1, 12)     // biPlanes
  bih.writeUInt16LE(32, 14)    // biBitCount
  bih.writeUInt32LE(0, 16)     // biCompression (BI_RGB)
  bih.writeUInt32LE(xorSize + andSize, 20) // biSizeImage
  bih.writeUInt32LE(0, 24)     // biXPelsPerMeter
  bih.writeUInt32LE(0, 28)     // biYPelsPerMeter
  bih.writeUInt32LE(0, 32)     // biClrUsed
  bih.writeUInt32LE(0, 36)     // biClrImportant

  const imageData = Buffer.concat([bih, xorMask, andMask])

  // ICO header
  const header = Buffer.alloc(6)
  header.writeUInt16LE(0, 0)   // reserved
  header.writeUInt16LE(1, 2)   // type: ICO
  header.writeUInt16LE(1, 4)   // count: 1

  // Directory entry
  const entry = Buffer.alloc(16)
  entry.writeUInt8(size >= 256 ? 0 : size, 0)  // width (0=256)
  entry.writeUInt8(size >= 256 ? 0 : size, 1)  // height (0=256)
  entry.writeUInt8(0, 2)   // colors
  entry.writeUInt8(0, 3)   // reserved
  entry.writeUInt16LE(1, 4)    // planes
  entry.writeUInt16LE(32, 6)   // bit count
  entry.writeUInt32LE(imageData.length, 8)  // image size
  entry.writeUInt32LE(22, 12)  // offset (6 + 16 = 22)

  return Buffer.concat([header, entry, imageData])
}

/* ── Proper PNG Generator (pure Node.js) ──────── */

function crc32(data) {
  let crc = 0xFFFFFFFF
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i]
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0)
    }
  }
  return (crc ^ 0xFFFFFFFF) >>> 0
}

function pngChunk(type, data) {
  const len = Buffer.alloc(4)
  len.writeUInt32BE(data.length)
  const typeB = Buffer.from(type, 'ascii')
  const crcData = Buffer.concat([typeB, data])
  const crcB = Buffer.alloc(4)
  crcB.writeUInt32BE(crc32(crcData))
  return Buffer.concat([len, typeB, data, crcB])
}

function generatePNG(size) {
  // Generate RGBA pixel data (top-down, with filter bytes)
  const rawRowSize = size * 4 // RGBA
  const rowSize = 1 + rawRowSize // filter byte + RGBA
  const rawData = Buffer.alloc(rowSize * size)

  for (let y = 0; y < size; y++) {
    const rowOffset = y * rowSize
    rawData[rowOffset] = 0 // filter: None

    for (let x = 0; x < size; x++) {
      const px = rowOffset + 1 + x * 4
      const cx = x - size / 2
      const cy = y - size / 2
      const dist = Math.sqrt(cx * cx + cy * cy)
      const radius = size * 0.42

      if (dist <= radius) {
        const fade = 1 - dist / radius
        let r = 24 + Math.round(fade * 60)
        let g = 12 + Math.round(fade * 20)
        let b = 18 + Math.round(fade * 30)
        let a = 255

        // Red accent bottom
        if (cy > 0) {
          r += Math.round(fade * 80 * (cy / (size / 2)))
          g -= Math.round(fade * 10)
        }

        // Inner glow
        if (dist < radius * 0.4) {
          r += Math.round(fade * 60)
          g += Math.round(fade * 30)
        }

        // Predator eye (vertical slit)
        if (Math.abs(cx) < size * 0.06 && cy > -size * 0.08 && cy < size * 0.15) {
          r = 255; g = 80; b = 50
        }

        // Subtle border
        if (dist > radius * 0.88) {
          const bfade = (dist - radius * 0.88) / (radius * 0.12)
          r = Math.round(r + (255 - r) * bfade * 0.3)
          g = Math.round(g - g * bfade * 0.2)
          b = Math.round(b - b * bfade * 0.2)
        }

        rawData[px] = Math.min(255, r)
        rawData[px + 1] = Math.min(255, g)
        rawData[px + 2] = Math.min(255, b)
        rawData[px + 3] = a
      }
    }
  }

  // Compress with zlib
  const compressed = zlib.deflateSync(rawData, { level: 9 })

  // Build PNG
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])

  // IHDR
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(size, 0)
  ihdr.writeUInt32BE(size, 4)
  ihdr.writeUInt8(8, 8)   // bit depth
  ihdr.writeUInt8(6, 9)   // color type: RGBA
  ihdr.writeUInt8(0, 10)  // compression
  ihdr.writeUInt8(0, 11)  // filter
  ihdr.writeUInt8(0, 12)  // interlace

  return Buffer.concat([
    signature,
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', compressed),
    pngChunk('IEND', Buffer.alloc(0)),
  ])
}

/* ── Main ──────────────────────────────────────── */

console.log('🎨 Generating Predator installer resources...\n')

// Sidebar BMP
console.log('  📐 Generating installer-sidebar.bmp (164x314)...')
fs.writeFileSync(path.join(RESOURCES_DIR, 'installer-sidebar.bmp'), generateBMP(164, 314, true))
console.log('     ✓ Done\n')

// Header BMP
console.log('  📐 Generating installer-header.bmp (150x57)...')
fs.writeFileSync(path.join(RESOURCES_DIR, 'installer-header.bmp'), generateBMP(150, 57, false))
console.log('     ✓ Done\n')

// Proper 256×256 PNG icon
console.log('  🖼️  Generating icon.png (256×256 RGBA PNG)...')
const pngBuf = generatePNG(256)
fs.writeFileSync(path.join(RESOURCES_DIR, 'icon.png'), pngBuf)
console.log('     ✓ Done\n')

// ICO icon for Windows installer
console.log('  🖼️  Generating icon.ico (256×256 Windows ICO)...')
fs.writeFileSync(path.join(RESOURCES_DIR, 'icon.ico'), generateICO(256))
console.log('     ✓ Done\n')

// Also generate smaller ICO for compatibility
console.log('  🖼️  Generating icon-32.ico (32×32 Windows ICO)...')
fs.writeFileSync(path.join(RESOURCES_DIR, 'icon-32.ico'), generateICO(32))
console.log('     ✓ Done\n')

// SVG icon as a fallback / reference
console.log('  🖼️  Generating icon.svg...')
const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256">
  <defs>
    <radialGradient id="bg" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#1a1a2e"/>
      <stop offset="100%" stop-color="#0a0a0f"/>
    </radialGradient>
    <linearGradient id="accent" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#ff4444"/>
      <stop offset="50%" stop-color="#ff6b35"/>
      <stop offset="100%" stop-color="#ff0044"/>
    </linearGradient>
  </defs>
  <circle cx="128" cy="128" r="120" fill="url(#bg)" stroke="url(#accent)" stroke-width="4"/>
  <path d="M128 40 C128 40 80 90 80 140 C80 175 101.5 200 128 200 C154.5 200 176 175 176 140 C176 90 128 40 128 40Z" fill="url(#accent)" opacity="0.9"/>
  <path d="M95 155 L60 210 L196 210 L161 155" stroke="url(#accent)" stroke-width="5" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
  <circle cx="128" cy="135" r="25" fill="rgba(255,255,255,0.15)"/>
  <circle cx="128" cy="135" r="15" fill="rgba(255,255,255,0.1)"/>
</svg>`
fs.writeFileSync(path.join(RESOURCES_DIR, 'icon.svg'), svg)
console.log('     ✓ Done\n')

console.log('✨ Resource generation complete!')
console.log(`   📁 ${RESOURCES_DIR}/\n`)
