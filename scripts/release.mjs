import { createReadStream, statSync } from 'fs'
import path from 'path'

const TOKEN = process.env.GITHUB_TOKEN
const OWNER = 'lumatones'
const REPO = 'Predator'
const TAG = 'v0.0.8'
const EXE_PATH = 'release/Predator-0.0.8.exe'

const GH = 'https://api.github.com'

async function gh(method, url, body) {
  const opts = {
    method,
    headers: {
      Authorization: `token ${TOKEN}`,
      Accept: 'application/vnd.github.v3+json',
    },
  }
  if (body) {
    opts.headers['Content-Type'] = 'application/json'
    opts.body = JSON.stringify(body)
  }
  const res = await fetch(url, opts)
  const data = await res.json()
  if (!res.ok) {
    throw new Error(`GitHub API error ${res.status}: ${data.message || JSON.stringify(data)}`)
  }
  return data
}

async function uploadAsset(uploadUrl, filePath, contentType) {
  const url = uploadUrl.replace('{?name,label}', `?name=${encodeURIComponent(path.basename(filePath))}`)
  const stat = statSync(filePath)
  const stream = createReadStream(filePath)

  // Read the file into a buffer
  const chunks = []
  for await (const chunk of stream) chunks.push(chunk)
  const buffer = Buffer.concat(chunks)

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `token ${TOKEN}`,
      'Content-Type': contentType || 'application/octet-stream',
      'Content-Length': buffer.length.toString(),
    },
    body: buffer,
  })
  const data = await res.json()
  if (!res.ok) {
    throw new Error(`Upload error ${res.status}: ${data.message || JSON.stringify(data)}`)
  }
  return data
}

async function main() {
  console.log('Creating release v0.0.8...')
  const release = await gh('POST', `${GH}/repos/${OWNER}/${REPO}/releases`, {
    tag_name: TAG,
    name: TAG,
    body: `## v0.0.8 — Extended scan, search, update indicator

### 🆕 New
- **5th mode "Extended"** — full system scan (files + processes + registry + Prefetch + DMA + browser history) in 6 phases
- **Search results** — real-time text filter for scan results
- **Update indicator** — pulsing red dot next to version when update is available
- **Periodic update check** — every 5 minutes in background

### 🔧 Improvements
- Async scanning without UI freezes (yieldToEventLoop after every file)
- useMemo for result filtering instead of IIFE
- Search query reset on clear/tab change

### 📦 Install
Download Predator-0.0.8.exe — auto-updater handles all future updates.`,
    draft: false,
    prerelease: false,
  })
  console.log(`Release created: ${release.html_url} (ID: ${release.id})`)

  console.log('Uploading Predator-0.0.8.exe...')
  const asset = await uploadAsset(release.upload_url, EXE_PATH, 'application/x-msdownload')
  console.log(`Asset uploaded: ${asset.browser_download_url} (${(asset.size / 1024 / 1024).toFixed(1)} MB)`)

  console.log('\n✅ Release v0.0.8 complete!')
}

main().catch(err => {
  console.error('❌', err.message)
  process.exit(1)
})
