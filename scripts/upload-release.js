const https = require('https');
const fs = require('fs');
const path = require('path');

// ── Config ─────────────────────────────────────
const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf-8'));
const OWNER = 'lumatones';
const REPO = 'Predator';
const TAG = process.argv.find(a => a.startsWith('--tag='))?.split('=')[1] || `v${pkg.version}`;
const VERSION = TAG.replace(/^v/, '');
const RELEASE_DIR = path.join(__dirname, '..', 'release');

// ── Token resolution ───────────────────────────
// Priority: --token= arg > GITHUB_TOKEN env > .env file
let GITHUB_TOKEN = process.env.GITHUB_TOKEN;

const tokenArg = process.argv.find(a => a.startsWith('--token='));
if (tokenArg) {
  GITHUB_TOKEN = tokenArg.split('=')[1];
}

// Try .env file
if (!GITHUB_TOKEN) {
  const envPath = path.join(__dirname, '..', '.env');
  if (fs.existsSync(envPath)) {
    const envContent = fs.readFileSync(envPath, 'utf-8');
    const match = envContent.match(/^GITHUB_TOKEN=(.+)$/m);
    if (match) GITHUB_TOKEN = match[1].trim();
  }
}

if (!GITHUB_TOKEN) {
  console.error('ERROR: GITHUB_TOKEN not found.');
  console.error('  Set it as:');
  console.error('  - Environment variable: set GITHUB_TOKEN=ghp_xxx');
  console.error('  - --token=ghp_xxx argument');
  console.error('  - GITHUB_TOKEN=... in .env file at project root');
  process.exit(1);
}

// ── Files to upload ────────────────────────────
const FILES = [
  { local: path.join(RELEASE_DIR, `Predator-${VERSION}.exe`), name: `Predator-${VERSION}.exe` },
  { local: path.join(RELEASE_DIR, 'latest.yml'), name: 'latest.yml' },
];

// ── HTTP helper ────────────────────────────────
function req(url, method, headers, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const opts = {
      hostname: u.hostname,
      port: 443,
      path: u.pathname + u.search,
      method,
      headers,
    };
    const r = https.request(opts, (res) => {
      let data = '';
      res.on('data', (c) => data += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, data }); }
      });
    });
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });
}

// ── Upload helper ──────────────────────────────
async function uploadFile(uploadUrl, filePath, fileName) {
  const content = fs.readFileSync(filePath);
  const cleanUrl = uploadUrl.replace('{?name,label}', '') + '?name=' + encodeURIComponent(fileName);

  const headers = {
    'Authorization': `token ${GITHUB_TOKEN}`,
    'User-Agent': 'Predator-Release-Upload',
    'Content-Type': 'application/octet-stream',
    'Content-Length': content.length,
    'Accept': 'application/vnd.github+json',
  };

  return req(cleanUrl, 'POST', headers, content);
}

// ── Main ──────────────────────────────────────
(async () => {
  console.log(`\n  🦅 Predator Release Uploader — ${TAG}\n`);
  console.log(`Registry: ${OWNER}/${REPO}`);
  console.log(`Files:`);
  for (const f of FILES) {
    const exists = fs.existsSync(f.local);
    console.log(`  ${exists ? '✓' : '✗'} ${f.name}${exists ? ` (${(fs.statSync(f.local).size / 1024 / 1024).toFixed(2)} MB)` : ' — NOT FOUND!'}`);
  }
  console.log('');

  // Check all files exist
  const missing = FILES.filter(f => !fs.existsSync(f.local));
  if (missing.length > 0) {
    console.error('ERROR: Missing files — build the release first.');
    process.exit(1);
  }

  // Get release
  console.log('1. Fetching release...');
  const rel = await req(
    `https://api.github.com/repos/${OWNER}/${REPO}/releases/tags/${TAG}`,
    'GET',
    { 'Authorization': `token ${GITHUB_TOKEN}`, 'User-Agent': 'Predator', 'Accept': 'application/vnd.github+json' }
  );

  if (rel.status !== 200) {
    console.error(`Release ${TAG} not found:`, rel.status, rel.data?.message || '(no message)');
    process.exit(1);
  }

  const release = rel.data;
  console.log(`  Found: ${release.tag_name} — ${release.name}`);

  // Delete existing assets
  if (release.assets?.length > 0) {
    console.log(`\n2. Deleting ${release.assets.length} old assets...`);
    for (const asset of release.assets) {
      console.log(`  Deleting ${asset.name}...`);
      const del = await req(
        `https://api.github.com/repos/${OWNER}/${REPO}/releases/assets/${asset.id}`,
        'DELETE',
        { 'Authorization': `token ${GITHUB_TOKEN}`, 'User-Agent': 'Predator', 'Accept': 'application/vnd.github+json' }
      );
      console.log(`  → Status: ${del.status}`);
    }
  }

  // Upload new files
  console.log(`\n3. Uploading ${FILES.length} files...`);
  for (const file of FILES) {
    const mb = (fs.statSync(file.local).size / 1024 / 1024).toFixed(2);
    console.log(`  Uploading ${file.name} (${mb} MB)...`);
    const result = await uploadFile(release.upload_url, file.local, file.name);
    if (result.status === 201) {
      console.log(`  ✅ ${result.data.name || file.name} uploaded`);
    } else {
      console.log(`  ⚠️  Status: ${result.status} — ${result.data?.message || JSON.stringify(result.data).slice(0, 200)}`);
    }
  }

  console.log(`\n✅ Done! Release: ${release.html_url}\n`);
})().catch(e => console.error('ERROR:', e));
