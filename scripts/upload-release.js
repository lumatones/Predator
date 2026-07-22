const https = require('https');
const fs = require('fs');
const path = require('path');

const TOKEN = process.env.GITHUB_TOKEN;
const OWNER = 'lumatones';
const REPO = 'Predator';
const TAG = 'v0.0.10';
const RELEASE_DIR = path.join(__dirname, '..', 'release');

const FILES = [
  { local: path.join(RELEASE_DIR, 'Predator-0.0.10.exe'), name: 'Predator-0.0.10.exe' },
  { local: path.join(RELEASE_DIR, 'latest.yml'), name: 'latest.yml' },
];

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

async function uploadFile(uploadUrl, filePath, fileName) {
  const content = fs.readFileSync(filePath);
  // Strip the {?name,label} template suffix from upload_url
  const cleanUrl = uploadUrl.replace('{?name,label}', '') + '?name=' + encodeURIComponent(fileName);

  const headers = {
    'Authorization': `token ${TOKEN}`,
    'User-Agent': 'Predator-Release-Upload',
    'Content-Type': 'application/octet-stream',
    'Content-Length': content.length,
    'Accept': 'application/vnd.github+json',
  };

  return req(cleanUrl, 'POST', headers, content);
}

(async () => {
  console.log('1. Getting release info...');
  const rel = await req(
    `https://api.github.com/repos/${OWNER}/${REPO}/releases/tags/${TAG}`,
    'GET',
    { 'Authorization': `token ${TOKEN}`, 'User-Agent': 'Predator', 'Accept': 'application/vnd.github+json' }
  );

  if (rel.status !== 200) {
    console.error('Release not found:', rel.status, rel.data);
    process.exit(1);
  }

  const release = rel.data;
  console.log('Release:', release.tag_name, '-', release.name);

  // Delete existing assets
  for (const asset of release.assets) {
    console.log('Deleting old:', asset.name);
    const del = await req(
      `https://api.github.com/repos/${OWNER}/${REPO}/releases/assets/${asset.id}`,
      'DELETE',
      { 'Authorization': `token ${TOKEN}`, 'User-Agent': 'Predator', 'Accept': 'application/vnd.github+json' }
    );
    console.log('  Deleted:', del.status);
  }

  // Upload new files
  for (const file of FILES) {
    if (!fs.existsSync(file.local)) {
      console.error('NOT FOUND:', file.local);
      continue;
    }
    const mb = (fs.statSync(file.local).size / 1024 / 1024).toFixed(2);
    console.log(`Uploading ${file.name} (${mb} MB)...`);
    const result = await uploadFile(release.upload_url, file.local, file.name);
    console.log(`  Status: ${result.status}`);
    console.log(`  Result:`, result.data.name || result.data.message || JSON.stringify(result.data).slice(0, 200));
  }

  console.log('\nDone! Release ready:', release.html_url);
})().catch(e => console.error('ERROR:', e));
