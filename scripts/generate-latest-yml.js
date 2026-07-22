const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const filePath = path.join(__dirname, '..', 'release', 'Predator-0.0.10.exe');

if (!fs.existsSync(filePath)) {
  console.error('ERROR: Predator-0.0.10.exe not found in release/');
  process.exit(1);
}

const stats = fs.statSync(filePath);
const size = stats.size;
const fileBuffer = fs.readFileSync(filePath);
const hash = crypto.createHash('sha512').update(fileBuffer).digest('base64');
const releaseDate = new Date().toISOString();

const yml = [
  'version: 0.0.10',
  'files:',
  '  - url: Predator-0.0.10.exe',
  '    sha512: ' + hash,
  '    size: ' + size,
  'path: Predator-0.0.10.exe',
  'sha512: ' + hash,
  'releaseDate: ' + releaseDate,
  ''
].join('\n');

const outPath = path.join(__dirname, '..', 'release', 'latest.yml');
fs.writeFileSync(outPath, yml, 'utf-8');
console.log('OK: latest.yml created at release/latest.yml');
console.log('Size:', size, 'bytes');
console.log('SHA512:', hash);
console.log('Date:', releaseDate);
