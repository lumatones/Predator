const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

// Read version from package.json
const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf-8'));
const version = pkg.version;
const exeName = `Predator-${version}.exe`;
const filePath = path.join(__dirname, '..', 'release', exeName);

if (!fs.existsSync(filePath)) {
  console.error(`ERROR: ${exeName} not found in release/`);
  process.exit(1);
}

const stats = fs.statSync(filePath);
const size = stats.size;
const fileBuffer = fs.readFileSync(filePath);
const hash = crypto.createHash('sha512').update(fileBuffer).digest('base64');
const releaseDate = new Date().toISOString();

const yml = [
  `version: ${version}`,
  'files:',
  `  - url: ${exeName}`,
  `    sha512: ${hash}`,
  `    size: ${size}`,
  `path: ${exeName}`,
  `sha512: ${hash}`,
  `releaseDate: ${releaseDate}`,
  ''
].join('\n');

const outPath = path.join(__dirname, '..', 'release', 'latest.yml');
fs.writeFileSync(outPath, yml, 'utf-8');

console.log(`OK: latest.yml created for v${version}`);
console.log(`  File: ${exeName}`);
console.log(`  Size: ${size} bytes`);
console.log(`  SHA512: ${hash}`);
console.log(`  Date: ${releaseDate}`);
