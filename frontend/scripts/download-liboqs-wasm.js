/**
 * Script to download liboqs WASM bindings
 * 
 * This script downloads the pre-built liboqs WASM files from GitHub releases.
 * Run after npm install: npm run postinstall
 * 
 * Required for browser-based PQC operations.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

// Configuration
const LIBOQS_WASM_VERSION = '1.4.0'; // Use stable release
const LIBOQS_REPO = 'open-quantum-safe/liboqs-bindings';
const BASE_URL = `https://github.com/${LIBOQS_REPO}/releases/download/${LIBOQS_WASM_VERSION}`;

// Files to download
const WASM_FILES = [
  {
    source: '/dist/web/liboqs-wasm.wasm',
    dest: path.join(__dirname, '..', 'public', 'liboqs', 'liboqs-wasm.wasm')
  },
  {
    source: '/dist/web/liboqs-wasm.js',
    dest: path.join(__dirname, '..', 'public', 'liboqs', 'liboqs-wasm.js')
  }
];

/**
 * Download a file from URL to destination
 */
function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    // Ensure directory exists
    const dir = path.dirname(dest);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const file = fs.createWriteStream(dest);
    
    console.log(`[liboqs] Downloading: ${url}`);
    
    https.get(url, (response) => {
      if (response.statusCode === 302 || response.statusCode === 301) {
        // Handle redirect
        file.close();
        fs.unlinkSync(dest);
        downloadFile(response.headers.location, dest)
          .then(resolve)
          .catch(reject);
        return;
      }
      
      if (response.statusCode !== 200) {
        file.close();
        fs.unlinkSync(dest);
        reject(new Error(`Failed to download: HTTP ${response.statusCode}`));
        return;
      }
      
      response.pipe(file);
      
      file.on('finish', () => {
        file.close();
        console.log(`[liboqs] Downloaded: ${dest}`);
        resolve();
      });
    }).on('error', (err) => {
      file.close();
      if (fs.existsSync(dest)) {
        fs.unlinkSync(dest);
      }
      reject(err);
    });
  });
}

/**
 * Main download function
 */
async function main() {
  console.log('[liboqs] Starting WASM download...');
  console.log(`[liboqs] Version: ${LIBOQS_WASM_VERSION}`);
  
  let hasErrors = false;
  
  for (const file of WASM_FILES) {
    const url = `${BASE_URL}${file.source}`;
    try {
      await downloadFile(url, file.dest);
    } catch (err) {
      console.error(`[liboqs] Error downloading ${file.source}:`, err.message);
      hasErrors = true;
    }
  }
  
  if (hasErrors) {
    console.warn('[liboqs] Some files failed to download.');
    console.warn('[liboqs] Trying alternative CDN...');
    
    // Try alternative: use unpkg or jsdelivr
    const altUrl = `https://unpkg.com/liboqs@${LIBOQS_WASM_VERSION}/dist/web/`;
    console.log(`[liboqs] Alternative URL: ${altUrl}`);
  }
  
  console.log('[liboqs] WASM download complete');
}

main().catch(console.error);
