# liboqs WASM Files

This directory should contain the liboqs WASM bindings for browser-based PQC operations.

## Automatic Setup

Run `npm install` in the frontend directory - this will automatically download the WASM files via the postinstall script.

## Manual Setup

If you need to download manually:

1. Download the latest release from: https://github.com/open-quantum-safe/liboqs-bindings/releases

2. Extract the following files:
   - `liboqs-wasm.wasm`
   - `liboqs-wasm.js`

3. Place them in this directory.

## Supported Algorithms

- **ML-KEM-1024** (formerly Kyber) - Key Encapsulation Mechanism
- **ML-DSA-87** (formerly Dilithium) - Digital Signatures

## Requirements

- Node.js 18+
- npm 9+

## Troubleshooting

If you see errors about liboqs WASM not loading:

1. Check that the WASM files exist in this directory
2. Ensure your server serves static files correctly
3. Check browser console for specific error messages
4. Try clearing npm cache and reinstalling
