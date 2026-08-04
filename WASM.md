<!--
Copyright (c) 2025 TRUSTEDGE LABS LLC
MPL-2.0: https://mozilla.org/MPL/2.0/
Project: sealedge — Privacy and trust at the edge.
GitHub: https://github.com/TrustEdge-Labs/sealedge
-->

# Sealedge WebAssembly (WASM) Guide

Complete guide to building, testing, and deploying Sealedge WebAssembly modules for browser and Node.js environments.

## 📋 Overview

Sealedge provides two WASM packages:

1. **`sealedge-wasm`** - Core cryptographic operations (AES-256-GCM, key derivation)
2. **`sealedge-seal-wasm`** - .seal archive verification (Ed25519, BLAKE3, continuity chains)

Both compile to `wasm32-unknown-unknown` and use `wasm-bindgen` for JavaScript interop.

---

## 🚀 Quick Start (5 Minutes)

### Prerequisites

```bash
# 1. Install wasm-pack (one-time setup)
cargo install wasm-pack

# 2. Add wasm32 target (one-time setup)
rustup target add wasm32-unknown-unknown

# 3. Verify installation
wasm-pack --version  # Should show v0.12+ or higher
```

### Build and Run Demo

```bash
# From project root
./scripts/build-wasm-demo.sh

# Serve the demo
cd web/demo && npx serve .

# Open browser to http://localhost:3000
# Drag a .seal archive directory into the browser to verify
```

**Expected Output**:
```
Building Sealedge WASM Demo...
Building WASM module...
[INFO]: ✨   Done in 4.90s
WASM module built successfully!
```

---

## 🏗️ Building WASM Modules

### Core WASM (`sealedge-wasm`)

**Purpose**: General cryptographic operations for browser/Node.js

```bash
# Development build (with debug symbols)
wasm-pack build crates/wasm --target web --dev

# Production build (optimized)
wasm-pack build crates/wasm --target web --release

# Output directory
ls crates/wasm/pkg/
# sealedge_wasm.js
# sealedge_wasm_bg.wasm
# sealedge_wasm.d.ts
# package.json
```

**Build Targets**:
- `--target web` - For direct browser use with ES modules
- `--target bundler` - For webpack/rollup bundlers
- `--target nodejs` - For Node.js environments
- `--target no-modules` - Legacy browser support

**Size Optimization**:
```bash
# Check binary size
ls -lh crates/wasm/pkg/*.wasm

# Typical sizes:
# - Development: ~800KB
# - Release: ~250KB (with wasm-opt)
# - Release + strip: ~180KB
```

---

### Archive Verification WASM (`sealedge-seal-wasm`)

**Purpose**: Client-side .seal archive verification

```bash
# Build for web demo (automatic output directory)
wasm-pack build crates/seal-wasm --target web --out-dir ../../web/demo/pkg

# Check output
ls web/demo/pkg/
# sealedge_seal_wasm.js
# sealedge_seal_wasm_bg.wasm
# sealedge_seal_wasm.d.ts
# package.json
```

**What It Includes**:
- Ed25519 signature verification (no hardware dependencies)
- BLAKE3 hashing for continuity chains
- Chunk hash validation
- Manifest canonicalization
- JSON output for verification results

---

## 🧪 Testing WASM

### Browser Tests (Headless)

```bash
# Chrome (headless)
wasm-pack test crates/wasm --chrome --headless
wasm-pack test crates/seal-wasm --chrome --headless

# Firefox (headless)
wasm-pack test crates/wasm --firefox --headless
wasm-pack test crates/seal-wasm --firefox --headless

# All browsers (CI mode)
make test-wasm  # Runs Chrome and Firefox
```

**Test Output**:
```
running 3 tests
test browser_test::test_encryption ... ok
test browser_test::test_key_derivation ... ok
test browser_test::test_signature ... ok

test result: ok. 3 passed; 0 failed; 0 ignored
```

---

### Browser Tests (Interactive)

Useful for debugging - opens actual browser:

```bash
# Interactive Chrome (with DevTools)
wasm-pack test crates/wasm --chrome

# Interactive Firefox
wasm-pack test crates/wasm --firefox
```

**Pro Tips**:
- Browser stays open for inspection
- Check DevTools console for WASM errors
- Use `console.log()` in test code for debugging

---

### Manual Browser Testing

```bash
# 1. Build the demo
./scripts/build-wasm-demo.sh

# 2. Serve locally
cd web/demo && python3 -m http.server 8000
# or
cd web/demo && npx serve .

# 3. Open http://localhost:8000 in browser

# 4. Open DevTools console (F12)

# 5. Test verification manually:
```

**Browser Console Test**:
```javascript
// Load the WASM module
import init, { verify_archive } from './pkg/sealedge_seal_wasm.js';

await init();

// Verify an archive directory (user selects it via the directory picker)
const dirHandle = await window.showDirectoryPicker();
const result = await verify_archive(dirHandle, "ed25519:...");
console.log(result);
```

---

## 📦 WASM Module APIs

### `sealedge-wasm` API

Located in `crates/wasm/src/lib.rs`:

```rust
#[wasm_bindgen]
pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, JsValue>;

#[wasm_bindgen]
pub fn decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, JsValue>;

#[wasm_bindgen]
pub fn derive_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, JsValue>;
```

**JavaScript Usage**:
```javascript
import init, { encrypt, decrypt, derive_key } from './pkg/sealedge_wasm.js';

await init();

const key = derive_key("password123", new Uint8Array(16));
const plaintext = new TextEncoder().encode("secret message");
const ciphertext = encrypt(plaintext, key);
const decrypted = decrypt(ciphertext, key);
```

---

### `sealedge-seal-wasm` API

Located in `crates/seal-wasm/src/lib.rs`:

```rust
#[wasm_bindgen]
pub fn verify_manifest(manifest_bytes: Vec<u8>, device_pub: String) -> Result<JsValue, JsValue>;

#[wasm_bindgen]
pub async fn verify_archive(
    dir_handle: FileSystemDirectoryHandle,
    device_pub: String,
) -> Result<JsValue, JsValue>;
```

Both gate on `trst_version == "0.2.0"` and return a `VerificationResult` object that
serializes as exactly `{ signature, continuity, segment_count }`.

**JavaScript Usage**:
```javascript
import init, { verify_archive } from './pkg/sealedge_seal_wasm.js';

await init();

// Verify an entire archive directory (user selects it via the directory picker)
const dirHandle = await window.showDirectoryPicker();
const result = await verify_archive(dirHandle, "ed25519:...");
console.log(result);
// {
//   "signature": "pass",
//   "continuity": "pass",
//   "segment_count": 32
// }
```

---

## 🔧 Development Workflow

### 1. Make Changes to WASM Code

```bash
# Edit Rust source
vim crates/seal-wasm/src/lib.rs
```

### 2. Rebuild WASM

```bash
# Quick rebuild
wasm-pack build crates/seal-wasm --target web --out-dir ../../web/demo/pkg

# With optimization
wasm-pack build crates/seal-wasm --target web --release --out-dir ../../web/demo/pkg
```

### 3. Test in Browser

```bash
# Serve the demo
cd web/demo && npx serve .

# Open browser, hard refresh (Ctrl+Shift+R) to clear cache
```

### 4. Run Automated Tests

```bash
# Test changes
wasm-pack test crates/seal-wasm --chrome --headless

# If tests pass, commit
git add crates/seal-wasm/src/lib.rs
git commit -m "feat(wasm): add new verification feature"
```

---

## 📊 Performance Optimization

### Binary Size Optimization

**Current Sizes** (after `wasm-opt`):
- `sealedge-wasm`: ~250KB (release)
- `sealedge-seal-wasm`: ~180KB (release)

**Optimization Techniques**:

1. **Enable LTO** (already configured in workspace `Cargo.toml`):
```toml
[profile.release]
opt-level = "s"  # Optimize for size
lto = true       # Link-time optimization
```

2. **Strip Debug Symbols**:
```bash
wasm-pack build --target web --release
wasm-strip pkg/*.wasm  # If wasm-strip is installed
```

3. **Check Size**:
```bash
ls -lh crates/seal-wasm/../../web/demo/pkg/*.wasm
```

---

### Runtime Performance

**Benchmark Results** (Chrome 120, M1 Mac):
- Signature verification: ~0.8ms per manifest
- BLAKE3 hashing: ~15 MB/s per chunk
- Full archive verification (32 chunks): ~45ms

**Optimization Tips**:
- Use `--release` builds (10x faster than dev)
- Enable WASM SIMD features (experimental)
- Batch operations when possible

---

## 🌐 Deployment

### Static Hosting (GitHub Pages, Netlify, Vercel)

```bash
# 1. Build production WASM
./scripts/build-wasm-demo.sh

# 2. Deploy web/demo directory
# - Netlify: drag web/demo folder
# - Vercel: vercel deploy web/demo
# - GitHub Pages: commit web/demo to gh-pages branch
```

**CORS Requirements**:
- WASM files must be served with `application/wasm` MIME type
- Some static hosts configure this automatically

---

### NPM Package Publication

```bash
# 1. Build for bundler target
wasm-pack build crates/seal-wasm --target bundler

# 2. Update package.json
cd crates/seal-wasm/pkg
vim package.json  # Update version, description

# 3. Publish to NPM
npm login
npm publish

# Users can then:
# npm install @sealedge/seal-wasm
```

---

### CDN Hosting (jsDelivr, unpkg)

After NPM publication, your package is automatically available:

```html
<!-- Load from CDN -->
<script type="module">
  import init from 'https://cdn.jsdelivr.net/npm/@sealedge/seal-wasm@latest/sealedge_seal_wasm.js';
  
  await init();
  // Use WASM functions
</script>
```

---

## 🔍 Debugging WASM

### Browser DevTools

1. **Enable WASM Debugging** (Chrome):
   - DevTools → Settings → Experiments
   - Enable "WebAssembly Debugging: Enable DWARF support"

2. **View WASM Stack Traces**:
   ```javascript
   try {
       verify_archive(badData);
   } catch (e) {
       console.error(e);  // Shows Rust function names
   }
   ```

3. **Performance Profiling**:
   - DevTools → Performance → Record
   - Run WASM operations
   - Stop recording
   - Look for `wasm-function[...]` entries

---

### Console Logging from Rust

```rust
use web_sys::console;

#[wasm_bindgen]
pub fn debug_verify(data: &[u8]) -> Result<String, JsValue> {
    console::log_1(&"Starting verification...".into());
    
    let result = verify_internal(data)?;
    
    console::log_1(&format!("Verified {} chunks", result.chunk_count).into());
    
    Ok(serde_json::to_string(&result)?)
}
```

**Browser Output**:
```
Starting verification...
Verified 32 chunks
```

---

### Common WASM Errors

#### 1. Memory Out of Bounds
**Symptom**: `RuntimeError: memory access out of bounds`
**Cause**: Buffer overflow or incorrect pointer arithmetic
**Fix**: Check array bounds in Rust code

#### 2. Unreachable Code
**Symptom**: `RuntimeError: unreachable executed`
**Cause**: Panic in Rust code without panic handler
**Fix**: Add panic hook:
```rust
#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
}
```

#### 3. Import Error
**Symptom**: `LinkError: import not found`
**Cause**: Missing JavaScript glue code
**Fix**: Ensure `init()` is called before using WASM functions

---

## 🧰 Tools and Resources

### Essential Tools

```bash
# Install all WASM tools
cargo install wasm-pack          # Build and test WASM
cargo install wasm-bindgen-cli   # Generate JS bindings
cargo install wasm-opt           # Optimize WASM binaries (via binaryen)
```

### Helpful Resources

- **wasm-pack Docs**: https://rustwasm.github.io/docs/wasm-pack/
- **wasm-bindgen Guide**: https://rustwasm.github.io/docs/wasm-bindgen/
- **WASM Spec**: https://webassembly.github.io/spec/
- **Can I Use WASM**: https://caniuse.com/wasm

---

## 📚 Related Documentation

- **Feature Flags**: See [FEATURES.md](FEATURES.md)
- **Testing Patterns**: See `docs/developer/wasm-testing.md`
- **Core Architecture**: See [README.md](README.md)

---

## ⚠️ Troubleshooting

### Build Fails with "wasm-pack not found"
```bash
cargo install wasm-pack
rustup target add wasm32-unknown-unknown
```

### Tests Fail with "ChromeDriver not found"
```bash
# macOS
brew install chromedriver

# Linux
sudo apt-get install chromium-chromedriver

# Or use Firefox
wasm-pack test --firefox --headless
```

### WASM File Not Loading in Browser
- Check browser console for CORS errors
- Ensure MIME type is `application/wasm`
- Verify `init()` is called before using functions
- Hard refresh (Ctrl+Shift+R) to clear cache

---

For more help, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md) or open an issue on GitHub.
