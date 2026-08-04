#!/bin/bash
# Copyright (c) 2025 TRUSTEDGE LABS LLC
# MPL-2.0: https://mozilla.org/MPL/2.0/
# Project: sealedge — Privacy and trust at the edge.
#
# Local CI check — mirrors .github/workflows/ci.yml
# Run before pushing to catch issues without burning GH Actions minutes.
#
# Usage:
#   ./scripts/ci-check.sh          # Fast incremental (default)
#   ./scripts/ci-check.sh --clean  # Full clean build (matches CI exactly)

set -e

cd "$(dirname "$0")/.."

CLEAN=false
if [ "$1" = "--clean" ]; then
    CLEAN=true
fi

PASS=0
FAIL=0
SKIP=0
WARN=0

step() {
    echo
    echo "■ $1"
}

pass() {
    echo "  ✔ $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  ✖ $1"
    FAIL=$((FAIL + 1))
}

skip() {
    echo "  ⚠ $1 (skipped)"
    SKIP=$((SKIP + 1))
}

warn() {
    echo "  ⚠ $1 (warning)"
    WARN=$((WARN + 1))
}

echo "● Sealedge local CI check"
if $CLEAN; then
    echo "  Mode: clean build"
else
    echo "  Mode: incremental (use --clean for fresh build)"
fi
echo

# ── Step 0: Optional clean ──────────────────────────────────────────
if $CLEAN; then
    step "Step 0: Clean build cache"
    cargo clean
    pass "Cache cleared"
fi

# ── Step 1: Copyright headers ───────────────────────────────────────
step "Step 1: Copyright headers"
missing=0
while IFS= read -r file; do
    if ! head -10 "$file" | grep -q "Copyright (c) 2025 TRUSTEDGE LABS LLC"; then
        echo "  Missing: $file"
        missing=$((missing + 1))
    fi
done < <(find . -type f \( -name "*.rs" -o -name "*.yml" -o -name "*.yaml" -o -name "*.toml" \) \
    -not -path "./target/*" -not -path "./.git/*" -not -path "./.planning/*" \
    -not -path "./.claude/*" -not -path "*/node_modules/*")
if [ $missing -gt 0 ]; then
    fail "$missing files missing copyright headers — run: ./scripts/fix-copyright.sh"
else
    pass "All source files have copyright headers"
fi

# ── Step 2: Security audit ──────────────────────────────────────────
step "Step 2: Security audit (cargo-audit)"
if command -v cargo-audit &> /dev/null; then
    if cargo audit; then
        pass "cargo audit"
    else
        fail "cargo audit — run: cargo audit to see details"
    fi
else
    skip "cargo-audit not installed (install: cargo install cargo-audit)"
fi

# ── Step 3: Format ──────────────────────────────────────────────────
step "Step 3: Format check"
if cargo fmt --all -- --check; then
    pass "cargo fmt"
else
    fail "cargo fmt — run: cargo fmt --all"
fi

# ── Step 4: Clippy (all features) ──────────────────────────────────
step "Step 4: Clippy"

HAS_ALSA=false
HAS_PCSC=false
pkg-config --exists alsa 2>/dev/null && HAS_ALSA=true
pkg-config --exists libpcsclite 2>/dev/null && HAS_PCSC=true

if $HAS_ALSA && $HAS_PCSC; then
    # All system deps available — per-crate clippy (postgres excluded: sqlx removed)
    if cargo clippy -p sealedge-core --all-targets --all-features -- -D warnings && \
       cargo clippy -p sealedge-platform --all-targets --features "http,ca,openapi,yubikey" -- -D warnings && \
       cargo clippy --workspace --all-targets --no-default-features -- -D warnings; then
        pass "clippy (all buildable features)"
    else
        fail "clippy (all buildable features)"
    fi
else
    # Fallback: workspace without optional features
    if cargo clippy --workspace --all-targets --no-default-features -- -D warnings; then
        pass "clippy (workspace, no default features)"
    else
        fail "clippy (workspace)"
    fi

    # Platform feature combinations
    if cargo clippy -p sealedge-platform --features "http" -- -D warnings && \
       cargo clippy -p sealedge-platform --features "http,ca" -- -D warnings; then
        pass "clippy sealedge-platform features"
    else
        fail "clippy sealedge-platform features"
    fi

    $HAS_ALSA && {
        if cargo clippy -p sealedge-core --all-targets --features audio -- -D warnings; then
            pass "clippy audio"
        else
            fail "clippy audio"
        fi
    }

    $HAS_PCSC && {
        if cargo clippy -p sealedge-core --all-targets --features yubikey -- -D warnings; then
            pass "clippy yubikey"
        else
            fail "clippy yubikey"
        fi
    }

    # Non-system-dep features
    for feat in git-attestation keyring insecure-tls; do
        if cargo clippy -p sealedge-core --all-targets --features "$feat" -- -D warnings; then
            pass "clippy $feat"
        else
            fail "clippy $feat"
        fi
    done
fi

# ── Step 5: Feature compatibility (cargo-hack) ─────────────────────
step "Step 5: Feature compatibility (cargo-hack)"
if command -v cargo-hack &> /dev/null; then
    if cargo hack check --each-feature --no-dev-deps --exclude-features audio --package sealedge-core && \
       cargo hack check --each-feature --no-dev-deps --package sealedge-cli; then
        pass "cargo-hack each-feature"
    else
        fail "cargo-hack each-feature"
    fi
else
    skip "cargo-hack not installed"
fi

# ── Step 6: Build + test ───────────────────────────────────────────
step "Step 6: Build and test"

# Build workspace
cargo build --workspace --bins --no-default-features

# Workspace tests (no default features)
if cargo test --workspace --no-default-features --locked; then
    pass "workspace tests (no default features)"
else
    fail "workspace tests"
fi

# Core tests with all non-yubikey features
CORE_FEATURES="git-attestation,keyring,insecure-tls"
$HAS_ALSA && CORE_FEATURES="audio,$CORE_FEATURES"
if cargo test -p sealedge-core --features "$CORE_FEATURES" --locked; then
    pass "sealedge-core tests ($CORE_FEATURES)"
else
    fail "sealedge-core tests ($CORE_FEATURES)"
fi

# YubiKey simulation tests (unit tests only, no hardware)
if $HAS_PCSC; then
    if cargo test -p sealedge-core --features yubikey --lib --locked; then
        pass "yubikey simulation tests"
    else
        fail "yubikey simulation tests"
    fi
else
    skip "PCSC not available"
fi

# Platform feature tests
# golden_vectors locks the .trst signing contract (canonical bytes + signature
# wire format) shared by the seal CLI and the platform verify engine (C1).
if cargo test -p sealedge-platform --lib --locked && \
   cargo test -p sealedge-platform --test golden_vectors --locked && \
   cargo test -p sealedge-platform --test verify_integration --locked && \
   cargo test -p sealedge-platform --test verify_integration --features http --locked; then
    pass "sealedge-platform tests"
else
    fail "sealedge-platform tests"
fi

# ── Step 7: WASM ───────────────────────────────────────────────────
step "Step 7: WASM build verification"
if rustup target list --installed | grep -q wasm32-unknown-unknown; then
    if cargo check -p sealedge-wasm --target wasm32-unknown-unknown && \
       cargo check -p sealedge-seal-wasm --target wasm32-unknown-unknown; then
        pass "WASM build"
    else
        fail "WASM build"
    fi
else
    skip "wasm32-unknown-unknown target not installed"
fi

# ── Step 8: Semver ─────────────────────────────────────────────────
step "Step 8: API compatibility (cargo-semver-checks)"
if command -v cargo-semver-checks &> /dev/null; then
    if cargo semver-checks --package sealedge-core --baseline-rev HEAD~1 2>/dev/null; then
        pass "semver check"
    else
        echo "  ⚠ semver check failed (non-blocking)"
    fi
else
    skip "cargo-semver-checks not installed"
fi

# ── Step 9: Dependency tree size ────────────────────────────────────
step "Step 9: Dependency tree size check"
dep_count=$(cargo tree --workspace --depth 1 --prefix none --no-dedupe 2>/dev/null | sort -u | wc -l)
baseline=70
threshold=$((baseline + 10))
echo "  Dependency tree: $dep_count unique crates (baseline: $baseline)"
if [ "$dep_count" -gt "$threshold" ]; then
    echo "  ⚠ Dependency tree grew beyond threshold ($dep_count > $threshold)"
    WARN=$((WARN + 1))
else
    pass "dependency tree within baseline"
fi

# ── Step 10: TODO hygiene ──────────────────────────────────────────
step "Step 10: TODO hygiene (no unimplemented markers)"
todo_count=0
while IFS= read -r match; do
    case "$match" in
        *"#[cfg(test)]"*) continue ;;
        *"_test_"*|*"test_"*) continue ;;
    esac
    echo "  Found: $match"
    todo_count=$((todo_count + 1))
done < <(grep -rn '// TODO\|// FIXME\|// HACK\|// XXX\|todo!()\|unimplemented!()' \
    --include="*.rs" crates/ \
    2>/dev/null || true)
if [ "$todo_count" -gt 0 ]; then
    fail "$todo_count unimplemented TODO/FIXME markers found"
else
    pass "No unimplemented TODO/FIXME markers"
fi

# ── Step 11: Secret struct derive check ────────────────────────────
step "Step 11: Secret struct derive check (no Serialize on secret-holding structs)"
SECRET_STRUCTS_OK=true

for file_struct in \
    "crates/core/src/backends/yubikey.rs:YubiKeyConfig" \
    "crates/core/src/backends/software_hsm.rs:SoftwareHsmConfig" \
    "crates/platform/src/ca/models.rs:LoginRequest" \
    "crates/platform/src/ca/mod.rs:CAConfig"; do
    FILE="${file_struct%%:*}"
    STRUCT="${file_struct##*:}"

    if grep -B2 "pub struct $STRUCT" "$FILE" | grep -q "Serialize"; then
        fail "$STRUCT in $FILE still has Serialize derive"
        SECRET_STRUCTS_OK=false
    fi

    if ! grep -q "REDACTED" "$FILE"; then
        fail "$STRUCT in $FILE missing [REDACTED] in Debug impl"
        SECRET_STRUCTS_OK=false
    fi
done

if [ "$SECRET_STRUCTS_OK" = true ]; then
    pass "No forbidden derives on secret-holding structs; all have [REDACTED] Debug impls"
fi

# ── Step 12: Dashboard bundle credential check ──────────────────────
step "Step 12: Dashboard bundle credential check"
if [ -d "web/dashboard" ] && command -v node &> /dev/null; then
    if (cd web/dashboard && npm install --silent 2>/dev/null && npm run build --silent 2>/dev/null); then
        if grep -r "VITE_API_KEY" web/dashboard/build/ 2>/dev/null; then
            fail "VITE_API_KEY found in dashboard bundle — credential leak detected"
        else
            pass "No API credentials in dashboard bundle"
        fi
    else
        warn "Dashboard build failed — skipping bundle credential check"
    fi
else
    skip "node not available or web/dashboard not present — skipping bundle check"
fi

# ── Summary ─────────────────────────────────────────────────────────
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Results: $PASS passed, $FAIL failed, $WARN warnings, $SKIP skipped"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ $FAIL -gt 0 ]; then
    echo "  ✖ Fix failures before pushing."
    exit 1
else
    echo "  ✔ All checks passed. Safe to push."
fi
