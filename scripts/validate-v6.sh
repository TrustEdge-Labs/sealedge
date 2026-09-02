#!/bin/bash
# Copyright (c) 2025 TRUSTEDGE LABS LLC
# MPL-2.0: https://mozilla.org/MPL/2.0/
# Project: sealedge — Privacy and trust at the edge.
#
# Full v6.0 validation gate — mirrors ci.yml build-and-test feature matrix
# plus WASM / dashboard build / docker compose e2e / demo roundtrip.
# Run before cutting the v6.0.0 tag to prove every gate is green.
#
# Writes validate-v6.log to $PWD (excerpted into 89-VERIFICATION.md per D-03).
#
# Usage:
#   ./scripts/validate-v6.sh                                     # Full run
#   ./scripts/validate-v6.sh --skip-docker                       # Skip docker gate (e.g. no docker daemon)
#   ./scripts/validate-v6.sh --allow-regression "<justification>"  # D-02 escape hatch — allow tests < 471

set -e
cd "$(dirname "$0")/.."

# ── Flag parsing ─────────────────────────────────────────────────────
SKIP_DOCKER=false
ALLOW_REGRESSION=false
REGRESSION_JUSTIFICATION=""
while [ $# -gt 0 ]; do
    case "$1" in
        --skip-docker)
            SKIP_DOCKER=true
            shift
            ;;
        --allow-regression)
            shift
            if [ $# -eq 0 ] || [ -z "$1" ]; then
                echo "ERROR: --allow-regression requires a non-empty justification string." >&2
                echo "Usage: ./scripts/validate-v6.sh --allow-regression \"<justification>\"" >&2
                exit 1
            fi
            ALLOW_REGRESSION=true
            REGRESSION_JUSTIFICATION="$1"
            shift
            ;;
        *)
            echo "ERROR: Unknown flag: $1" >&2
            echo "Usage: ./scripts/validate-v6.sh [--skip-docker] [--allow-regression \"<justification>\"]" >&2
            exit 1
            ;;
    esac
done

# Capture all stdout/stderr to validate-v6.log (evidence for 89-VERIFICATION.md per D-03)
exec > >(tee validate-v6.log) 2>&1

# ── Counters + helpers (copied verbatim from scripts/ci-check.sh) ────
PASS=0
FAIL=0
SKIP=0
WARN=0
step() { echo; echo "■ $1"; }
pass() { echo "  ✔ $1"; PASS=$((PASS + 1)); }
fail() { echo "  ✖ $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  ⚠ $1 (skipped)"; SKIP=$((SKIP + 1)); }
warn() { echo "  ⚠ $1 (warning)"; WARN=$((WARN + 1)); }

# ── Banner ───────────────────────────────────────────────────────────
echo "● Sealedge v6.0 validation gate"
echo "  Mode: full matrix + WASM + dashboard + docker e2e"
if $SKIP_DOCKER; then
    echo "  Docker gate: SKIPPED (--skip-docker)"
fi
if $ALLOW_REGRESSION; then
    echo "  D-02 floor: REGRESSION ALLOWED — $REGRESSION_JUSTIFICATION"
fi
echo

# ── Step 1: Local CI parity matrix (via ci-check.sh) ─────────────────
# Delegates the full D-01 feature matrix (workspace, sealedge-core features,
# yubikey lib, sealedge-platform lib + verify_integration + http) to
# ci-check.sh --clean, which is the single source of truth for CI parity.
step "Step 1: Local CI parity matrix (via ci-check.sh --clean)"
if ./scripts/ci-check.sh --clean; then
    pass "ci-check.sh --clean (full feature matrix: cargo test --workspace --no-default-features --locked + core features + yubikey --lib + platform lib + verify_integration + verify_integration --features http)"
else
    fail "ci-check.sh --clean"
fi

# ── Step 2: WASM cargo check ─────────────────────────────────────────
step "Step 2: WASM cargo check (wasm32-unknown-unknown)"
if rustup target list --installed | grep -q wasm32-unknown-unknown; then
    if cargo check -p sealedge-wasm --target wasm32-unknown-unknown && \
       cargo check -p sealedge-seal-wasm --target wasm32-unknown-unknown; then
        pass "WASM cargo check (sealedge-wasm + sealedge-seal-wasm)"
    else
        fail "WASM cargo check"
    fi
else
    skip "wasm32-unknown-unknown target not installed (rustup target add wasm32-unknown-unknown)"
fi

# ── Step 3: WASM build + size check ──────────────────────────────────
step "Step 3: WASM build + size check (wasm-pack + 2 MB floor per D-11)"
if command -v wasm-pack &> /dev/null; then
    WASM_BUILD_OK=true
    if ! (cd crates/wasm && wasm-pack build --target web --release); then
        WASM_BUILD_OK=false
    fi
    if ! (cd crates/seal-wasm && wasm-pack build --target web --release); then
        WASM_BUILD_OK=false
    fi
    if $WASM_BUILD_OK; then
        SEALEDGE_WASM_SIZE=$(wc -c < crates/wasm/pkg/sealedge_wasm_bg.wasm 2>/dev/null || echo 0)
        SEAL_WASM_SIZE=$(wc -c < crates/seal-wasm/pkg/sealedge_seal_wasm_bg.wasm 2>/dev/null || echo 0)
        echo "  sealedge-wasm:      $SEALEDGE_WASM_SIZE bytes (floor: < 2097152 bytes = 2 MB, wasm-tests.yml parity)"
        echo "  sealedge-seal-wasm: $SEAL_WASM_SIZE bytes (informational — no floor per D-11)"
        if [ "$SEALEDGE_WASM_SIZE" -gt 2097152 ]; then
            fail "sealedge-wasm exceeds 2 MB limit ($SEALEDGE_WASM_SIZE > 2097152)"
        else
            pass "WASM size check (sealedge-wasm under 2 MB floor)"
        fi
    else
        fail "wasm-pack build"
    fi
else
    skip "wasm-pack not installed (cargo install wasm-pack)"
fi

# ── Step 4: Dashboard build + typecheck ──────────────────────────────
step "Step 4: Dashboard build + typecheck (web/dashboard per D-12)"
if [ -d "web/dashboard" ]; then
    DASHBOARD_OK=true
    if (cd web/dashboard && npm ci); then
        pass "dashboard npm ci"
    else
        fail "dashboard npm ci"
        DASHBOARD_OK=false
    fi
    if $DASHBOARD_OK; then
        if (cd web/dashboard && npm run build); then
            pass "dashboard npm run build"
        else
            fail "dashboard npm run build"
            DASHBOARD_OK=false
        fi
    fi
    if $DASHBOARD_OK; then
        if (cd web/dashboard && npm run check); then
            pass "dashboard npm run check (typecheck)"
        else
            fail "dashboard npm run check"
        fi
    fi
else
    skip "web/dashboard directory not found"
fi

# ── Step 5: Docker compose + demo roundtrip ──────────────────────────
step "Step 5: Docker stack + demo end-to-end (D-13)"
DOCKER_BROUGHT_UP=false

# Always tear down docker stack on exit (with volumes for a clean slate on next run).
cleanup_docker() {
    if $DOCKER_BROUGHT_UP; then
        docker compose -f deploy/docker-compose.yml down -v 2>/dev/null || true
    fi
}
trap cleanup_docker EXIT

if $SKIP_DOCKER; then
    skip "docker gate skipped (--skip-docker flag)"
elif command -v docker &> /dev/null && docker compose version &> /dev/null; then
    if docker compose -f deploy/docker-compose.yml up --build -d; then
        DOCKER_BROUGHT_UP=true

        # Wait-for-health loop: 30 retries x 2s = 60s max
        RETRIES=30
        HEALTHY=false
        until curl -sf http://localhost:3001/healthz > /dev/null 2>&1; do
            sleep 2
            RETRIES=$((RETRIES - 1))
            if [ $RETRIES -le 0 ]; then
                break
            fi
        done
        if curl -sf http://localhost:3001/healthz > /dev/null 2>&1; then
            HEALTHY=true
        fi

        if $HEALTHY; then
            pass "docker stack healthy (/healthz responding)"
            if ./scripts/demo.sh; then
                pass "demo roundtrip (docker mode auto-detected via /healthz)"
            else
                fail "demo roundtrip"
            fi
        else
            fail "platform /healthz not responding after 60s"
        fi

        # Explicit teardown with volumes (trap will also run, but fine to teardown eagerly)
        docker compose -f deploy/docker-compose.yml down -v
        DOCKER_BROUGHT_UP=false
    else
        fail "docker compose up --build"
    fi
else
    skip "docker not available"
fi

# ── Summary ──────────────────────────────────────────────────────────
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Results: $PASS passed, $FAIL failed, $WARN warnings, $SKIP skipped"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ $FAIL -gt 0 ]; then
    echo "  ✖ Fix failures before tagging v6.0.0."
    exit 1
else
    echo "  ✔ All v6.0 validation gates passed. Safe to cut v6.0.0 tag."
fi

# ── D-02 test-count floor enforcement (≥ 471) ─────────────────────────
# Parse validate-v6.log for `test result: ok. N passed` lines and sum N.
# Floor rationale (D-02): the v6.0 release validated at 471 green tests; a count
# below that must be explicit (--allow-regression), guarding against silently
# dropped tests.
TOTAL_TESTS=$(grep -oE 'test result: ok\. [0-9]+ passed' validate-v6.log 2>/dev/null | awk '{s+=$4} END {print s+0}')
echo "  Total green tests: $TOTAL_TESTS (floor: 471)"
if [ "$TOTAL_TESTS" -lt 471 ]; then  # D-02 floor (v6.0 validation baseline)
    if $ALLOW_REGRESSION; then
        echo "  ⚠ Test count below v6.0 floor (471), but --allow-regression set."
        echo "  D-02 JUSTIFICATION: $REGRESSION_JUSTIFICATION"
        # Log the justification so 89-VERIFICATION.md §1 can cite it.
        # Per D-02 escape hatch — caller MUST also record this justification
        # text in 89-VERIFICATION.md §1 ("D-02 justification: <text>").
    else
        echo "  ✖ Test count below v6.0 floor — record justification in 89-VERIFICATION.md before proceeding."
        echo "  Use --allow-regression \"<justification>\" to acknowledge and continue (D-02 escape hatch)."
        exit 1
    fi
fi
