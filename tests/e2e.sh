# Hellas E2E test: multi-provider, multi-node scenarios with discovery.
#
# Starts 3 server nodes with different policies, then runs client scenarios
# testing direct execution, policy decline, discovery failover, and health.
#
# Run via: nix run .#e2e
# Requires: all source files tracked by git (git add)
#
# Environment:
#   HF_HOME  – HuggingFace cache dir (default: ~/.cache/huggingface).
#              Set this to reuse pre-downloaded models and skip downloads.

TEST_DIR=$(mktemp -d -t hellas-e2e-XXXXXX)

cleanup() {
  echo "Cleaning up..."
  kill "$PID_OPEN" "$PID_RESTRICT" "$PID_SKIP" 2>/dev/null || true
  wait "$PID_OPEN" "$PID_RESTRICT" "$PID_SKIP" 2>/dev/null || true
  rm -rf "$TEST_DIR"
}
trap cleanup EXIT

PASS=$'\033[0;32mPASS\033[0m'
FAIL=$'\033[0;31mFAIL\033[0m'
INFO=$'\033[1;33m----\033[0m'

pass() { printf '%s: %s\n' "$PASS" "$1"; }
fail() { printf '%s: %s\n' "$FAIL" "$1"; exit 1; }
info() { printf '%s: %s\n' "$INFO" "$1"; }

# ── Resolve HF model cache ───────────────────────────────────────

if [ -n "${HF_HOME:-}" ]; then
  info "HF model cache (HF_HOME): $HF_HOME"
elif [ -d "$HOME/.cache/huggingface" ]; then
  export HF_HOME="$HOME/.cache/huggingface"
  info "HF model cache (default): $HF_HOME"
else
  info "No HF model cache found; models will be downloaded on first use"
fi

# ── Start three server nodes with different policies ─────────────

info "Starting open node (eager policies)..."
IROH_DATA_DIR="$TEST_DIR/iroh-open" RUST_LOG=info \
  hellas-cli serve \
    --download-policy=eager --execute-policy=eager \
  >"$TEST_DIR/open.stdout" 2>"$TEST_DIR/open.stderr" &
PID_OPEN=$!

info "Starting restrictive node (only allows SomeOtherModel)..."
IROH_DATA_DIR="$TEST_DIR/iroh-restrict" RUST_LOG=info \
  hellas-cli serve \
    --download-policy=skip '--execute-policy=allow(hf/SomeOtherModel/*)' \
  >"$TEST_DIR/restrict.stdout" 2>"$TEST_DIR/restrict.stderr" &
PID_RESTRICT=$!

info "Starting skip-all node (refuses everything)..."
IROH_DATA_DIR="$TEST_DIR/iroh-skip" RUST_LOG=info \
  hellas-cli serve \
    --download-policy=skip --execute-policy=skip \
  >"$TEST_DIR/skip.stdout" 2>"$TEST_DIR/skip.stderr" &
PID_SKIP=$!

# ── Wait for each node to print its address ──────────────────────

wait_for_nodeid() {
  local file=$1 name=$2 timeout="${3:-60}"
  local i
  for i in $(seq 1 "$timeout"); do
    if grep -q "Node Address:" "$file" 2>/dev/null; then
      grep "Node Address:" "$file" | head -1 | awk '{print $NF}'
      return 0
    fi
    sleep 1
  done
  info "stderr tail for $name:"
  tail -20 "${file%stdout}stderr" >&2
  fail "Timed out waiting for $name to print its node address (${timeout}s)"
}

NODE_OPEN=$(wait_for_nodeid "$TEST_DIR/open.stdout" "open node")
info "Open node:        $NODE_OPEN"

NODE_RESTRICT=$(wait_for_nodeid "$TEST_DIR/restrict.stdout" "restrictive node")
info "Restrictive node: $NODE_RESTRICT"

NODE_SKIP=$(wait_for_nodeid "$TEST_DIR/skip.stdout" "skip-all node")
info "Skip-all node:    $NODE_SKIP"

# ── Trigger model download on open node, then wait for weights ───

info "Sending warm-up request via discovery to trigger model load..."
IROH_DATA_DIR="$TEST_DIR/iroh-warmup" RUST_LOG=info \
  hellas-cli execute -p "warmup" --max-seq 1 --retries 0 --backup-quotes 0 \
  >"$TEST_DIR/warmup.stdout" 2>"$TEST_DIR/warmup.stderr" || true
info "Waiting for model weights..."
for i in $(seq 1 300); do
  if grep -q "weights ready" "$TEST_DIR/open.stderr" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$PID_OPEN" 2>/dev/null; then
    tail -20 "$TEST_DIR/open.stderr" >&2
    fail "Open node exited while waiting for weights"
  fi
  if (( i % 30 == 0 )); then
    info "Still waiting for weights... (${i}s elapsed)"
  fi
  sleep 1
done
if ! grep -q "weights ready" "$TEST_DIR/open.stderr"; then
  info "Server stderr (last 50 lines):"
  tail -50 "$TEST_DIR/open.stderr" >&2
  fail "Timed out waiting for weights (300s)"
fi
info "Weights ready"

# ── Scenario 1: Direct execution against open node ───────────────

info "Scenario 1: Direct execution against open node"
IROH_DATA_DIR="$TEST_DIR/iroh-c1" RUST_LOG=warn \
  hellas-cli execute "$NODE_OPEN" -p "Hello" --max-seq 8 \
  >"$TEST_DIR/s1.stdout" 2>"$TEST_DIR/s1.stderr" || {
    cat "$TEST_DIR/s1.stderr" >&2
    fail "direct execution failed"
  }
[ -s "$TEST_DIR/s1.stdout" ] \
  || fail "direct execution returned empty output"
pass "Direct execution: $(head -c 120 "$TEST_DIR/s1.stdout")"

# ── Scenario 2: Restrictive node declines (expect failure) ───────

info "Scenario 2: Direct execution against restrictive node (expect decline)"
if IROH_DATA_DIR="$TEST_DIR/iroh-c2" RUST_LOG=warn \
  hellas-cli execute "$NODE_RESTRICT" -p "Hello" --max-seq 8 \
  >"$TEST_DIR/s2.stdout" 2>"$TEST_DIR/s2.stderr"; then
  fail "Restrictive node should have declined"
fi
grep -qiE "declined|denied|permission" "$TEST_DIR/s2.stderr" || {
  cat "$TEST_DIR/s2.stderr" >&2
  fail "Expected policy-related error"
}
pass "Restrictive node declined"

# ── Scenario 3: Discovery-based execution with failover ──────────

info "Scenario 3: Discovery-based execution (failover across 3 nodes)"
IROH_DATA_DIR="$TEST_DIR/iroh-c3" RUST_LOG=info \
  hellas-cli execute -p "What is 1+1?" --max-seq 8 \
    --retries 2 --backup-quotes 0 \
  >"$TEST_DIR/s3.stdout" 2>"$TEST_DIR/s3.stderr" || {
    cat "$TEST_DIR/s3.stderr" >&2
    fail "discovery execution failed"
  }
[ -s "$TEST_DIR/s3.stdout" ] \
  || fail "discovery execution returned empty output"
if grep -q "declined" "$TEST_DIR/s3.stderr"; then
  pass "Discovery with failover: $(head -c 120 "$TEST_DIR/s3.stdout")"
else
  pass "Discovery (no decline observed): $(head -c 120 "$TEST_DIR/s3.stdout")"
fi

# ── Scenario 4: Health check ─────────────────────────────────────

info "Scenario 4: Health check against open node"
IROH_DATA_DIR="$TEST_DIR/iroh-c4" RUST_LOG=warn \
  hellas-cli health "$NODE_OPEN" \
  >"$TEST_DIR/s4.stdout" 2>"$TEST_DIR/s4.stderr" || {
    cat "$TEST_DIR/s4.stderr" >&2
    fail "health check failed"
  }
grep -q "Version:" "$TEST_DIR/s4.stdout" \
  || fail "health output missing Version"
grep -q "Node ID:" "$TEST_DIR/s4.stdout" \
  || fail "health output missing Node ID"
pass "Health check: $(tr '\n' ' ' < "$TEST_DIR/s4.stdout")"

echo ""
printf '\033[0;32m%s\033[0m\n' "All E2E scenarios passed!"
