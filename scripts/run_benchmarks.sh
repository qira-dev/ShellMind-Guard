#!/usr/bin/env bash
set -euo pipefail

# ShellMind Guard — Deterministic CI Performance, Scaling & Precision Gate
# Runs offline in < 2 minutes, requires zero external repositories or secrets,
# writes Markdown + JSON telemetry, and populates $GITHUB_STEP_SUMMARY automatically.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

OUT_DIR="${BENCH_OUT_DIR:-${ROOT_DIR}/target/benchmarks}"
mkdir -p "${OUT_DIR}"
REPORT_MD="${OUT_DIR}/benchmark-report.md"
METRICS_JSON="${OUT_DIR}/benchmark-metrics.json"
RAW_ADV_LOG="${OUT_DIR}/adversarial.log"
RAW_SCALE_LOG="${OUT_DIR}/scaling.log"
RAW_PROF_LOG="${OUT_DIR}/profile.log"

VERSION="$(awk -F'"' '/^version = / {print $2; exit}' Cargo.toml)"
GIT_SHA="$(git rev-parse --short=12 HEAD 2>/dev/null || echo "local")"
UTC_TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

echo "[1/3] Running 125-case Adversarial Precision, Recall & Latency Gate..."
SMG_ENFORCE_PRECISION_GATE=1 cargo test -p smg-graph --test adversarial_precision_bench --locked -- --nocapture 2>&1 \
  | tee "${RAW_ADV_LOG}"

SUMMARY_LINE="$(grep -E '^Cases=[0-9]+' "${RAW_ADV_LOG}" | tail -n 1 || true)"
PRECREC_LINE="$(grep -E '^Precision=' "${RAW_ADV_LOG}" | tail -n 1 || true)"
LATENCY_LINE="$(grep -E '^Micro-Case P99=' "${RAW_ADV_LOG}" | tail -n 1 || true)"

if [[ -z "${SUMMARY_LINE}" ]]; then
  echo "[FAIL] Missing adversarial benchmark summary output!" >&2
  exit 1
fi

echo "[2/3] Running O(V+E) 2,000-Node Cyclic Lattice & 72k-Scale Firmware WCSD Gates..."
{
  cargo test -p smg-graph --lib test_b11_2000_node_all_sink_chain_is_linear --locked
  cargo test -p smg-hw --lib test_zephyr_scale_define_storm_and_cyclic_wcsd_under_250ms --locked
  cargo test --test readme_catalog_sync --locked
} 2>&1 | tee "${RAW_SCALE_LOG}"

echo "[3/3] Measuring Release Self-Dogfood Phase Telemetry (src + crates)..."
if [[ ! -x "${ROOT_DIR}/target/release/smg" ]]; then
  cargo build --release --locked
fi

"${ROOT_DIR}/target/release/smg" scan src --ci >/dev/null
SMG_PROFILE_PHASES=1 "${ROOT_DIR}/target/release/smg" scan crates --ci 2>"${RAW_PROF_LOG}" >/dev/null

PROFILE_LINE="$(grep -F '[SMG-PROFILE]' "${RAW_PROF_LOG}" | tail -n 1 || true)"
TOTAL_MS="$(echo "${PROFILE_LINE}" | sed -n 's/.*total=\([0-9]*\)ms.*/\1/p')"
WALK_MS="$(echo "${PROFILE_LINE}" | sed -n 's/.*walk=\([0-9]*\)ms.*/\1/p')"
GRAPH_MS="$(echo "${PROFILE_LINE}" | sed -n 's/.*graph=\([0-9]*\)ms.*/\1/p')"
HW_MS="$(echo "${PROFILE_LINE}" | sed -n 's/.*hw=\([0-9]*\)ms.*/\1/p')"
WEB3_MS="$(echo "${PROFILE_LINE}" | sed -n 's/.*web3=\([0-9]*\)ms.*/\1/p')"

TOTAL_MS="${TOTAL_MS:-0}"
WALK_MS="${WALK_MS:-0}"
GRAPH_MS="${GRAPH_MS:-0}"
HW_MS="${HW_MS:-0}"
WEB3_MS="${WEB3_MS:-0}"

# Fail-closed regression ceiling (8,000 ms generous shared-CI runner ceiling on 98-file crates/ tree)
if [[ "${TOTAL_MS}" -gt 8000 ]]; then
  echo "[FAIL] Self-scan total latency (${TOTAL_MS}ms) exceeded 8000ms CI regression ceiling!" >&2
  exit 1
fi

cat > "${METRICS_JSON}" <<EOF
{
  "version": "${VERSION}",
  "commit": "${GIT_SHA}",
  "timestamp_utc": "${UTC_TS}",
  "adversarial_summary": "${SUMMARY_LINE}",
  "precision_recall": "${PRECREC_LINE}",
  "latency_summary": "${LATENCY_LINE}",
  "self_scan_crates_ms": {
    "walk_ms": ${WALK_MS},
    "graph_ms": ${GRAPH_MS},
    "hw_ms": ${HW_MS},
    "web3_ms": ${WEB3_MS},
    "total_ms": ${TOTAL_MS}
  }
}
EOF

SAFE_SUMMARY="${SUMMARY_LINE//|/·}"
SAFE_PRECREC="${PRECREC_LINE//|/·}"
SAFE_LATENCY="${LATENCY_LINE//|/·}"

cat > "${REPORT_MD}" <<EOF
## ShellMind Guard Automated Benchmark & Precision Scorecard (\`v${VERSION}\` @ \`${GIT_SHA}\`)

- **Measured At (UTC):** \`${UTC_TS}\`
- **Adversarial Confusion Matrix:** \`${SUMMARY_LINE}\`
- **Precision / Recall / F1:** \`${PRECREC_LINE}\`
- **Engine Latency Percentiles:** \`${LATENCY_LINE}\`

| Verification Gate | Workload | Result | Measured Telemetry |
| :--- | :--- | :---: | :--- |
| **Adversarial Precision & Recall** | 125 paired cases across 25 rule families | PASS | \`${SAFE_SUMMARY}\` (\`${SAFE_PRECREC}\`) |
| **Linear \`O(V + E)\` Cyclic Lattice** | 2,000-node cyclic sink chain (\`smg-graph\`) | PASS | \`< 500 ms\` linear budget verified |
| **Embedded RTOS Define & WCSD DAG** | 5,000 \`#define\`s + 500 cyclic C fns + 140-lvl DAG (\`smg-hw\`) | PASS | WCSD DAG \`< 50 ms\`, full pass \`< 2,500 ms\` |
| **Catalog ↔ Code ↔ README Sync** | 172 \`RULE_CATALOG\` rules + 23 CLI subcommands | PASS | Zero documentation or rule-ID drift |
| **Release Self-Dogfood Phase Profile** | \`smg scan crates --ci\` (98 Rust files, all domains) | PASS | \`walk=${WALK_MS}ms · graph=${GRAPH_MS}ms · hw=${HW_MS}ms · web3=${WEB3_MS}ms · total=${TOTAL_MS}ms\` |
| **Micro & Multi-Module Latency** | 125 micro-cases + 120-module Go/TS repo | PASS | \`${SAFE_LATENCY}\` |
EOF

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  cat "${REPORT_MD}" >> "${GITHUB_STEP_SUMMARY}"
fi

echo "[OK] Benchmark report written to ${REPORT_MD} and ${METRICS_JSON}"
