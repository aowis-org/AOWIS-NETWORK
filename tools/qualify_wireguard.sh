#!/usr/bin/env bash
# WireGuard qualification run (ROADMAP items 1-2): builds once, runs the Go
# race detector once, then repeats the full encrypted e2e suites N times and
# collects timings and failures into one archive to upload.
#
#   ./tools/qualify_wireguard.sh [runs]     (default 10)
#
# Output: qualification/<timestamp>/ (logs, summary.txt) and
#         qualification/<timestamp>.tar.gz
set -uo pipefail

runs="${1:-10}"
[[ "$runs" =~ ^[1-9][0-9]*$ ]] || { printf 'runs must be a positive integer\n' >&2; exit 2; }
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
build="$root/build-linux-tests"
stamp="$(date +%Y%m%d-%H%M%S)"
out="$root/qualification/$stamp"
mkdir -p "$out"
cd "$root"

now_ms() { date +%s%3N; }
log() { printf '%s\n' "$*" | tee -a "$out/summary.txt"; }

log "AOWIS-NETWORK WireGuard qualification $stamp ($runs runs)"
log "host: $(uname -srm); go: $(go version 2>/dev/null || echo missing)"
log "commit: $(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)$(git -C "$root" diff --quiet 2>/dev/null || echo ' (dirty)')"

# 1. Build and run the complete suite once.
if ! { cmake -S "$root" -B "$build" -G Ninja -DAOWIS_NETWORK_WITH_WIREGUARD=ON -DBUILD_TESTING=ON \
       && cmake --build "$build" --parallel "${AOWIS_BUILD_JOBS:-8}"; } >"$out/build.log" 2>&1; then
    log "BUILD FAILED (see build.log)"
    tar -C "$root/qualification" -czf "$out.tar.gz" "$stamp"; exit 1
fi
if ctest --test-dir "$build" --output-on-failure >"$out/ctest-full.log" 2>&1; then
    log "full ctest: PASS"
else
    log "full ctest: FAIL (see ctest-full.log)"
fi

# 2. Data races in the Go engine (proxy counters, telemetry, re-resolution
#    monitor, session close), across every Go test including e2e.
start=$(now_ms)
if (cd bridge && GOWORK=off go test -mod=readonly -race -count=1 -timeout=300s ./...) >"$out/go-race.log" 2>&1; then
    log "go -race: PASS ($(( ($(now_ms) - start) / 1000 ))s)"
else
    log "go -race: FAIL (see go-race.log)"
fi

# 3. Repeated encrypted end-to-end runs: Go engine (gVisor peer, restart,
#    wrong key, independent tunnels, no host fallback) and the full Qt ->
#    C++ ABI -> Go -> UDP -> remote netstack path.
go_failures=0
qt_failures=0
for i in $(seq 1 "$runs"); do
    start=$(now_ms)
    if (cd bridge && GOWORK=off go test -mod=readonly -count=1 -v -timeout=180s -run '^TestWireGuardE2E' ./...) \
        >"$out/go-e2e-$i.log" 2>&1; then go_state=PASS; else go_state=FAIL; go_failures=$((go_failures + 1)); fi
    go_ms=$(( $(now_ms) - start ))
    start=$(now_ms)
    if ctest --test-dir "$build" -R '^aowis-network-qt-wireguard-e2e$' --output-on-failure \
        >"$out/qt-e2e-$i.log" 2>&1; then qt_state=PASS; else qt_state=FAIL; qt_failures=$((qt_failures + 1)); fi
    qt_ms=$(( $(now_ms) - start ))
    log "run $i/$runs: go-e2e $go_state (${go_ms} ms)  qt-e2e $qt_state (${qt_ms} ms)"
done

# 4. Per-test timing spread (go test -v: "--- PASS: TestX (1.23s)").
{
    printf '\n== Go e2e per-test durations over %s runs (min / max / mean s) ==\n' "$runs"
    cat "$out"/go-e2e-*.log | awk '/^ *--- (PASS|FAIL): TestWireGuardE2E/ {
        name=$3; d=$4; gsub(/[()s]/, "", d); n[name]++; s[name]+=d;
        if (!(name in mn) || d < mn[name]) mn[name]=d; if (d > mx[name]) mx[name]=d;
        if ($2 == "FAIL:") f[name]++ }
        END { for (k in n) printf "%-50s %6.2f %6.2f %6.2f  fail %d/%d\n", k, mn[k], mx[k], s[k]/n[k], f[k]+0, n[k] }' | sort
    printf '\n== Failure lines ==\n'
    grep -h -E -- '--- FAIL|FAIL:|panic:|DATA RACE|Failed|timed out' "$out"/*.log | sort | uniq -c | sort -rn | head -40
} >>"$out/summary.txt"
log ""
log "totals: go-e2e failures $go_failures/$runs, qt-e2e failures $qt_failures/$runs"

tar -C "$root/qualification" -czf "$out.tar.gz" "$stamp"
printf '\nUpload: %s\n' "$out.tar.gz"
