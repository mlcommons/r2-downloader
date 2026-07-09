#!/bin/bash
# Test harness for the parallel-download behavior in mlc-r2-downloader.sh.
#
# Tiers (each implies the ones before it):
#   (default)          Offline unit tests for the dynamic -j default formula and flag
#                       validation. No network access, runs in well under a second.
#   --network           + debug-mode (-x) smoke tests against real datasets. Hits the
#                       network but never downloads actual dataset files.
#   --download           + a real parallel download + checksum verification of
#                       frames-benchmark-dataset (small, ~7 files).
#   --download-medium     + the same for YOLO-COCO2017-dataset (~1527 files, ~390MB).
#   --download-large       + the same for llama3-1-8b-instruct_calibrated-xpu
#                       (10 files, ~5.8GB). Slow; only run this deliberately.
#   --all               Shorthand for --download-large.
#
# Downloaded files go to a temp directory removed on exit unless --keep is passed.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
DOWNLOADER="$REPO_ROOT/mlc-r2-downloader.sh"

FRAMES_URL="https://inference.mlcommons-storage.org/metadata/frames-benchmark-dataset.uri"
YOLO_URL="https://inference.mlcommons-storage.org/metadata/YOLO-COCO2017-dataset.uri"
LLAMA_URL="https://inference.mlcommons-storage.org/metadata/llama3-1-8b-instruct_calibrated-xpu.uri"

RUN_NETWORK=0
RUN_DOWNLOAD=0
RUN_DOWNLOAD_MEDIUM=0
RUN_DOWNLOAD_LARGE=0
KEEP_ARTIFACTS=0

for arg in "$@"; do
    case "$arg" in
        --network) RUN_NETWORK=1 ;;
        --download) RUN_NETWORK=1; RUN_DOWNLOAD=1 ;;
        --download-medium) RUN_NETWORK=1; RUN_DOWNLOAD=1; RUN_DOWNLOAD_MEDIUM=1 ;;
        --download-large|--all) RUN_NETWORK=1; RUN_DOWNLOAD=1; RUN_DOWNLOAD_MEDIUM=1; RUN_DOWNLOAD_LARGE=1 ;;
        --keep) KEEP_ARTIFACTS=1 ;;
        -h|--help)
            sed -n '2,20p' "$0"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            exit 1
            ;;
    esac
done

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  ok   - $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL - $1"; }

WORK_DIR="$(mktemp -d)"
cleanup() {
    if [[ "$KEEP_ARTIFACTS" == 1 ]]; then
        echo "Artifacts kept at: $WORK_DIR"
    else
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup EXIT

# ============================================================
# Tier 0: offline unit tests (always run)
# ============================================================

echo "== Unit: dynamic default job count (1 below SMALL_DATASET_FILE_THRESHOLD, else"
echo "   DEFAULT_MAX_PARALLEL_JOBS; never more jobs than files) =="

DEFAULT_MAX_PARALLEL_JOBS="$(grep -m1 '^DEFAULT_MAX_PARALLEL_JOBS=' "$DOWNLOADER" | cut -d= -f2)"
if [[ -z "$DEFAULT_MAX_PARALLEL_JOBS" ]]; then
    fail "could not read DEFAULT_MAX_PARALLEL_JOBS from $DOWNLOADER"
    DEFAULT_MAX_PARALLEL_JOBS=4
else
    pass "DEFAULT_MAX_PARALLEL_JOBS=$DEFAULT_MAX_PARALLEL_JOBS"
fi

SMALL_DATASET_FILE_THRESHOLD="$(grep -m1 '^SMALL_DATASET_FILE_THRESHOLD=' "$DOWNLOADER" | cut -d= -f2)"
if [[ -z "$SMALL_DATASET_FILE_THRESHOLD" ]]; then
    fail "could not read SMALL_DATASET_FILE_THRESHOLD from $DOWNLOADER"
    SMALL_DATASET_FILE_THRESHOLD=20
else
    pass "SMALL_DATASET_FILE_THRESHOLD=$SMALL_DATASET_FILE_THRESHOLD"
fi

# Mirrors the default-selection + never-more-jobs-than-files logic in mlc-r2-downloader.sh.
# $2 (explicit), if non-empty, simulates a user-supplied -j/MLC_PARALLEL_JOBS value.
compute_jobs() {
    local total_files=$1 explicit=$2 jobs
    if [[ -n "$explicit" ]]; then
        jobs=$explicit
    elif (( total_files < SMALL_DATASET_FILE_THRESHOLD )); then
        jobs=1
    else
        jobs=$DEFAULT_MAX_PARALLEL_JOBS
    fi
    if (( total_files > 0 && jobs > total_files )); then
        jobs=$total_files
    fi
    echo "$jobs"
}

echo "-- default (no explicit -j) --"
for case in "0::1" "1::1" "2::1" "3::1" "10::1" "19::1" "20::4" "21::4" "100::4" "1527::4"; do
    IFS=':' read -r total_files explicit expected <<< "$case"
    got="$(compute_jobs "$total_files" "$explicit")"
    if [[ "$got" == "$expected" ]]; then
        pass "total_files=$total_files -> $got job(s)"
    else
        fail "total_files=$total_files -> expected $expected job(s), got $got"
    fi
done

echo "-- explicit -j capped at file count --"
for case in "3:50:3" "1:10:1" "20:2:2"; do
    IFS=':' read -r total_files explicit expected <<< "$case"
    got="$(compute_jobs "$total_files" "$explicit")"
    if [[ "$got" == "$expected" ]]; then
        pass "total_files=$total_files, -j $explicit -> $got job(s)"
    else
        fail "total_files=$total_files, -j $explicit -> expected $expected job(s), got $got"
    fi
done

echo "== Unit: -j / MLC_PARALLEL_JOBS validation (rejected before any network use) =="

for bad in "abc" "0" "-1" "1.5" ""; do
    if [[ -z "$bad" ]]; then
        continue # -j with no argument is a getopts-level error, tested separately below
    fi
    out="$(bash "$DOWNLOADER" -j "$bad" some-placeholder-url 2>&1)"; rc=$?
    if [[ $rc -ne 0 && "$out" == *"positive integer"* ]]; then
        pass "-j '$bad' rejected"
    else
        fail "-j '$bad' should be rejected with a positive-integer error (rc=$rc, out=$out)"
    fi

    out="$(MLC_PARALLEL_JOBS="$bad" bash "$DOWNLOADER" some-placeholder-url 2>&1)"; rc=$?
    if [[ $rc -ne 0 && "$out" == *"positive integer"* ]]; then
        pass "MLC_PARALLEL_JOBS='$bad' rejected"
    else
        fail "MLC_PARALLEL_JOBS='$bad' should be rejected with a positive-integer error (rc=$rc, out=$out)"
    fi
done

# A well-formed -j value must not be rejected by option parsing, even though the bogus
# placeholder URL will fail later on. Keeping this offline (no real dataset URL) means it
# doesn't depend on network availability; the real dataset case is covered under --network.
out="$(bash "$DOWNLOADER" -j 3 -x some-placeholder-url 2>&1 </dev/null)"; rc=$?
if [[ "$out" != *"positive integer"* ]]; then
    pass "-j 3 accepted by option parsing"
else
    fail "-j 3 should not be rejected (out=$out)"
fi

echo
echo "Unit tests: $PASS passed, $FAIL failed"

if [[ "$RUN_NETWORK" != 1 ]]; then
    echo
    echo "Skipping network/download tiers (pass --network, --download, --download-medium,"
    echo "--download-large, or --all to run them)."
    [[ "$FAIL" == 0 ]] && exit 0 || exit 1
fi

# ============================================================
# Tier 1: debug-mode smoke tests against real datasets (network, no download)
# ============================================================

echo
echo "== Network: debug-mode (-x) smoke tests against real datasets =="

# Sets DEBUG_FILE_COUNT as a side effect (avoiding a `cmd | tail` pipeline, which would run
# this function in a subshell and lose its pass/fail counter updates).
check_debug() {
    local name="$1" url="$2"
    local out rc file_count
    out="$(cd "$WORK_DIR" && bash "$DOWNLOADER" -x "$url" 2>&1)"
    rc=$?
    file_count="$(echo "$out" | grep -m1 '^file_count:' | awk '{print $2}')"
    DEBUG_FILE_COUNT=""

    if [[ $rc -ne 0 ]]; then
        fail "$name: debug mode exited $rc (out=$out)"
        return
    fi
    if [[ -z "$file_count" || "$file_count" -le 0 ]]; then
        fail "$name: could not parse a positive file_count (out=$out)"
        return
    fi
    pass "$name: file_count=$file_count"
    DEBUG_FILE_COUNT="$file_count"
}

check_debug "frames-benchmark-dataset" "$FRAMES_URL"; frames_file_count="$DEBUG_FILE_COUNT"
check_debug "YOLO-COCO2017-dataset" "$YOLO_URL"; yolo_file_count="$DEBUG_FILE_COUNT"
check_debug "llama3-1-8b-instruct_calibrated-xpu" "$LLAMA_URL"; llama_file_count="$DEBUG_FILE_COUNT"

out="$(cd "$WORK_DIR" && bash "$DOWNLOADER" -x -j 2 "$FRAMES_URL" 2>&1)"
if echo "$out" | grep -q '^PARALLEL_JOBS: 2$'; then
    pass "explicit -j 2 reflected in debug output"
else
    fail "explicit -j 2 not reflected in debug output (out=$out)"
fi

if [[ "$RUN_DOWNLOAD" != 1 ]]; then
    echo
    echo "Skipping real downloads (pass --download, --download-medium, --download-large,"
    echo "or --all to run them)."
    [[ "$FAIL" == 0 ]] && exit 0 || exit 1
fi

# ============================================================
# Tier 2+: real parallel downloads + checksum verification
# ============================================================

# Sets LAST_DURATION_S (seconds, as a side effect) on success so callers can compare timings.
run_download_test() {
    local name="$1" url="$2" expected_file_count="$3"
    shift 3
    local extra_args=("$@")
    local dir="$WORK_DIR/$name"
    mkdir -p "$dir"
    LAST_DURATION_S=""

    echo
    echo "== Download: $name (expected $expected_file_count files) =="
    local start end out rc
    start=$(date +%s)
    out="$(cd "$dir" && bash "$DOWNLOADER" -d "$dir" "${extra_args[@]}" "$url" 2>&1)"
    rc=$?
    end=$(date +%s)

    if [[ $rc -ne 0 ]]; then
        fail "$name: download exited $rc (last 20 lines below)"
        echo "$out" | tail -20
        return 1
    fi

    if ! echo "$out" | grep -q "Checksum verification completed successfully!"; then
        fail "$name: checksum verification message not found"
        echo "$out" | tail -20
        return 1
    fi

    local actual_file_count
    actual_file_count=$(find "$dir" -type f ! -name '*.md5' | wc -l | tr -d ' ')
    if [[ "$actual_file_count" != "$expected_file_count" ]]; then
        fail "$name: expected $expected_file_count downloaded files, found $actual_file_count"
        return 1
    fi

    LAST_DURATION_S=$((end - start))
    pass "$name: downloaded $actual_file_count file(s), checksums verified, ${LAST_DURATION_S}s"
}

if [[ -n "$frames_file_count" ]]; then
    run_download_test "frames-default-jobs" "$FRAMES_URL" "$frames_file_count"
    run_download_test "frames-serial" "$FRAMES_URL" "$frames_file_count" -j 1

    # Parallel and serial downloads of the same dataset must produce byte-identical output.
    if [[ -d "$WORK_DIR/frames-default-jobs" && -d "$WORK_DIR/frames-serial" ]]; then
        if diff -rq --exclude='*.md5' "$WORK_DIR/frames-default-jobs" "$WORK_DIR/frames-serial" >/dev/null; then
            pass "frames: parallel and serial downloads are byte-identical"
        else
            fail "frames: parallel and serial downloads differ"
        fi
    fi
else
    fail "frames-benchmark-dataset: skipped download test, file_count unknown from debug tier"
fi

if [[ "$RUN_DOWNLOAD_MEDIUM" == 1 && -n "$yolo_file_count" ]]; then
    run_download_test "yolo-coco2017" "$YOLO_URL" "$yolo_file_count"
    yolo_default_duration="$LAST_DURATION_S"

    run_download_test "yolo-coco2017-j16" "$YOLO_URL" "$yolo_file_count" -j 16
    yolo_j16_duration="$LAST_DURATION_S"

    if [[ -n "$yolo_default_duration" && -n "$yolo_j16_duration" ]]; then
        if (( yolo_j16_duration < yolo_default_duration )); then
            pass "yolo: -j 16 (${yolo_j16_duration}s) faster than default -j4 (${yolo_default_duration}s)"
        else
            fail "yolo: -j 16 (${yolo_j16_duration}s) not faster than default -j4 (${yolo_default_duration}s)"
        fi
    fi
fi

if [[ "$RUN_DOWNLOAD_LARGE" == 1 && -n "$llama_file_count" ]]; then
    echo
    echo "NOTE: llama3-1-8b-instruct_calibrated-xpu is ~5.8GB; this will take a while."
    run_download_test "llama3-1-8b" "$LLAMA_URL" "$llama_file_count"
fi

echo
echo "Total: $PASS passed, $FAIL failed"
[[ "$FAIL" == 0 ]] && exit 0 || exit 1
