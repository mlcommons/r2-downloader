#!/usr/bin/env bats
# CLI behavior tests for mlc-r2-downloader.sh. Runs against a local checkout by default;
# set EXEC_MODE=docker (plus PLATFORM/IMAGE_REF) to run the same tests against a built
# container image instead. See test_helper.bash for how invocation is routed.

load test_helper

setup() {
    AUTH_TEST_URL="https://auth-test.mlcommons-storage.org/metadata/dataset.uri"
    NO_AUTH_URL="https://no-auth-test.mlcommons-storage.org/metadata/dataset.uri"
    SINGLE_FILE_URL="https://no-auth-test.mlcommons-storage.org/metadata/single-file-dataset.uri"
    # 25-file datasets (over the 20-file auto-parallel threshold), used to test that
    # parallel downloads are auto-detected without needing -j/MLC_PARALLEL_JOBS.
    AUTH_BULK_URL="https://auth-test.mlcommons-storage.org/metadata/bulkset.uri"
    NO_AUTH_BULK_URL="https://no-auth-test.mlcommons-storage.org/metadata/bulkset.uri"
}

@test "help flag works without a URL" {
    downloader_run -h
    [ "$status" -eq 0 ]
}

@test "debug mode with service account" {
    downloader_run -xs "$AUTH_TEST_URL"
    [ "$status" -eq 0 ]
}

@test "service account flag without URL fails" {
    downloader_run -s
    [ "$status" -eq 1 ]
}

@test "multiple flags without URL fails" {
    downloader_run -s -t
    [ "$status" -eq 1 ]
}

@test "download directory flag without directory argument fails" {
    downloader_run -d
    [ "$status" -eq 1 ]
}

@test "service account with testing mode succeeds (auth required)" {
    downloader_run -st -d test/dataset "$AUTH_TEST_URL"
    [ "$status" -eq 0 ]
}

@test "no authentication required dataset succeeds" {
    downloader_run -st -d test/dataset "$NO_AUTH_URL"
    [ "$status" -eq 0 ]
    # Below the 20-file auto-parallel threshold, so it should stay sequential by default.
    [[ "$output" == *"up to 1 parallel connection(s)"* ]]
}

@test "single-file dataset downloads to the current directory by default" {
    # cd's inside a bats @test are process-local and don't leak to other tests, so this
    # confines the file it drops in cwd to the gitignored test/ dir instead of repo root.
    mkdir -p test
    cd test
    downloader_run "$SINGLE_FILE_URL"
    [ "$status" -eq 0 ]
    # Docker mode has no volume mount, so the downloaded file only exists inside the
    # ephemeral container - can't assert on it from the host.
    if [[ "${EXEC_MODE:-local}" != "docker" ]]; then
        [ -f "blacktest.png" ]
    fi
}

@test "single-file dataset with -d downloads to the specified directory" {
    downloader_run -d test/single-file "$SINGLE_FILE_URL"
    [ "$status" -eq 0 ]
    if [[ "${EXEC_MODE:-local}" != "docker" ]]; then
        [ -f "test/single-file/blacktest.png" ]
    fi
}

@test "invalid URL format fails" {
    downloader_run -st not-a-valid-url
    [ "$status" -eq 1 ]
}

@test "service account without credentials fails" {
    downloader_run --no-creds -s "$AUTH_TEST_URL"
    [ "$status" -eq 1 ]
    [[ "$output" == *"CF_ACCESS_CLIENT_ID and/or CF_ACCESS_CLIENT_SECRET are not set"* ]]
}

@test "-j requires a positive integer" {
    downloader_run -j abc
    [ "$status" -eq 1 ]
    [[ "$output" == *"positive integer"* ]]
}

@test "MLC_PARALLEL_JOBS must be a positive integer" {
    MLC_PARALLEL_JOBS=abc downloader_run
    [ "$status" -eq 1 ]
    [[ "$output" == *"positive integer"* ]]
}

@test "-h works even when MLC_PARALLEL_JOBS is garbage" {
    MLC_PARALLEL_JOBS=abc downloader_run -h
    [ "$status" -eq 0 ]
}

@test "-j overrides a bad MLC_PARALLEL_JOBS instead of erroring first" {
    MLC_PARALLEL_JOBS=abc downloader_run -j 3 -h
    [ "$status" -eq 0 ]
}

@test "service account auth succeeds with forced parallel downloads" {
    downloader_run -st -j 2 -d test/dataset-parallel "$AUTH_TEST_URL"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Downloaded:"* ]]
}

@test "no-auth dataset at/over the file-count threshold auto-detects parallel downloads" {
    downloader_run -st -d test/dataset-bulk-noauth "$NO_AUTH_BULK_URL"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Starting download of 25 file(s) with up to 4 parallel connection(s)"* ]]
    [[ "$output" == *"Downloaded: 25/25 files"* ]]
}

@test "auth dataset at/over the file-count threshold auto-detects parallel downloads" {
    downloader_run -st -d test/dataset-bulk-auth "$AUTH_BULK_URL"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Starting download of 25 file(s) with up to 4 parallel connection(s)"* ]]
    [[ "$output" == *"Downloaded: 25/25 files"* ]]
}
