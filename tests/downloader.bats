#!/usr/bin/env bats
# CLI behavior tests for mlc-r2-downloader.sh. Runs against a local checkout by default;
# set EXEC_MODE=docker (plus PLATFORM/IMAGE_REF) to run the same tests against a built
# container image instead. See test_helper.bash for how invocation is routed.

load test_helper

setup() {
    AUTH_TEST_URL="https://auth-test.mlcommons-storage.org/metadata/dataset.uri"
    NO_AUTH_URL="https://no-auth-test.mlcommons-storage.org/metadata/dataset.uri"
    SINGLE_FILE_URL="https://no-auth-test.mlcommons-storage.org/metadata/single-file-dataset.uri"
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
}

@test "single-file dataset download succeeds" {
    downloader_run "$SINGLE_FILE_URL"
    [ "$status" -eq 0 ]
}

@test "invalid URL format fails" {
    downloader_run -st not-a-valid-url
    [ "$status" -eq 1 ]
}

@test "service account without credentials fails" {
    downloader_run --no-creds -s "$AUTH_TEST_URL"
    [ "$status" -eq 1 ]
}
