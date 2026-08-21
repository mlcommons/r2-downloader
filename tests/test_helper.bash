# Invokes the CLI under test the same way from every bats test regardless of environment.
#
# Local (default): runs mlc-r2-downloader.sh directly with bash.
# Docker (EXEC_MODE=docker): runs it inside a container via `docker run`, using PLATFORM
# and IMAGE_REF from the environment. Needed because docker's `bash -lc` takes one combined
# command string rather than discrete argv, unlike the local case.
downloader_run() {
    local creds=1
    if [[ "$1" == "--no-creds" ]]; then
        creds=0
        shift
    fi

    if [[ "${EXEC_MODE:-local}" == "docker" ]]; then
        local joined="r2-downloader"
        local a
        for a in "$@"; do
            joined+=" $(printf '%q' "$a")"
        done
        local docker_args=(--rm --pull always --platform "$PLATFORM")
        if [[ "$creds" == 1 ]]; then
            docker_args+=(-e CF_ACCESS_CLIENT_ID -e CF_ACCESS_CLIENT_SECRET)
        fi
        run docker run "${docker_args[@]}" "$IMAGE_REF" bash -lc "$joined"
    else
        if [[ "$creds" == 1 ]]; then
            run bash "$BATS_TEST_DIRNAME/../mlc-r2-downloader.sh" "$@"
        else
            run env -u CF_ACCESS_CLIENT_ID -u CF_ACCESS_CLIENT_SECRET \
                bash "$BATS_TEST_DIRNAME/../mlc-r2-downloader.sh" "$@"
        fi
    fi
}
