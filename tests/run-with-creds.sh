#!/usr/bin/env bash
# Runs tests/downloader.bats locally with CF_ACCESS_CLIENT_ID/CF_ACCESS_CLIENT_SECRET
# injected from 1Password, the same op:// references CI uses (see .github/workflows/
# test-downloader.yml). Requires the `op` CLI signed in (or an OP_SERVICE_ACCOUNT_TOKEN
# in the environment) with read access to those secrets.
#
# USAGE: tests/run-with-creds.sh [bats args...]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export CF_ACCESS_CLIENT_ID="op://x4h33jlflygxmifnxfrizew4oa/7g2fhcv3tpsogr2vhkielewvsm/wsyxxjrdsyj36zsaanbh3kybfe"
export CF_ACCESS_CLIENT_SECRET="op://x4h33jlflygxmifnxfrizew4oa/7g2fhcv3tpsogr2vhkielewvsm/5x3sr7bry5a3ealsemvx5vcbuy"

exec op run -- "$SCRIPT_DIR/libs/bats-core/bin/bats" "$SCRIPT_DIR/downloader.bats" "$@"
