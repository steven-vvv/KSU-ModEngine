#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ -x .tools/rust/bin/cargo ]]; then
    export PATH="$PWD/.tools/rust/bin:$PATH"
fi
if [[ $(uname -s) != Linux ]]; then
    printf '%s\n' 'This package target requires Linux.' >&2
    exit 1
fi
cargo build --workspace --release --locked
pnpm --dir webui install --frozen-lockfile
pnpm --dir webui run build
python3 scripts/package-preview.py
