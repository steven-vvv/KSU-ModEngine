#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ -x .tools/rust/bin/cargo ]]; then
    export PATH="$PWD/.tools/rust/bin:$PATH"
fi
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --locked
python3 tests/e2e.py
pnpm --dir webui install --frozen-lockfile
pnpm --dir webui run test
pnpm --dir webui run build
