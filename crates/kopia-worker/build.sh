#!/usr/bin/env bash
set -euo pipefail

cargo build --target wasm32-unknown-unknown --release
mkdir -p build/worker

wasm-bindgen \
  --target bundler \
  --out-dir build/worker \
  --out-name index \
  ../../target/wasm32-unknown-unknown/release/kopia_worker.wasm

# Rename index_bg.wasm -> index.wasm if needed, or import whichever exists.
if [ -f build/worker/index_bg.wasm ]; then
  mv build/worker/index_bg.wasm build/worker/index.wasm
fi

cat > build/worker/shim.mjs <<'EOF'
import * as imports from "./index_bg.js";
export * from "./index_bg.js";
import wasmModule from "./index.wasm";
import { WorkerEntrypoint } from "cloudflare:workers";

const instance = new WebAssembly.Instance(wasmModule, {
  "./index_bg.js": imports,
});

imports.__wbg_set_wasm(instance.exports);
instance.exports.__wbindgen_start?.();

export { wasmModule };

class Entrypoint extends WorkerEntrypoint {
  async fetch(request) {
    return await imports.fetch(request, this.env, this.ctx);
  }
}

export default Entrypoint;
EOF
