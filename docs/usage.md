# CrocodileJump 使用与部署指南

本文档涵盖从 **Kopia 仓库初始化**、**本地校验**、**Cloudflare Workers 部署** 到 **上层应用 Worker 通过 Service Binding 集成** 的完整流程。

---

## 1. 初始化 Kopia 仓库（写入端）

使用官方 `kopia` CLI 在远端 WebDAV 上创建仓库时，需锁定以下算法组合以兼容纯 Rust 读取端：

```bash
export KOPIA_PASSWORD="your-strong-repo-password"
export KOPIA_WEBDAV_USERNAME="your-webdav-user"
export KOPIA_WEBDAV_PASSWORD="your-webdav-password"

kopia repository create webdav \
  --url="https://your-webdav-host/dav/my-repo/" \
  --encryption=AES256-GCM-HMAC-SHA256 \
  --block-hash=HMAC-SHA256 \
  --object-splitter=DYNAMIC-4M-BUZHASH

# 启用 zstd 压缩
kopia policy set --global --compression=zstd

# 推送首个快照
kopia snapshot create /path/to/your/data
```

> **提示**：请使用默认的 `[1, 3]` 目录分片结构（即不要传入 `--flat`），与当前 `kopia-core` 的 WebDAV 路径映射保持一致。

---

## 2. 导出 `KOPIA_FORMAT_JSON`（零 KDF 冷启动）

为避免 Cloudflare Worker 每次冷启动都在单线程 Wasm 中执行 `scrypt-65536-8-1`，推荐在本地预先解密 `kopia.repository.f` 并导出 `KOPIA_FORMAT_JSON`：

```bash
cargo run -q -p kopia-cli -- --export-format
```

输出为单行 JSON（包含 `masterKey`、`secret`、`hash`、`encryption`、`indexVersion` 等），将其妥善保存并作为 Worker Secret 注入。

---

## 3. 构建与本地测试

### 3.1 环境依赖
* Rust 工具链（含 `wasm32-unknown-unknown` target）：
  ```bash
  rustup target add wasm32-unknown-unknown
  ```
* `wasm-bindgen-cli`（需与 `Cargo.lock` 中的 `wasm-bindgen` 版本对齐，当前为 `0.2.130`）：
  ```bash
  cargo install wasm-bindgen-cli --version 0.2.130 --locked
  ```
* Node.js / Wrangler（可通过 `npx wrangler` 调用）。

### 3.2 运行单元测试与构建 Wasm
```bash
# 运行工作区单元测试
cargo test --workspace

# 编译并生成 Cloudflare Workers 构建产物（输出至 crates/kopia-worker/build/worker/）
cd crates/kopia-worker && bash ./build.sh
```

### 3.3 本地 `wrangler dev` 联调
在 `crates/kopia-worker/.dev.vars` 中写入本地环境变量（该文件已在 `.gitignore` 中忽略）：
```dotenv
WEBDAV_URL=https://your-webdav-host/dav/my-repo
WEBDAV_USERNAME=your-webdav-user
WEBDAV_PASSWORD=your-webdav-password
KOPIA_FORMAT_JSON={"hash":"HMAC-SHA256","encryption":"AES256-GCM-HMAC-SHA256",...}
```

启动本地开发服务器：
```bash
cd crates/kopia-worker && npx wrangler dev --port 8787
```

---

## 4. 部署到 Cloudflare Workers

```bash
cd crates/kopia-worker

# 1. 部署 Worker 代码
npx wrangler deploy

# 2. 注入生产 Secrets（按提示粘贴对应值）
npx wrangler secret put WEBDAV_URL
npx wrangler secret put WEBDAV_USERNAME
npx wrangler secret put WEBDAV_PASSWORD
npx wrangler secret put KOPIA_FORMAT_JSON
```

> **生产安全建议**：由于本 Worker 定位为**无鉴权基础设施层**，当仅由上层应用 Worker 通过 Service Binding 调用时，请在 `crates/kopia-worker/wrangler.toml` 中取消注释 `workers_dev = false` 并重新部署，关闭 `*.workers.dev` 公网入口。

---

## 5. HTTP 接口调用说明

* **列出快照**
  ```http
  GET /_snapshots
  ```
  返回按 `startTime` 降序排列的快照 JSON 数组（`Cache-Control: public, max-age=30`）。

* **列出目录条目**
  ```http
  GET /s/<snapshot-id>/<dir>/
  ```
  返回目录条目 JSON 数组（含 `name`、`type`、`size`、`mtime`、`obj`），带 `immutable` 长效缓存。

* **获取文件元信息（零 Pack 回源）**
  ```http
  HEAD /s/<snapshot-id>/<path>
  ```
  返回 `200 OK`、`Content-Length`、`ETag: "<object-id>"`、`Accept-Ranges: bytes` 与 `immutable` 缓存头。

* **读取文件与分段 `Range`**
  ```http
  GET /s/<snapshot-id>/<path>
  Range: bytes=0-1048575
  ```
  * 文件路径支持 UTF-8 percent-encoding（如中文、空格文件名）。
  * 带合法 `Range` 返回 `206 Partial Content` 与 `Content-Range`；越界返回 `416 Range Not Satisfiable`。
  * 小于等于 `20MB` 的不可变文件全量 `200 OK` 响应会自动写入 `caches.default`，后续边缘命中可直接跳过回源与解密。
  * 大于 `20MB` 或带 `Range` 的请求通过 4 路滑动窗口并发拉取并流式返回，避免内存溢出。

* **便利最新快照路由**
  ```http
  GET /latest/<path>
  ```
  自动解析最新快照并读取对应路径（`Cache-Control: public, max-age=60`）。

---

## 6. 上层应用 Worker 集成示例（Service Binding）

在上层应用 Worker（例如静态网站托管或带鉴权的私有网盘）的 `wrangler.toml` 中绑定本基础设施 Worker：

```toml
[[services]]
binding = "KOPIA_GATEWAY"
service = "crocodile-jump-kopia"
```

在上层 Worker 中利用 `/_snapshots` + `/s/<snapshot-id>/...` 实现**零 Cache Purge 的原子发布与秒级回滚**：

```ts
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // 1. 鉴权 / 路由重写（如自动补全 index.html、MIME 映射等）
    const url = new URL(request.url);
    const relPath = url.pathname === "/" ? "index.html" : url.pathname.slice(1);

    // 2. 获取最新快照 ID（Gateway 内部已在边缘缓存 30s）
    const snapResp = await env.KOPIA_GATEWAY.fetch("https://internal/_snapshots");
    const snapshots = await snapResp.json<Array<{ id: string }>>();
    const latestId = snapshots[0]?.id;
    if (!latestId) return new Response("No snapshots", { status: 404 });

    // 3. 转发至不可变路径，充分利用长效缓存与 Range 透传
    const targetUrl = `https://internal/s/${latestId}/${relPath}`;
    return env.KOPIA_GATEWAY.fetch(new Request(targetUrl, request));
  },
};
```
