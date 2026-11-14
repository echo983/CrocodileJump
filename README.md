# CrocodileJump

基于 Cloudflare Workers（纯 Rust Wasm）的只读基础设施层存储网关，用于将远端 WebDAV 上的官方 [Kopia](https://kopia.io/) 加密去重仓库暴露为支持标准 HTTP `Range` 与边缘长效缓存的只读 HTTP 接口。

* 架构设计详见 [docs/architecture.md](docs/architecture.md)。

## 工程结构

* `crates/kopia-core`：100% 纯 Rust（零 C FFI）的 Kopia 只读协议解析库，支持 `kopia.repository` 解密、`IndexV2` 二进制索引解析与合并、`AES256-GCM-HMAC-SHA256`、`zstd`（`ruzstd`）与 `gzip`（`flate2` `rust_backend`）解压，以及精确字节区间 `Range` 读取。
* `crates/kopia-cli`：本地命令行验证工具（对接 WebDAV 测试与导出 `KOPIA_FORMAT_JSON`）。
* `crates/kopia-worker`：Cloudflare Workers 入口，集成 WebDAV `StorageReader` 与 `caches.default` 长效缓存。

## HTTP API

| 方法与路径 | 用途 | 缓存策略 |
| --- | --- | --- |
| `GET /_snapshots` | 列出快照列表（JSON） | `public, max-age=30` |
| `GET /s/<snapshot-id>/<dir>/` | 列出目录条目（JSON） | `public, max-age=31536000, immutable` |
| `HEAD /s/<snapshot-id>/<path>` | 获取文件长度与 `ETag`（零 Pack 回源） | `public, max-age=31536000, immutable` |
| `GET /s/<snapshot-id>/<path>` | 读取文件（支持 `Range` 返回 `206` / `416`） | `public, max-age=31536000, immutable` |
| `GET /latest/<path>` | 读取最新快照下的文件（便利路由） | `public, max-age=60` |

## 本地检查与构建

```bash
# 运行单元测试与本机检查
cargo test --workspace

# 交叉编译并生成 Cloudflare Workers 构建产物（需要 wasm-bindgen-cli 0.2.130）
cd crates/kopia-worker && bash ./build.sh
```

## Worker 环境变量 / Secrets

| 变量名 | 说明 |
| --- | --- |
| `WEBDAV_URL` | Kopia WebDAV 仓库根 URL |
| `WEBDAV_USERNAME` | WebDAV 用户名 |
| `WEBDAV_PASSWORD` | WebDAV 密码（Secret） |
| `KOPIA_FORMAT_JSON` | 解密后的仓库格式配置 JSON（Secret，推荐注入以避免 Wasm 冷启动执行 `scrypt`） |
| `KOPIA_PASSWORD` | 仓库密码（可选兜底，未配置 `KOPIA_FORMAT_JSON` 时使用） |
