# CrocodileJump 架构设计文档

## 1. 定位与核心边界

**CrocodileJump** 是一个基于 Cloudflare Workers 的**无状态、无鉴权、纯只读基础设施层存储网关**，用于将远端 WebDAV 上的官方 Kopia 加密去重仓库，暴露为支持标准 HTTP `Range` 与边缘长效缓存的只读 HTTP 接口。

* **定位**：纯粹的基础设施层（Storage / Read Gateway）。
  * **不做**用户鉴权、静态站路由重写（如 `index.html` 自动补全）或网盘 UI，这些高级逻辑由上层应用 Worker 通过 **Cloudflare Service Bindings** 调用本服务来实现。
  * **不做**超出 Cloudflare Worker 内存（128MB）与单请求子请求配额（Paid 版 1,000 次）的文件支持。
* **写入端**：官方 Kopia（CLI / KopiaUI），直接写入欧洲机房的 WebDAV 服务端。
* **读取端**：纯 Rust 编译为 `wasm32-unknown-unknown` 运行在 Cloudflare Workers（Paid Plan）上。
* **密钥与安全**：解密所需密钥（Master Key 或 Repository Secret）**仅通过 Cloudflare Worker 环境变量 / Secret 注入**，不接受请求动态传密，避免冷启动时在 Wasm 中重复执行高开销的 `scrypt` KDF。

---

## 2. 仓库算法锁定（写入端约束）

为保证读取端 100% 纯 Rust（零 C FFI 绑定）且体积可控，Kopia 仓库初始化时锁定以下标准算法组合：

| 模块 | Kopia 锁定参数 | Rust 读取端 Crate（纯 Rust） |
| --- | --- | --- |
| **对称加密与认证** | `AES256-GCM-HMAC-SHA256`（或 `CHACHA20-POLY1305-HMAC-SHA256`） | `aes-gcm` / `chacha20poly1305`, `hmac`, `sha2`, `hkdf` |
| **数据压缩** | `zstd` / `gzip`（Manifest 内部封装） | `ruzstd`（纯 Rust 解压）、`flate2`（`rust_backend`） |
| **分块策略** | `DYNAMIC-4M-BUZHASH`（或 `1M`） | 无需分块计算，按索引与对象片段表顺序拼接 |
| **序列化与传输** | JSON + 二进制索引 + WebDAV XML | `serde`, `serde_json`, `quick-xml` |

---

## 3. HTTP API 契约与 Cloudflare 长效缓存设计

为最大化利用 Cloudflare 边缘 CDN 与 Worker `caches.default`（二者默认均以完整 URL 作为 Cache Key，忽略自定义请求头），**快照版本标识必须置于 URL 路径中**：

### 3.1 接口列表

| 方法与路径 | 用途 | 缓存策略 | 说明 |
| --- | --- | --- | --- |
| `GET /_snapshots` | 列出可用快照列表（JSON） | `Cache-Control: public, max-age=30` | 供上层 Worker 发现最新 `snapshot-id` 或历史版本列表 |
| `GET /s/<snapshot-id>/<path>` | 读取指定快照下的文件内容 | `Cache-Control: public, max-age=31536000, immutable` + `ETag: "<object-id>"` | **绝对主流流量**。支持 `Range: bytes=...`（返回 `206 Partial Content`、`Content-Range`、`Accept-Ranges: bytes`） |
| `HEAD /s/<snapshot-id>/<path>` | 获取文件元信息 | 同上 | 仅解析 `DirectoryEntry` 即可返回 `Content-Length` 与 `ETag`，**零 Pack 回源** |
| `GET /s/<snapshot-id>/<dir>/` | 列出指定快照下的目录条目（JSON） | `Cache-Control: public, max-age=31536000, immutable` | 返回文件名、类型、精确字节大小、修改时间、`object-id` |
| `GET /latest/<path>` | 便利接口：读取最新快照下的文件 | `Cache-Control: public, max-age=60` | 方便调试或简单场景使用；生产推荐上层先查 `/_snapshots` 再走 `/s/<id>/...` |

### 3.2 缓存与回滚红利
* **零 Purge 原子切换与回滚**：上层应用 Worker 缓存 `/_snapshots` 约 30 秒，随后通过 Service Binding 请求 `/s/<snapshot-id>/<path>`。发布新版本或回滚历史版本时，新旧版本各自隔离在不同不可变 URL 下，无需调用 Cloudflare Cache Purge。
* **小文件整包缓存 + 边缘自动 Range 切片**：`caches.default` 仅缓存 `200 OK` 完整响应。对于小于阈值（如 `<= 20MB`）的文件，底层可将其完整明文异步写入 `caches.default`；后续即使客户端携带 `Range` 请求，边缘缓存命中后也会自动切片返回 `206`。超过阈值的大文件则直接纯流式并发拉取 Pack 片段透传，不经过 `caches.default`，防止触发 128MB 内存 OOM。

---

## 4. 工程目录结构（Cargo Workspace）

采用核心库与运行时彻底解耦的 Workspace 布局：

```text
CrocodileJump/
├── Cargo.toml                  # Workspace 定义
├── docs/
│   ├── 初步的想法.txt
│   └── architecture.md         # 本文档
└── crates/
    ├── kopia-core/             # 100% 纯 Rust 核心解析库（无运行时/网络绑定）
    │                           # 抽象 async StorageReader trait（list_blobs / read_blob_range）
    ├── kopia-cli/              # 本地验证工具（读取本地测试仓库或 WebDAV，校验字节级解析与 Range）
    └── kopia-worker/           # Cloudflare Workers 入口（workers-rs + WebDAV + Cache API）
```

---

## 5. 分阶段落地路线

1. **阶段一：协议解剖与 `kopia-core` 本地验证（已完成）**
   * 使用官方 `kopia` CLI 创建 WebDAV 测试仓库（锁定 `AES256-GCM-HMAC-SHA256` + `zstd` + `DYNAMIC-4M-BUZHASH`）。
   * 在 `kopia-core` 中实现并验证：
     1. `kopia.repository` 与 Master Key / HKDF 子密钥派生；
     2. `xn*` 二进制索引分片解析、Epoch 合并与二分查找；
     3. Snapshot Manifest（`m*`，gzip + JSON）与目录树（`DirectoryEntry`）遍历；
     4. `p*` Pack 数据包按 `Offset + Length` 精准拉取、解密与 `ruzstd` 解压；
     5. 跨多 Chunk 的任意 `Range` 字节区间精确切片拼接。
   * 通过 `kopia-cli` 与原文件进行逐字节（SHA-256）一致性比对。
2. **阶段二：`kopia-worker` 接入 WebDAV 与 Cloudflare Workers（已完成基础网关并本地验证）**
   * 实现基于 `worker::Fetch` + `PROPFIND` + `GET Range` 的 `StorageReader`（复用 `kopia_core::webdav`）。
   * 接入 `caches.default`（缓存 `xn*` 索引分片、目录 JSON 及 `<= 20MB` 小文件明文 `200 OK`）。
   * 实现标准 `GET` / `HEAD` / `Range`（`206` / `416`）与 `ETag` / `immutable` 缓存头，gzip 压缩后 `.wasm` 体积约 `338KB`。
   * 后续按需增强：多 Chunk 并发滑动窗口流式输出（`TransformStream`）、URL percent-decoding。
3. **阶段三：压测与上层 Service Binding 联调**
   * 在 Cloudflare Paid Plan 环境下验证冷启动内存、CPU 时间、1000 子请求边界及大文件 Range 流式稳定性。
