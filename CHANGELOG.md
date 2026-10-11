# Changelog / 变更记录

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.0.2] - 2026-10-11

多代理深度审查（安全 / 正确性 / Rust 地道性 / 性能与依赖四域并行）后的修复版，全部为小 diff，无破坏性 API 变更。

### Fixed

- **redis 驱动默认端口错误**：`servers` 缺省值此前写死 memcached 端口 `127.0.0.1:11211`，未显式配置 `servers` 的 redis 部署会静默错连（黑名单查询全失败 → fail-closed 全站 401）。默认改为空列表，由各驱动按自身默认回落（redis → `127.0.0.1:6379`、memcached → `127.0.0.1:11211`），与 README 承诺一致
- **redis 驱动无连接/读写超时**：SYN 黑洞或半开连接会无限阻塞并持锁梗死整个驱动；现与 memcached 驱动对齐（1 秒建连与读写超时）
- **leeway 无上限校验**：`JWT_LEEWAY` 过大会在 jsonwebtoken 内部整数下溢——debug 构建请求路径 panic、release 构建全量判过期；现装配期校验上限 86400 秒并报配置错误
- **memcached 多服务器「全有或全无」**：一台服务器不可达会导致整个驱动构建失败；现为每服务器独立连接池 + 跨进程稳定的确定性哈希路由，单台宕机仅剔除该台（健康节点继续服务的降级语义），全部不可达才报 Storage
- **`RetryTokenStorage` 把 Config 错误降级为 Storage**：错误码 5 丢失、`fail_open` 类型判断被放大（Config 被当存储故障放行）；Config 错误现保持原类型返回
- **无 `exp` 令牌的 `blacklist()` 假成功**：四个驱动都会拒写 ttl ≤ 0 的条目却返回 `Ok(true)`；现显式返回 `Err`（登出不再谎报成功），文档同步注明无 `jti` 令牌返回 `Ok(false)`
- **TOML `path = ""` 落盘到进程 CWD**：与 env 的空值归一化对齐（视同未配置，回落默认目录）
- **file 驱动空 `jti` 生成裸 `.json` 文件名**：改为 sha256 摘要名，与 redis/memcached 键规则的空串处理对齐
- **redis / memcached 超长全 hex `jti` 无长度护栏**：超过 64 字符的全 hex `jti` 转 sha256 摘要（键长恒定；memcached 键有 250 字节协议上限）
- **`refresh()` 中不可达的 `expect`**：改为返回类型化错误，库路径不再存在 panic 点
- **retry 错误串中的 camelCase 操作名**（`isBlacklisted` → `is_blacklisted`）
- **依赖瘦身**：redis 关闭默认 feature（`default-features = false`），不再编译 acl / streams / geospatial / script / num-bigint

### Security

- **`JwtConfig` 的 `Debug` 输出泄露 `secret_key`**：改为手写 Debug 打码（`[redacted]`），与 crate「持有密钥材料不实现 Debug」的立场统一
- **HMAC 算法接受 PEM 材料**：RSA 公钥（公开信息）误配进 `secret_key` 且算法缺省 HS256 时，公钥即密钥、人人可伪造令牌；现装配期报配置错误（与 RS256 分支对传公钥的防线对称）
- **file 驱动已存在目录不校验权限**：group/other 可写的目录（他人可删除/伪造黑名单条目）现在装配期直接拒绝，并做写入探测（属主不符/只读挂载同样启动期失败）；新建目录仍为 0700
- **安全负路径回归锁**：新增篡改签名 / HS512→HS256 算法混淆 / `alg:"none"` / future-nbf / 无 exp 登出 / leeway 上限 / PEM 误配等单元测试；九个适配层补齐「已拉黑 → 401」端到端用例，axum 另增 refresh 误用与 `fail_open` 双分支端到端

### Changed

- `Validation` 装配期构建一次，`decode` 每请求不再重建（省 3 次堆分配 + 消除逐次覆盖 jsonwebtoken 默认值的隐患）
- SQLite 驱动启用 `prepare_cached` 与预拼 SQL；hex 编码改 `write!` 进预分配 String（jti 生成、sha256 摘要、文件名转写三处）
- redis / memcached 单元测试在服务不可达时由静默 skip 改为**显式失败**（避免本地「假绿」；设 `JWT_TEST_SKIP_SERVICES=1` 显式跳过；CI 本就配了 service 容器）
- 存储类型补 `Debug` 派生（file / database / retry / redis / memcached，不含密钥材料，下游可安全组合）；`Jwt`/`JwtError` 等核心类型补一节 rustdoc；公开查询与 builder 方法补 `#[must_use]`
- README（中英同步）：示例密钥改为故意通不过长度校验的占位串（`openssl rand -hex 32` 生成）；补充 axum `attach` 时序要求、`is_blacklisted` 的 fail-open 语义、file 目录位置与权限、memcached 键长上限、leeway 上限改写
- CI 新增：文档构建门禁（`RUSTDOCFLAGS=-D warnings cargo doc --all-features`）、打包校验（`cargo package`，覆盖 `include_str!` 资源进包）与 core-only + 逐个单 feature 编译矩阵

### Behavioral notes（行为语义说明，README 均已注明）

- `blacklist()` 对无 `exp` 令牌由「静默假成功」改为显式 `Err`；file 目录权限校验为新增防线
- memcached 多服务器由「任一不可达即整体失败」改为「剔除不可达者继续服务」（健康节点继续服务；被剔除服务器上的键在恢复前不可见，属降级语义）
- 超长（>64 字符）全 hex `jti` 的缓存键由原样保留改为 sha256 摘要（仅影响此类外部 jti）

## [1.0.1] - 2026-10-07

### Added

- docs.rs 元数据 `all-features = true`：文档页纳入全部框架适配模块
- 英文版 README（README.en.md）与英文版设计图（architecture / features / lifecycle 的 .en.svg）
- GitHub Actions CI：fmt / clippy / test（全 feature，含 redis 与 memcached 服务）/ MSRV 1.88 / cargo-audit
- README 徽章与「存储驱动是同步 IO」须知

### Changed

- 无（本版为文档与工程化改进，代码不变）

## [1.0.0] - 2026-10-07

### Added

- 首发：框架无关内核 + 九种接入方式（原生 Rust Guard 与 axum / actix-web / rocket / poem / salvo / warp / bee-rust / e-cat 适配，含 e-cat gRPC 拦截器）
- 四种可插拔黑名单存储（file / redis / database(SQLite) / memcached），fail_open 与 RetryTokenStorage 自动重试
- 中英双语文档图、项目宠物「钥匙小卫 Kee」、宠物图标与社交预览图
- 109 个测试（79 单元 + 29 集成 + 1 doctest）
