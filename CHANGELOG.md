# Changelog / 变更记录

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与 [语义化版本](https://semver.org/lang/zh-CN/)。

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
