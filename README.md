drizzleDumper (Rust rewrite)
============================

简介
----

`drizzleDumper` 现已使用 Rust 重写，修复了旧版 C 实现中在现代 Android (ART/64bit) 上的崩溃问题，并提供安全的内存扫描与 DEX dump 能力。项目可直接交叉编译至 `aarch64-linux-android`，方便在实体机上测试。

Usage
-----

```
drizzle_dumper --mcp-server [bind_addr]
drizzle_dumper <package_name> [wait_seconds] [options]
```

* 需要 root 权限（远程调用除外，远程调用由服务器侧负责权限）。
* 默认轮询间隔为 0 秒，可通过 `wait_seconds` 指定轮询周期。
* dump 成功后文件保存在 `/data/local/tmp/<package>_dumped_<addr>.dex`。
* `--mcp-server` 启动符合 Streamable HTTP 规范的 MCP 服务器。远程调用可通过 MCP 会话调用工具，或直接 `POST /mcp/tools/dump` 传入 JSON（至少包含 `package`）。服务器同时提供 `dump_dex_ptrace`（强制 ptrace）与 `dump_dex_frida`（强制 FRIDA）两个独立工具，还额外提供 `prepare_frida_gadget` / `inject_frida_gadget` / `cleanup_frida_gadget` 三个工具，便于按需部署与回收 Gadget。
* 支持两种导出后端：默认 `ptrace` 扫描模式，以及 `--mode frida`（或 `--frida`）启用的 FRIDA Hook 模式。FRIDA 模式可搭配 `--frida-remote <host:port>`、`--frida-usb`、`--frida-attach`、`--frida-script <path>`、`--frida-chunk <bytes>` 等参数细化行为。
* 若无 `frida-server` 环境，可使用 `--frida-gadget` 让 drizzleDumper 自动写入/注入 FRIDA Gadget（可自定义 `--frida-gadget-port`、`--frida-gadget-path`、`--frida-gadget-config` 等）。
  * 当前 Gadget 模式默认以 attach 方式工作，请先启动目标应用或配合 `--frida-attach` 使用。

FRIDA Hook Mode
---------------

FRIDA 模式通过 Hook `libart.so` 中的 `DexFile::OpenCommon` / `DexFile::OpenMemory` / `DexFile::DexFile` 等入口，实时截获 ART 装载的明文 DEX 并以块形式回传至宿主，由 Rust 侧完成去重、清单记录与可选的 header 修复。

* 编译时需启用 `frida` feature：`cargo build --release --features frida`（交叉编译亦同）。默认仍会构建 ptrace 版本，未启用该 feature 时程序会提示“FRIDA 未启用”。若需将 gadget 一并打包，可额外开启 `frida-gadget-bundle` 并在 `assets/frida/arm64/` 放置 `frida-gadget.so`（GitHub Workflow 的手动触发会默认下载稳定版 `16.3.6`，也可自定义版本）。
* 运行期需确保本机或远端已有 `frida-server`（通常以 root 权限运行）。`--frida-remote 127.0.0.1:27042` 可连接远端，`--frida-usb` 可优先选择 USB 设备。
* 默认使用 `spawn` 冷启动目标；若需 attach 到已运行的进程使用 `--frida-attach`。如需在 dump 结束前保持暂停，可搭配 `--frida-no-resume`。
* 注入脚本可自定义（`--frida-script <path>`），否则使用内置脚本，按需分块（`--frida-chunk`，默认 16 MiB）发送二进制数据，Rust 端会自动合并、去重、保存并更新 `dump_manifest.csv`。
* 所有 FRIDA 相关 MCP 参数与 CLI 参数保持一致，HTTP 请求体内可新增 `"mode": "frida"`、`"frida_remote"` 等字段直接切换后端。

Build
-----

本地交叉编译（示例使用 Android NDK r26 和 API 24）：

```
rustup target add aarch64-linux-android
export ANDROID_NDK_HOME=/path/to/android-ndk-r26d
export ANDROID_API_LEVEL=24
export TOOLCHAIN_DIR="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
export CC_aarch64_linux_android="$TOOLCHAIN_DIR/aarch64-linux-android${ANDROID_API_LEVEL}-clang"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"
cargo build --release --target aarch64-linux-android

# 启用 FRIDA hook（若需要）
cargo build --release --target aarch64-linux-android --features frida
```

GitHub Actions
--------------

仓库包含 `.github/workflows/android-arm64.yml`，可在 push/PR 时自动生成 `aarch64-linux-android` 版本，并作为构建产物上传。

License
-------

Licensed under the Apache License, Version 2.0. 原始项目版权归 DrizzleRisk；Rust 重写保留该许可。
