drizzleDumper (Rust rewrite)
============================

简介
----

`drizzleDumper` 现已使用 Rust 重写，修复了旧版 C 实现中在现代 Android (ART/64bit) 上的崩溃问题，并提供安全的内存扫描与 DEX dump 能力。项目可直接交叉编译至 `aarch64-linux-android`，方便在实体机上测试。

Usage
-----

```
drizzle_dumper dump <package_name> [wait_seconds] [options]
drizzle_dumper mcp-server [bind_addr]
```

* 子命令结构类似 Go 的 Cobra：`dump` 负责本地 dump，`mcp-server` 负责启动远程服务。`drizzle_dumper --help` 或任意子命令的 `--help` 会自动生成完整参数表。
* dump 需要 root 权限（远程调用除外，远程调用由服务器侧负责权限）。
* 默认轮询间隔为 0 秒，可通过 `wait_seconds` 指定轮询周期。
* dump 成功后文件保存在 `/data/local/tmp/<package>_dumped_<addr>.dex`。
* `mcp-server [bind_addr]` 启动符合 Streamable HTTP 规范的 MCP 服务器。远程调用可通过 MCP 会话调用工具，或直接 `POST /mcp/tools/dump` 传入 JSON（至少包含 `package`）。服务器同时提供 `dump_dex_ptrace`（强制 ptrace）与 `dump_dex_frida`（强制 FRIDA）两个独立工具，还额外提供 `prepare_frida_gadget` / `inject_frida_gadget` / `cleanup_frida_gadget` 三个工具，便于按需部署与回收 Gadget。
* 支持两种导出后端：默认 `ptrace` 扫描模式，以及 `--mode frida`（或 `--frida`）启用的 FRIDA Hook 模式。FRIDA 模式可搭配 `--frida-remote <host:port>`、`--frida-usb`、`--frida-attach`、`--frida-script <path>`、`--frida-chunk <bytes>` 等参数细化行为。
* 若无 `frida-server` 环境，可使用 `--frida-gadget` 让 drizzleDumper 自动写入/注入 FRIDA Gadget（可自定义 `--frida-gadget-port`、`--frida-gadget-path`、`--frida-gadget-config` 等）。
  * 当前 Gadget 模式默认以 attach 方式工作，请先启动目标应用或配合 `--frida-spawn` 使用；`--frida-gadget-timeout` 与 `--frida-quiet-ms` 可控制 gadget 超时与静默退出。
* 当需要“开机即注入”时，可安装本仓库提供的 Zygisk 模块并在 CLI/MCP 中启用 `--zygisk`。此模式会跳过 ptrace 注入，直接连接到模块在 zygote 阶段加载的 Gadget。

FRIDA Hook Mode
---------------

FRIDA 模式通过 Hook `libart.so` 中的 `DexFile::OpenCommon` / `DexFile::OpenMemory` / `DexFile::DexFile` 等入口，实时截获 ART 装载的明文 DEX 并以块形式回传至宿主，由 Rust 侧完成去重、清单记录与可选的 header 修复。

* 编译时需启用 `frida` feature：`cargo build --release --features frida`（交叉编译亦同）。默认仍会构建 ptrace 版本，未启用该 feature 时程序会提示“FRIDA 未启用”。若需将 gadget 一并打包，可额外开启 `frida-gadget-bundle` 并在 `assets/frida/arm64/` 放置 `frida-gadget.so`（GitHub Workflow 的手动触发现默认下载稳定版 `16.1.4`，也可自定义版本）。当启用 `frida` feature 时，依赖的 `frida` crate 当前锁定在 crates.io 的 `0.17.x` 发行版。
* 运行期需确保本机或远端已有 `frida-server`（通常以 root 权限运行）。`--frida-remote 127.0.0.1:27042` 可连接远端，`--frida-usb` 可优先选择 USB 设备。
* 默认使用 `spawn` 冷启动目标；若需 attach 到已运行的进程使用 `--frida-attach`。如需在 dump 结束前保持暂停，可搭配 `--frida-no-resume`。
* 启用 `--zygisk` 时，drizzle-dumper 会等待系统级 Gadget 监听端口就绪（默认 127.0.0.1:27042，可通过 `--frida-gadget-port` 调整），并避免重复注入。
* 注入脚本可自定义（`--frida-script <path>`），否则使用内置脚本，按需分块（`--frida-chunk`，默认 16 MiB）发送二进制数据，Rust 端会自动合并、去重、保存并更新 `dump_manifest.csv`。
* 所有 FRIDA 相关 MCP 参数与 CLI 参数保持一致，HTTP 请求体内可新增 `"mode": "frida"`、`"frida_remote"` 等字段直接切换后端。

Zygisk Module
-------------

`zygisk/` 目录包含一个参考实现，可将 Frida Gadget 持久注入到目标应用的 zygote 分支中。GitHub Actions（`.github/workflows/zygisk-module.yml`）会自动构建该模块并将 aarch64 版 `drizzle_dumper` 一并放入 `bin/` 目录，方便刷入后直接使用。手动构建时可按以下步骤操作：

1. 按 `zygisk/README.md` 编译生成 `libdrizzlezygisk.so` 并打包为 Magisk 模块。
2. 修改 `zygisk/config/targets.json` 定义需要注入的包名以及 Gadget/配置文件位置。
3. 通过 Magisk 安装模块并重启，确保模块在 `logcat` 中记录 Gadget 加载信息。
4. 运行 drizzle-dumper 时附加 `--zygisk`（或在 MCP 请求体增加 `"zygisk": true`），让工具仅连接 gadget 而不再 ptrace 注入。模块安装后，可直接使用 `/data/adb/modules/drizzle-zygisk/bin/drizzle_dumper`。

该模块默认在 `service.sh` 中同步 drizzle-dumper 生成的 `frida-gadget.so` 和配置文件，并自动启动 `drizzle_dumper mcp-server --bind <config/mcp_bind>`（默认 `0.0.0.0:45831`），便于通过 MCP 协议远程触发 dump。

### WebUI 支持

- 模块内置 `webroot/`，兼容 KernelSU/APatch 的 WebUI 规范。刷入后在模块详情页点击“打开页面”即可通过浏览器对以下内容进行管理：
  - 列出 / 搜索所有第三方应用包名并批量勾选。
  - 修改 MCP 监听地址、重启 drizzle-dumper MCP 服务。
  - 后台触发一次 `drizzle_dumper dump <pkg> --zygisk`。
- 生成的自定义名单保存在 `/data/adb/modules/drizzle-zygisk/config/package_custom.list`；MCP 监听配置存放在 `/data/adb/modules/drizzle-zygisk/config/mcp_bind`。
- Magisk 用户需额外安装 [KSU WebUI](https://magiskmodule.gitlab.io/blog/how-to-use-webui-modules-on-magisk/) 或类似应用才能显示 WebUI 页面。

Build
-----

本地交叉编译（示例使用 Android NDK r26 和 API 24）：

```
rustup target add aarch64-linux-android
export ANDROID_NDK_HOME=/path/to/android-ndk-r26d
export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
export ANDROID_API_LEVEL=24
export NDK_SYSROOT="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/sysroot"
export TOOLCHAIN_DIR="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
export CC_aarch64_linux_android="$TOOLCHAIN_DIR/aarch64-linux-android${ANDROID_API_LEVEL}-clang"
export AR_aarch64_linux_android="$TOOLCHAIN_DIR/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_AR="$AR_aarch64_linux_android"
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android="--target=aarch64-linux-android${ANDROID_API_LEVEL} --sysroot=$NDK_SYSROOT -I$NDK_SYSROOT/usr/include -I$NDK_SYSROOT/usr/include/aarch64-linux-android -D__ANDROID_API__=${ANDROID_API_LEVEL}"
export BINDGEN_EXTRA_CLANG_ARGS_aarch64-linux-android="$BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android"
export PKG_CONFIG_ALLOW_CROSS=1
cargo build --release --target aarch64-linux-android

# 启用 FRIDA hook（若需要）
cargo build --release --target aarch64-linux-android --features frida
```

> 提示：`BINDGEN_EXTRA_CLANG_ARGS_*` 环境变量会让 `bindgen` 使用 NDK sysroot 及 `aarch64-linux-android` 头文件，避免误引用宿主机的 glibc 头文件。

GitHub Actions
--------------

仓库包含 `.github/workflows/android-arm64.yml`，可在 push/PR 时自动生成 `aarch64-linux-android` 版本，并作为构建产物上传。
工作流会自动下载 `frida-core-devkit`（默认版本 `16.1.4`），设置 `FRIDA_CORE_DEVKIT`、`PKG_CONFIG_PATH`、`BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android` 等环境变量，并允许交叉 pkg-config，确保启用 `frida` feature 时能够找到头文件与库。

License
-------

Licensed under the Apache License, Version 2.0. 原始项目版权归 DrizzleRisk；Rust 重写保留该许可。
