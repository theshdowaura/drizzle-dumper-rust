drizzleDumper (Rust rewrite)
============================

简介
----

`drizzleDumper` 现已使用 Rust 重写，修复了旧版 C 实现中在现代 Android (ART/64bit) 上的崩溃问题，并提供安全的内存扫描与 DEX dump 能力。项目可直接交叉编译至 `aarch64-linux-android`，方便在实体机上测试。

Usage
-----

```
drizzle_dumper <package_name> [wait_seconds]
```

* 需要 root 权限。
* 默认轮询间隔为 0 秒，可通过 `wait_seconds` 指定轮询周期。
* dump 成功后文件保存在 `/data/local/tmp/<package>_dumped_<addr>.dex`。

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
```

GitHub Actions
--------------

仓库包含 `.github/workflows/android-arm64.yml`，可在 push/PR 时自动生成 `aarch64-linux-android` 版本，并作为构建产物上传。

License
-------

Licensed under the Apache License, Version 2.0. 原始项目版权归 DrizzleRisk；Rust 重写保留该许可。
