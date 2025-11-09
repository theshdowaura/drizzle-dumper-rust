# DrizzleDumper Zygisk Module

This directory contains a reference implementation of a Magisk **Zygisk** module
that preloads the Frida Gadget into whitelisted application processes during the
zygote specialization phase.  Deploying the module allows drizzle-dumper to
observe targets from the very beginning of their lifecycle without relying on
ptrace attach timing.

## Layout

```
zygisk/
├── module.prop          # Magisk metadata (id, version, description)
├── sepolicy.rule        # Optional SELinux relaxations for gadget socket access
├── service.sh           # Late_start service script used to copy/refresh assets
├── config/
│   ├── targets.json     # Package filter and gadget path configuration
│   └── mcp_bind         # drizzle_dumper MCP server bind address
├── bin/
│   └── drizzle_dumper   # Prebuilt CLI binary (aarch64) bundled for convenience
├── libs/
│   └── arm64-v8a/
│       └── libdrizzlezygisk.so  # Built shared object registered with Zygisk
└── src/
    ├── Android.bp       # Example Soong build description
    ├── CMakeLists.txt   # Alternative CMake build definition
    └── module.cpp       # Zygisk module implementation
```

Only the `module.prop`, `config/targets.json`, and `libs/<abi>/libdrizzlezygisk.so`
files are strictly required at runtime.  `config/mcp_bind` controls the MCP server
监听地址（默认 `0.0.0.0:45831`）。`bin/` 目录虽然可选，但发布包中已经附带
the published workflow bundles an aarch64 build of `drizzle_dumper` so the CLI
is available on-device as soon as the module is flashed.  The `src/` tree
provides build tooling for AOSP or standalone NDK environments.

## Build (standalone CMake)

```
export ANDROID_NDK=/path/to/android-ndk
cmake -S zygisk/src -B out/zygisk -DANDROID_ABI=arm64-v8a \
      -DANDROID_PLATFORM=android-29 -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake
cmake --build out/zygisk --target drizzlezygisk --config Release
mkdir -p zygisk/libs/arm64-v8a
cp out/zygisk/libdrizzlezygisk.so zygisk/libs/arm64-v8a/
```

For Soong users, copy `src/Android.bp` into the build tree of a Magisk module
project and run the standard `m`/`mmm` workflows.

## Deployment

Package the contents of this directory into a Magisk module archive:

```
zip -r drizzle-zygisk.zip module.prop service.sh sepolicy.rule \
    libs config bin
```

Install the module with the Magisk app or using `adb shell magisk --install-module`.
After reboot, the module will:

1. Read `config/targets.json` to determine which package names should load the gadget.
2. Copy `frida-gadget.so` and `frida-gadget.config` from `/data/local/tmp/drizzle_gadget/latest`
   (or a custom path defined in the JSON) into the module private directory.
3. When a watched app forks from zygote, Zygisk calls `handle_app_specialize`.
   The module checks the package name and, if matched, `dlopen`s the gadget before
   the application `onCreate` executes.
4. Service 脚本会在 late_start 阶段自动启动  
   `/data/adb/modules/drizzle-zygisk/bin/drizzle_dumper mcp-server --bind <config/mcp_bind>`，
   方便通过 MCP 工具触发 dump。需要手动交互时也可直接执行该二进制。

The running drizzle-dumper instance can detect the presence of the module through
the new CLI flag `--zygisk`, which toggles gadget management to “passive” mode
without further ptrace injection attempts.

## Configuration File

`config/targets.json` example:

```json
{
  "gadget_path": "/data/adb/modules/drizzle-dumper/frida/frida-gadget.so",
  "config_path": "/data/adb/modules/drizzle-dumper/frida/frida-gadget.config",
  "packages": [
    "com.example.protectedapp",
    "com.target.launcher"
  ],
  "denylist": [
    "com.android.systemui"
  ]
}
```

- `gadget_path` and `config_path` point to the assets to be loaded.
- `packages` lists process names (usually identical to package names) that should be instrumented.
- `denylist` acts as a safeguard so that even if a process matches another criterion, it is skipped.

The module will reload this configuration on every `handleAppSpecialize` invocation, so you can
push updated JSON without rebooting.

## Limitations

- ARM64 only (matching drizzle-dumper’s gadget injector).  Additional ABIs can be added by
  building and packaging the corresponding `.so`.
- The example implementation performs a best-effort `dlopen` and logs to `logcat` if loading fails.
- SELinux rules may need adjustment on heavily restricted ROMs; the provided `sepolicy.rule`
  grants socket access for localhost gadget communication.

## Integration with drizzle-dumper CLI

After the module is installed, invoke drizzle-dumper with the new `--zygisk` flag to:

- Skip ptrace gadget injection.
- Validate gadget presence by connecting to the configured port.
- Leave the FRIDA session running for extended monitoring unless explicitly terminated.

MCP clients can pass `"zygisk": true` in the command request to achieve the same behavior.
