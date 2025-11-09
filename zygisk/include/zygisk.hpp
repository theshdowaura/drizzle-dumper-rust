/*
 * Copyright (C) 2021-2024 topjohnwu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <jni.h>

namespace zygisk {

enum class Option {
    /**
     * Whether dlclose the module shared object after initialization.
     * Default is true.
     */
    DLCLOSE_MODULE_LIBRARY,
};

enum class Property {
    /**
     * Set or clear exec spawn privilege so that the app can still use exec*()
     * to spawn new processes. Default is false.
     */
    ALLOW_UNSAFE_ENVIRON,
};

class AppSpecializeArgs {
public:
    JNIEnv* env;
    jstring* nice_name;
    jobjectArray* app_data_dir;
    jobjectArray* public_source_dir;
    jobjectArray* data_dir;
};

class ServerSpecializeArgs {
public:
    JNIEnv* env;
};

class Api {
public:
    void setOption(Option, bool) {}
    void setProperty(Property, bool) {}
};

class ModuleBase {
public:
    virtual ~ModuleBase() = default;

    virtual void onLoad(Api*, JNIEnv*) {}
    virtual void preAppSpecialize(AppSpecializeArgs*) {}
    virtual void postAppSpecialize(const AppSpecializeArgs*) {}
    virtual void preServerSpecialize(ServerSpecializeArgs*) {}
    virtual void postServerSpecialize(const ServerSpecializeArgs*) {}
    virtual void onUnload() {}
};

} // namespace zygisk

extern "C" void zygisk_module_load(zygisk::Api*, JNIEnv*);
extern "C" void zygisk_module_unload();

#define REGISTER_ZYGISK_MODULE(module)                                      \
    extern "C" void zygisk_module_load(zygisk::Api* api, JNIEnv* env) {      \
        static auto& _module = module;                                      \
        _module.onLoad(api, env);                                           \
    }                                                                       \
    extern "C" void zygisk_module_unload() { module.onUnload(); }

#define REGISTER_ZYGISK_MODULE(module)                                      \
    extern "C" void zygisk_module_load(zygisk::Api* api, JNIEnv* env) {      \
        static auto& _module = module;                                      \
        _module.onLoad(api, env);                                           \
    }                                                                       \
    extern "C" void zygisk_module_unload() { module.onUnload(); }
