#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <zygisk.hpp>

#ifdef DRIZZLE_ZYGISK_EMBED_JSON
#include <algorithm>
#else
#include <nlohmann/json.hpp>
#endif

namespace {

constexpr char kLogTag[] = "DrizzleZygisk";
constexpr char kConfigPath[] = "/data/adb/modules/drizzle-zygisk/config/targets.json";
constexpr char kDefaultGadgetPath[] =
    "/data/adb/modules/drizzle-zygisk/frida/frida-gadget.so";
constexpr char kDefaultConfigPath[] =
    "/data/adb/modules/drizzle-zygisk/frida/frida-gadget.config";

struct Settings {
  std::string gadget_path = kDefaultGadgetPath;
  std::string gadget_config = kDefaultConfigPath;
  std::vector<std::string> packages;
  std::vector<std::string> denylist;
};

std::string ReadFile(const char *path) {
  std::ifstream input(path, std::ios::in | std::ios::binary);
  if (!input.is_open()) {
    return {};
  }
  return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

Settings LoadSettings() {
  Settings cfg;
  const std::string json = ReadFile(kConfigPath);
  if (json.empty()) {
    return cfg;
  }
#ifdef DRIZZLE_ZYGISK_EMBED_JSON
  auto extract_array = [&](std::string_view key, std::vector<std::string> &out) {
    const auto pos = json.find(std::string("\"") + std::string(key) + "\"");
    if (pos == std::string::npos) {
      return;
    }
    const auto start = json.find('[', pos);
    const auto end = json.find(']', start);
    if (start == std::string::npos || end == std::string::npos || end <= start) {
      return;
    }
    std::string array = json.substr(start + 1, end - start - 1);
    size_t begin = 0;
    while (begin < array.size()) {
      size_t quote = array.find('"', begin);
      if (quote == std::string::npos) {
        break;
      }
      size_t quote_end = array.find('"', quote + 1);
      if (quote_end == std::string::npos) {
        break;
      }
      out.emplace_back(array.substr(quote + 1, quote_end - quote - 1));
      begin = quote_end + 1;
    }
  };
  auto extract_string = [&](std::string_view key, std::string &out) {
    const auto pos = json.find(std::string("\"") + std::string(key) + "\"");
    if (pos == std::string::npos) {
      return;
    }
    const auto colon = json.find(':', pos);
    const auto first_quote = json.find('"', colon);
    const auto second_quote = json.find('"', first_quote + 1);
    if (first_quote == std::string::npos || second_quote == std::string::npos) {
      return;
    }
    out = json.substr(first_quote + 1, second_quote - first_quote - 1);
  };
  extract_string("gadget_path", cfg.gadget_path);
  extract_string("config_path", cfg.gadget_config);
  extract_array("packages", cfg.packages);
  extract_array("denylist", cfg.denylist);
#else
  try {
    nlohmann::json doc = nlohmann::json::parse(json);
    if (doc.contains("gadget_path")) {
      cfg.gadget_path = doc["gadget_path"].get<std::string>();
    }
    if (doc.contains("config_path")) {
      cfg.gadget_config = doc["config_path"].get<std::string>();
    }
    if (doc.contains("packages")) {
      cfg.packages = doc["packages"].get<std::vector<std::string>>();
    }
    if (doc.contains("denylist")) {
      cfg.denylist = doc["denylist"].get<std::vector<std::string>>();
    }
  } catch (const std::exception &e) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "failed to parse %s: %s", kConfigPath, e.what());
  }
#endif
  return cfg;
}

bool Matches(const std::vector<std::string> &patterns, std::string_view value) {
  for (const auto &pattern : patterns) {
    if (pattern == value) {
      return true;
    }
  }
  return false;
}

void ExportGadgetConfig(const std::string &nice_name, const Settings &cfg) {
  if (cfg.gadget_config.empty()) {
    return;
  }
  setenv("FRIDA_GADGET_CONFIG", cfg.gadget_config.c_str(), 1);
  __android_log_print(ANDROID_LOG_INFO, kLogTag,
                      "process %s using config %s", nice_name.c_str(),
                      cfg.gadget_config.c_str());
}

}  // namespace

class DrizzleModule : public zygisk::ModuleBase {
 public:
  void onLoad(zygisk::Api *api, JNIEnv *env) override {
    api_ = api;
    env_ = env;
    settings_ = LoadSettings();
    api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY, false);
  }

  void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
    current_nice_name_.clear();
    if (args->nice_name) {
      current_nice_name_ = args->nice_name->c_str();
    }
    should_inject_ = ShouldInject(current_nice_name_);
    if (should_inject_) {
      api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY, false);
    }
  }

  void postAppSpecialize(const zygisk::AppSpecializeArgs * /*args*/) override {
    if (!should_inject_) {
      return;
    }
    ExportGadgetConfig(current_nice_name_, settings_);
    if (access(settings_.gadget_path.c_str(), R_OK) != 0) {
      __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                          "gadget %s not readable", settings_.gadget_path.c_str());
      return;
    }
    void *handle = dlopen(settings_.gadget_path.c_str(), RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
      __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                          "dlopen failed: %s", dlerror());
      return;
    }
    __android_log_print(ANDROID_LOG_INFO, kLogTag,
                        "Gadget loaded into %s", current_nice_name_.c_str());
  }

  void onUnload() override { should_inject_ = false; }

 private:
  bool ShouldInject(const std::string &nice_name) {
    if (nice_name.empty()) {
      return false;
    }
    if (Matches(settings_.denylist, nice_name)) {
      return false;
    }
    if (!settings_.packages.empty()) {
      return Matches(settings_.packages, nice_name);
    }
    return true;
  }

  zygisk::Api *api_{nullptr};
  JNIEnv *env_{nullptr};
  Settings settings_;
  std::string current_nice_name_;
  bool should_inject_{false};
};

static DrizzleModule g_module;

REGISTER_ZYGISK_MODULE(g_module);
