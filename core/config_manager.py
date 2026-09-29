import yaml
import os

class ConfigManager:
    _instance = None

    # Friendly names for feature groups that aren't per-tool entries under `scanner:`
    # (their `enabled` flag sits directly under the group), so --enable-module/--disable-module
    # can address them with the same short name used elsewhere (e.g. evaluation/services.json).
    MODULE_GROUP_ALIASES = {
        "webtech": "web_tech_lookup",
        "github_exploit": "github_exploit_search",
    }

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(ConfigManager, cls).__new__(cls, *args, **kwargs)
            cls._instance.__initialized = False
        return cls._instance

    def __init__(self, config_path="/opt/striga/config.yaml"):
        if self.__initialized:
            return
        self.__initialized = True
        self.config_path = config_path
        self.config = self.load_config()
        self.scan_id = "scan-default"
        self.debug = self.get_config_value("debug", "framework")
        self.timeout = self.get_config_value("timeout", "framework")
        self.cached_scan_id = None
        self.vuln_cache_file = None
        self.vuln_cache_path = None
        self.continue_scan = False
        self.frm_path = self.get_config_value("location", "framework")
        self.version = self.get_config_value("version", "framework")
        self.cache_path = None
        self.no_confirm = False

        self.prepare_cache()

        self.last_scan_file = self.cache_path + "last_scan"
        self.get_cached_scan_id()
    
    def reinitialize(self, config_path):
        from core import gen_id
        self.config_path = config_path
        self.config = self.load_config()
        self.scan_id = gen_id()
        self.debug = self.get_config_value("debug", "framework")
        self.timeout = self.get_config_value("timeout", "framework")
        self.cached_scan_id = None
        self.vuln_cache_file = None
        self.vuln_cache_path = None
        self.continue_scan = False
        self.frm_path = self.get_config_value("location", "framework")
        self.cache_path = None
        self.prepare_cache()
        self.save_scan_id()
        self.get_cached_scan_id()
    
    def prepare_scan_id(self):
        from core import gen_id
        self.scan_id = gen_id()

    def prepare_cache(self):
        from core import check_dir
        self.cache_path = self.frm_path + '/' + ".cache" + '/'
        check_dir(self.cache_path)

    def clean_cache(self):
        # Clear the cache dir contents without shelling out to `rm -rf` on an
        # interpolated path (a space or stray glob in cache_path would make that
        # dangerous, and os.system blocks the event loop). Only ever touches the
        # framework's own .cache dir, never the caller's cwd.
        import shutil
        if not self.cache_path or not os.path.isdir(self.cache_path):
            return
        for entry in os.listdir(self.cache_path):
            path = os.path.join(self.cache_path, entry)
            try:
                if os.path.isdir(path) and not os.path.islink(path):
                    shutil.rmtree(path)
                else:
                    os.unlink(path)
            except OSError:
                pass

    def save_scan_id(self):
        with open(self.last_scan_file, "w") as f:
            f.write(self.scan_id)
        f.close()

    def get_cached_scan_id(self):
        if not os.path.exists(self.last_scan_file):
            return
        with open (self.last_scan_file, "r") as f:
            self.cached_scan_id = f.read()
        f.close()

    def load_config(self):
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Configuration file {self.config_path} not found!")
        
        with open(self.config_path, "r") as file:
            return yaml.safe_load(file)

    def get_tool_flags(self, tool_name, group):
        tool_config = self.config.get(group, {}).get(tool_name, {})
        if not tool_config.get("enabled", False):
            return [] 

        flags = tool_config.get("flags", [])
        if not isinstance(flags, list):
            raise ValueError(f"Invalid format for {tool_name} flags in YAML file.")

        return flags

    def get_config_value(self, attribute, group):
        keys = group.split(":")
        config_section = self.config

        for key in keys:
            config_section = config_section.get(key, {})

        return config_section.get(attribute, None)

    def set_config_value(self, attribute, group, value):
        """Overrides a single config value in memory for this run (config.yaml on
        disk is untouched) -- e.g. a CLI flag overriding sandbox.timeout. Creates
        intermediate group dicts if the group doesn't already exist in the loaded
        config (e.g. a deployed config.yaml that predates the section)."""
        keys = group.split(":")
        config_section = self.config

        for key in keys:
            config_section = config_section.setdefault(key, {})

        config_section[attribute] = value


    def get_target_scan_path(self, target):
        return  self.frm_path + '/' + self.scan_id + '/' + target + '/'

    def set_module_enabled(self, module_name, enabled):
        """Overrides a module's `enabled` flag in the loaded config for this run
        (in-memory only, config.yaml on disk is untouched). Handles both shapes
        used across the config: per-tool entries under `scanner:` and standalone
        feature groups (web_tech_lookup, github_exploit_search, sandbox).
        Returns True if the module was found and updated, False otherwise."""
        scanner_group = self.config.get("scanner", {})
        if module_name in scanner_group and isinstance(scanner_group[module_name], dict):
            scanner_group[module_name]["enabled"] = enabled
            return True

        group_name = self.MODULE_GROUP_ALIASES.get(module_name, module_name)
        group = self.config.get(group_name)
        if isinstance(group, dict) and "enabled" in group:
            group["enabled"] = enabled
            return True

        return False

    

