import yaml
import os

class ConfigManager:
    _instance = None

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
        os.system(f"rm -rf {self.cache_path}/*")

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

    
    def get_target_scan_path(self, target):
        return  self.frm_path + '/' + self.scan_id + '/' + target + '/'

    

