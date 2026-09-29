from .config_manager import ConfigManager
from .arg_parser import ArgumentParser
from .scan_id import gen_id
from .check_dir import check_dir
from .logger import Logger
from .module_adder import run_module_adder
from .scanner_adder import run_scanner_adder
from .concurrency import bounded_gather
from .vhost import select_vhost, suggest_unresolved_hosts, curl_style_vhost_flags, registrable_domain

def initialize_globals():
    global logger, config, parser
    config = ConfigManager()
    parser = ArgumentParser()
    logger = Logger()


initialize_globals()

__all__ = [
    "ConfigManager", 
    "config", 
    "parser", 
    "logger", 
    "check_dir", 
    "gen_id",
    "run_module_adder",
    "run_scanner_adder",
    "bounded_gather",
    "select_vhost",
    "suggest_unresolved_hosts",
    "curl_style_vhost_flags",
    "registrable_domain"
]  # config variable is global like a singleton class