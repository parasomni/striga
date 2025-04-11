import asyncio
import subprocess
from core import config
from core import logger

from colorama import Fore, Style

module_name = "nikto"

async def run_nikto_scanner(target):
    enabled = config.get_config_value("enabled", f"scanner:{module_name}")
    if not enabled:
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} {module_name} scanning is disabled in the configuration.")
        return
    
    nikto_flags = config.get_tool_flags(module_name, "scanner")

    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Launching {module_name} on {target}...")

    cmd = [module_name] + nikto_flags + "-h" + [target]
    
    process = await asyncio.create_subprocess_exec(
        *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    
    stdout, stderr = await process.communicate()
    
    if process.returncode != 0:
        logger.log(f"[ERROR] Nikto scan failed for {target}: {stderr.decode()}")
        return []


    return stdout.decode()
