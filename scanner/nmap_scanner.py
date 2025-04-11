import asyncio
import subprocess
from core import config
from core import logger

from colorama import Fore, Style

module_name = "nmap"

async def run_nmap(target):
    enabled = config.get_config_value("enabled", f"scanner:{module_name}")
    if not enabled:
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} {module_name} scanning is disabled in the configuration.")
        return
    
    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Launching {module_name} scan on {target}...")
    
    nmap_flags = config.get_tool_flags(module_name, "scanner")

    cmd = [module_name] + nmap_flags + [target]
    
    process = await asyncio.create_subprocess_exec(
        *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} {module_name} scan failed for {target}: {stderr.decode()}")
        return {}

    results = stdout.decode()

    write_results(results, target)

    logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} {module_name} scan finished for {target}.")

    return results


def write_results(results, target):
    result_file = config.get_target_scan_path(target) + f'{module_name}.txt'
    with open(result_file, 'w') as f:
        f.write(str(results))
    f.close()
    logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} {module_name} results written to {Fore.LIGHTCYAN_EX}{result_file}{Style.RESET_ALL}")
        