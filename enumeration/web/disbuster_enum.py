import asyncio
import subprocess
from colorama import Fore, Style
from core import config, logger

module_name = "dirbuster"

async def run_dirbuster_enum(target, port=80, scheme="http", host=None):
    enabled = config.get_config_value("enabled", f"scanner:{module_name}")
    if not enabled:
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} {module_name} scanning is disabled in the configuration.")
        return

    # dirbuster has no Host-header override, so it must use a resolvable name in the
    # URL -- prefer the discovered vhost (relies on it resolving; see the /etc/hosts
    # suggestion striga prints when it doesn't).
    conn_host = host or target
    url = f"{scheme}://{conn_host}:{port}/"

    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Launching {module_name} scan on {url}...")

    module_flags = config.get_tool_flags(module_name, "scanner")

    result_file = config.get_target_scan_path(target) + f'{module_name}_{port}.txt'

    cmd = [module_name] + module_flags + [url] + ["-o", result_file]
    
    logger.debug(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Executing module: {cmd}")

    process = await asyncio.create_subprocess_exec(
        *cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
    )

    try:
        _, stderr = await asyncio.wait_for(process.communicate(), timeout=config.timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} {module_name} scan timed out for {url}.")
        return {}

    if process.returncode != 0:
        logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} {module_name} scan failed for {url}: {stderr.decode()}")
        return {}

    logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} {module_name} results written to {Fore.LIGHTCYAN_EX}{result_file}{Style.RESET_ALL}")
    logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} {module_name} scan finished for {url}.")

    return {}