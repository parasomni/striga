import asyncio
import subprocess
from colorama import Fore, Style
from core import config, logger

module_name = "nmap-http"

async def run_nmap_http_enum(target, port=80, scheme="http", host=None):
    enabled = config.get_config_value("enabled", f"scanner:{module_name}")
    if not enabled:
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} {module_name} scanning is disabled in the configuration.")
        return

    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Launching {module_name} scan on {target}:{port}...")

    module_flags = config.get_tool_flags(module_name, "scanner")

    # Route the http-* NSE scripts at the discovered vhost via the http.host library
    # arg, so they send the right Host header while still connecting to the target IP.
    host_args = ["--script-args", f"http.host={host}"] if (host and host != target) else []

    result_file = config.get_target_scan_path(target) + f'{module_name}_{port}.txt'

    cmd = ["nmap"] + module_flags + host_args + ["-p", str(port), "-oN", result_file] + [target]

    logger.debug(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Executing module: {cmd}")
    
    process = await asyncio.create_subprocess_exec(
        *cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
    )

    try:
        _, stderr = await asyncio.wait_for(process.communicate(), timeout=config.timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} {module_name} scan timed out for {target}.")
        return {}

    if process.returncode != 0:
        logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} {module_name} scan failed for {target}: {stderr.decode()}")
        return {}

    logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} {module_name} results written to {Fore.LIGHTCYAN_EX}{result_file}{Style.RESET_ALL}")
    logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} {module_name} scan finished for {target}.")

    return {}