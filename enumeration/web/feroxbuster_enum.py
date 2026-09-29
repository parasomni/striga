import asyncio
import subprocess
from colorama import Fore, Style
from core import config, logger, curl_style_vhost_flags

module_name = "feroxbuster"

async def run_feroxbuster_enum(target, port=80, scheme="http", host=None):
    """Fast recursive content discovery (Rust). A performance-oriented alternative
    to gobuster/dirbuster: bounded recursion depth and a scan limit keep it from
    exploding into an unbounded crawl while still finding nested paths those
    single-level tools miss. Same (target, port, scheme) + per-port result-file
    shape as the other web-enum modules."""
    enabled = config.get_config_value("enabled", f"scanner:{module_name}")
    if not enabled:
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} {module_name} scanning is disabled in the configuration.")
        return

    url = f"{scheme}://{target}:{port}/"

    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Launching {module_name} scan on {url}" + (f" (vhost {host})" if host and host != target else "") + "...")

    module_flags = config.get_tool_flags(module_name, "scanner")
    vhost_flags = curl_style_vhost_flags(host, target, scheme, module_flags)

    result_file = config.get_target_scan_path(target) + f'{module_name}_{port}.txt'

    # -k (insecure TLS) is safe/expected against lab https endpoints with self-signed
    # certs; --silent keeps stdout clean since results go to the -o file. vhost_flags
    # adds the Host header when fingerprinting found a distinct virtual host.
    cmd = [module_name, "-u", url, "-o", result_file] + module_flags + vhost_flags

    logger.debug(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Executing module: {cmd}")

    process = await asyncio.create_subprocess_exec(
        *cmd, stdout=subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE
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
