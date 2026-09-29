import asyncio
import json
import os
import subprocess
from colorama import Fore, Style
from core import config, logger

module_name = "wpscan"


def _looks_like_wordpress(target, port):
    """Only run wpscan where fingerprinting already found WordPress. Reads the
    webtech_<port>.json this port's whatweb/webtech pass wrote (product keys), so
    wpscan costs nothing on the overwhelming majority of ports that aren't WP --
    the whole point of gating an expensive, WP-specific scanner on cheap evidence
    that already exists on disk."""
    webtech_file = config.get_target_scan_path(target) + f"webtech_{port}.json"
    try:
        with open(webtech_file, "r") as f:
            products = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return False
    return any("wordpress" in name.lower() for name in products)


async def run_wpscan_enum(target, port=80, scheme="http", host=None):
    """WordPress security scanner (vulnerable plugins/themes, user enum). Gated on
    an existing WordPress fingerprint so it never fires against non-WP endpoints.
    Runs AFTER the whatweb/webtech fingerprint pass, so the webtech file it reads
    is guaranteed present in the normal pipeline order."""
    enabled = config.get_config_value("enabled", f"scanner:{module_name}")
    if not enabled:
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} {module_name} scanning is disabled in the configuration.")
        return

    if not _looks_like_wordpress(target, port):
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} {module_name} skipped for {target}:{port} (no WordPress fingerprint).")
        return

    # WordPress generates absolute URLs from its configured site host, so wpscan
    # needs the real vhost in the URL (not the IP) to avoid redirect loops.
    conn_host = host or target
    url = f"{scheme}://{conn_host}:{port}/"

    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} WordPress detected -- launching {module_name} on {url}...")

    module_flags = config.get_tool_flags(module_name, "scanner")

    # Optional WPScan API token from an untracked file, appended live so it never
    # has to sit in tracked config.yaml (same secret-handling stance as the rest
    # of the framework). Absent/empty file -> scan runs unauthenticated.
    api_token_file = config.get_config_value("api_token_file", "scanner:wpscan")
    if api_token_file and os.path.exists(api_token_file):
        try:
            with open(api_token_file, "r") as f:
                token = f.read().strip()
            if token:
                module_flags = module_flags + ["--api-token", token]
        except OSError:
            pass

    if scheme == "https" and "--disable-tls-checks" not in module_flags:
        module_flags = module_flags + ["--disable-tls-checks"]

    result_file = config.get_target_scan_path(target) + f'{module_name}_{port}.txt'

    cmd = [module_name, "--url", url, "-o", result_file] + module_flags

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

    # wpscan exits non-zero (5) when it *finds* vulnerabilities -- that's a
    # successful run, not a failure. Only treat it as failed if no result file
    # was produced.
    if process.returncode not in (0, 5) and not os.path.exists(result_file):
        logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} {module_name} scan failed for {url}: {stderr.decode()}")
        return {}

    logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} {module_name} results written to {Fore.LIGHTCYAN_EX}{result_file}{Style.RESET_ALL}")
    logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} {module_name} scan finished for {url}.")

    return {}
