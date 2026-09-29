import asyncio
import subprocess
from colorama import Fore, Style
from core import config, logger, registrable_domain
from scanner.port_utils import is_ip_literal

# Discovers name-based virtual hosts the cert/redirect didn't reveal, by fuzzing
# the Host header (Host: FUZZ.<domain>) against the web port while connecting to
# the target's IP. Uses the ffuf binary (like nmap-http uses the nmap binary under
# a distinct module name), auto-calibrated (-ac) so the default vhost's baseline
# response is filtered out and only *different* vhosts surface.

module_name = "vhostfuzz"

async def run_vhostfuzz_enum(target, port=80, scheme="http", host=None):
    enabled = config.get_config_value("enabled", f"scanner:{module_name}")
    if not enabled:
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} {module_name} scanning is disabled in the configuration.")
        return

    # Need an apex domain to fuzz subdomains under. Prefer the discovered vhost;
    # fall back to the target itself when the operator targeted a hostname. With a
    # bare IP and no discovered domain there's nothing to fuzz -- skip cleanly.
    base = host or (target if not is_ip_literal(target) else None)
    domain = registrable_domain(base)
    if not domain:
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} {module_name} skipped for {target}:{port} (no base domain to fuzz).")
        return

    url = f"{scheme}://{target}:{port}/"
    host_header = f"Host: FUZZ.{domain}"

    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Launching {module_name} on {url} (fuzzing FUZZ.{domain})...")

    module_flags = config.get_tool_flags(module_name, "scanner")
    tls_flags = ["-k"] if (scheme == "https" and "-k" not in module_flags) else []

    result_file = config.get_target_scan_path(target) + f'{module_name}_{port}.txt'

    cmd = ["ffuf"] + module_flags + tls_flags + ["-u", url, "-H", host_header, "-o", result_file]

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
