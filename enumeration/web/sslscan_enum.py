import asyncio
import subprocess
from colorama import Fore, Style
from core import config, logger

module_name = "sslscan"

async def run_sslscan_enum(target, port=443, scheme="https", host=None):
    """Cheap, high-signal TLS/SSL audit (protocols, weak ciphers, cert expiry,
    Heartbleed) against a single endpoint. Only meaningful over TLS, so it no-ops
    on plain-http ports -- this is the resource/finding trade-off in action: a few
    hundred ms per https port, skipped entirely everywhere else."""
    enabled = config.get_config_value("enabled", f"scanner:{module_name}")
    if not enabled:
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} {module_name} scanning is disabled in the configuration.")
        return

    if scheme != "https":
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} {module_name} skipped for non-TLS {scheme}://{target}:{port}.")
        return

    endpoint = f"{target}:{port}"

    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Launching {module_name} scan on {scheme}://{endpoint}...")

    module_flags = config.get_tool_flags(module_name, "scanner")

    # Present the discovered vhost as the TLS SNI so a name-based https server
    # returns that vhost's certificate instead of the default one.
    sni_flags = ["--sni", host] if (host and host != target and "--sni" not in module_flags) else []

    result_file = config.get_target_scan_path(target) + f'{module_name}_{port}.txt'

    cmd = [module_name] + module_flags + sni_flags + [endpoint]

    logger.debug(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Executing module: {cmd}")

    with open(result_file, "w", encoding="utf-8") as outfile:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=outfile,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            _, stderr = await asyncio.wait_for(process.communicate(), timeout=config.timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} {module_name} scan timed out for {endpoint}.")
            return {}

        if process.returncode != 0:
            logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} {module_name} scan failed for {endpoint}: {stderr.decode()}")
            return {}

    logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} {module_name} results written to {Fore.LIGHTCYAN_EX}{result_file}{Style.RESET_ALL}")
    logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} {module_name} scan finished for {endpoint}.")

    return {}
