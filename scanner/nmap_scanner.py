import asyncio
import re
import subprocess
from core import config
from core import logger

from colorama import Fore, Style

module_name = "nmap"

# Port-selection flags that only make sense for the discovery phase -- stripped
# from the configured flags before the (port-scoped) service-detection phase so we
# don't re-scan the full range with -sV.
_PORT_SELECTION_FLAGS = ("-p-",)

_GREPABLE_OPEN_PORTS = re.compile(r"(\d+)/open/tcp")


async def _run_nmap(cmd):
    process = await asyncio.create_subprocess_exec(
        *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    return process.returncode, stdout, stderr


def _discovery_flags():
    """Fast SYN-ish sweep: full port range, no version detection. Rate and the
    -Pn/-T4 posture mirror the configured scan so behaviour is predictable."""
    rate = config.get_config_value("discovery_min_rate", "performance") or 2000
    return ["-p-", "-T4", "-Pn", "-n", f"--min-rate={rate}", "-oG", "-"]


def _service_flags(configured_flags, ports):
    """Configured nmap flags with the full-range selector removed and the
    discovered open ports pinned instead -- keeps -sV, -Pn, -T4 and any NSE the
    operator added, but scopes them to ports we already know are open. Adds
    ssl-cert/http-title NSE (config performance.hostname_scripts, default on) so
    the scan surfaces TLS cert names and HTTP redirects that extract_hostnames()
    turns into vhost targets -- cheap here because it only runs on open ports."""
    kept = [f for f in configured_flags if f not in _PORT_SELECTION_FLAGS]
    if "-sV" not in kept:
        kept = ["-sV"] + kept

    want_scripts = config.get_config_value("hostname_scripts", "performance")
    already_scripting = "-sC" in kept or "--script" in kept or any(str(f).startswith("--script") for f in kept)
    if want_scripts is not False and not already_scripting:
        kept = kept + ["--script", "ssl-cert,http-title"]

    return kept + ["-p", ports]


def _parse_open_ports(grepable_stdout):
    ports = _GREPABLE_OPEN_PORTS.findall(grepable_stdout.decode(errors="ignore"))
    # Preserve order, de-duplicate.
    seen = []
    for p in ports:
        if p not in seen:
            seen.append(p)
    return ",".join(seen)


async def _two_phase_scan(target, configured_flags):
    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} {module_name} phase 1: fast port discovery on {target}...")
    rc, stdout, stderr = await _run_nmap(["nmap"] + _discovery_flags() + [target])
    if rc != 0:
        logger.log(f"{Fore.LIGHTYELLOW_EX}[-]{Style.RESET_ALL} {module_name} discovery phase failed for {target}, falling back to single-phase scan: {stderr.decode(errors='ignore')}")
        return await _single_phase_scan(target, configured_flags)

    ports = _parse_open_ports(stdout)
    if not ports:
        logger.log(f"{Fore.LIGHTYELLOW_EX}[-]{Style.RESET_ALL} {module_name} found no open TCP ports on {target}.")
        return ""

    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} {module_name} phase 2: service/version detection on {target} ports {ports}...")
    rc, stdout, stderr = await _run_nmap(["nmap"] + _service_flags(configured_flags, ports) + [target])
    if rc != 0:
        logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} {module_name} service scan failed for {target}: {stderr.decode(errors='ignore')}")
        return {}
    return stdout.decode()


async def _single_phase_scan(target, configured_flags):
    cmd = ["nmap"] + configured_flags + [target]
    rc, stdout, stderr = await _run_nmap(cmd)
    if rc != 0:
        logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} {module_name} scan failed for {target}: {stderr.decode(errors='ignore')}")
        return {}
    return stdout.decode()


async def run_nmap(target):
    enabled = config.get_config_value("enabled", f"scanner:{module_name}")
    if not enabled:
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} {module_name} scanning is disabled in the configuration.")
        return

    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Launching {module_name} scan on {target}...")

    nmap_flags = config.get_tool_flags(module_name, "scanner")

    two_phase = config.get_config_value("two_phase_scan", "performance")
    if two_phase:
        results = await _two_phase_scan(target, nmap_flags)
    else:
        results = await _single_phase_scan(target, nmap_flags)

    # Preserve the previous contract: {} on hard failure, "" when there was simply
    # nothing open; only write/return real -sV text output.
    if isinstance(results, dict):
        return results

    write_results(results, target)

    logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} {module_name} scan finished for {target}.")

    return results


def write_results(results, target):
    result_file = config.get_target_scan_path(target) + f'{module_name}.txt'
    with open(result_file, 'w') as f:
        f.write(str(results))
    f.close()
    logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} {module_name} results written to {Fore.LIGHTCYAN_EX}{result_file}{Style.RESET_ALL}")
