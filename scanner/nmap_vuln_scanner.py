import asyncio
import subprocess
import xmltodict
import json

from colorama import Fore, Style

from core import config
from core import logger

from scanner.port_utils import extract_open_port_numbers

module_name = "nmap-vuln"


def _scoped_port_flags(target, existing_flags):
    """Scope the vuln scan to the ports the initial -p- sweep already found open,
    read from the target's cached nmap.txt. This turns a fresh top-1000 -sV+NSE
    rescan (the single biggest redundant cost in the pipeline) into a targeted
    scan of only known-open ports -- faster, and it also covers non-standard open
    ports the default range would have skipped. If the operator already pinned an
    explicit port range in config, or no cached scan exists yet (e.g. --auto-exploit
    with no prior enumeration), leave the flags untouched so behaviour is unchanged."""
    if any(f in ("-p", "-p-", "--top-ports") or str(f).startswith("-p") for f in existing_flags):
        return existing_flags

    try:
        with open(config.get_target_scan_path(target) + "nmap.txt", "r") as f:
            ports = extract_open_port_numbers(f.read())
    except FileNotFoundError:
        return existing_flags

    if not ports:
        return existing_flags

    logger.debug(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} {module_name} scoped to open ports {ports} on {target}.")
    return ["-p", ports] + existing_flags


async def run_nmap_vuln_scan(target):
    nmap_flags = config.get_tool_flags(module_name, "scanner")

    if not nmap_flags:
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} {module_name} scanning is disabled in the configuration.")
        return

    nmap_flags = _scoped_port_flags(target, nmap_flags)

    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Launching {module_name} on {target}...")

    cmd = ["nmap"] + nmap_flags + [target]
    
    process = await asyncio.create_subprocess_exec(
        *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} {module_name} failed for {target}: {stderr.decode()}")
        return {}
    
    namp_json_results = parse_namp_vuln_results(stdout)
    logger.log(f"{Fore.LIGHTBLUE_EX}[+]{Style.RESET_ALL} {module_name} vulnerability scan for {target} finished.")
    return json.dumps(namp_json_results, indent=4)


def parse_namp_vuln_results(stdout):
    parsed_xml = xmltodict.parse(stdout)
    json_output = json.dumps(parsed_xml, indent=4)
    return json.loads(json_output)


def extract_vulnerabilities(nmap_json):
    vulnerabilities = []
    
    try:
        ports = nmap_json["nmaprun"]["host"]["ports"]["port"]
        for port in ports:
            if "script" in port:
                vuln_info = {
                    "port": port["portid"],
                    "service": port["service"]["name"],
                    "vulnerability": port["script"]["output"]
                }
                vulnerabilities.append(vuln_info)
    except KeyError:
        logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} No vulnerabilities found in scan results.")
    
    return vulnerabilities
