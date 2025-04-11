import asyncio
import subprocess
import xmltodict
import json

from colorama import Fore, Style

from core import config
from core import logger

module_name = "nmap-vuln"

async def run_nmap_vuln_scan(target):
    nmap_flags = config.get_tool_flags(module_name, "scanner")

    if not nmap_flags:
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} {module_name} scanning is disabled in the configuration.")
        return
    
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
