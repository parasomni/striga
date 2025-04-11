import asyncio
import subprocess
import json
import xmltodict
import re

from colorama import Fore, Style

from core import config
from core import gen_id
from core import logger
from core import check_dir


async def run_nmap_vuln_scan(target):
    from scanner import run_nmap_vuln_scan

    enabled = config.get_config_value("enabled", "scanner:nmap-vuln")
    if not enabled:
        return None

    results = await run_nmap_vuln_scan(target)
    return {"nmap-vuln": results}

async def run_nikto_scan(target):
    from scanner import run_nikto_scanner

    enabled = config.get_config_value("enabled", "scanner:nikto")
    if not enabled:
        return None

    output = await run_nikto_scanner(target)
    return {"nikto_scan": output} if output else None

async def run_nuclei_vuln_can(target):
    from scanner import run_nuclei_vuln_scan

    enabled = config.get_config_value("enabled", "scanner:nuclei")
    if not enabled:
        return None

    results = await run_nuclei_vuln_scan(target)
    return {"nuclei-vuln": results}

async def run_all_scanners(target):
    tasks = {
        "nmap-vuln": run_nmap_vuln_scan(target),
        "nikto": run_nikto_scan(target),
        "nuclei": run_nuclei_vuln_can(target)
    }
    
    results = await asyncio.gather(*tasks.values())

    merged_results = {name: result for name, result in zip(tasks.keys(), results) if result}

    return merged_results


async def run_vuln_scanners(target):
    results = await run_all_scanners(target)

    use_cache = config.get_config_value("use_cache", "performance")
    if use_cache:
        with open(config.vuln_cache_file, "w") as f:
            json.dump(results, f)
        f.close()
        logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Cached vuln results.")

    logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} Vulnerability scan completed.")
    return results
