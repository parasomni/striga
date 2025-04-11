import asyncio
import subprocess
import json
from colorama import Fore, Style

from core import config
from core import logger

module_name = "nuclei"

async def run_nuclei_vuln_scan(target):
    enabled = config.get_config_value("enabled", f"scanner:{module_name}")
    if not enabled:
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} {module_name} scanning is disabled in the configuration.")
        return

    nuclei_flags = config.get_tool_flags(module_name, "scanner")

    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Launching {module_name} on {target}...")

    cmd = [module_name, "-target", target] + nuclei_flags

    process = await asyncio.create_subprocess_exec(
        *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} {module_name} failed for {target}: {stderr.decode()}")
        return {}

    nuclei_results = parse_nuclei_results(stdout)
    logger.log(f"{Fore.LIGHTBLUE_EX}[+]{Style.RESET_ALL} {module_name} scan for {target} finished.")
    return json.dumps(nuclei_results, indent=4)


def parse_nuclei_results(stdout):
    try:
        output = stdout.decode().strip()
        if not output:
            return []  

        results = output.split("\n") 
        vulnerabilities = []

        for line in results:
            try:
                vulnerabilities.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        return vulnerabilities

    except Exception as e:
        logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} Failed to parse {module_name} results: {str(e)}")
        return []

