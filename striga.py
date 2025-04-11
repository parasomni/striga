import asyncio
import os
import subprocess
import re

from colorama import Fore, Style
from datetime import datetime

from core import parser
from core import config
from core import logger
from core import check_dir

from enumeration.web import run_ffuf_enum
from enumeration.web import run_nmap_http_enum
from enumeration.web import run_gobuster_enum
from enumeration.web import run_dirbuster_enum
from enumeration.web import run_whatweb_enum
from enumeration.web import run_whois_enum
from enumeration.smb import run_enum4linux_enum
from enumeration.smb import run_smbclient_enum
from enumeration.dns import run_dnsenum_enum
from enumeration.dns import run_nslookup_enum
from enumeration.sql import run_sqlmap_enum
from enumeration.ldap import run_ldapsearch_enum
from enumeration import run_enumerator
from enumeration import run_module_adder

from evaluation import run_presenter
from evaluation import list_services
from evaluation import get_services_list

from exploitation import exploit_from_cve_results

from scanner import run_nmap
from scanner import run_vuln_scanners  

def run_script(script_name, script_args):
    if not re.match(r'^[a-zA-Z0-9_]+$', script_name):
        logger.log(f"Invalid script name: {script_name}")
        return

    interpreters = {
        ".py": ["python3"],
        ".sh": ["bash"],
        ".js": ["node"],
        ".pl": ["perl"],
        ".rb": ["ruby"],
        ".ps1": ["pwsh", "-File"],
        ".php": ["php"],
    }

    for ext, command in interpreters.items():
        script_path = f"/opt/striga/utils/{script_name}{ext}"
        if os.path.exists(script_path):
            subprocess.run(command + [script_path] + script_args)
            return

    logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} Script not found: {Fore.LIGHTCYAN_EX}{script_name}{Style.RESET_ALL}")


def prepare_vuln_cache(target):
    config.vuln_cache_path = config.get_config_value("location", "framework") + '/' + config.scan_id + '/' + target + '/'
    check_dir(config.vuln_cache_path)         
    config.vuln_cache_file = config.vuln_cache_path + config.get_config_value("vuln_cache", "framework")

async def enumeration(target):
    """Performs scanning, then triggers enumeration asynchronously."""    
    check_dir(config.get_config_value("location", "framework") + '/' + config.scan_id + '/' + target + '/')

    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Scanning {target}...")
    scan_results = await run_nmap(target) 

    enum_tasks = []
    if "smb" in scan_results:
        enum_tasks.append(run_smbclient_enum(target))
        enum_tasks.append(run_enum4linux_enum(target))
        
    if "http" in scan_results:
        enum_tasks.append(run_ffuf_enum(target))
        enum_tasks.append(run_nmap_http_enum(target))
        enum_tasks.append(run_gobuster_enum(target))
        enum_tasks.append(run_dirbuster_enum(target))
        enum_tasks.append(run_whatweb_enum(target))
        enum_tasks.append(run_whois_enum(target))

    if "dns" in scan_results:
        enum_tasks.append(run_dnsenum_enum(target))
        enum_tasks.append(run_nslookup_enum)

    if "sql" in scan_results:
        enum_tasks.append(run_sqlmap_enum(target))

    if "ldap" in scan_results:
        enum_tasks.append(run_ldapsearch_enum(target))

    if enum_tasks:
        await asyncio.gather(*enum_tasks)
    logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} Enumeration completed for {target}.")


async def exploiting(target, cve_file=None):
    """Runs a vulnerability scanner and launches exploits if vulnerabilities are found."""
    prepare_vuln_cache(target)
    vulnerabilities = ""

    if not cve_file:
        if config.continue_scan and not os.path.exists(config.vuln_cache_file):
            logger.log(f"{Fore.LIGHTRED_EX}[-]{Style.RESET_ALL} No cached scan results found for {target}.")
            logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Launching vulnerability scanner on {target}...")
            vulnerabilities = await run_vuln_scanners(target) 
        elif not config.continue_scan:
            logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Launching vulnerability scanner on {target}...")
            vulnerabilities = await run_vuln_scanners(target) 

    else:
        try:
            with open(cve_file, 'r') as file:
                vulnerabilities = file.read()
            file.close()
        except Exception as error:
            logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} Failed to open CVE file: {error}")

    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Executing exploit launcher...")
    await exploit_from_cve_results(target, vulnerabilities)


def print_striga():
    logger.log(rf"""{Fore.LIGHTBLACK_EX}
          __          __              
  _______/  |________|__| _________   
 /  ___/\   __\_  __ \  |/ ___\__  \  
 \___  \ |  |  |  | \/  / /_/  / __ \_
/____  / |__|  |__|  |__\___  (____  /
     \/                /_____/     \/ v{config.version}

{Style.RESET_ALL}""")

async def run_striga(args):
    if args.config:
        config.reinitialize(args.config)
    
    config.clean_cache()

    targets = []
    if args.target:
        targets.append(args.target)
    elif args.targets:
        with open(args.targets, "r") as f:
            targets.extend(line.strip() for line in f.readlines())

    if not targets:
        logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} No target specified. Use --target or --targets.")
        exit(1)

    continue_last_scan = args.continue_scan and config.cached_scan_id
    if continue_last_scan:
        logger.log(f"{Fore.LIGHTBLUE_EX}[+]{Style.RESET_ALL} Continuing {config.cached_scan_id}")
        config.continue_scan = True
        config.scan_id = config.cached_scan_id
        config.save_scan_id()
    
    continue_scan_id = args.continue_scan_id
    if continue_scan_id:
        logger.log(f"{Fore.LIGHTBLUE_EX}[+]{Style.RESET_ALL} Continuing {continue_scan_id}")
        config.continue_scan = True
        config.scan_id = continue_scan_id
        config.save_scan_id()
    
    new_scan = False if (config.continue_scan and continue_last_scan) or (config.continue_scan and config.cached_scan_id) else True 
    if new_scan:
        config.prepare_scan_id()
        config.save_scan_id()

    logger.log(f"{Fore.LIGHTBLUE_EX}[+]{Style.RESET_ALL} Scan ID: {config.scan_id}")

    if args.interactive:
        logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Running in interactive mode...")
        while True:
            logger.log(f"{Fore.LIGHTBLUE_EX}[?]{Style.RESET_ALL} What would you like to do? (scan, enum, exploit, exit) ")
            choice = input(f"{Fore.LIGHTBLUE_EX}[?]{Style.RESET_ALL} > ").strip().lower()
            if choice == "scan":
                for target in targets:
                    await run_nmap(target)
            elif choice == "enum":
                logger.log(f"{Fore.LIGHTBLUE_EX}[?]{Style.RESET_ALL} What service would you like to enumerate? Type 'all' to include every service.")
                service_list, _ = get_services_list()
                list_services(service_list)
                service = input(f"{Fore.LIGHTBLUE_EX}[?]{Style.RESET_ALL} Select service: ").strip().lower()
                for target in targets:
                    await run_enumerator(target, service)
            elif choice == "exploit":
                for target in targets:
                    await exploiting(target)
            elif choice == "exit":
                logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Exiting interactive mode.")
                break
            else:
                logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} Invalid choice.")

    if args.scan:
        for target in targets:
            await run_nmap(target)

    if args.enum_service:
        for target in targets:
            await run_enumerator(target, args.enum_service)

    if args.cve_file:
        for target in targets:
            await exploiting(target, args.cve_file)

    if args.auto_enum:
        for target in targets:
            await enumeration(target)

    if args.auto_exploit:
        for target in targets:
            await exploiting(target)

    if args.auto_all:
        scan_tasks = [enumeration(target) for target in targets]

        vuln_tasks = [exploiting(target) for target in targets]

        await asyncio.gather(*scan_tasks, *vuln_tasks)

        logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} Execution complete.")


def main():
    print_striga()
    logger.log(f"{Fore.LIGHTBLUE_EX}[+]{Style.RESET_ALL} Starting striga v{config.version} at {datetime.now().replace(microsecond=0).isoformat()}") 
    args = parser.parse_args()

    if args.debug:
        config.debug = True
    
    if config.debug:
        logger.log(f"{Fore.LIGHTGREEN_EX}[*]{Style.RESET_ALL} Debug enabled.")

    if args.script:
        run_script(args.script, args.script_args)
    elif args.service or args.list_services:
        run_presenter(args.service, args.show_id, args.list_services)
    elif args.list_modules:
        run_presenter(args.service, args.show_id, args.list_services, args.list_modules)
    elif args.add_module:
        module, service = args.add_module
        run_module_adder(module, service)
    else:
        try:
            asyncio.run(run_striga(args))
        except KeyboardInterrupt:
            logger.log(f"\r\n{Fore.LIGHTYELLOW_EX}[W]{Style.RESET_ALL} Keyboard interrupt detected.")

if __name__ in '__main__':
    main()