import asyncio

from colorama import Fore, Style

from core import logger
from core import config
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

from evaluation import get_services_list

async def run_enumerator(target, service):
    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Launching enumerator for {target}.")    
    check_dir(config.get_config_value("location", "framework") + '/' + config.scan_id + '/' + target + '/')

    services_list, _ = get_services_list()

    if service not in services_list and service != "all":
        logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} Specified service {service} not found. Use --list-services to check for available options.")
        return

    enum_tasks = []
    if service in ["smb", "all"]:
        enum_tasks.append(run_smbclient_enum(target))
        enum_tasks.append(run_enum4linux_enum(target))
    if service in ["web", "all"]:
        enum_tasks.append(run_ffuf_enum(target))
        enum_tasks.append(run_nmap_http_enum(target))
        enum_tasks.append(run_gobuster_enum(target))
        enum_tasks.append(run_dirbuster_enum(target))
        enum_tasks.append(run_whatweb_enum(target))
        enum_tasks.append(run_whois_enum(target))
    if service in ["dns", "all"]:
        enum_tasks.append(run_nslookup_enum)
        enum_tasks.append(run_dnsenum_enum)
    if service in ["sql", "all"]:
        enum_tasks.append(run_sqlmap_enum(target))
    if service in ["ldap", "all"]:
        enum_tasks.append(run_ldapsearch_enum(target))


    if enum_tasks:
        await asyncio.gather(*enum_tasks)

    logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} Enumerator completed for {target}.")