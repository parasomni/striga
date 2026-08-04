import asyncio
import json

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
from enumeration.web import run_webtech_enum
from enumeration.smb import run_enum4linux_enum
from enumeration.smb import run_smbclient_enum
from enumeration.dns import run_dnsenum_enum
from enumeration.dns import run_nslookup_enum
from enumeration.sql import run_sqlmap_enum
from enumeration.ldap import run_ldapsearch_enum

from scanner import extract_web_ports, extract_all_ports

from evaluation import get_services_list


def _read_cached_nmap_output(target):
    nmap_result_file = config.get_target_scan_path(target) + "nmap.txt"
    try:
        with open(nmap_result_file, "r") as f:
            return f.read()
    except FileNotFoundError:
        return None


def _discover_web_ports(target):
    """run_enumerator can be invoked standalone (e.g. `--enum web`) without a fresh
    nmap scan in this call, so it reads the target's last nmap.txt (if any) to find
    the actual open web ports instead of assuming port 80."""
    nmap_output = _read_cached_nmap_output(target)
    if nmap_output is None:
        return [{"port": 80, "scheme": "http", "service": "http"}]

    web_ports = extract_web_ports(nmap_output)
    return web_ports or [{"port": 80, "scheme": "http", "service": "http"}]


def _discover_all_ports(target):
    """Same as _discover_web_ports but unfiltered -- whatweb/webtech should probe
    every open port from the last scan, not just ones nmap tagged as http-ish."""
    nmap_output = _read_cached_nmap_output(target)
    if nmap_output is None:
        return [{"port": 80, "scheme": "http", "service": "http"}]

    all_ports = extract_all_ports(nmap_output)
    return all_ports or [{"port": 80, "scheme": "http", "service": "http"}]


def _promote_confirmed_web_ports(target, all_ports, web_ports):
    """After whatweb/webtech have run against every open port, promote any port
    nmap didn't tag as http but that webtech actually found product/version data
    on into web_ports -- so ffuf/gobuster/dirbuster/nmap-http still only ever
    target ports with real evidence of a web service, not every open port (which
    would waste time/traffic brute-forcing e.g. an SSH port)."""
    web_port_numbers = {e["port"] for e in web_ports}
    promoted = list(web_ports)

    for endpoint in all_ports:
        port = endpoint["port"]
        if port in web_port_numbers:
            continue

        webtech_file = config.get_target_scan_path(target) + f"webtech_{port}.json"
        try:
            with open(webtech_file, "r") as f:
                products = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            continue

        if products:
            detected = ", ".join(products.keys())
            logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} Port {port} on {target} wasn't nmap-tagged as http, but webtech confirmed a web app there ({detected}) -- adding to brute-force targets.")
            promoted.append(endpoint)
            web_port_numbers.add(port)

    return promoted


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
        all_ports = _discover_all_ports(target)
        fingerprint_summary = ", ".join(f"{e['scheme']}://{target}:{e['port']}" for e in all_ports)
        logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Fingerprinting all open port(s) on {target}: {fingerprint_summary}")
        fingerprint_tasks = []
        for endpoint in all_ports:
            fingerprint_tasks.append(run_whatweb_enum(target, endpoint["port"], endpoint["scheme"]))
            fingerprint_tasks.append(run_webtech_enum(target, endpoint["port"], endpoint["scheme"]))
        await asyncio.gather(*fingerprint_tasks)

        web_ports = _promote_confirmed_web_ports(target, all_ports, _discover_web_ports(target))
        endpoint_summary = ", ".join(f"{e['scheme']}://{target}:{e['port']}" for e in web_ports)
        logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Web enumeration targets for {target}: {endpoint_summary}")

        enum_tasks.append(run_whois_enum(target))
        for endpoint in web_ports:
            port, scheme = endpoint["port"], endpoint["scheme"]
            enum_tasks.append(run_ffuf_enum(target, port, scheme))
            enum_tasks.append(run_nmap_http_enum(target, port, scheme))
            enum_tasks.append(run_gobuster_enum(target, port, scheme))
            enum_tasks.append(run_dirbuster_enum(target, port, scheme))
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