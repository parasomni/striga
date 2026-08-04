import glob
import json
import os

from core import config
from core import logger

from colorama import Fore,Style


def load_results(file_name):
    with open(file_name, 'r') as file:
        results = file.read()
    file.close()

    return results

def get_services_list():
    with open(config.get_config_value("services_list", "framework"), 'r') as file:
        json_doc = json.load(file)

    services_list = list(json_doc.keys())
    return services_list, json_doc


def list_services(services_list):
    logger.log(f"{Fore.LIGHTBLUE_EX}=" * 50)
    logger.log(f"{Fore.LIGHTYELLOW_EX}[*]{Style.RESET_ALL} Listing available services: ")
    
    for service in services_list:
        logger.log(f"{Fore.LIGHTYELLOW_EX}[+]{Style.RESET_ALL} {service}")
    
    logger.log(f"{Fore.LIGHTBLUE_EX}=" * 50)


def show_service(service, scanid, json_doc):
    tools = json_doc[service]

    tool_path = config.frm_path + '/' + scanid + '/'

    for path, targets, files in os.walk(tool_path):
        for target in targets:
            for tool in tools:
                target_dir = tool_path + target + '/'

                # Per-port web tools now write <tool>_<port>.txt/.json (one file per
                # discovered web port) instead of a single <tool>.txt/.json, so match
                # both shapes rather than a single exact filename.
                matches = sorted(set(
                    glob.glob(target_dir + f'{tool}.txt') +
                    glob.glob(target_dir + f'{tool}.json') +
                    glob.glob(target_dir + f'{tool}_*.txt') +
                    glob.glob(target_dir + f'{tool}_*.json')
                ))

                if not matches:
                    logger.debug(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} Tool file not found: {target_dir}{tool}(.txt|.json)")
                    continue

                for tool_file in matches:
                    logger.log(f"{Fore.LIGHTBLUE_EX}=" * 50)
                    results = load_results(tool_file)
                    logger.log(f"{Fore.LIGHTYELLOW_EX}[+]{Style.RESET_ALL} Results for {Fore.LIGHTCYAN_EX}{os.path.basename(tool_file)}{Style.RESET_ALL}:")
                    logger.log(results)


def show_all(services_list, scanid, json_doc):
    for service in services_list:
        show_service(service, scanid, json_doc)


def get_module_names(json_doc):
    modules = set()
    for tools in json_doc.values():
        modules.update(tools)
    return modules


def show_module(module, scanid):
    tool_path = config.frm_path + '/' + scanid + '/'

    found_any = False
    for path, targets, files in os.walk(tool_path):
        for target in targets:
            target_dir = tool_path + target + '/'

            # Same per-port glob as show_service(): a module can have written
            # <module>_<port>.txt/.json (one per discovered port) instead of a
            # single <module>.txt/.json.
            matches = sorted(set(
                glob.glob(target_dir + f'{module}.txt') +
                glob.glob(target_dir + f'{module}.json') +
                glob.glob(target_dir + f'{module}_*.txt') +
                glob.glob(target_dir + f'{module}_*.json')
            ))

            if not matches:
                continue

            found_any = True
            for tool_file in matches:
                logger.log(f"{Fore.LIGHTBLUE_EX}=" * 50)
                results = load_results(tool_file)
                logger.log(f"{Fore.LIGHTYELLOW_EX}[+]{Style.RESET_ALL} Results for {Fore.LIGHTCYAN_EX}{target}/{os.path.basename(tool_file)}{Style.RESET_ALL}:")
                logger.log(results)

    if not found_any:
        logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} No saved results found for module '{module}' in scan {scanid}.")

def list_modules(services_list, json_doc):
    logger.log(f"{Fore.LIGHTBLUE_EX}=" * 50)
    logger.log(f"{Fore.LIGHTYELLOW_EX}[*]{Style.RESET_ALL} Listing available modules: ")
    
    for service in services_list:
        logger.log(f"{Fore.LIGHTYELLOW_EX}[+] {service}{Style.RESET_ALL}")
        for module in json_doc[service]:
            logger.log(f"{Fore.LIGHTCYAN_EX}[|] -- {module}{Style.RESET_ALL}")
    
    logger.log(f"{Fore.LIGHTBLUE_EX}=" * 50)

def list_scanners(services_list, json_doc):
    logger.log(f"{Fore.LIGHTBLUE_EX}=" * 50)
    logger.log(f"{Fore.LIGHTYELLOW_EX}[*]{Style.RESET_ALL} Listing available scanners: ")
    
    for service in services_list:
        if service == "scanner":
            logger.log(f"{Fore.LIGHTYELLOW_EX}[+] {service}{Style.RESET_ALL}")
            for module in json_doc[service]:
                logger.log(f"{Fore.LIGHTCYAN_EX}[|] -- {module}{Style.RESET_ALL}")
    
    logger.log(f"{Fore.LIGHTBLUE_EX}=" * 50)

def run_presenter(service, scanid, list_svc=False, list_mdl=False, list_sca=False, module=None):
    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Launching presenter...")

    services_list, json_doc = get_services_list()

    if list_svc:
        list_services(services_list)
        logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Presenter finished.")
        return

    if list_mdl:
        list_modules(services_list, json_doc)
        logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Presenter finished.")
        return

    if list_sca:
        list_scanners(services_list, json_doc)
        logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Presenter finished.")
        return

    if not scanid:
        scanid = config.cached_scan_id

    if module:
        if module not in get_module_names(json_doc):
            logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} Unknown module: {module}. Use --list-modules/--list-scanners to see available names.")
            return
        logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Printing results for module {Fore.LIGHTCYAN_EX}{module}{Style.RESET_ALL} in {scanid}.")
        show_module(module, scanid)
        logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Presenter finished.")
        return

    if service == "all":
        logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Printing results for {scanid}.")
        show_all(services_list, scanid, json_doc)

    elif service in services_list:
        logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Printing results for {scanid}.")
        show_service(service, scanid, json_doc)

    else:
        logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} Service not found: {service}")
        return
    
    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Presenter finished.")
    


    

