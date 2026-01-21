import sys
import re
import json
import yaml

from colorama import Fore, Style

striga_file = "/opt/striga/striga.py"
enumerator_file = "/opt/striga/enumeration/enumerator.py"
services_list_file = "/opt/striga/evaluation/services.json"

def read_file(file):
    try:
        with open(file, 'r') as f:
            data = f.read()
        f.close()
    except Exception as error:
        sys.exit(error)

    return data

def read_json(file):
    try:
        with open(file, 'r') as f:
            data = json.load(f)
        f.close()
    except Exception as error:
        sys.exit(error)

    return data

def write_file(file, data):
    try:
        with open(file, "w") as f:
            f.write(data)
        f.close()
    except Exception as error:
        sys.exit(error)

def write_json(file, data):
    try:
        with open(file, "w") as f:
            json.dump(data, f, indent=4)
        f.close()
    except Exception as error:
        sys.exit(error)

def write_module_file(module, service):
    module_script = f"""
import asyncio
import subprocess
from colorama import Fore, Style
from core import config, logger

module_name = "{module}"

async def run_{module}_enum(target):
""" + """
    enabled = config.get_config_value("enabled", f"scanner:{module_name}")
    if not enabled:
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} {module_name} scanning is disabled in the configuration.")
        return
    
    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Launching {module_name} scan on {target}...")
    
    module_flags = config.get_tool_flags(module_name, "scanner")

    result_file = config.get_target_scan_path(target) + f'{module_name}.txt'

    cmd = [module_name] + module_flags + [target] + [">", result_file]
    
    logger.debug(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Executing module: {cmd}")

    with open(result_file, "w", encoding="utf-8") as outfile:
        process = await asyncio.create_subprocess_exec(
            module_name, *module_flags, target,
            stdout=outfile,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            _, stderr = await asyncio.wait_for(process.communicate(), timeout=config.timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} {module_name} scan timed out for {target}.")
            return {}

        if process.returncode != 0:
            logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} {module_name} scan failed for {target}: {stderr.decode()}")
            return {}

    logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} {module_name} results written to {Fore.LIGHTCYAN_EX}{result_file}{Style.RESET_ALL}")
    logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} {module_name} scan finished for {target}.")

    return {}
"""

    module_file = "/opt/striga/enumeration/" + service + '/' + module + "_enum.py"
    
    write_file(module_file, module_script)
    return module_file


def modify_yaml(module, category="scanner"):
    from core import logger
    file_path = "/opt/striga/config.yaml"
    module_config = {
        'enabled': False,
        'flags': [" "]
    }

    with open(file_path, 'r') as file:
        data = yaml.safe_load(file)

    if category not in data:
        data[category] = {}

    if module not in data[category]:
        data[category][module] = module_config
    else:
        logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} '{module}' already exists in yaml config.")
        return

    with open(file_path, 'w') as file:
        yaml.dump(data, file, default_flow_style=False, sort_keys=False)


def modify_striga(module, service):
    from core import logger
    striga_data = read_file(striga_file)

    module_import = f"from enumeration.{service} import run_{module}_enum"

    module_import_matches = [match for match in re.finditer(module_import, striga_data)]

    if not module_import_matches:
        logger.debug(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Adding {module_import} to striga.py")
        matches = [match for match in re.finditer(r"from enumeration\..+", striga_data)]
        if not matches:
            logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} This should never happen.")
            sys.exit()
            
        last_match = matches[-1]
        insert_position = last_match.end()

        striga_data = striga_data[:insert_position] + "\n" + module_import + striga_data[insert_position:]

    if service == "web":
        service = "http"

    matches = list(re.finditer(
        r'\n\s*if\s+"[^"]+"\s+in\s+scan_results\s*:\n((?:\s+enum_tasks\.append\(.*\)\n)+)',
        striga_data
    ))

    new_task_line = f"enum_tasks.append(run_{module}_enum(target))"

    if matches:
        for match in matches:
            logger.debug(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Adding {new_task_line} to striga.py")
            if f'"{service}" in scan_results' in match.group(0):
                existing_block = match.group(0)
                last_line_indent = re.search(r'(\s*)enum_tasks\.append', match.group(1))
                indentation = last_line_indent.group(1) if last_line_indent else " " * 8
                new_block = existing_block + f"{indentation}{new_task_line}\n"
                striga_data = striga_data.replace(existing_block, new_block)
                break
        else:
            logger.debug(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Adding {new_task_line} to striga.py")
            last_block = matches[-1]
            insertion_point = last_block.end()
            indent = " " * 4
            new_if_block = (
                f"\n{indent}if \"{service}\" in scan_results:\n"
                f"{indent*2}{new_task_line}\n"
            )
            striga_data = striga_data[:insertion_point] + new_if_block + striga_data[insertion_point:]

    else:
        logger.debug(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Adding {new_task_line} to striga.py")
        fallback_match = re.search(r'\n\s*if\s+enum_tasks\s*:', striga_data)
        insertion_point = fallback_match.start() if fallback_match else len(striga_data)

        indent = " " * 4
        new_if_block = (
            f"\n{indent}if \"{service}\" in scan_results:\n"
            f"{indent*2}{new_task_line}\n"
        )
        striga_data = striga_data[:insertion_point] + new_if_block + striga_data[insertion_point:]

    write_file(striga_file, striga_data)


def modify_enumerator(module, service):
    from core import logger
    enumerator_data = read_file(enumerator_file)
    lines = enumerator_data.splitlines(keepends=True)

    module_import = f"from enumeration.{service} import run_{module}_enum\n"
    new_task_line = f"        enum_tasks.append(run_{module}_enum(target))\n"

    if module_import.strip() not in "".join(lines):
        logger.debug(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Adding import: {module_import.strip()}")
        import_indexes = [i for i, line in enumerate(lines) if line.startswith("from enumeration.")]
        if not import_indexes:
            sys.exit(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} No import lines found.")
        insert_idx = import_indexes[-1] + 1
        lines.insert(insert_idx, module_import)

    block_start = None
    block_end = None
    for i, line in enumerate(lines):
        if line.strip().startswith("if service in [") and f'"{service}"' in line:
            block_start = i
            for j in range(i + 1, len(lines)):
                if not lines[j].startswith(" " * 8) and lines[j].strip() != "":
                    block_end = j
                    break
            else:
                block_end = len(lines)
            break

    if block_start is not None:
        block_lines = lines[block_start:block_end]
        if new_task_line in block_lines:
            logger.debug(f"{Fore.YELLOW}[=]{Style.RESET_ALL} Task already exists. Skipping.")
        else:
            logger.debug(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Adding task to service block.")
            lines.insert(block_end, new_task_line)
    else:
        logger.debug(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Creating new block for service '{service}'.")
        fallback_idx = next((i for i, line in enumerate(lines) if "if enum_tasks" in line), len(lines))
        new_block = (
            f"\n    if service in [\"{service}\", \"all\"]:\n"
            f"{new_task_line}"
        )
        lines.insert(fallback_idx, new_block)

    write_file(enumerator_file, "".join(lines))


def modify_init(module, service):
    function_name = f"run_{module}_enum"
    import_line = f"from .{module}_enum import {function_name}"

    init_file = f"/opt/striga/enumeration/{service}/__init__.py"
    init_code = read_file(init_file)

    if import_line not in init_code:
        import_lines = re.findall(r'^from\s+\..*?import\s+.*$', init_code, re.MULTILINE)
        if import_lines:
            last_import = import_lines[-1]
            insert_pos = init_code.index(last_import) + len(last_import)
            init_code = init_code[:insert_pos] + "\n" + import_line + init_code[insert_pos:]
        else:
            init_code = import_line + "\n" + init_code

    all_block_pattern = r'__all__\s*=\s*\[(.*?)\]'
    all_block_match = re.search(all_block_pattern, init_code, re.DOTALL)

    if all_block_match:
        all_list_raw = all_block_match.group(1)
        items = re.findall(r'"(.*?)"', all_list_raw)

        if function_name not in items:
            items.append(function_name)
            new_all = '__all__ = [\n' + ''.join(f'    "{item}",\n' for item in items) + ']'
            init_code = re.sub(all_block_pattern, new_all, init_code, flags=re.DOTALL)
    else:
        init_code += f'\n__all__ = [\n    "{function_name}",\n]\n'

    write_file(init_file, init_code)


def modify_services_list(module, service):
    services_list = read_json(services_list_file)

    if service in services_list:
        if module not in services_list[service]:
            services_list[service].append(module)
        else:
            return False
    
    else:
        services_list[service] = [module]

    write_json(services_list_file, services_list)
    return True


def run_module_adder(module, service):
    from core import logger
    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Starting module adder.")
    
    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Adding %s to services list." % (module))
    if not modify_services_list(module, service):
        logger.log(f"{Fore.LIGHTYELLOW_EX}[W]{Style.RESET_ALL} Module already added to striga.")
        sys.exit()
    
    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Generating %s script file." % (module))
    module_file = write_module_file(module, service)
    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Adding %s to init file." % (module))
    modify_yaml(module)
    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Adding %s to yaml config." % (module))
    modify_init(module, service)
    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Adding %s to enumerator." % (module))
    modify_enumerator(module, service)
    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Adding %s to striga." % (module))
    modify_striga(module, service)
    logger.log(f"{Fore.LIGHTGREEN_EX}[*]{Style.RESET_ALL} Module %s added successfully." % (module))

    logger.log(f"{Fore.LIGHTYELLOW_EX}[W]{Style.RESET_ALL} Note: The target flag may has to be manually adjusted in the script file {Fore.LIGHTCYAN_EX}{module_file}{Style.RESET_ALL} depending on the added tool.")


