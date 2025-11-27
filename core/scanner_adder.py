import sys
import re
import json
import yaml

from colorama import Fore, Style

striga_file = "/opt/striga/striga.py"
enumerator_file = "/opt/striga/scanner/scanner.py"
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

def write_scanner_file(scanner):
    module_script = f"""
import asyncio
import subprocess
import json
from colorama import Fore, Style

from core import config
from core import logger

module_name = "{scanner}"

async def run_{scanner}_scan(target):
    enabled = config.get_config_value("enabled", f"scanner:{{module_name}}")
    if not enabled:
        logger.debug(f"{{Fore.LIGHTYELLOW_EX}}[!]{{Style.RESET_ALL}} {{module_name}} scanning is disabled in the configuration.")
        return

    {scanner}_flags = config.get_tool_flags(module_name, "scanner")

    logger.log(f"{{Fore.LIGHTBLUE_EX}}[*]{{Style.RESET_ALL}} Launching {{module_name}} on {{target}}...")

    cmd = [module_name, "-target", target] + {scanner}_flags

    process = await asyncio.create_subprocess_exec(
        *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        logger.log(f"{{Fore.LIGHTRED_EX}}[!]{{Style.RESET_ALL}} {{module_name}} failed for {{target}}: {{stderr.decode()}}")
        return {{}}

    {scanner}_results = parse_{scanner}_results(stdout)
    logger.log(f"{{Fore.LIGHTBLUE_EX}}[+]{{Style.RESET_ALL}} {{module_name}} scan for {{target}} finished.")
    return json.dumps({scanner}_results, indent=4)


def parse_{scanner}_results(stdout):
    try:
        output = stdout.decode().strip()
        if not output:
            return []  

        results = output.split("\\n") 
        vulnerabilities = []

        for line in results:
            try:
                vulnerabilities.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        return vulnerabilities

    except Exception as e:
        logger.log(f"{{Fore.LIGHTRED_EX}}[!]{{Style.RESET_ALL}} Failed to parse {{module_name}} results: {{str(e)}}")
        return []
"""
    module_file = "/opt/striga/scanner/"+ scanner + "_scanner.py"
    
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


def modify_striga(module):
    from core import logger
    striga_data = read_file(striga_file)

    module_import = f"from scanner import run_{module}_scan"

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

    write_file(striga_file, striga_data)
    

def modify_scanner(scanner):
    from core import logger
    enumerator_data = read_file(enumerator_file)
    lines = enumerator_data.splitlines(keepends=True)

    module_import = f"""
async def run_{scanner}_scan(target):
    from scanner import run_{scanner}_scan

    enabled = config.get_config_value("enabled", "scanner:{scanner}")
    if not enabled:
        return None

    results = await run_{scanner}_scan(target)
    return {{"{scanner}": results}}
"""
    import_pattern = re.compile(r'^\s*(import\s+.+|from\s+\S+\s+import\s+.+)')
    last_import_index = -1

    for i, line in enumerate(lines):
        stripped = line.strip()
        if import_pattern.match(line):
            last_import_index = i
        elif stripped.startswith("#") or stripped == "":
            # allow comments and blanks inside the import block
            continue
        else:
            if last_import_index != -1:
                break


    block_lines = [line if line.endswith("\n") else line + "\n" for line in module_import.splitlines()]

    insert_index = last_import_index + 1
    lines[insert_index:insert_index] = block_lines

    if module_import.strip() not in "".join(lines):
        logger.debug(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Adding import: {module_import.strip()}")
        import_indexes = [i for i, line in enumerate(lines) if line.startswith("from scanner.")]
        if not import_indexes:
            sys.exit(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} No import lines found.")
        insert_idx = import_indexes[-1] + 1
        lines.insert(insert_idx, module_import)

    # ---------------------------------------
    # Insert new scanner entry into tasks dict
    # ---------------------------------------
    task_pattern = re.compile(r'^\s*tasks\s*=\s*\{')
    task_start = None
    task_end = None

    for i, line in enumerate(lines):
        if task_pattern.match(line):
            task_start = i
            break

    if task_start is not None:
        for j in range(task_start + 1, len(lines)):
            if lines[j].strip().startswith("}"):
                task_end = j
                break

    if task_start is None or task_end is None:
        logger.debug(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} Could not locate tasks block.")
    else:
        # Build new task entry (NO comma at end)
        new_task_line = f'        "{scanner}": run_{scanner}_scan(target)\n'

        # Check if already exists
        if new_task_line not in lines:
            logger.debug(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Adding scanner task entry: {scanner}")

            # 1. Fix last entry above: ensure it ends with a comma
            last_task_line_index = task_end - 1
            if not lines[last_task_line_index].rstrip().endswith(','):
                lines[last_task_line_index] = lines[last_task_line_index].rstrip() + ",\n"

            # 2. Insert new line BEFORE closing brace '}'
            lines.insert(task_end, new_task_line)
        else:
            logger.debug(f"{Fore.LIGHTYELLOW_EX}[i]{Style.RESET_ALL} Scanner task '{scanner}' already present.")

    write_file(enumerator_file, "".join(lines))

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

def modify_init(module):
    function_name = f"run_{module}_scan"
    import_line = f"from .{module}_scanner import {function_name}"

    init_file = f"/opt/striga/scanner/__init__.py"
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


def run_scanner_adder(module):
    from core import logger
    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Starting scanner adder.")

    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Adding %s to services list." % (module))
    if not modify_services_list(module, "scanner"):
        logger.log(f"{Fore.LIGHTYELLOW_EX}[W]{Style.RESET_ALL} Module already added to striga.")
        sys.exit()

    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Generating %s script file." % (module))
    module_file = write_scanner_file(module)
    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Adding %s to init file." % (module))
    modify_yaml(module)
    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Adding %s to yaml config." % (module))
    modify_init(module)
    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Adding %s to vuln_scanner." % (module))
    modify_scanner(module)
    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Adding %s to striga." % (module))
    modify_striga(module)
    logger.log(f"{Fore.LIGHTGREEN_EX}[*]{Style.RESET_ALL} Scanner %s added successfully." % (module))

    logger.log(f"{Fore.LIGHTYELLOW_EX}[W]{Style.RESET_ALL} Note: The target flag may has to be manually adjusted in the script file {Fore.LIGHTCYAN_EX}{module_file}{Style.RESET_ALL} depending on the added tool.")


