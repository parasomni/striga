import argparse
import os

from colorama import Fore, Style

class CustomArgumentParser(argparse.ArgumentParser):
    def format_help(self):
        help_message = super().format_help()
        utils_scripts = self.get_utils_scripts()
        if utils_scripts:
            help_message += "\nAvailable scripts in utils folder:\n"
            help_message += "\n".join(f"  {script}" for script in utils_scripts)

        example_section = """\n
Examples:
  python3 striga.py --target 10.10.14.109 --exploit cve_numbers.json
  python3 striga.py --targets targets.txt --auto-all
  python3 striga.py revshells -h
        """
        return help_message + example_section

    def get_utils_scripts(self):
        utils_dir = os.path.join(os.path.dirname(__file__), '..', 'utils')
        supported_extensions = ['.py', '.sh', '.js', '.pl', '.rb', '.ps1', '.php']

        scripts = []
        for f in os.listdir(utils_dir):
            name, ext = os.path.splitext(f)
            if ext in supported_extensions:
                scripts.append(name)

        return scripts


class ArgumentParser:
    def __init__(self):
        self.parser = CustomArgumentParser(description=f"{Fore.LIGHTCYAN_EX}[{Fore.LIGHTBLACK_EX}Striga Attack Framework{Fore.LIGHTCYAN_EX}]{Style.RESET_ALL}")
        self.add_arguments()

    def add_arguments(self):
        target_group = self.parser.add_argument_group("Target specification")
        automation_group = self.parser.add_argument_group("Automation")
        manual_group = self.parser.add_argument_group("Manual execution")
        general_group = self.parser.add_argument_group("General configuration")
        result_group = self.parser.add_argument_group("Result presentation")
        developer_group = self.parser.add_argument_group("Developer options")
        
        target_group.add_argument("--target", help="Specify a single target (IP or domain)")
        target_group.add_argument("--targets", help="Specify a file with multiple targets")

        automation_group.add_argument("--auto-enum", action="store_true", help="Enable automated enumeration")
        automation_group.add_argument("--auto-exploit", action="store_true", help="Enable automated exploitation")
        automation_group.add_argument("--auto-all", action="store_true", help="Enable full automation (scan -> enum -> exploit)")

        manual_group.add_argument("--scan", action="store_true", help="Run scanning module manually")
        manual_group.add_argument("--enum", dest="enum_service", help="Specify the service for manual enumeration (or <all> to include every service)")
        manual_group.add_argument("--exploit", dest="cve_file", help="Run exploitation module manually by providing a file containing CVE's")
        manual_group.add_argument("--interactive", action="store_true", help="Run in interactive mode")

        general_group.add_argument("--config", help="Specify a custom configuration file")
        general_group.add_argument("--log", help="Specify a custom logging file")
        general_group.add_argument("--continue", dest="continue_scan", action="store_true", help="Continues the last scan")
        general_group.add_argument("--continue-scanid", dest="continue_scan_id", help="Continues a scan by id")
    
        result_group.add_argument("--show-service", dest="service", help="Show the results of a specified service(e.g web, smb or all for including every service)")
        result_group.add_argument("--list-services", action="store_true", help="List all available services to present")
        result_group.add_argument("--list-modules", action="store_true", help="List all available enumeration modules")
        result_group.add_argument("--show-id", help="Specify a scan id to show results. If this option is not provided, the last scan id is used.")

        developer_group.add_argument("--debug", action="store_true", help="Enable debug mode")
        developer_group.add_argument("--add-module", type=lambda s: s.split(','), help="Specify the module name and service (eg. 'whatweb,web')")

        self.parser.add_argument('script', nargs='?', help='Script to run from utils folder')
        self.parser.add_argument('script_args', nargs=argparse.REMAINDER, help='Arguments for the script')

    def parse_args(self):
        return self.parser.parse_args()
