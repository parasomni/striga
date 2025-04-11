<div align="center">
  <h1 style="font-size: 30px; margin-bottom: 0;">Striga Attack Framework</h1>
</div>
<p align="center">
  <img src="logo/STRIGA.png" alt="Striga Logo" width="300"/>
</p>

This Framework is intended to automate scanning, enumeration and exploitation. It uses common tools for those tasks and evaluates their findings. The modular design allows to add any tool for further investigations as administer tools manually in the yaml configuration. Striga has an inbuild script execution for useful programs that can be added to the utils folder.

## Installation
Run the `install.sh` script to install striga:

    ./install.sh

After the install script has finished, striga can be executed by just typing `striga`.

## Help menu:

    [ user ~  ]# striga -h

               __         .__              
       _______/  |________|__| _________   
      /  ___/\   __\_  __ \  |/ ___\__  \  
      \___  \ |  |  |  | \/  / /_/  / __ \_
     /____  / |__|  |__|  |__\___  (____  /
          \/                /_____/     \/ v1.0.0


    [+] Starting striga v1.0.0 at 2025-04-09T15:59:22
    usage: striga.py [-h] [--target TARGET] [--targets TARGETS] [--auto-enum] [--auto-exploit] [--auto-all] [--scan] [--enum ENUM_SERVICE]
                    [--exploit CVE_FILE] [--interactive] [--config CONFIG] [--log LOG] [--continue] [--continue-scanid CONTINUE_SCAN_ID]
                    [--show-service SERVICE] [--list-services] [--list-modules] [--show-id SHOW_ID] [--debug] [--add-module ADD_MODULE]
                    [script] ...

    [Striga Attack Framework]

    positional arguments:
      script                Script to run from utils folder
      script_args           Arguments for the script

    options:
      -h, --help            show this help message and exit

    Target specification:
      --target TARGET       Specify a single target (IP or domain)
      --targets TARGETS     Specify a file with multiple targets

    Automation:
      --auto-enum           Enable automated enumeration
      --auto-exploit        Enable automated exploitation
      --auto-all            Enable full automation (scan -> enum -> exploit)

    Manual execution:
      --scan                Run scanning module manually
      --enum ENUM_SERVICE   Specify the service for manual enumeration (or <all> to include every service)
      --exploit CVE_FILE    Run exploitation module manually by providing a file containing CVE's
      --interactive         Run in interactive mode

    General configuration:
      --config CONFIG       Specify a custom configuration file
      --log LOG             Specify a custom logging file
      --continue            Continues the last scan
      --continue-scanid CONTINUE_SCAN_ID
                            Continues a scan by id

    Result presentation:
      --show-service SERVICE
                            Show the results of a specified service(e.g web, smb)
      --list-services       List all available services to present
      --list-modules        List all available enumeration modules
      --show-id SHOW_ID     Specify a scan id to show results. If this option is not provided, the last scan id is used.

    Developer options:
      --debug               Enable debug mode
      --add-module ADD_MODULE
                            Specify the module name and service (eg. 'whatweb,web')

    Available scripts in utils folder:
      pwdfinder
      revshells
      ...

    Examples:
      python3 striga.py --target 10.10.14.109 --exploit cve_numbers.json
      python3 striga.py --targets targets.txt --auto-all
      python3 striga.py revshells -h


## Scanning and Enumeration
Striga can include a wide range of tools to automate scanning and enumeration tasks. The `--auto-enum`  feature launches enabled tools based on a `nmap` port scan to detect services used on the target system. The results are saved to individual files in the `/etc/striga` directory.

    python3 striga.py --target 10.10.14.109 --auto-enum

## Exploitation
Dealing with vulnerability scanners and metasploit to find already working exploits for detected CVE numbers can be time intensive and tough sometimes. Striga's exploit feature helps to automate this task. It executes various vulnerability scanner, sums up their results and searches for exploits matching the CVE number in the metasploit database. After matching an `excellent` ranked exploit striga launches `metatsploit` to set the required options and finally launches the exploit on the target. If the exploit was successfull a shell will prompt to interact with the target system.
To use this feature `--exploit` or `--auto-exploit` can be selected:

    python3 striga.py --target 10.10.14.109 --auto-exploit
    python3 striga.py --target 10.10.14.109 --exploit cve_numbers.json

## Evaluation
After a successfull target enumeration the `--show-service` option can be used to print the results based on the selected service.

## Script execution
Sometimes it can be helpful to keep frequently used scripts in one spot. `Striga` can execute those scripts located in the `utils` folder like one of their own features.

    python3 striga.py revshells -h