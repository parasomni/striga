import asyncio
import json
import os
import subprocess
import re
import shutil
import time

from colorama import Fore, Style
from datetime import datetime

from core import parser
from core import config
from core import logger
from core import check_dir
from core import run_scanner_adder
from core import run_module_adder
from core import bounded_gather
from core import select_vhost
from core import suggest_unresolved_hosts

from enumeration.web import run_ffuf_enum
from enumeration.web import run_nmap_http_enum
from enumeration.web import run_gobuster_enum
from enumeration.web import run_dirbuster_enum
from enumeration.web import run_whatweb_enum
from enumeration.web import run_whois_enum
from enumeration.web import run_webtech_enum
from enumeration.web import run_feroxbuster_enum
from enumeration.web import run_sslscan_enum
from enumeration.web import run_wpscan_enum
from enumeration.web import run_vhostfuzz_enum
from enumeration.smb import run_enum4linux_enum
from enumeration.smb import run_smbclient_enum
from enumeration.smb import run_smbmap_enum
from enumeration.dns import run_dnsenum_enum
from enumeration.dns import run_nslookup_enum
from enumeration.snmp import run_snmpbulkwalk_enum
from enumeration.sql import run_sqlmap_enum
from enumeration.ldap import run_ldapsearch_enum
from scanner import run_rustscan_scan
from enumeration import run_enumerator

from evaluation import run_presenter
from evaluation import list_services
from evaluation import get_services_list

# NB: the evaluation.ai layer is imported lazily inside run_ai_evaluation() /
# _ai_collect_findings(), never at module top level. It pulls in an LLM backend
# client and is entirely optional -- a missing/broken AI layer (absent client,
# uninstalled backend dep) must degrade to "AI eval skipped", not take down the
# whole framework's scanning/enumeration/exploitation on import.

from exploitation import exploit_from_cve_results
from exploitation import lookup_cves_for_target

from scanner import run_nmap
from scanner import run_scanners
from scanner import extract_web_ports
from scanner import extract_all_ports
from scanner import extract_hostnames

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



# --- AI evaluation integration ------------------------------------------------
# Runs the local LLM findings-evaluation layer over a finished scan's saved tool
# output. Deterministic layer (evaluation/ai) verifies evidence, grounds CVEs,
# aligns severity to CVSS and flags low-confidence items; the model only triages.

_AI_BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".pdf",
    ".pcap", ".pcapng", ".bin", ".gz", ".zip", ".tar", ".7z", ".so", ".o", ".exe",
}

# Best-effort module -> service grouping so the report reads by service. Unknown
# modules fall back to "misc"; add new tools here as you extend the framework.
_AI_SERVICE_BY_MODULE = {
    "nmap": "scan", "rustscan": "scan",
    "ffuf": "web", "gobuster": "web", "dirbuster": "web", "whatweb": "web",
    "webtech": "web", "whois": "web", "nmap_http": "web", "http": "web",
    "feroxbuster": "web", "sslscan": "web", "wpscan": "web", "vhostfuzz": "web",
    "smbclient": "smb", "enum4linux": "smb", "smbmap": "smb",
    "dnsenum": "dns", "nslookup": "dns",
    "snmpbulkwalk": "snmp",
    "sqlmap": "sql",
    "ldapsearch": "ldap",
    "vuln_results": "vuln",
}


def _ai_llm_cfg():
    """Assemble the llm config dict from the [llm] section of config.yaml,
    tolerating a missing section/keys so the framework runs without it."""
    def val(key, default=None):
        try:
            v = config.get_config_value(key, "llm")
            return default if v is None else v
        except Exception:
            return default
    return {
        "enabled": val("enabled", True),
        "provider": val("provider", "ollama"),
        "model": val("model", "qwen2.5:14b-instruct"),
        "base_url": val("base_url", "http://127.0.0.1:11434"),
        "api_key_file": val("api_key_file", None),
        "timeout": val("timeout", 120),
        "temperature": val("temperature", 0.0),
        "max_input_chars": val("max_input_chars", 12000),
        "chunk_overlap_chars": val("chunk_overlap_chars", 400),
        "max_chunks_per_finding": val("max_chunks_per_finding", 20),
        "review_min_confidence": val("review_min_confidence", 0.5),
        "review_max_fp": val("review_max_fp", 0.5),
        "drop_below_confidence": val("drop_below_confidence", None),
        "output_format": val("output_format", "markdown"),
        "autostart": val("autostart", True),
    }


def _ai_module_name(filename):
    """nmap.txt -> nmap, whatweb_80.json -> whatweb, webtech_8080.json -> webtech."""
    stem = os.path.splitext(filename)[0]
    return re.sub(r"_\d+$", "", stem)


def _ai_vuln_cache_path(target):
    base = config.get_config_value("location", "framework") + '/' + config.scan_id + '/' + target + '/'
    return base + config.get_config_value("vuln_cache", "framework")


def _ai_target_cves(target):
    """Ground CVEs from the target's vulnerability cache so the evaluator can
    validate any CVE the model claims. Returns a de-duplicated list of CVE ids."""
    ids = set()
    try:
        with open(_ai_vuln_cache_path(target), "r", errors="replace") as f:
            ids.update(m.upper() for m in re.findall(r"CVE-\d{4}-\d{4,7}", f.read(), re.IGNORECASE))
    except Exception:
        pass
    return sorted(ids)


# vulners/nmap-vuln NSE prints "CVE-XXXX-YYYY\t<cvss>\t<url>". The (?!\d) stops the
# CVE id matching a prefix of a longer number (so CVE-2021-41773 isn't read as
# CVE-2021-4177 + "3"); the bounded numeric (0-9.x, 10 or 10.0) and <=6 non-digit
# gap keep it from pairing a CVE with an unrelated nearby number.
_CVSS_PAIR_RE = re.compile(r"(CVE-\d{4}-\d{4,7})(?!\d)\D{0,6}((?:10(?:\.0)?)|[0-9](?:\.[0-9])?)")


def _walk_cvss(node, scores):
    """Recursively pull {cve: cvss} pairs out of parsed scanner JSON. Handles
    nuclei's info.classification ({"cve-id": [...], "cvss-score": 7.5}) at any
    nesting depth, keying off whichever field spelling the tool used."""
    if isinstance(node, dict):
        score = node.get("cvss-score", node.get("cvss_score"))
        cves = node.get("cve-id") or node.get("cve_id") or node.get("cve")
        if score is not None and cves:
            try:
                s = float(score)
            except (TypeError, ValueError):
                s = None
            if s is not None and 0.0 <= s <= 10.0:
                for cve in (cves if isinstance(cves, list) else [cves]):
                    key = str(cve).strip().upper()
                    if key:
                        scores[key] = max(scores.get(key, 0.0), s)
        for value in node.values():
            _walk_cvss(value, scores)
    elif isinstance(node, list):
        for value in node:
            _walk_cvss(value, scores)


def _ai_target_cvss(target):
    """Best-effort {CVE: cvss_score} harvested from artifacts already on disk (the
    vuln cache: nuclei classification scores + vulners/nmap-vuln 'CVE  CVSS' lines).
    No network calls -- lets the evaluator align severity to CVSS deterministically
    instead of trusting the model's severity guess. Empty when nothing scored is
    cached yet (e.g. --auto-enum without an exploitation/vuln-scan pass)."""
    scores = {}
    try:
        with open(_ai_vuln_cache_path(target), "r", errors="replace") as f:
            text = f.read()
    except Exception:
        return {}

    # Structural pass: the cache is {scanner: result}, where a result may itself be
    # a JSON-encoded string (nuclei-vuln/nmap-vuln are stored as json.dumps(...)).
    try:
        cache = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        cache = None
    if cache is not None:
        def _maybe_decode(value):
            if isinstance(value, str):
                try:
                    return json.loads(value)
                except (json.JSONDecodeError, ValueError):
                    return value
            return value
        if isinstance(cache, dict):
            for value in cache.values():
                _walk_cvss(_maybe_decode(value), scores)
        else:
            _walk_cvss(cache, scores)

    # Text pass: catches vulners.nse "CVE  CVSS" lines that aren't structured JSON.
    for cve, score in _CVSS_PAIR_RE.findall(text):
        try:
            s = float(score)
        except ValueError:
            continue
        key = cve.upper()
        scores[key] = max(scores.get(key, 0.0), s)

    return scores


def _ai_collect_findings(target):
    """Read the target's saved tool outputs into RawFindings. Skips binary files
    and the evaluator's own report; derives module/service from the file name."""
    from evaluation.ai.schema import RawFinding

    scan_path = config.get_target_scan_path(target)
    if not os.path.isdir(scan_path):
        return []
    cve_ids = _ai_target_cves(target)
    cvss = _ai_target_cvss(target)
    base_context = {}
    if cve_ids:
        base_context["cve_ids"] = cve_ids
    if cvss:
        base_context["cvss"] = cvss
    findings = []
    for name in sorted(os.listdir(scan_path)):
        if name.startswith("ai_evaluation."):
            continue
        path = os.path.join(scan_path, name)
        if not os.path.isfile(path):
            continue
        if os.path.splitext(name)[1].lower() in _AI_BINARY_EXTS:
            continue
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError:
            continue
        if b"\x00" in blob[:8192]:
            continue
        raw = blob.decode("utf-8", "replace")
        if not raw.strip():
            continue
        module = _ai_module_name(name)
        service = _AI_SERVICE_BY_MODULE.get(module, "misc")
        findings.append(RawFinding(
            scan_id=config.scan_id, target=target, service=service, module=module,
            raw=raw, context=dict(base_context),
        ))
    return findings


def _ensure_ollama_running(llm_cfg, client):
    """Best-effort: if the (ollama) backend isn't reachable but the `ollama` binary
    is installed, start `ollama serve` in the background and wait briefly for it to
    come up. Only runs for the ollama provider, gated by llm.autostart (default on).
    Returns True once the backend is reachable, False otherwise -- never raises, so
    a failure here just falls through to the normal "backend unreachable" skip.

    Note: this starts the server, not the model. If the model isn't pulled yet the
    server will still answer health() but evaluation will surface per-item 'model
    not found' notices -- run `ollama pull <model>` once to fix that."""
    if client.health():
        return True
    if not llm_cfg.get("autostart", True):
        return False
    if str(llm_cfg.get("provider", "")).lower() != "ollama":
        return False
    if not shutil.which("ollama"):
        return False

    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Ollama not reachable at {Fore.LIGHTCYAN_EX}{llm_cfg.get('base_url')}{Style.RESET_ALL}; starting 'ollama serve'...")
    try:
        # Detached so it outlives this process; output discarded.
        subprocess.Popen(
            ["ollama", "serve"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as error:
        logger.log(f"{Fore.LIGHTYELLOW_EX}[-]{Style.RESET_ALL} Could not start Ollama: {error}")
        return False

    for _ in range(15):  # poll up to ~15s for the API to come up
        time.sleep(1)
        if client.health():
            logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} Ollama is up.")
            return True

    logger.log(f"{Fore.LIGHTYELLOW_EX}[-]{Style.RESET_ALL} Ollama did not become reachable in time.")
    return False


def run_ai_evaluation(args, target):
    """Evaluate a finished scan's findings with the local LLM layer. Gated by
    --ai-eval / --no-ai-eval (CLI) over llm.enabled (config.yaml). The AI layer is
    optional: if it can't be imported (missing client, uninstalled backend), log
    and skip rather than letting it propagate out of a finished scan."""
    try:
        from evaluation.ai import build_evaluator, is_ai_enabled, render
    except Exception as error:  # noqa: BLE001 - optional layer, never fatal
        logger.log(f"{Fore.LIGHTYELLOW_EX}[-]{Style.RESET_ALL} AI evaluation layer unavailable ({error}); skipping.")
        return

    llm_cfg = _ai_llm_cfg()
    if not is_ai_enabled(llm_cfg, cli_override=getattr(args, "ai_eval", None)):
        return

    evaluator = build_evaluator(llm_cfg)
    if not _ensure_ollama_running(llm_cfg, evaluator.client):
        logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} AI evaluation skipped: LLM backend unreachable at {Fore.LIGHTCYAN_EX}{llm_cfg.get('base_url')}{Style.RESET_ALL}")
        return

    findings = _ai_collect_findings(target)
    if not findings:
        logger.log(f"{Fore.LIGHTYELLOW_EX}[-]{Style.RESET_ALL} AI evaluation: no results to evaluate for {target}.")
        return

    fmt = getattr(args, "ai_format", None) or llm_cfg.get("output_format", "markdown")
    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Running AI evaluation for {Fore.LIGHTCYAN_EX}{target}{Style.RESET_ALL} ({len(findings)} module output(s))...")
    report = render(evaluator.evaluate(findings), fmt, source=findings)
    logger.log(report)

    ext = {"markdown": "md", "json": "json", "table": "txt"}.get(fmt, "txt")
    out_path = os.path.join(config.get_target_scan_path(target), f"ai_evaluation.{ext}")
    try:
        with open(out_path, "w") as fh:
            fh.write(report)
        logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} AI evaluation saved to {Fore.LIGHTCYAN_EX}{out_path}{Style.RESET_ALL}")
    except OSError as error:
        logger.log(f"{Fore.LIGHTYELLOW_EX}[-]{Style.RESET_ALL} Could not write AI evaluation report: {error}")


async def enumeration(target):
    """Performs scanning, then triggers enumeration asynchronously."""
    check_dir(config.get_config_value("location", "framework") + '/' + config.scan_id + '/' + target + '/')

    nmap_result_file = config.get_target_scan_path(target) + "nmap.txt"
    if config.continue_scan and os.path.exists(nmap_result_file):
        logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Continuing {config.scan_id}: cached scan/enumeration results found for {target}, skipping scanning and enumeration.")
        return

    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Scanning {target}...")
    scan_results = await run_nmap(target)

    enum_tasks = []
    if "smb" in scan_results:
        enum_tasks.append(run_smbclient_enum(target))
        enum_tasks.append(run_enum4linux_enum(target))
        enum_tasks.append(run_smbmap_enum(target))

    if "snmp" in scan_results:
        enum_tasks.append(run_snmpbulkwalk_enum(target))

    all_ports = extract_all_ports(scan_results)
    web_ports = extract_web_ports(scan_results)
    if not web_ports and "http" in scan_results:
        web_ports = [{"port": 80, "scheme": "http", "service": "http"}]
        all_ports = all_ports or web_ports

    if all_ports:
        fingerprint_summary = ", ".join(f"{e['scheme']}://{target}:{e['port']}" for e in all_ports)
        logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Fingerprinting all open port(s) on {target}: {fingerprint_summary}")
        # webtech_enum already runs whatweb (--log-json -a 3) internally plus the
        # Wappalyzer/httpx supplements, so a separate whatweb_enum pass here would
        # just launch whatweb a second time per port. Fingerprint via webtech only.
        fingerprint_tasks = []
        for endpoint in all_ports:
            fingerprint_tasks.append(run_webtech_enum(target, endpoint["port"], endpoint["scheme"]))
        await bounded_gather(fingerprint_tasks)

        web_ports = _promote_confirmed_web_ports(target, all_ports, web_ports)

    if web_ports:
        # Pull any virtual-host / DNS name out of the scan (TLS cert CN/SAN, HTTP
        # redirect, rDNS) so web enum targets the real hostname instead of the bare
        # IP -- name-based vhosts serve the wrong site by IP and SNI TLS needs the
        # name. Routed via Host header / SNI (non-persistent); unresolved names get
        # an /etc/hosts suggestion for tools that need real DNS.
        hostnames = extract_hostnames(scan_results)
        vhost = select_vhost(target, hostnames)
        if vhost:
            logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} Using virtual host {Fore.LIGHTCYAN_EX}{vhost}{Style.RESET_ALL} for web enumeration on {target}.")
        suggest_unresolved_hosts(hostnames, target)

        endpoint_summary = ", ".join(f"{e['scheme']}://{target}:{e['port']}" for e in web_ports)
        logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Web service(s) detected on {target}: {endpoint_summary}")
        enum_tasks.append(run_whois_enum(target))
        for endpoint in web_ports:
            port, scheme = endpoint["port"], endpoint["scheme"]
            enum_tasks.append(run_ffuf_enum(target, port, scheme, host=vhost))
            enum_tasks.append(run_nmap_http_enum(target, port, scheme, host=vhost))
            enum_tasks.append(run_gobuster_enum(target, port, scheme, host=vhost))
            enum_tasks.append(run_dirbuster_enum(target, port, scheme, host=vhost))
            enum_tasks.append(run_feroxbuster_enum(target, port, scheme, host=vhost))
            enum_tasks.append(run_sslscan_enum(target, port, scheme, host=vhost))
            enum_tasks.append(run_wpscan_enum(target, port, scheme, host=vhost))
            enum_tasks.append(run_vhostfuzz_enum(target, port, scheme, host=vhost))

    if "dns" in scan_results:
        enum_tasks.append(run_dnsenum_enum(target))
        enum_tasks.append(run_nslookup_enum(target))

    if "sql" in scan_results:
        enum_tasks.append(run_sqlmap_enum(target))

    if "ldap" in scan_results:
        enum_tasks.append(run_ldapsearch_enum(target))

    if enum_tasks:
        await bounded_gather(enum_tasks)
    logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} Enumeration completed for {target}.")


async def exploiting(target, cve_file=None):
    """Runs a vulnerability scanner and launches exploits if vulnerabilities are found."""
    prepare_vuln_cache(target)
    vulnerabilities = ""

    if not cve_file:
        if config.continue_scan and os.path.exists(config.vuln_cache_file):
            logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Continuing {config.scan_id}: reusing cached vulnerability scan results for {target} instead of re-scanning.")
            with open(config.vuln_cache_file, "r") as f:
                try:
                    vulnerabilities = json.load(f)
                except json.JSONDecodeError:
                    vulnerabilities = ""

        if not vulnerabilities:
            if config.continue_scan:
                logger.log(f"{Fore.LIGHTRED_EX}[-]{Style.RESET_ALL} No cached scan results found for {target}.")
            logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Launching vulnerability scanner on {target}...")
            vulnerabilities = await run_scanners(target)

        if isinstance(vulnerabilities, dict):
            # Always merge webtech-derived CVEs, whether this run just scanned fresh
            # or reused a cached vuln_results.json -- it's a cheap read of already
            # -cached webtech_*.json fingerprint files, not a rescan, so there's no
            # reason --continue should skip it.
            webtech_cves = lookup_cves_for_target(target)
            if webtech_cves:
                vulnerabilities["webtech-cve"] = webtech_cves

    else:
        try:
            with open(cve_file, 'r') as file:
                vulnerabilities = file.read()
            file.close()
        except Exception as error:
            logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} Failed to open CVE file: {error}")

    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Executing exploit launcher...")
    await exploit_from_cve_results(target, vulnerabilities)


async def full_pipeline(target):
    """Runs enumeration to completion before exploitation for a single target, so the
    webtech fingerprint (used for CVE lookup) is guaranteed to exist before it's read.
    Used by --auto-all instead of racing enumeration(target) and exploiting(target)."""
    await enumeration(target)
    await exploiting(target)


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
        if args.debug:
            config.debug = True

    config.no_confirm = args.no_confirm

    for module in args.enable_module or []:
        if config.set_module_enabled(module, True):
            logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} Module {Fore.LIGHTCYAN_EX}{module}{Style.RESET_ALL} force-enabled for this run.")
        else:
            logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} Unknown module: {module}. Use --list-modules/--list-scanners to see available names.")

    for module in args.disable_module or []:
        if config.set_module_enabled(module, False):
            logger.log(f"{Fore.LIGHTYELLOW_EX}[-]{Style.RESET_ALL} Module {Fore.LIGHTCYAN_EX}{module}{Style.RESET_ALL} force-disabled for this run.")
        else:
            logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} Unknown module: {module}. Use --list-modules/--list-scanners to see available names.")

    if args.skip_github_poc:
        config.set_module_enabled("github_exploit_search", False)
        logger.log(f"{Fore.LIGHTYELLOW_EX}[-]{Style.RESET_ALL} GitHub PoC index fallback disabled for this run (--skip-github-poc).")

    if args.exploit_timeout is not None:
        config.set_config_value("timeout", "sandbox", args.exploit_timeout)
        logger.log(f"{Fore.LIGHTYELLOW_EX}[-]{Style.RESET_ALL} Sandboxed PoC timeout set to {Fore.LIGHTCYAN_EX}{args.exploit_timeout}s{Style.RESET_ALL} for this run (--exploit-timeout).")

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
            run_ai_evaluation(args, target)

    if args.auto_exploit:
        for target in targets:
            await exploiting(target)

    if args.auto_all:
        # Orchestrator coroutines (not leaf subprocess tasks): keep an unbounded
        # gather across targets so cross-target concurrency is preserved. The
        # shared semaphore inside each target's leaf gathers (enumeration's task
        # fan-out, run_scanners) is what actually caps total live subprocesses.
        await asyncio.gather(*(full_pipeline(target) for target in targets))

        for target in targets:
            run_ai_evaluation(args, target)

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
    elif args.module:
        run_presenter(args.service, args.show_id, module=args.module)
    elif args.list_modules:
        run_presenter(args.service, args.show_id, args.list_services, args.list_modules)
    elif args.list_scanners:
        run_presenter("scanner", args.show_id, args.list_services, args.list_modules,  args.list_scanners)
    elif args.add_module:
        module, service = args.add_module
        run_module_adder(module, service)
    elif args.add_scanner:
        scanner = args.add_scanner
        run_scanner_adder(scanner)
    else:
        try:
            asyncio.run(run_striga(args))
        except KeyboardInterrupt:
            logger.log(f"\r\n{Fore.LIGHTYELLOW_EX}[W]{Style.RESET_ALL} Keyboard interrupt detected.")

if __name__ in '__main__':
    main()