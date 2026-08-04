import asyncio
import json

from colorama import Fore, Style
from core import config, logger

module_name = "webtech"

WRONG_HTTPX_MARKERS = ("--follow-redirects", "--http2", "--params")
_warned_wrong_httpx = False


async def _run_httpx_tech_supplement(url):
    """Best-effort, same contract as _run_wappalyzer_supplement: any failure
    (binary not installed, timeout, unparseable output) just skips this step.
    httpx is a separate Go binary (github.com/projectdiscovery/httpx), not a
    Python package -- don't confuse it with the unrelated Python `httpx` HTTP
    client library of the same name."""
    binary = config.get_config_value("httpx_binary", "web_tech_lookup") or "httpx"

    try:
        process = await asyncio.create_subprocess_exec(
            binary, "-u", url, "-tech-detect", "-json", "-silent",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} {binary} (projectdiscovery) not installed, skipping supplemental fingerprinting.")
        return {}

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=15)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} httpx tech-detect timed out for {url}.")
        return {}

    if process.returncode != 0 and not stdout:
        global _warned_wrong_httpx
        output = stderr.decode(errors="ignore")
        if any(marker in output for marker in WRONG_HTTPX_MARKERS):
            if not _warned_wrong_httpx:
                _warned_wrong_httpx = True
                logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} '{binary}' on PATH is the Python httpx HTTP client's CLI (pip install httpx[cli]), "
                            f"not ProjectDiscovery's recon tool (github.com/projectdiscovery/httpx) -- they share a binary name. "
                            f"Run 'which -a httpx' to find ProjectDiscovery's copy, then set web_tech_lookup.httpx_binary to its full path in config.yaml. "
                            f"(This message won't repeat for the rest of this run.)")
            else:
                logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} httpx tech-detect skipped for {url} (wrong httpx on PATH, already warned).")
        else:
            logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} httpx tech-detect failed for {url}: {output}")
        return {}

    products = {}
    for line in stdout.decode(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        for entry in data.get("tech", []):
            name, _, version = entry.partition(":")
            products[name] = version

    return products


def _run_wappalyzer_supplement(url):
    """Best-effort: any failure here (package not installed, network hiccup,
    parsing issue) just skips this step -- it's a supplement to whatweb, not a
    replacement, and must never break webtech detection as a whole."""
    try:
        from Wappalyzer import Wappalyzer, WebPage
    except ImportError as e:
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} python-Wappalyzer unavailable, skipping supplemental fingerprinting: {e}")
        return {}

    try:
        webpage = WebPage.new_from_url(url, timeout=15)
        wappalyzer = Wappalyzer.latest()
        results = wappalyzer.analyze_with_versions(webpage)
    except Exception as e:
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} Wappalyzer supplemental fingerprinting failed for {url}: {e}")
        return {}

    products = {}
    for tech, info in results.items():
        versions = info.get("versions") if isinstance(info, dict) else None
        if versions:
            products[tech] = versions[0]

    return products


def _extract_products(whatweb_entry):
    products = {}
    plugins = whatweb_entry.get("plugins", {})
    skip = ("Title", "IP", "Country", "RedirectLocation", "Cookies", "UncommonHeaders", "Meta-Author", "Email")

    for name, data in plugins.items():
        if name in skip or not isinstance(data, dict):
            continue

        versions = data.get("version")
        if versions:
            products[name] = versions[0] if isinstance(versions, list) else str(versions)
            continue

        string_value = data.get("string")
        if not string_value:
            continue

        value = string_value[0] if isinstance(string_value, list) else str(string_value)
        parts = value.split("/", 1)
        if len(parts) == 2:
            products[parts[0]] = parts[1]
        else:
            products[value] = ""

    return products


async def run_webtech_enum(target, port=80, scheme="http"):
    enabled = config.get_config_value("enabled", "web_tech_lookup")
    if enabled is False:
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} {module_name} detection is disabled in the configuration.")
        return {}

    url = f"{scheme}://{target}:{port}"

    logger.log(f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL} Fingerprinting web technologies on {url}...")

    result_file = config.get_target_scan_path(target) + f"{module_name}_{port}.json"

    process = await asyncio.create_subprocess_exec(
        "whatweb", "--log-json=-", "-a", "3", url,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=config.timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} {module_name} detection timed out for {url}.")
        return {}

    if process.returncode != 0 and not stdout:
        logger.log(f"{Fore.LIGHTRED_EX}[!]{Style.RESET_ALL} {module_name} detection failed for {url}: {stderr.decode(errors='ignore')}")
        return {}

    products = {}
    try:
        entries = json.loads(stdout.decode(errors="ignore") or "[]")
        for entry in entries:
            products.update(_extract_products(entry))
    except json.JSONDecodeError:
        logger.debug(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} Could not parse {module_name} JSON output for {url}.")

    wappalyzer_products = await asyncio.to_thread(_run_wappalyzer_supplement, url)
    for name, version in wappalyzer_products.items():
        if version and not products.get(name):
            products[name] = version

    httpx_products = await _run_httpx_tech_supplement(url)
    for name, version in httpx_products.items():
        if version and not products.get(name):
            products[name] = version

    with open(result_file, "w", encoding="utf-8") as outfile:
        json.dump(products, outfile, indent=4)

    if products:
        summary = ", ".join(f"{name} {version}".strip() for name, version in products.items())
        logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} Detected {Fore.LIGHTCYAN_EX}{len(products)}{Style.RESET_ALL} technologies on {url}: {summary}")
    else:
        logger.log(f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL} No versioned technologies detected on {url}.")

    logger.log(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} {module_name} results written to {Fore.LIGHTCYAN_EX}{result_file}{Style.RESET_ALL}")

    return products
