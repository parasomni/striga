import re

# nmap's default -sV text output (no -oX/-oG) looks like:
#   PORT      STATE SERVICE     VERSION
#   22/tcp    open  ssh         OpenSSH 8.2p1 ...
#   80/tcp    open  http        nginx 1.18.0
#   8080/tcp  open  http-proxy  Node.js Express framework
# The web enum tools previously just hit the bare target (i.e. assumed port 80),
# so any web service on a non-standard port was silently skipped. This parses the
# same nmap stdout already captured by run_nmap() to find every open port, instead
# of guessing a single port.
OPEN_PORT_PATTERN = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", re.MULTILINE)


def _scheme_for_service(service):
    service_lower = service.lower()
    return "https" if ("https" in service_lower or "ssl" in service_lower) else "http"


def extract_all_ports(nmap_output):
    """Returns a list of {"port": int, "scheme": "http"|"https", "service": str} for
    every open TCP port, regardless of nmap's service label. whatweb/webtech should
    scan all of these -- nmap's service-name guess is frequently wrong or "unknown",
    and a web app can be sitting behind a port nmap didn't tag as http at all.
    Returns [] if nmap_output isn't parseable text (e.g. empty, or a different -o
    format)."""
    if not isinstance(nmap_output, str):
        return []

    endpoints = []
    for port, proto, service in OPEN_PORT_PATTERN.findall(nmap_output):
        if proto != "tcp":
            continue

        endpoints.append({"port": int(port), "scheme": _scheme_for_service(service), "service": service})

    return endpoints


def extract_web_ports(nmap_output):
    """Returns a list of {"port": int, "scheme": "http"|"https", "service": str}
    for every open TCP port nmap tagged with an http-ish service name. Used to scope
    tools that only make sense against a known web service (ffuf, gobuster,
    dirbuster, nmap-http) -- whatweb/webtech should use extract_all_ports instead,
    since they're cheap fingerprinting probes worth running against every port."""
    return [e for e in extract_all_ports(nmap_output) if "http" in e["service"].lower()]
