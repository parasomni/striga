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


# Hostname sources in nmap text output, in rough order of trust:
#  - rDNS/provided name on the scan-report line: "Nmap scan report for foo.htb (10.10.10.10)"
#  - TLS cert (needs --script ssl-cert or -sC): "commonName=foo.htb", "DNS:foo.htb, DNS:www.foo.htb"
#  - HTTP redirect (needs http-title/-sC): "Did not follow redirect to https://foo.htb/"
_HOSTNAME_PATTERNS = (
    re.compile(r"Nmap scan report for ([^\s()]+) \("),
    re.compile(r"commonName=([A-Za-z0-9.*_-]+)"),
    re.compile(r"DNS:([A-Za-z0-9.*_-]+)"),
    re.compile(r"Did not follow redirect to https?://([^/\s:]+)"),
    re.compile(r"http-title:.*?https?://([^/\s:]+)"),
)

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HOSTNAME_IGNORE = {"localhost", "localhost.localdomain", "example.com"}


def is_ip_literal(value):
    """True if value is a bare IPv4/IPv6 address (so we never treat it as a vhost)."""
    if _IPV4_RE.match(value):
        return True
    return ":" in value  # crude IPv6 check -- good enough to exclude from vhosts


def _normalize_hostname(name):
    name = name.strip().rstrip(".").lower()
    if name.startswith("*."):     # wildcard cert -> its base domain
        name = name[2:]
    return name


def extract_hostnames(nmap_output):
    """Pull plausible virtual-host / DNS names out of nmap text output so web enum
    can target the real hostname instead of the bare IP (name-based vhosts return
    the wrong site by IP, and SNI TLS needs the name). Deduplicated, order-preserved,
    with bare IPs and known-noise names dropped. Best surfaced when the scan ran
    ssl-cert/http-title (striga's two-phase service scan adds these by default)."""
    if not isinstance(nmap_output, str):
        return []

    ordered = []
    seen = set()
    for pattern in _HOSTNAME_PATTERNS:
        for match in pattern.findall(nmap_output):
            host = _normalize_hostname(match)
            if not host or host in seen or host in _HOSTNAME_IGNORE:
                continue
            if is_ip_literal(host):
                continue
            seen.add(host)
            ordered.append(host)
    return ordered


def extract_open_port_numbers(nmap_output):
    """Returns a comma-joined string of every open TCP port (e.g. "22,80,8080"),
    or "" if nothing parseable. Used to scope the follow-up nmap vuln scan to the
    ports the initial -p- sweep already found open, instead of re-scanning nmap's
    default top-1000 from scratch (slower AND blind to non-standard open ports)."""
    ports = [str(e["port"]) for e in extract_all_ports(nmap_output)]
    return ",".join(ports)


def extract_web_ports(nmap_output):
    """Returns a list of {"port": int, "scheme": "http"|"https", "service": str}
    for every open TCP port nmap tagged with an http-ish service name. Used to scope
    tools that only make sense against a known web service (ffuf, gobuster,
    dirbuster, nmap-http) -- whatweb/webtech should use extract_all_ports instead,
    since they're cheap fingerprinting probes worth running against every port."""
    return [e for e in extract_all_ports(nmap_output) if "http" in e["service"].lower()]
