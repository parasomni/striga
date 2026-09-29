import socket

from colorama import Fore, Style

# Turns hostnames discovered in an nmap scan into something web-enum tools can use,
# WITHOUT modifying the system. The strategy is deliberately non-persistent:
# connect to the known-reachable target (the IP the operator scanned) and route
# the virtual host at the HTTP layer via a `Host:` header (and TLS SNI), instead of
# editing /etc/hosts. For names that still won't resolve where a tool needs real
# resolution, we only *log a suggestion* -- the operator decides whether to add it.


def select_vhost(target, hostnames):
    """Which host to route web enum at. If the operator already targeted a hostname
    (not an IP), respect it. Otherwise use the first discovered name. Returns None
    when there's no distinct vhost to apply (i.e. just use the bare target)."""
    from core import config
    from scanner.port_utils import is_ip_literal
    if config.get_config_value("use_vhost", "web_enum") is False:
        return None
    if not is_ip_literal(target):
        return None  # operator gave a name already; tools use `target` directly
    return hostnames[0] if hostnames else None


def suggest_unresolved_hosts(hostnames, target):
    """Non-persistent helper: for any discovered hostname that doesn't resolve,
    print the exact /etc/hosts line the operator can add. We never write it
    ourselves -- Host-header routing already covers most vhost cases; this is for
    tools/servers that genuinely need name resolution (e.g. strict SNI)."""
    from core import logger

    target_ip = _resolve_target_ip(target)
    unresolved = [h for h in hostnames if not _already_resolves(h)]
    if not unresolved:
        return

    if target_ip:
        lines = "\n    ".join(f"{target_ip}\t{h}" for h in unresolved)
        logger.log(f"{Fore.LIGHTYELLOW_EX}[-]{Style.RESET_ALL} Discovered vhost(s) that don't resolve. If a tool needs real DNS "
                   f"(e.g. strict SNI), add to /etc/hosts:\n    {lines}")
    else:
        logger.log(f"{Fore.LIGHTYELLOW_EX}[-]{Style.RESET_ALL} Discovered vhost(s) that don't resolve: {', '.join(unresolved)}")


def registrable_domain(hostname):
    """Best-effort apex domain to fuzz subdomains under: the last two labels of the
    name (board.htb, portal.board.htb -> board.htb). A deliberately simple
    heuristic -- correct for the single-label TLDs labs/CTFs and most engagements
    use (.htb/.local/.com/.io); it would clip a multi-part TLD like .co.uk, which
    the operator can work around by targeting the hostname directly."""
    if not hostname:
        return None
    labels = hostname.strip(".").split(".")
    if len(labels) < 2:
        return None
    return ".".join(labels[-2:])


def curl_style_vhost_flags(host, target, scheme, existing_flags):
    """Extra CLI flags for ffuf/gobuster/feroxbuster so they connect to the
    reachable target but route the discovered virtual host at the HTTP layer:
      -H "Host: <host>"   when a distinct vhost was found (no /etc/hosts needed)
      -k                  on https, unless the tool's flags already disable TLS
                          verification (avoids a duplicate flag)."""
    extra = []
    if host and host != target:
        extra += ["-H", f"Host: {host}"]
    if scheme == "https" and "-k" not in existing_flags and "--no-tls-validation" not in existing_flags:
        extra += ["-k"]
    return extra


def _resolve_target_ip(target):
    from scanner.port_utils import is_ip_literal
    if is_ip_literal(target):
        return target
    try:
        return socket.gethostbyname(target)
    except OSError:
        return None


def _already_resolves(hostname):
    try:
        socket.gethostbyname(hostname)
        return True
    except OSError:
        return False
