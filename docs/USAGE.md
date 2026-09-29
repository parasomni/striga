# Striga — Usage Guide

Striga is a Python CLI that automates authorized penetration-testing workflows end to end:

```
port scan  →  service enumeration  →  vulnerability evaluation  →  exploitation
```

It wraps established tools (nmap, rustscan, nuclei, nikto, ffuf, gobuster, feroxbuster, whatweb,
sslscan, wpscan, enum4linux, smbmap, sqlmap, ldapsearch, dnsenum, snmpbulkwalk, msfconsole, …) behind
one pipeline and a single YAML config, saves every tool's output to disk, and can optionally triage the
results with a local LLM.

> ⚠️ **Authorized use only.** Striga is for systems you are explicitly authorized to test — labs, CTFs,
> and engagements with signed scope. It performs active scanning, brute-forcing, and exploitation. Do not
> point it at anything you do not own or have written permission to attack.

---

## 1. Requirements & installation

Striga orchestrates external binaries; it does not bundle them. The tools it can call are expected to be
on `PATH` (e.g. `nmap`, `rustscan`, `nuclei`, `ffuf`, `gobuster`, `feroxbuster`, `whatweb`, `httpx`
[ProjectDiscovery], `sslscan`, `wpscan`, `enum4linux`, `smbmap`, `sqlmap`, `ldapsearch`, `dnsenum`,
`snmpbulkwalk`, `msfconsole`). Anything not installed simply logs a failure for that module and the rest
of the run continues.

Python dependencies are in `requirements.txt` (`pyyaml`, `requests`, `pymetasploit3`, `xmltodict`,
`pexpect`, `bs4`, `colorama`, `python-Wappalyzer`, …).

Install with the bundled script (auto-detects the distro, installs/configures Docker for the PoC sandbox,
and deploys Striga to `/opt/striga`):

```bash
./install.sh
```

After install, run it from anywhere as `striga`. From a source checkout you can also run `python3 striga.py …`.

Optional extras:
- **Metasploit RPC** — for `--auto-exploit`/`--exploit`. Configure `exploit_launcher.*` in `config.yaml`.
- **Docker** — for the GitHub PoC sandbox (installed by `install.sh`).
- **Ollama** (or any OpenAI-compatible endpoint) — for AI evaluation. Pull a model, e.g.
  `ollama pull qwen2.5:14b-instruct`.

---

## 2. Quick start

```bash
# Full automation against one target: scan → enum → (CVE lookup) → exploit → AI report
striga --target 10.10.14.109 --auto-all

# Enumerate only (scan + all service enum), then AI-triage the findings
striga --target 10.10.14.109 --auto-enum

# Several targets from a file, full pipeline
striga --targets targets.txt --auto-all

# Show the web results of the last scan
striga --show-service web
```

`targets.txt` is one IP or hostname per line.

---

## 3. Command reference

Options are grouped the same way `striga -h` prints them.

### Target specification
| Flag | Meaning |
|------|---------|
| `--target TARGET` | Single target — IP **or** hostname. |
| `--targets FILE` | File with one target per line. |

### Automation
| Flag | Meaning |
|------|---------|
| `--auto-enum` | Scan, then run every enabled enumeration tool for the services nmap detected. Runs AI evaluation afterward. |
| `--auto-exploit` | Run the vulnerability scanners and launch matching exploits (Metasploit, then GitHub PoC fallback). |
| `--auto-all` | Full pipeline per target: enumeration **then** exploitation (ordered so the web fingerprint exists before CVE lookup), then AI evaluation. |
| `--no-confirm` | Skip the human confirmation prompt before running a fetched GitHub PoC. High-risk PoCs are **still** skipped. |
| `--skip-github-poc` | Never fall back to the GitHub PoC index (same as `--disable-module github_exploit`). |
| `--exploit-timeout SECONDS` | Max seconds a sandboxed PoC may run before it's killed (overrides `sandbox.timeout`). |

### Manual execution
| Flag | Meaning |
|------|---------|
| `--scan` | Run only the nmap port scan for each target. |
| `--enum SERVICE` | Run enumeration for one service (`web`, `smb`, `dns`, `sql`, `ldap`, `snmp`) or `all`. Uses the last cached `nmap.txt` to find ports if you don't scan in the same run. |
| `--exploit CVE_FILE` | Run exploitation from a file of CVE numbers instead of a fresh vuln scan. |
| `--interactive` | Interactive prompt loop (`scan`, `enum`, `exploit`, `exit`). |

### General configuration
| Flag | Meaning |
|------|---------|
| `--config FILE` | Use a custom `config.yaml` (see the staleness note below). |
| `--log FILE` | Custom log file. |
| `--continue` | Continue the **last** scan (reuses its scan-id and cached results). |
| `--continue-scanid ID` | Continue a specific scan by id. |

### Result presentation
| Flag | Meaning |
|------|---------|
| `--show-service SERVICE` | Print saved results for a service (`web`, `smb`, … or `all`). |
| `--show-module MODULE` | Print saved results for a single tool (`nmap`, `ffuf`, `webtech`, …) across every target. |
| `--list-services` | List services that can be presented. |
| `--list-modules` | List enumeration modules. |
| `--list-scanners` | List scanners. |
| `--show-id ID` | Which scan-id to present (default: the last scan). |

### AI evaluation
| Flag | Meaning |
|------|---------|
| `--ai-eval` | Force-enable AI evaluation this run (overrides `llm.enabled`). |
| `--no-ai-eval` | Force-disable it this run. |
| `--ai-format {markdown,json,table}` | Report format (overrides `llm.output_format`). |

### Module control
| Flag | Meaning |
|------|---------|
| `--enable-module MODULE` | Force-enable a module for this run only (repeatable). |
| `--disable-module MODULE` | Force-disable a module for this run only (repeatable). |

### Developer options
| Flag | Meaning |
|------|---------|
| `--debug` | Verbose debug logging. |
| `--add-module 'name,service'` | Scaffold and register a new enumeration module. |
| `--add-scanner NAME` | Scaffold and register a new scanner. |

### Script execution (positional)
Any script placed in `utils/` (`.py/.sh/.js/.pl/.rb/.ps1/.php`) can be run as a first-class subcommand:

```bash
striga revshells -h
striga pwdfinder
```

---

## 4. Modes & workflows

### Scan only
```bash
striga --target 10.10.14.109 --scan
```
Runs a two-phase nmap scan (fast discovery, then version detection on open ports) and writes `nmap.txt`.

### Automated enumeration
```bash
striga --target 10.10.14.109 --auto-enum
```
Scans, then dispatches enumeration tasks **conditionally on the services nmap found**:
- **web** ports → whatweb/webtech fingerprint, then ffuf, gobuster, dirbuster, feroxbuster, nmap-http,
  sslscan (https only), wpscan (only if WordPress was fingerprinted), vhostfuzz, plus whois.
- **smb** → enum4linux, smbclient, smbmap.
- **dns** → dnsenum, nslookup.
- **snmp** → snmpbulkwalk.
- **sql** → sqlmap.  **ldap** → ldapsearch.

Every open web port is enumerated individually (not just port 80). See §7 for the virtual-host behavior.

### Manual, per-service enumeration
```bash
striga --target 10.10.14.109 --enum web
striga --target 10.10.14.109 --enum all
```
Reads the last cached `nmap.txt` to discover ports/hostnames if you don't scan in the same invocation.

### Exploitation
```bash
striga --target 10.10.14.109 --auto-exploit         # vuln-scan then exploit
striga --target 10.10.14.109 --exploit cve_list.txt # exploit from a CVE file
```
Striga runs the vulnerability scanners (nmap-vuln, nuclei, …), merges in CVEs derived from web-tech
fingerprints, then for each CVE tries a ranked Metasploit module and — if none works — falls back to a
vetted, sandboxed GitHub PoC. **Set up a listener first** for reverse shells: `nc -lnvp 4444` (match
`LHOST`/`LPORT` in config). A written `exploitation_summary.txt` records every module/PoC tried.

### Full automation
```bash
striga --target 10.10.14.109 --auto-all
striga --targets targets.txt --auto-all
```
Per target, enumeration runs to completion before exploitation (so the web fingerprint used for CVE
lookup exists first); targets run concurrently. AI evaluation runs at the end.

### Continue a scan
```bash
striga --target 10.10.14.109 --auto-all --continue
striga --continue-scanid a1b2c3
```
Reuses cached results (`nmap.txt`, `vuln_results.json`) instead of re-running work already done.

---

## 5. Output layout

Everything is written under the framework location (default `/etc/striga`), keyed by scan-id and target:

```
/etc/striga/
  <scan_id>/
    logs/framework.log            # per-scan log
    <target>/
      nmap.txt                    # service-detection scan output
      ffuf_80.txt, gobuster_80.txt, feroxbuster_8080.txt, …   # per-port web enum
      whatweb_80.json / webtech_80.json                        # fingerprints
      sslscan_443.txt, wpscan_80.txt, vhostfuzz_80.txt
      enum4linux.txt, smbmap.txt, snmpbulkwalk.txt, …
      vuln_results.json           # cached vulnerability-scan results
      exploitation_summary.txt    # every exploit attempt (tried/skipped/run)
      ai_evaluation.md            # AI triage report (or .json/.txt)
```

Per-port tools use `<tool>_<port>.<ext>` because one target can expose several web ports.

Present saved results without re-running anything:
```bash
striga --show-service web          # all web tools for the last scan
striga --show-module ffuf          # just ffuf, across all targets
striga --show-service all --show-id a1b2c3
```

---

## 6. Configuration (`config.yaml`)

The default config is `/opt/striga/config.yaml`; pass `--config ./config.yaml` to use another.

> **`--config` timing:** the config singleton loads its *default* path when the framework starts (before
> `--config` is parsed) and re-loads with `--config` shortly after. This is handled internally, but it
> means the **deployed** `/opt/striga/config.yaml` is what runs unless you pass `--config`. If you edit
> the repo's `config.yaml`, either redeploy with `install.sh` or run with `--config ./config.yaml`.

Key sections:

| Section | Purpose |
|---------|---------|
| `framework` | Name/version, `location` (output root), logging paths, global `timeout` (per-tool ceiling). |
| `scanner.<tool>` | Per-tool `enabled` flag and `flags` list. This is where you tune nmap/ffuf/gobuster/nuclei/etc. |
| `performance` | `max_concurrency` (global cap on concurrent tool subprocesses), `two_phase_scan`, `discovery_min_rate`, `hostname_scripts`, `use_cache`. |
| `web_enum` | `use_vhost` — route web enum at the discovered virtual host (§7). |
| `web_tech_lookup` | Web-fingerprint → CVE lookup (Vulners/NVD URLs, `httpx_binary`, optional `nvd_api_key_file`). |
| `github_exploit_search` | PoC-in-GitHub fallback (`max_candidates`, `min_stars`, `exclude_discovery_scripts`). |
| `sandbox` | Docker PoC sandbox limits (`cpu_limit`, `memory_limit`, `pids_limit`, `timeout`, `strict_egress`, per-language images). |
| `llm` | AI evaluation (§8). |
| `exploit_launcher` | Metasploit RPC connection + `LHOST`/`LPORT`/`CHOST`/`CPORT` callbacks. |

**Enabling/tuning a tool** is just editing its `scanner.<tool>` block. Example — switch web content
discovery from gobuster to feroxbuster for one run:
```bash
striga --target 10.10.14.109 --auto-enum --disable-module gobuster --enable-module feroxbuster
```

Module names accept short aliases for the standalone feature groups: `webtech` → `web_tech_lookup`,
`github_exploit` → `github_exploit_search`.

---

## 7. Virtual host / hostname handling

Web servers behind name-based virtual hosting return the wrong site when hit by IP, and HTTPS with SNI
needs the hostname. Striga handles this automatically and **without modifying your system**:

1. It extracts hostnames from the nmap output — TLS cert CN/SAN (the service scan runs `ssl-cert`),
   HTTP redirect `Location` (`http-title`), and rDNS.
2. It picks a virtual host (`web_enum.use_vhost`, default on) — respecting a hostname you passed as the
   target, otherwise the first discovered name.
3. Web tools **connect to the reachable IP** but route the vhost at the protocol layer: a `Host:` header
   (ffuf/gobuster/feroxbuster), TLS `--sni` (sslscan), or `http.host` NSE arg (nmap-http). HTTPS gets
   `-k` automatically.
4. `vhostfuzz` fuzzes `Host: FUZZ.<domain>` to discover additional virtual hosts.

If a discovered hostname doesn't resolve, Striga **prints the exact `/etc/hosts` line** for you to add
(for tools/servers that need real DNS) — it never edits `/etc/hosts` itself.

---

## 8. AI evaluation (optional)

After a scan, Striga can triage the saved tool output with a local LLM and write a ranked report
(`ai_evaluation.md`). The model only classifies; every claim it makes is then cross-checked
deterministically (evidence is verified against the raw output, CVEs are grounded, and severity is
aligned to CVSS harvested from the vuln scan).

Enable/configure via the `llm` section and/or the CLI flags:

```yaml
llm:
  enabled: true
  provider: ollama                 # or an OpenAI-compatible endpoint
  model: qwen2.5:14b-instruct
  base_url: http://127.0.0.1:11434
  output_format: markdown          # markdown | json | table
```

```bash
striga --target 10.10.14.109 --auto-enum --ai-eval --ai-format table
```

- **Ollama needs no API key.** With `provider: ollama` everything works keyless. For an OpenAI-compatible
  backend, set `api_key_file` in the `llm` section.
- If the backend is unreachable, AI evaluation is **skipped** (the scan is unaffected). If the backend is
  up but the model isn't pulled, run `ollama pull <model>` first.
- CVSS-based severity grounding only fires when a vulnerability scan has run (i.e. `--auto-all` /
  `--auto-exploit`), because that's what produces the CVSS data on disk.

See the Developer Guide for how the evaluator's trust layer works.

---

## 9. Exploitation & the GitHub PoC sandbox

When Metasploit has no working module for a CVE, Striga can fall back to public PoCs:
1. Look the CVE up in the curated `nomi-sec/PoC-in-GitHub` index (not live GitHub search).
2. Download the candidate as a zip (no `git clone` — nothing executes on fetch) and **statically vet** it
   for red flags (obfuscation, `curl|sh`, destructive/exfil/miner patterns).
3. Run the vetted PoC in a disposable, non-root, resource-limited Docker container whose network egress
   is pinned to the target and your `LHOST:LPORT` only.

**Public PoCs are a known malware vector.** Striga asks for confirmation before running one by default;
`--no-confirm` skips the prompt for automation but still refuses PoCs the static vetting scored high-risk.
Don't remove the confirmation gate or egress restriction as a "convenience."

Set up your listener before exploiting reverse-shell PoCs: `nc -lnvp 4444`.

---

## 10. Tips & troubleshooting

- **Speed:** the biggest levers are `performance.max_concurrency` (raise on a strong host/network, lower
  if you trip rate limits/IDS) and `performance.two_phase_scan` (keep on). Drop the AI model to a 7–8B
  size for faster triage.
- **Redundant content discovery:** ffuf, gobuster, dirbuster, and feroxbuster overlap. Enable one primary
  tool per run and leave the rest off to save time.
- **"AI evaluation layer unavailable / backend unreachable":** expected when Ollama isn't running — the
  scan still completes; start Ollama or pass `--no-ai-eval`.
- **New config not taking effect:** you're likely running the deployed `/opt/striga/config.yaml`.
  Redeploy with `install.sh` or use `--config ./config.yaml`.
- **HTTPS enum "fails":** ensure the tool got `-k` (self-signed labs) — Striga adds it automatically for
  the built-in modules on `https` ports.

---

For architecture and how to extend Striga with new tools, see [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md).
```
