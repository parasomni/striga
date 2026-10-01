# Striga — Developer Guide

This document explains Striga's architecture and the role of **every file** in the codebase, plus the
conventions and non-obvious gotchas you need to know before changing it. For operator/CLI usage see
[USAGE.md](USAGE.md); for the densest running notes see the repo-root `CLAUDE.md`.

---

## 1. Architecture at a glance

Striga is a **sequential pipeline** of config-driven stages, not a set of independent ones. Each stage is
its own Python package and each external tool is a thin async wrapper, but the stages have a strict order:
**an nmap discovery scan is mandatory and drives everything downstream** — enumeration only runs the tools
that match the services nmap detected, and exploitation works on what enumeration produced.

```
   striga.py (entry) ──► run_striga(args)  — parses mode, orchestrates

   ┌───────────────────────── scanner/ (nmap discovery) ─────────────────────────┐
   │  run_nmap (2-phase)  ──►  OPEN PORTS + SERVICE NAMES   [MANDATORY: no scan, │
   │                                                        no enumeration]      │
   └───────────────────────────────────┬─────────────────────────────────────────┘
                                       │ scan_results text  (gates every task)
                                       ▼
   ┌───────────────────────── enumeration/ ──────────────────────────────────────┐
   │  per-service wrappers, dispatched ONLY for detected services:               │
   │  web→ffuf/gobuster/feroxbuster/webtech/…  smb→enum4linux/smbmap  dns/…  snmp │
   │  writes <tool>_<port>.* and webtech_<port>.json                             │
   └───────────────────────────────────┬─────────────────────────────────────────┘
                                       │ reads saved fingerprints/CVEs
                                       ▼
   ┌───────────────────────── exploitation/ ─────────────────────────────────────┐
   │  scanner/ (vuln scanners: nmap-vuln, nuclei, nikto, rustscan) → CVEs        │
   │  → Metasploit → sandboxed GitHub PoC                                        │
   └─────────────────────────────────────────────────────────────────────────────┘

   evaluation/  presenter (show saved results) · ai/ (LLM triage, reads files)
   core/        config · logger · scan-id · concurrency · vhost   (used by all stages)
```

> **The `scanner/` package plays two distinct roles.** `run_nmap` (in `nmap_scanner.py`) is the
> **discovery** scan that feeds **enumeration** and is a hard prerequisite for it. The **vulnerability**
> scanners (`nmap-vuln`, `nuclei`, `nikto`, `rustscan`, dispatched by `scanner.py:run_scanners`) run in
> the **exploitation** stage, not enumeration. Both live under `scanner/`, but they sit at different
> points in the pipeline.

**Core principles**
- **Scanning is mandatory and drives enumeration.** `enumeration(target)` runs `run_nmap` first and gates
  every enumeration task on the scan text (`"smb" in scan_results`, `extract_web_ports(scan_results)`,
  `"dns"`, `"snmp"`, …). No open service detected → that service's tools never run; an empty/failed scan
  → no enumeration at all. The standalone `--enum` path (`run_enumerator`) doesn't scan in-call, so it
  **requires a cached `nmap.txt`** from a previous scan to know which ports/services exist (falling back
  to a single port-80/http guess only when no scan data exists at all). Practically: always scan before
  (or with) enumerating.
- **Config-driven:** a tool runs only if `scanner.<tool>.enabled` is true; its CLI flags come from
  `scanner.<tool>.flags`. No tool-specific logic lives in the orchestrator.
- **Async fan-out, globally bounded:** enumeration/scan tasks are dispatched with `asyncio` and gathered
  through `core.bounded_gather` so at most `performance.max_concurrency` subprocesses run at once.
- **Everything to disk:** each tool writes a file under `<location>/<scan_id>/<target>/`; later stages
  (evaluation, exploitation, AI) read those files rather than passing objects around. This is what makes
  `--continue` and `--show-*` work.
- **Deterministic trust for AI:** the LLM only classifies; `evaluation/ai/evaluator.py` verifies every
  claim against the raw data.

---

## 2. Execution flow

1. `striga.py:main()` prints the banner, builds `args` via `core.parser`, and calls
   `asyncio.run(run_striga(args))`.
2. `run_striga()` applies `--config`, `--enable/disable-module`, `--exploit-timeout`, resolves targets,
   establishes the scan-id (new, `--continue`, or `--continue-scanid`), then dispatches by mode:
   - `--scan` → `run_nmap` per target.
   - `--enum SERVICE` → `run_enumerator`.
   - `--exploit FILE` → `exploiting(target, cve_file)`.
   - `--auto-enum` → `enumeration(target)` then `run_ai_evaluation`.
   - `--auto-exploit` → `exploiting(target)`.
   - `--auto-all` → `full_pipeline(target)` (enumeration **then** exploiting) gathered across targets,
     then `run_ai_evaluation`.
   - `--interactive` → a prompt loop.
3. `enumeration(target)` scans, fingerprints all open ports (webtech), promotes confirmed web ports,
   derives the virtual host, and fans per-service enumeration tasks out through `bounded_gather`.
4. `exploiting(target)` runs/loads the vuln scan, merges webtech-derived CVEs, and hands off to
   `exploitation.exploit_from_cve_results`.

---

## 3. File-by-file reference

### Top level
| File | Role |
|------|------|
| `striga.py` | Entry point and orchestrator. Owns `run_striga`, `enumeration`, `exploiting`, `full_pipeline`, the per-port web fan-out, and the AI-evaluation integration (`_ai_llm_cfg`, `_ai_collect_findings`, `_ai_target_cves`, `_ai_target_cvss`, `run_ai_evaluation`). Also `run_script` (utils dispatch, name-validated). |
| `config.yaml` | Live framework configuration (framework paths, per-tool flags, `performance`, `web_enum`, `web_tech_lookup`, `github_exploit_search`, `sandbox`, `llm`, `exploit_launcher`). |
| `cve_mappings.json` | Local CVE → Metasploit-module cache; only written on confirmed exploit success. |
| `vulners_api.key` | Optional Vulners API key (empty in-repo). |
| `install.sh` | Distro-aware installer: sets up/repairs Docker for the PoC sandbox, deploys to `/opt/striga`, installs the `striga` launcher. |
| `README.md` | Project overview + help output. |
| `CLAUDE.md` | Dense engineering notes / decisions (source of truth for gotchas). |
| `requirements.txt` | Python dependencies. |
| `striga` | Thin launcher script (installed on `PATH`). |

### `core/` — shared plumbing
| File | Role |
|------|------|
| `__init__.py` | Package init. `initialize_globals()` constructs the singletons `config`, `parser`, `logger` (imported everywhere as `from core import config, logger`). Re-exports `bounded_gather` and the `vhost` helpers. |
| `config_manager.py` | `ConfigManager` singleton. Loads YAML, `get_config_value`/`set_config_value` (`group:subgroup` path syntax), `get_tool_flags` (returns `[]` when a tool is disabled), `set_module_enabled` (CLI overrides, with `MODULE_GROUP_ALIASES`), scan-id cache, `clean_cache` (shutil-based). |
| `arg_parser.py` | `CustomArgumentParser` — the entire CLI surface, grouped; also lists runnable `utils/` scripts in `--help`. |
| `logger.py` | `Logger` — writes `<scan_id>/logs/framework.log`, recomputing the path per call from the current `scan_id` (never cache it). |
| `scan_id.py` | `gen_id()` — random scan-id generator. |
| `check_dir.py` | `check_dir()` — idempotent directory creation. |
| `concurrency.py` | `bounded_gather(coros)` + one lazy process-wide `asyncio.Semaphore` sized by `performance.max_concurrency`. Bounds **leaf** subprocess tasks only. |
| `vhost.py` | Virtual-host handling: `select_vhost`, `curl_style_vhost_flags` (Host header + `-k`), `registrable_domain` (fuzz base), `suggest_unresolved_hosts` (prints `/etc/hosts` lines, never writes). |
| `module_adder.py` / `scanner_adder.py` | Back the `--add-module` / `--add-scanner` scaffolding: create a new wrapper module and register it in `config.yaml` / `services.json`. |

### `scanner/` — port & vulnerability scanning
| File | Role |
|------|------|
| `__init__.py` | Re-exports the scanner entry points and `port_utils` helpers. |
| `scanner.py` | `run_scanners`/`run_all_scanners` — the **vulnerability**-scan dispatcher (nmap-vuln, nuclei, nikto, rustscan), gathered via `bounded_gather`; caches merged results to `vuln_results.json`. |
| `nmap_scanner.py` | `run_nmap` — the primary **discovery** scan. Two-phase by default: fast port sweep (`-oG`), then `-sV` + `ssl-cert,http-title` NSE scoped to open ports. Returns/writes the `-sV` text the pipeline parses. |
| `nmap_vuln_scanner.py` | `run_nmap_vuln_scan` — NSE `vuln` scripts, port-scoped from the cached scan (`_scoped_port_flags`); parses XML→dict. |
| `nuclei_vuln_scanner.py` | `run_nuclei_vuln_scan` — runs nuclei (`-jsonl` + severity/rate flags), parses JSONL findings. |
| `nikto_scanner.py` | `run_nikto_scanner` — nikto wrapper. |
| `rustscan_scanner.py` | `run_rustscan_scan` — fast port scanner wrapper (alternative discovery front-end). |
| `port_utils.py` | Pure parsers over nmap text: `extract_all_ports`, `extract_web_ports`, `extract_open_port_numbers`, `extract_hostnames`, `is_ip_literal`. No I/O — trivially testable. |

### `enumeration/` — per-service enumeration
| File | Role |
|------|------|
| `__init__.py` | Exports `run_enumerator`, `run_module_adder`. |
| `enumerator.py` | `run_enumerator(target, service)` — the `--enum` path. Reads cached `nmap.txt` to discover ports/hostnames, fans web enum per port, applies vhost routing, gathers via `bounded_gather`. |
| `module_adder.py` | Scaffolding logic for new enumeration modules. |
| `web/ffuf_enum.py` | Content discovery (ffuf). Host-header vhost + `-k` on https. |
| `web/gobuster_enum.py` | Content discovery (gobuster). Host-header vhost + `-k`. |
| `web/disbuster_enum.py` | Content discovery (dirbuster); vhost goes in the URL (no Host override). |
| `web/feroxbuster_enum.py` | Fast recursive content discovery (feroxbuster), bounded depth/threads. |
| `web/nmap_http_enum.py` | http-* NSE scripts on a web port; `http.host` script-arg for vhost. |
| `web/whatweb_enum.py` | Standalone whatweb fingerprint. **Not** in the auto fan-out (webtech runs whatweb internally) — kept for explicit use. |
| `web/webtech_enum.py` | Primary fingerprinting: whatweb JSON + Wappalyzer + ProjectDiscovery `httpx` supplements, merged into `webtech_<port>.json` (`{product: version}`). Feeds the CVE lookup. |
| `web/whois_enum.py` | whois lookup. |
| `web/sslscan_enum.py` | TLS/cipher/cert audit; https-only self-skip; `--sni` vhost. |
| `web/wpscan_enum.py` | WordPress scan; self-gates on a WordPress fingerprint in `webtech_<port>.json`; optional untracked API token. |
| `web/vhostfuzz_enum.py` | Virtual-host discovery via ffuf `Host: FUZZ.<domain>` (`-ac`); self-skips without a base domain. |
| `smb/enum4linux_enum.py` | SMB/AD enumeration (enum4linux). |
| `smb/smbclient_enum.py` | SMB share listing (smbclient). |
| `smb/smbmap_enum.py` | SMB share + permission enumeration (smbmap). |
| `dns/dnsenum_enum.py` | DNS enumeration (dnsenum). |
| `dns/nslookup_enum.py` | DNS record lookup (nslookup). |
| `snmp/snmpbulkwalk_enum.py` | SNMP walk (snmpbulkwalk); dispatched when nmap tags `snmp`. |
| `sql/sqlmap_enum.py` | SQL injection testing (sqlmap). |
| `ldap/ldapsearch_enum.py` | LDAP enumeration (ldapsearch). |

### `evaluation/` — result presentation & AI triage
| File | Role |
|------|------|
| `__init__.py` | Exports `run_presenter`, `list_services`, `get_services_list`. |
| `presenter.py` | `show_service` / `show_module` — render saved results (per-port glob) for `--show-service` / `--show-module`; `get_module_names` validates names. |
| `services.json` | Maps each presentable service → its tool list (drives `--show-service`, `--list-*`). Add new per-port tools here. |
| `ai/__init__.py` | AI-layer facade: `is_ai_enabled`, `build_evaluator`, and re-exports; also a standalone `_main()` CLI. |
| `ai/client.py` | `LLMClient` — backend HTTP client (Ollama `/api/chat` structured outputs; OpenAI-compatible `/v1/chat/completions`). `health()` + `complete_json()`; lenient JSON parsing; retries. |
| `ai/evaluator.py` | `Evaluator` + `EvalConfig` — chunking, per-chunk LLM call, and the **deterministic trust layer**: evidence verification, CVE grounding, CVSS-band severity, review flags, dedup/sort, and the `render()` reporters (markdown/json/table). Also `load_results_dir`. |
| `ai/schema.py` | Data model: `RawFinding`, `Classification`, `EvaluatedFinding`, `Severity`. Verification fields are set by the evaluator, never the model. |
| `ai/prompts.py` | System/user prompt construction + the enforced `OUTPUT_SCHEMA`. Bakes in the prompt-injection trust boundary (tool output is untrusted data). |

### `exploitation/` — CVE → exploit
| File | Role |
|------|------|
| `__init__.py` | Exports `exploit_from_cve_results`, `lookup_cves_for_target`. |
| `exploit_launcher.py` | The exploit engine: maps CVEs to Metasploit modules (via `cve_mappings.json`, MITRE/Vulners), drives msfconsole through `pymetasploit3`, orchestrates the GitHub PoC fallback, and records the attempt summary. Reads its config live (`_load_launcher_config`). |
| `cve_finder.py` | `lookup_cves_for_target` — reads `webtech_<port>.json` fingerprints and queries Vulners + NVD per product (parallel `ThreadPoolExecutor`, optional NVD key) to produce CVE ids. |
| `poc_search.py` | Looks a CVE up in the curated `nomi-sec/PoC-in-GitHub` index; filters obvious discovery/patch scripts. |
| `poc_vetting.py` | Downloads a PoC candidate as a zip (no clone), resolves the real default branch, and statically scans it for malware/red-flag patterns before anything runs. |
| `sandbox_runner.py` | Runs a vetted PoC in a disposable, non-root, resource-limited Docker container with egress pinned to target + `LHOST:LPORT`; builds sandbox images; detects PoC invocation flags. |
| `sandbox_images/` | Dockerfiles for the per-language sandbox images (e.g. `python-poc.Dockerfile`). |

### `utils/`, `reverse_shells/`, `logo/`
| Path | Role |
|------|------|
| `utils/revshells.py`, `utils/pwdfinder.sh` | Standalone helper scripts runnable as `striga <name>`. |
| `utils/reverse_shells/`, `reverse_shells/` | Reverse-shell payload templates used by `revshells.py`. |
| `logo/` | Branding assets. |

---

## 4. Data model (AI layer)

- **`RawFinding`** — one unit of tool output: `(scan_id, target, service, module, raw, context)`.
  `context` carries deterministic hints (`cve_ids`, `cvss`) used for grounding.
- **`Classification`** — one evaluated issue. The model fills title/severity/confidence/evidence/etc.;
  the evaluator fills `evidence_verified`, `review_required`, `notes`.
- **`EvaluatedFinding`** — a `RawFinding` + its `Classification` (or an `error` notice).

The evaluator never deletes a finding by default — low-confidence/unverified items are **flagged for
review**, not dropped (the only hard drop is the opt-in `drop_below_confidence` floor).

---

## 5. Adding a new tool (recipe)

Match the existing wrapper shape:

1. **Create the module** `enumeration/<service>/<tool>_enum.py` (or `scanner/<tool>_scanner.py`) exposing
   an async `run_<tool>_enum(target, port=80, scheme="http", host=None)` (web) or `run_<tool>_*(target)`.
   Copy an existing sibling: read `enabled`, read flags via `config.get_tool_flags(<name>, "scanner")`,
   build `cmd`, run with `asyncio.create_subprocess_exec` + `asyncio.wait_for(timeout=config.timeout)`,
   write to `config.get_target_scan_path(target) + f"{name}_{port}.txt"`.
2. **Export it** in the package `__init__.py`.
3. **Register config** — add a `scanner.<name>` block (`enabled`, `flags`) to `config.yaml`.
4. **Register presentation** — add the tool to its service list in `evaluation/services.json`.
5. **Wire it into the fan-out** — append the task in `striga.py:enumeration()` **and**
   `enumeration/enumerator.py:run_enumerator()`, using `bounded_gather` (never a bare `asyncio.gather`).
6. **(AI)** add the module→service mapping in `striga.py:_AI_SERVICE_BY_MODULE`.

Web modules must take `(target, port, scheme, host=None)` and route the vhost via Host header / SNI —
don't reintroduce a bare-target/port-80 assumption, and don't write `/etc/hosts`.

A tool that reuses an existing binary under a new name (like `vhostfuzz`→ffuf, `nmap-http`→nmap) hardcodes
the binary in the module and uses the module name only for config/results/`services.json`.

---

## 6. Conventions & gotchas

- **Read config live.** Never capture a config value as an import-time module constant — the singleton
  loads its *default* path before `--config` is applied, so a top-level `X = config.get_config_value(...)`
  silently ignores `--config` forever. Read inside the function that uses it.
- **`bounded_gather` on leaves only.** Bounding orchestrator coroutines (`full_pipeline`) that internally
  await the same semaphore would deadlock — keep the `--auto-all` cross-target gather unbounded.
- **Optional layers import lazily.** The AI layer and its backend client are imported inside the functions
  that use them, guarded by try/except, so a broken/absent AI layer never breaks core scanning.
- **whatweb runs once.** `webtech_enum` already invokes whatweb; don't re-add `whatweb_enum` to the auto
  fan-out.
- **Preserve the safety gates.** Keep `run_script`'s filename validation + interpreter allowlist, the
  GitHub-PoC confirmation prompt, the high-risk carve-out under `--no-confirm`, and the sandbox egress
  restriction. Don't loosen these as conveniences.
- **Secrets.** `config.yaml` currently ships a plaintext `exploit_launcher.MSF_PASSWORD` — treat it as a
  leaked secret to migrate to an untracked override; never add new secrets to tracked config.
- **Verification.** There's no pytest suite (`tests/` is gitignored/ad hoc). Verify with `py_compile`, the
  pure `port_utils`/`vhost` helpers (unit-testable), stub-backed evaluator runs, and the real CLI against
  a lab target.

---

For the running list of engineering decisions and freshest gotchas, keep reading (and updating) the
repo-root `CLAUDE.md`.
```
