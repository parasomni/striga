#!/bin/bash

echo "==== Striga install script ===="

INSTALL_ROOT="/opt/striga"
DATA_ROOT="/etc/striga"
CONFIG_FILE="$INSTALL_ROOT/config.yaml"

# ---- Detect fresh install vs. update -----------------------------------------
# An existing install is identified by the deployed entry point. On update we
# refresh the code but deliberately preserve runtime state: the user's config
# (deep-merged, never clobbered) and their Vulners API key.
UPDATE=false
if [ -f "$INSTALL_ROOT/striga.py" ]; then
    UPDATE=true
    echo "Existing installation detected at $INSTALL_ROOT -- running in UPDATE mode."
    echo "(config.yaml and $DATA_ROOT are preserved; only code and new config keys are updated.)"
else
    echo "No existing installation found -- running a FRESH install."
fi

# ---- Copy the repo payload into a destination, excluding junk ----------------
# tar-based copy so VCS, virtualenvs, caches, and the local-only tests dir never
# get deployed (the old `cp -r .` dragged .git and venv/ into /opt/striga).
copy_payload() {
    local dest="$1"
    tar --exclude='./.git' \
        --exclude='./venv' \
        --exclude='./.venv' \
        --exclude='./__pycache__' \
        --exclude='*/__pycache__' \
        --exclude='./tests' \
        -cf - . | ( cd "$dest" && tar -xf - )
}

# ---- Preserve the Vulners API key --------------------------------------------
# Fresh install relocates the (repo-empty) key file to $DATA_ROOT so the operator
# can fill it in once. On update we must NOT overwrite a key they've already set,
# so we drop the freshly-copied empty one and keep the existing $DATA_ROOT copy.
handle_vulners_key() {
    local copied="$INSTALL_ROOT/vulners_api.key"
    [ -f "$copied" ] || return 0
    if [ -f "$DATA_ROOT/vulners_api.key" ]; then
        rm -f "$copied"
        echo "Preserved existing Vulners API key at $DATA_ROOT/vulners_api.key."
    else
        mv "$copied" "$DATA_ROOT/"
        echo "Installed Vulners API key placeholder to $DATA_ROOT/vulners_api.key."
    fi
}

echo "==== Creating system directories ===="
if [ ! -d "$DATA_ROOT" ]; then
    echo "mkdir $DATA_ROOT"
    sudo mkdir "$DATA_ROOT"
    echo "chown $USER:$USER -R $DATA_ROOT"
    sudo chown $USER:$USER -R "$DATA_ROOT"
else
    echo "$DATA_ROOT already exists"
fi

if [ ! -d "$INSTALL_ROOT" ]; then
    echo "mkdir $INSTALL_ROOT"
    sudo mkdir "$INSTALL_ROOT"
    echo "chown $USER:$USER -R $INSTALL_ROOT"
    sudo chown $USER:$USER -R "$INSTALL_ROOT"
else
    echo "$INSTALL_ROOT already exists"
fi

# ==============================================================================
# Docker setup runs only on a FRESH install. It restarts the Docker daemon and
# rewrites daemon.json, which is disruptive and unnecessary when merely updating
# striga's own files. Re-run a fresh install (or configure Docker manually) if a
# future release needs new host-level Docker changes.
# ==============================================================================
detect_os() {
    OS_ID=""
    OS_ID_LIKE=""
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID:-}"
        OS_ID_LIKE="${ID_LIKE:-}"
    fi
    is_arch=false
    is_debian=false
    case " $OS_ID $OS_ID_LIKE " in
        *" arch "*) is_arch=true ;;
    esac
    case " $OS_ID $OS_ID_LIKE " in
        *" debian "*) is_debian=true ;;
    esac
    echo "Detected OS: ID=$OS_ID ID_LIKE=$OS_ID_LIKE (arch=$is_arch debian=$is_debian)"
}

setup_docker() {
    echo "==== Setting up Docker (required for the GitHub PoC sandbox feature) ===="
    if command -v docker >/dev/null 2>&1; then
        echo "Docker already installed, skipping package install."
    elif $is_arch; then
        echo "Installing docker via pacman..."
        sudo pacman -Sy --needed --noconfirm docker
    elif $is_debian; then
        echo "Installing docker via apt (docker.io)..."
        sudo apt-get update
        sudo apt-get install -y docker.io
    else
        echo "Unrecognized distro (ID=$OS_ID, ID_LIKE=$OS_ID_LIKE) -- skipping automated Docker install."
        echo "Install Docker manually; striga's GitHub PoC sandbox won't work without it."
    fi

    if command -v docker >/dev/null 2>&1; then
        sudo systemctl enable --now docker 2>/dev/null || true

        echo "---- Configuring Docker daemon DNS ----"
        # Containers get their own network namespace + resolv.conf. If the host uses
        # systemd-resolved (its 127.0.0.53 stub is only valid in the host's own
        # netns), Docker can copy that straight into containers, breaking DNS for
        # every container -- including the sandbox image build's own `pip install`
        # step. Merge (never overwrite) a real DNS server into daemon.json.
        sudo mkdir -p /etc/docker
        tmp_daemon_json="$(mktemp)"
        python3 - "$tmp_daemon_json" <<'PYEOF'
import json, os, sys

path = "/etc/docker/daemon.json"
out_path = sys.argv[1]
cfg = {}
if os.path.exists(path):
    try:
        with open(path) as f:
            cfg = json.load(f)
    except (json.JSONDecodeError, OSError):
        cfg = {}

if "dns" not in cfg:
    cfg["dns"] = ["1.1.1.1", "8.8.8.8"]
    print("added default dns servers")
else:
    print("dns key already present, left untouched")

with open(out_path, "w") as f:
    json.dump(cfg, f, indent=2)
PYEOF
        sudo cp "$tmp_daemon_json" /etc/docker/daemon.json
        rm -f "$tmp_daemon_json"
        sudo systemctl restart docker 2>/dev/null || true

        if [ -f /etc/containerd/config.toml ]; then
            echo "---- Checking containerd cgroup driver ----"
            # Only relevant if a standalone containerd is in play (common on Arch;
            # Debian's docker.io normally bundles its own private containerd and
            # doesn't touch /etc/containerd/config.toml at all). A containerd runc
            # runtime left on the cgroupfs default while Docker itself uses the
            # systemd cgroup driver is a common cause of "OCI runtime create failed"
            # errors that give no useful explanation.
            if grep -q "SystemdCgroup = false" /etc/containerd/config.toml 2>/dev/null; then
                sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
                sudo systemctl restart containerd 2>/dev/null || true
                echo "Set SystemdCgroup = true in /etc/containerd/config.toml."
            fi
        fi

        echo "---- Checking AppArmor confinement of container tools ----"
        # AppArmor profiles for docker-default/podman/crun/runc/buildah have been
        # observed in enforce mode by default on some distros, blocking legitimate
        # container operations (memfd-exec, netns access, dlopen) with "permission
        # denied" errors that don't explain why. Switch just these to complain mode;
        # everything else AppArmor confines on the system is left as-is.
        if command -v aa-status >/dev/null 2>&1; then
            for profile in docker-default podman crun runc buildah; do
                if sudo aa-status 2>/dev/null | grep -qE "^\s*${profile}\s*$"; then
                    sudo aa-complain "$profile" >/dev/null 2>&1 && echo "Set AppArmor profile '$profile' to complain mode."
                fi
            done
        fi

        echo "---- Verifying Docker actually works ----"
        if sudo docker run --rm hello-world >/dev/null 2>&1; then
            echo "Docker sandbox check passed."
        else
            echo "WARNING: 'docker run --rm hello-world' failed -- the GitHub PoC sandbox"
            echo "feature will not work until this is resolved. Known causes:"
            echo "  - containerd/runc cgroup driver mismatch (checked above, but a restart"
            echo "    may still be needed: sudo systemctl restart containerd docker)"
            echo "  - AppArmor still enforcing on a container-related profile: sudo aa-status"
            echo "  - a runc/libpathrs version regression on very recent installs -- if"
            echo "    'docker run' fails instantly with something like 'runc did not"
            echo "    terminate successfully', check the installed runc/libpathrs versions"
            echo "    against https://archive.archlinux.org/packages/r/runc/ for a known-good"
            echo "    pairing rather than assuming this script's fixes cover it; this class of"
            echo "    bug is version-specific and can't be reliably auto-fixed here"
            echo "  - Docker+VPN routing interactions if this host uses a VPN"
            echo "Re-run 'sudo docker run --rm hello-world' after addressing these."
        fi
    else
        echo "WARNING: Docker is not installed. striga's GitHub PoC sandbox feature"
        echo "(exploitation/sandbox_runner.py) will not work until it is."
    fi
}

# ==============================================================================
# Optional: Ollama, the default local LLM backend for the AI evaluation layer.
# We never force this -- if ollama isn't installed we ASK before installing it,
# and we ASK again before pulling the (multi-GB) model. Both prompts are skipped
# in a non-interactive run (piped installer), so automation never blocks.
# ==============================================================================
setup_ollama() {
    echo "==== Optional: Ollama (local LLM backend for AI evaluation) ===="
    if command -v ollama >/dev/null 2>&1; then
        echo "Ollama is already installed."
    else
        local reply="n"
        if [ -t 0 ]; then
            read -r -p "Ollama is not installed. Install it now to enable AI evaluation? [y/N] " reply
        else
            echo "Non-interactive run: skipping Ollama install (install it manually to enable AI evaluation)."
        fi
        case "$reply" in
            [yY]|[yY][eE][sS])
                if $is_arch; then
                    echo "Installing ollama via pacman..."
                    sudo pacman -Sy --needed --noconfirm ollama
                elif command -v curl >/dev/null 2>&1; then
                    echo "Installing ollama via the official script (https://ollama.com/install.sh)..."
                    curl -fsSL https://ollama.com/install.sh | sh
                else
                    echo "curl not found and distro isn't Arch -- install Ollama manually from https://ollama.com/download."
                fi
                ;;
            *)
                echo "Skipping Ollama install. AI evaluation will be skipped at runtime until a backend is reachable."
                return 0
                ;;
        esac
    fi

    command -v ollama >/dev/null 2>&1 || return 0
    sudo systemctl enable --now ollama 2>/dev/null || true

    # Which model does the deployed config ask for? Read it with the venv python
    # (has PyYAML); default to the shipped model if anything goes wrong.
    local py="$INSTALL_ROOT/.venv/bin/python"
    [ -x "$py" ] || py="python3"
    local model
    model="$("$py" - "$CONFIG_FILE" <<'PYEOF'
import sys
try:
    import yaml
    with open(sys.argv[1]) as f:
        cfg = yaml.safe_load(f) or {}
    print((cfg.get("llm") or {}).get("model", "") or "")
except Exception:
    print("")
PYEOF
)"
    [ -n "$model" ] || model="qwen2.5:14b-instruct"

    if ollama list 2>/dev/null | grep -q "$model"; then
        echo "AI evaluation model '$model' already present."
    else
        local pull="n"
        if [ -t 0 ]; then
            read -r -p "Pull the AI evaluation model '$model' now? (multi-GB download) [y/N] " pull
        else
            echo "Non-interactive run: skipping model pull. Run 'ollama pull $model' to enable AI evaluation."
        fi
        case "$pull" in
            [yY]|[yY][eE][sS]) ollama pull "$model" ;;
            *) echo "Skipping model pull. Run 'ollama pull $model' before using AI evaluation." ;;
        esac
    fi
}

echo "==== Detecting operating system ===="
detect_os

if ! $UPDATE; then
    setup_docker
else
    echo "==== Skipping Docker setup (update mode) ===="
    echo "Docker configuration is left untouched. Re-run a fresh install if a new"
    echo "release requires host-level Docker changes."
fi

# ==============================================================================
# Deploy striga's files.
# ==============================================================================
if $UPDATE; then
    echo "==== Updating striga files ===="
    # Preserve the current config before the new tree lands on top of it.
    config_backup="$(mktemp)"
    had_config=false
    if [ -f "$CONFIG_FILE" ]; then
        cp "$CONFIG_FILE" "$config_backup"
        had_config=true
    fi

    copy_payload "$INSTALL_ROOT"
    handle_vulners_key

    if $had_config; then
        echo "==== Merging configuration (your settings are preserved) ===="
        # Deep-merge: the newly-copied config.yaml is the TEMPLATE (supplies any new
        # keys/sections this release added); the backed-up deployed config supplies
        # the VALUES (the operator's settings win on every key that already existed,
        # and operator-only keys are kept). Only framework name/version are taken
        # from the new template, since those track the code, not user configuration.
        # The pre-merge config is also saved to config.yaml.bak for safety.
        merge_py="$INSTALL_ROOT/.venv/bin/python"
        [ -x "$merge_py" ] || merge_py="python3"
        "$merge_py" - "$CONFIG_FILE" "$config_backup" "$CONFIG_FILE" <<'PYEOF'
import sys
try:
    import yaml
except ImportError:
    print("PyYAML unavailable; leaving your existing config.yaml untouched.")
    # Restore the operator's original config verbatim and stop.
    import shutil
    shutil.copyfile(sys.argv[2], sys.argv[1])
    sys.exit(0)

template_path, user_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]

def load(path):
    with open(path) as f:
        return yaml.safe_load(f) or {}

added = []

def deep_merge(template, user, trail=""):
    """User values win; template fills in keys the user doesn't have yet."""
    if isinstance(template, dict) and isinstance(user, dict):
        out = {}
        for key, tval in template.items():
            dotted = f"{trail}.{key}".lstrip(".")
            if key in user:
                out[key] = deep_merge(tval, user[key], dotted)
            else:
                out[key] = tval
                added.append(dotted)
        for key, uval in user.items():
            if key not in template:
                out[key] = uval  # operator-only key -- never drop it
        return out
    # scalar / list: keep the operator's value
    return user

template = load(template_path)
user = load(user_path)
merged = deep_merge(template, user)

# Metadata that must track the installed code, not the old deployment.
if isinstance(merged.get("framework"), dict) and isinstance(template.get("framework"), dict):
    for meta_key in ("name", "version"):
        if meta_key in template["framework"]:
            merged["framework"][meta_key] = template["framework"][meta_key]

# Safety backup of the operator's pre-merge config.
import shutil
shutil.copyfile(user_path, out_path + ".bak")

with open(out_path, "w") as f:
    yaml.safe_dump(merged, f, sort_keys=False, default_flow_style=False)

if added:
    print(f"Added {len(added)} new config key(s) from this release:")
    for key in added:
        print(f"  + {key}")
else:
    print("No new config keys in this release; your config is unchanged in substance.")
print(f"Previous config backed up to {out_path}.bak")
PYEOF
    fi
    rm -f "$config_backup"
else
    echo "==== Installing striga ===="
    copy_payload "$INSTALL_ROOT"
    handle_vulners_key
fi

echo "==== Installing python requirements ===="
# Reuse the existing virtualenv on update; create it on a fresh install. pip
# install always runs so new dependencies in requirements.txt are picked up.
if [ ! -d "$INSTALL_ROOT/.venv" ]; then
    python3 -m venv "$INSTALL_ROOT/.venv"
fi

if [ -n "$BASH_VERSION" ] || [ -n "$ZSH_VERSION" ]; then
    source "$INSTALL_ROOT/.venv/bin/activate"
else
    echo "Unsupported shell: This script must be run in Bash or Zsh."
    exit 1
fi

pip install -r requirements.txt
deactivate

setup_ollama

echo "==== Setting up Striga executable ===="
sudo cp striga /usr/bin
sudo chmod +x /usr/bin/striga

if $UPDATE; then
    echo "==== Update complete ===="
else
    echo "==== Install complete ===="
fi
