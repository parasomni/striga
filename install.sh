#!/bin/bash

echo "==== Striga install script ===="

echo "==== Creating system directories ===="
if [ ! -d "/etc/striga" ]; then
    echo "mkdir /etc/striga"
    sudo mkdir /etc/striga
    echo "chown $USER:$USER -R /etc/striga"
    sudo chown $USER:$USER -R /etc/striga
else
    echo "/etc/striga already exists"
fi

if [ ! -d "/opt/striga" ]; then
    echo "mkdir /opt/striga"
    sudo mkdir /opt/striga
    echo "chown $USER:$USER -R /opt/striga"
    sudo chown $USER:$USER -R /opt/striga
else
    echo "/opt/striga already exists"
fi

echo "==== Detecting operating system ===="
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
echo "Detected: ID=$OS_ID ID_LIKE=$OS_ID_LIKE (arch=$is_arch debian=$is_debian)"

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

echo "==== Installing striga ===="
cp -r . /opt/striga
mv /opt/striga/vulners_api.key /etc/striga

echo "==== Installing python requirements ===="
python3 -m venv /opt/striga/.venv

if [ -n "$BASH_VERSION" ]; then
    source /opt/striga/.venv/bin/activate
elif [ -n "$ZSH_VERSION" ]; then
    source /opt/striga/.venv/bin/activate.zsh
else
    echo "Unsupported shell: This script must be run in Bash or Zsh."
    exit 1
fi

pip install -r requirements.txt
deactivate

echo "==== Setting up Striga executable ===="
sudo cp striga /usr/bin
sudo chmod +x /usr/bin/striga
