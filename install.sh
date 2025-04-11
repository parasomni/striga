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
