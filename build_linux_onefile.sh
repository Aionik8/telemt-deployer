#!/usr/bin/env bash
set -euo pipefail

python3 -m venv .venv-build
. .venv-build/bin/activate
python -m pip install --upgrade pip
pip install -r requirements-build.txt
pyinstaller --onefile --windowed --clean --name TelemtDeployer-linux-x86_64 telemt_gui_deployer.py

echo "Built: dist/TelemtDeployer-linux-x86_64"
