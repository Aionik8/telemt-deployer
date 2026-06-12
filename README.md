# Telemt Deployer

A desktop GUI tool for installing and configuring [telemt](https://github.com/telemt/telemt) on a Debian/Ubuntu VPS over SSH.

> The project is experimental. Use it only on servers you control.

## Features

- Quick mode and expert mode
- SSH password or SSH key authentication
- SSH fingerprint confirmation
- Installs the latest telemt release
- Supports FakeTLS domains and default ports
- UFW / nftables / MTproxy-reanimation tuning
- Test presets for experimental telemt configurations
- Generates a ready-to-copy `tg://proxy` link
- Windows one-file EXE build via PyInstaller

## Supported target servers

- Debian 11/12/13
- Ubuntu 20.04/22.04/24.04
- systemd
- x86_64 / aarch64

## Build Windows EXE

Install Python 3.8+ on Windows, then run:

```bat
build_onefile_exe.bat
```

The script creates:

```text
TelemtDeployer.exe
```

## Build Linux one-file binary

```bash
python3 -m venv .venv-build
. .venv-build/bin/activate
pip install -r requirements-build.txt
pyinstaller --onefile --windowed --clean --name TelemtDeployer-linux-x86_64 telemt_gui_deployer.py
```

The binary will be created in `dist/`.

## Security notes

- The app does not intentionally store SSH passwords, SSH private keys, telemt secrets, or sudo passwords.
- Confirmed SSH fingerprints are stored locally to detect server key changes.
- The app modifies firewall, systemd and telemt configuration on the target server.

## License

MIT
