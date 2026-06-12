#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Telemt GUI Deployer
Локальный GUI-мастер: подключается к VPS по SSH, проверяет систему/права/порты,
показывает план и деплоит telemt-инстанс.

Пароли и SSH-ключи не сохраняются.
"""
from __future__ import annotations

import os
import queue
import re
import secrets
import base64
import hashlib
import json
import shlex
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

try:
    import paramiko
except Exception as exc:  # pragma: no cover
    print("Не найден модуль paramiko. Установите: pip install paramiko", file=sys.stderr)
    raise

DEFAULT_PAIRS: List[Tuple[int, str]] = [
    (443, "www.cloudflare.com"),
    (5223, "www.apple.com"),
    (8530, "www.microsoft.com"),
]
SUPPORTED_OS_TEXT = "Поддерживаются: Debian 11/12/13; Ubuntu 20.04/22.04/24.04; systemd; x86_64/aarch64"
SINGLE_INSTANCE_PORT = 48731
SINGLE_INSTANCE_TOKEN = "telemt-deployer-v1"

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
APP_DATA_DIR = Path(os.environ.get("APPDATA") or Path.home()) / "TelemtDeployer"
TRUSTED_HOSTS_FILE = APP_DATA_DIR / "known_hosts.json"


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def q(s: str) -> str:
    return shlex.quote(str(s))


def bool01(value: bool) -> str:
    return "1" if value else "0"


def shell_env_text(values: Dict[str, str]) -> str:
    return "".join(f"{k}={q(v)}\n" for k, v in values.items())


def describe_ss_owner(line: str) -> str:
    """Human-readable owner from one ss -ltnp line."""
    pairs = re.findall(r'"([^"]+)",pid=(\d+)', line or "")
    if pairs:
        seen = []
        for name, pid in pairs:
            item = f"{name} (pid {pid})"
            if item not in seen:
                seen.append(item)
        return ", ".join(seen)
    if "users:" in (line or ""):
        return line.split("users:", 1)[1].strip()
    return "процесс не виден через ss; возможно, нужны root-права или порт занят ядром/службой"


def load_trusted_hosts() -> Dict[str, str]:
    try:
        if TRUSTED_HOSTS_FILE.exists():
            data = json.loads(TRUSTED_HOSTS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items()}
    except Exception:
        pass
    return {}


def save_trusted_hosts(data: Dict[str, str]) -> None:
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    TRUSTED_HOSTS_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def ssh_key_fingerprint_sha256(key) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    fp = base64.b64encode(digest).decode("ascii").rstrip("=")
    return f"SHA256:{fp}"


def probe_ssh_server_key(host: str, port: int, timeout: int = 12):
    transport = paramiko.Transport((host, port))
    try:
        transport.start_client(timeout=timeout)
        return transport.get_remote_server_key()
    finally:
        transport.close()


def known_host_id(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


def domain_hex(domain: str) -> str:
    return domain.encode("utf-8").hex()


def full_secret(raw: str, domain: str) -> str:
    return "ee" + raw.lower() + domain_hex(domain)


def normalize_secret(value: str) -> str:
    v = value.strip().lower()
    if not v:
        return secrets.token_hex(16)
    if not re.fullmatch(r"[0-9a-f]+", v):
        raise ValueError("Secret должен быть hex-строкой")
    if len(v) == 32:
        return v
    if v.startswith("ee") and len(v) > 34:
        raw = v[2:34]
        if re.fullmatch(r"[0-9a-f]{32}", raw):
            return raw
    raise ValueError("Secret должен быть raw 32 hex или полным ee... secret")


def parse_port_rule(text: str, default_proto: str = "tcp") -> str:
    v = text.strip().lower()
    if not v:
        raise ValueError("Пустой порт")
    if "/" in v:
        port_s, proto = v.split("/", 1)
        proto = proto.strip()
    else:
        port_s, proto = v, default_proto
    if proto not in {"tcp", "udp"}:
        raise ValueError("Протокол должен быть tcp или udp")
    if not port_s.isdigit():
        raise ValueError("Порт должен быть числом")
    p = int(port_s)
    if not (1 <= p <= 65535):
        raise ValueError("Порт должен быть 1..65535")
    return f"{p}/{proto}"


def is_valid_ipv4(value: str) -> bool:
    parts = value.strip().split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if len(part) > 1 and part.startswith("0"):
            # 01 is ambiguous; keep the UI strict.
            return False
        n = int(part)
        if n < 0 or n > 255:
            return False
    return True


def parse_ssh_config() -> List[Dict[str, str]]:
    path = Path.home() / ".ssh" / "config"
    if not path.exists():
        return []
    entries: List[Dict[str, str]] = []
    current_hosts: List[str] = []
    current: Dict[str, str] = {}

    def flush() -> None:
        nonlocal current_hosts, current
        if not current_hosts:
            return
        for host in current_hosts:
            if "*" in host or "?" in host or host.lower() == "*":
                continue
            item = {"alias": host}
            item.update(current)
            entries.append(item)
        current_hosts = []
        current = {}

    try:
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if " " in line:
                key, val = line.split(None, 1)
            else:
                key, val = line, ""
            key_l = key.lower()
            if key_l == "host":
                flush()
                current_hosts = val.split()
            elif current_hosts:
                if key_l in {"hostname", "user", "port", "identityfile"}:
                    current[key_l] = val.strip().strip('"')
        flush()
    except Exception:
        return []
    return entries



class Tooltip:
    def __init__(self, widget, text: str, delay: int = 450):
        self.widget = widget
        self.text = text
        self.delay = delay
        self._after = None
        self._tip = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _event=None):
        self._cancel()
        self._after = self.widget.after(self.delay, self._show)

    def _cancel(self):
        if self._after:
            try:
                self.widget.after_cancel(self._after)
            except Exception:
                pass
            self._after = None

    def _show(self):
        if self._tip or not self.text:
            return
        try:
            x = self.widget.winfo_rootx() + 18
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 8
            self._tip = tk.Toplevel(self.widget)
            self._tip.wm_overrideredirect(True)
            self._tip.wm_geometry(f"+{x}+{y}")
            # Border gives depth without needing RGBA alpha
            frm = tk.Frame(self._tip, background="#1e2330", padx=12, pady=8,
                           highlightthickness=1, highlightbackground="#0d1117")
            frm.pack(fill="both", expand=True)
            # Top accent line
            tk.Frame(frm, background="#3b82f6", height=2).pack(fill="x", pady=(0, 6))
            lbl = tk.Label(frm, text=self.text, justify="left", background="#1e2330",
                           foreground="#e2e8f0", padx=0, pady=0, wraplength=400,
                           font=("Segoe UI", 9))
            lbl.pack()
        except Exception:
            self._tip = None

    def _hide(self, _event=None):
        self._cancel()
        if self._tip:
            try:
                self._tip.destroy()
            except Exception:
                pass
            self._tip = None


def add_tooltip(widget, text: str):
    Tooltip(widget, text)
    return widget


class SearchableSSHConfigPicker(ttk.Frame):
    """Compact selector for ~/.ssh/config with search inside popup."""
    def __init__(self, master, variable: tk.StringVar, command=None, **kwargs):
        super().__init__(master, **kwargs)
        self.variable = variable
        self.command = command
        self.values: List[str] = []
        self._theme: Dict[str, str] = {}
        self.entry = ttk.Entry(self, textvariable=self.variable, state="readonly", width=34)
        self.entry.grid(row=0, column=0, sticky="ew")
        # Small canvas arrow instead of a full ttk.Button: same visual height as the field,
        # no oversized button padding.
        self.button = tk.Canvas(self, width=24, height=22, highlightthickness=1, bd=0, cursor="hand2")
        self.button.grid(row=0, column=1, sticky="nsw", padx=(1, 0))
        self.columnconfigure(0, weight=1)
        self.entry.bind("<Button-1>", lambda e: self.open_popup())
        self.button.bind("<Button-1>", lambda e: self.open_popup())
        self._draw_arrow()

    def set_values(self, values: List[str]):
        self.values = values
        if self.variable.get() not in values:
            self.variable.set("")

    def apply_theme(self, theme: Dict[str, str]) -> None:
        self._theme = theme or {}
        self._draw_arrow()

    def _draw_arrow(self) -> None:
        field = self._theme.get("field", "#f4f6fb")
        border = self._theme.get("border", "#d1d8e8")
        muted = self._theme.get("muted", "#6b7280")
        self.button.configure(bg=field, highlightbackground=border, highlightcolor=border)
        self.button.delete("all")
        w = int(self.button.cget("width"))
        h = int(self.button.cget("height"))
        cx, cy = w // 2, h // 2 + 1
        self.button.create_polygon(cx - 4, cy - 2, cx + 4, cy - 2, cx, cy + 3, fill=muted, outline=muted)

    def open_popup(self):
        top = tk.Toplevel(self)
        top.title("SSH config")
        top.transient(self.winfo_toplevel())
        top.geometry(f"420x300+{self.winfo_rootx()}+{self.winfo_rooty()+self.winfo_height()+4}")
        top.rowconfigure(1, weight=1)
        top.columnconfigure(0, weight=1)
        search_var = tk.StringVar()
        search = ttk.Entry(top, textvariable=search_var)
        search.grid(row=0, column=0, sticky="ew", padx=8, pady=8)
        lb = tk.Listbox(top, activestyle="dotbox")
        lb.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0,8))

        def fill():
            term = search_var.get().strip().lower()
            lb.delete(0, tk.END)
            for v in self.values:
                if not term or term in v.lower():
                    lb.insert(tk.END, v or "<пусто / ручной ввод>")

        def choose(_event=None):
            sel = lb.curselection()
            if not sel:
                return
            raw = lb.get(sel[0])
            self.variable.set("" if raw.startswith("<пусто") else raw)
            try:
                top.destroy()
            except Exception:
                pass
            if self.command:
                self.command()

        search_var.trace_add("write", lambda *_: fill())
        lb.bind("<Double-Button-1>", choose)
        lb.bind("<Return>", choose)
        search.bind("<Down>", lambda e: (lb.focus_set(), lb.selection_set(0)) if lb.size() else None)
        fill()
        search.focus_set()

class ToggleSwitch(tk.Canvas):
    def __init__(self, master, variable: tk.BooleanVar, command=None, width=60, height=32, **kwargs):
        super().__init__(master, width=width, height=height, highlightthickness=0, bd=0, cursor="hand2", **kwargs)
        self.variable = variable
        self.command = command
        self.w = width
        self.h = height
        self._anim_job: Optional[str] = None
        self._anim_pos: float = 1.0 if variable.get() else 0.0
        self.bind("<Button-1>", self._toggle)
        self.draw()

    def _toggle(self, _event=None):
        self.variable.set(not self.variable.get())
        self._animate()
        if self.command:
            self.command()

    def _animate(self):
        """Smooth knob slide animation."""
        target = 1.0 if self.variable.get() else 0.0
        step = 0.18
        diff = target - self._anim_pos
        if abs(diff) < step:
            self._anim_pos = target
            self._anim_job = None
            self.draw()
            return
        self._anim_pos += step if diff > 0 else -step
        self.draw()
        self._anim_job = self.after(14, self._animate)

    @staticmethod
    def _lerp_color(c1: str, c2: str, t: float) -> str:
        r1, g1, b1 = int(c1[1:3], 16), int(c1[3:5], 16), int(c1[5:7], 16)
        r2, g2, b2 = int(c2[1:3], 16), int(c2[3:5], 16), int(c2[5:7], 16)
        r = int(r1 + (r2 - r1) * t)
        g = int(g1 + (g2 - g1) * t)
        b = int(b1 + (b2 - b1) * t)
        return f"#{r:02x}{g:02x}{b:02x}"

    def draw(self):
        self.delete("all")
        t = self._anim_pos

        parent_bg = getattr(self, "app_bg", None)
        if not parent_bg:
            try:
                parent_bg = self.master.cget("background")
            except Exception:
                parent_bg = "#f5f5f5"
        self.configure(bg=parent_bg)

        # True capsule switch: two circles + rectangle, not polygon smoothing.
        # This avoids the slightly squared corners that Tk polygon smoothing can give.
        x1, y1 = 1, 1
        x2, y2 = self.w - 1, self.h - 1
        r = (y2 - y1) / 2

        off_track = "#e6e7eb"
        off_border = "#cfd3dc"
        on_track = "#3b82f6"
        track_col = self._lerp_color(off_track, on_track, t)
        border_col = self._lerp_color(off_border, on_track, t)

        # Outer capsule = border/off outline.
        self._capsule(x1, y1, x2, y2, fill=border_col, outline=border_col)
        # Inner capsule = actual track. In ON state border becomes invisible because both colors match.
        inset = 2
        self._capsule(x1 + inset, y1 + inset, x2 - inset, y2 - inset, fill=track_col, outline=track_col)

        knob_d = self.h - 6
        margin = 3
        x_min = margin
        x_max = self.w - knob_d - margin
        kx = x_min + (x_max - x_min) * t
        ky = margin
        self.create_oval(kx, ky, kx + knob_d, ky + knob_d, fill="#ffffff", outline="#ffffff")

    def _capsule(self, x1: float, y1: float, x2: float, y2: float, **kwargs):
        d = y2 - y1
        r = d / 2
        self.create_rectangle(x1 + r, y1, x2 - r, y2, **kwargs)
        self.create_oval(x1, y1, x1 + d, y2, **kwargs)
        self.create_oval(x2 - d, y1, x2, y2, **kwargs)


class RoundedCard(tk.Frame):
    """Canvas-backed card with rounded corners and an inner content frame.

    Standard ttk.LabelFrame cannot draw rounded borders. This class keeps the
    public layout simple: grid/pack the RoundedCard itself, then put widgets into
    `.content`.
    """
    def __init__(self, master, text: str, theme: Optional[Dict[str, str]] = None,
                 radius: int = 14, padding: Tuple[int, int, int, int] = (12, 19, 12, 12)):
        self._theme = theme or {}
        self.text = text
        self.radius = radius
        self.padding = padding
        bg = self._theme.get("bg", "#eef0f5")
        card = self._theme.get("card", "#ffffff")
        muted = self._theme.get("muted", "#6b7280")
        super().__init__(master, bg=bg, highlightthickness=0, bd=0)
        self.canvas = tk.Canvas(self, highlightthickness=0, bd=0, bg=bg)
        self.canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self.content = tk.Frame(self, bg=card, highlightthickness=0, bd=0)
        self.content._rounded_card_content = True  # type: ignore[attr-defined]
        l, t, r, b = self.padding
        self.content.grid(row=0, column=0, sticky="nsew", padx=(l, r), pady=(t, b))
        self.title_label = tk.Label(
            self, text=text, bg=card, fg=muted,
            font=("Segoe UI", 9, "bold"), padx=5, pady=0, bd=0, highlightthickness=0,
        )
        self.title_label.place(x=13, y=1)
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.bind("<Configure>", lambda _e: self._draw(), add="+")
        self.after_idle(self._draw)

    def set_theme(self, theme: Dict[str, str]) -> None:
        self._theme = theme
        bg = theme.get("bg", "#eef0f5")
        card = theme.get("card", "#ffffff")
        muted = theme.get("muted", "#6b7280")
        self.configure(bg=bg)
        self.canvas.configure(bg=bg)
        self.content.configure(bg=card)
        self.title_label.configure(bg=card, fg=muted)
        self._draw()

    def _round_rect(self, x1, y1, x2, y2, radius=14, **kwargs):
        points = [
            x1+radius, y1, x2-radius, y1, x2, y1, x2, y1+radius,
            x2, y2-radius, x2, y2, x2-radius, y2, x1+radius, y2,
            x1, y2, x1, y2-radius, x1, y1+radius, x1, y1,
        ]
        return self.canvas.create_polygon(points, smooth=True, **kwargs)

    def _draw(self) -> None:
        w = max(2, self.winfo_width())
        h = max(2, self.winfo_height())
        theme = self._theme
        bg = theme.get("bg", "#eef0f5")
        card = theme.get("card", "#ffffff")
        border = theme.get("border", "#d1d8e8")
        self.canvas.delete("all")
        self.canvas.configure(bg=bg)
        # Border starts below the title, as with LabelFrame, but with rounded corners.
        self._round_rect(1, 8, w - 2, h - 2, radius=self.radius, fill=card, outline=border, width=1)

@dataclass
class TelemtConfig:
    name: str
    port: Optional[int] = None
    domain: str = ""
    raw: str = ""
    api: str = ""
    path: str = ""


@dataclass
class RemoteState:
    connected: bool = False
    root_mode: str = ""
    os_id: str = ""
    os_version: str = ""
    pretty_name: str = ""
    arch: str = ""
    glibc: str = ""
    systemd: bool = False
    supported: bool = False
    public_ports: List[str] = field(default_factory=list)
    public_ports_keep: List[str] = field(default_factory=list)
    used_tcp_ports: List[int] = field(default_factory=list)
    port_owners: Dict[int, List[str]] = field(default_factory=dict)
    telemt_configs: Dict[str, TelemtConfig] = field(default_factory=dict)
    default_available: List[Tuple[int, str]] = field(default_factory=list)
    raw_ss: str = ""


@dataclass(frozen=True)
class DeployParams:
    """Immutable snapshot created after successful validation.

    The GUI is allowed to keep changing after validation, but the plan/deploy
    must use exactly this snapshot. This avoids accidental differences between
    what the user reviewed and what is deployed.
    """
    data: Dict[str, str]
    fingerprint: str


class SSHSession:
    def __init__(self, host: str, port: int, user: str, password: str = "", key_path: str = "",
                 key_passphrase: str = "", sudo_password: str = "", host_key=None) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.key_path = key_path
        self.key_passphrase = key_passphrase
        self.sudo_password = sudo_password
        self.host_key = host_key
        self.client: Optional[paramiko.SSHClient] = None
        self.root_mode = ""

    def connect(self, timeout: int = 15) -> None:
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.RejectPolicy())
        if self.host_key is not None:
            host_id = known_host_id(self.host, self.port)
            cli.get_host_keys().add(host_id, self.host_key.get_name(), self.host_key)
            cli.get_host_keys().add(self.host, self.host_key.get_name(), self.host_key)
        kwargs = dict(hostname=self.host, port=self.port, username=self.user, timeout=timeout,
                      banner_timeout=timeout, auth_timeout=timeout, look_for_keys=True, allow_agent=True)
        if self.key_path:
            kwargs["key_filename"] = self.key_path
            if self.key_passphrase:
                kwargs["passphrase"] = self.key_passphrase
        elif self.password:
            kwargs["password"] = self.password
            kwargs["look_for_keys"] = False
            kwargs["allow_agent"] = False
        cli.connect(**kwargs)
        self.client = cli

    def close(self) -> None:
        if self.client:
            self.client.close()
            self.client = None

    def is_alive(self, timeout: int = 5) -> bool:
        if not self.client:
            return False
        try:
            transport = self.client.get_transport()
            if not transport or not transport.is_active():
                return False
            stdin, stdout, stderr = self.client.exec_command("true", timeout=timeout)
            _ = stdout.channel.recv_exit_status()
            return True
        except Exception:
            return False

    def _remote_command(self, cmd: str, sudo: bool = False) -> Tuple[str, Optional[str], bool]:
        stdin_data = None
        get_pty = False
        remote_cmd = cmd
        if sudo:
            if self.root_mode == "root":
                remote_cmd = cmd
            elif self.root_mode == "sudo-nopass":
                remote_cmd = f"sudo -n bash -lc {q(cmd)}"
            elif self.root_mode == "sudo-pass":
                remote_cmd = f"sudo -S -p '' bash -lc {q(cmd)}"
                stdin_data = (self.sudo_password or self.password) + "\n"
                get_pty = True
            else:
                raise RuntimeError("Права root/sudo не проверены")
        return remote_cmd, stdin_data, get_pty

    def run(self, cmd: str, timeout: int = 60, sudo: bool = False) -> Tuple[int, str, str]:
        if not self.client:
            raise RuntimeError("SSH не подключён")
        remote_cmd, stdin_data, get_pty = self._remote_command(cmd, sudo=sudo)
        stdin, stdout, stderr = self.client.exec_command(remote_cmd, timeout=timeout, get_pty=get_pty)
        if stdin_data is not None:
            stdin.write(stdin_data)
            stdin.flush()
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        code = stdout.channel.recv_exit_status()
        return code, out, err

    def run_stream(self, cmd: str, timeout: int = 900, sudo: bool = False, on_output=None) -> Tuple[int, str, str]:
        """Run command and stream stdout/stderr chunks to callback.

        Paramiko's stdout.read() returns only after command completion. For apt
        downloads/installations this looks like a frozen GUI. This method polls
        the channel and forwards chunks while the command is running.
        """
        if not self.client:
            raise RuntimeError("SSH не подключён")
        remote_cmd, stdin_data, get_pty = self._remote_command(cmd, sudo=sudo)
        transport = self.client.get_transport()
        if not transport or not transport.is_active():
            raise RuntimeError("SSH-соединение не активно")
        channel = transport.open_session(timeout=timeout)
        if get_pty:
            channel.get_pty()
        channel.settimeout(1.0)
        channel.exec_command(remote_cmd)
        if stdin_data is not None:
            channel.sendall(stdin_data.encode("utf-8"))
        out_parts: List[str] = []
        err_parts: List[str] = []
        start = time.time()
        while True:
            if timeout and time.time() - start > timeout:
                try:
                    channel.close()
                finally:
                    raise TimeoutError(f"Команда выполнялась дольше {timeout} секунд")
            got = False
            try:
                while channel.recv_ready():
                    chunk = channel.recv(4096).decode("utf-8", "replace")
                    out_parts.append(chunk)
                    got = True
                    if on_output and chunk:
                        on_output(strip_ansi(chunk))
                while channel.recv_stderr_ready():
                    chunk = channel.recv_stderr(4096).decode("utf-8", "replace")
                    err_parts.append(chunk)
                    got = True
                    if on_output and chunk:
                        on_output(strip_ansi(chunk))
            except socket.timeout:
                pass
            if channel.exit_status_ready():
                # drain remaining bytes
                while channel.recv_ready():
                    chunk = channel.recv(4096).decode("utf-8", "replace")
                    out_parts.append(chunk)
                    if on_output and chunk:
                        on_output(strip_ansi(chunk))
                while channel.recv_stderr_ready():
                    chunk = channel.recv_stderr(4096).decode("utf-8", "replace")
                    err_parts.append(chunk)
                    if on_output and chunk:
                        on_output(strip_ansi(chunk))
                return channel.recv_exit_status(), "".join(out_parts), "".join(err_parts)
            if not got:
                time.sleep(0.1)

    def upload_text(self, remote_path: str, content: str, mode: int = 0o700) -> None:
        if not self.client:
            raise RuntimeError("SSH не подключён")
        sftp = self.client.open_sftp()
        try:
            with sftp.file(remote_path, "w") as f:
                f.write(content)
            sftp.chmod(remote_path, mode)
        finally:
            sftp.close()

    def detect_rights(self) -> str:
        code, out, err = self.run("id -u", timeout=10)
        if code != 0:
            raise RuntimeError(err.strip() or "Не удалось выполнить id -u")
        if int(out.strip()) == 0:
            self.root_mode = "root"
            return self.root_mode
        code, _, _ = self.run("sudo -n true", timeout=10)
        if code == 0:
            self.root_mode = "sudo-nopass"
            return self.root_mode
        sp = self.sudo_password or self.password
        if sp:
            if not self.client:
                raise RuntimeError("SSH не подключён")
            stdin, stdout, stderr = self.client.exec_command("sudo -S -p '' true", timeout=10, get_pty=True)
            stdin.write(sp + "\n")
            stdin.flush()
            _ = stderr.read()
            code2 = stdout.channel.recv_exit_status()
            if code2 == 0:
                self.root_mode = "sudo-pass"
                return self.root_mode
        raise PermissionError("Нужен root или sudo. Войдите root, настройте passwordless sudo или укажите sudo-пароль.")


REMOTE_DEPLOY_SCRIPT = r'''#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info(){ echo -e "${CYAN}[INFO]${NC} $*"; }
ok(){ echo -e "${GREEN}[OK]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
die(){ echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

: "${TELEMT_ACTION:?}"
: "${TELEMT_PORT:?}"
: "${TELEMT_DOMAIN:?}"
: "${TELEMT_RAW_SECRET:?}"
: "${TELEMT_UFW_ENABLE:?}"
: "${TELEMT_SSH_PORT:?}"
ALLOW_RULES="${TELEMT_ALLOW_RULES:-}"
TELEMT_TUNE_MODE="${TELEMT_TUNE_MODE:-native}"
TELEMT_REPLACE_INSTANCE="${TELEMT_REPLACE_INSTANCE:-}"
TELEMT_NATIVE_SYNLIMIT="${TELEMT_NATIVE_SYNLIMIT:-0}"
TELEMT_NATIVE_BACKEND="${TELEMT_NATIVE_BACKEND:-nftables}"
TELEMT_NATIVE_PRESET="${TELEMT_NATIVE_PRESET:-hard}"
MTPR_ENABLE_NFT="${MTPR_ENABLE_NFT:-0}"
MTPR_ENABLE_SERVICE="${MTPR_ENABLE_SERVICE:-0}"
MTPR_APPLY_TUNING="${MTPR_APPLY_TUNING:-0}"
MTPR_IOS_KEEPALIVE="${MTPR_IOS_KEEPALIVE:-0}"
MTPR_IOS2_FIX="${MTPR_IOS2_FIX:-0}"
MTPR_PRESET="${MTPR_PRESET:-hard}"
MTPR_METER_TIMEOUT="${MTPR_METER_TIMEOUT:-60s}"
MTPR_EXTRA_PORTS="${MTPR_EXTRA_PORTS:-}"
MTPR_CUSTOM_RATE="${MTPR_CUSTOM_RATE:-}"
MTPR_CUSTOM_BURST="${MTPR_CUSTOM_BURST:-}"
MTPR_CUSTOM_TG_CONNECT="${MTPR_CUSTOM_TG_CONNECT:-}"
MTPR_CUSTOM_HANDSHAKE="${MTPR_CUSTOM_HANDSHAKE:-}"
MTPR_CUSTOM_KEEPALIVE="${MTPR_CUSTOM_KEEPALIVE:-}"
TELEMT_CUSTOM_TOML_B64="${TELEMT_CUSTOM_TOML_B64:-}"
TELEMT_MIN_MSS_VERSION="3.4.15"
BACKUP_TAG="$(date +%Y%m%d-%H%M%S)"
TARGET_NAME=""; CONFIG_PATH=""; SERVICE_PATH=""; API_PORT=""
TELEMT_GUI_DIR="/opt/telemt-gui"
TELEMT_GUI_STATE_DIR="/etc/telemt-gui"
TELEMT_BIN="${TELEMT_GUI_DIR}/bin/telemt"
MANAGED_FILE="${TELEMT_GUI_STATE_DIR}/managed-instances"
HAD_CONFIG=0; HAD_SERVICE=0; CFG_BAK=""; SVC_BAK=""

[[ ${EUID} -eq 0 ]] || die "Нужны root-права"

version_ge(){ [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$2" ]]; }

validate_inputs(){
  [[ "$TELEMT_PORT" =~ ^[0-9]+$ ]] || die "TELEMT_PORT должен быть числом"
  (( TELEMT_PORT >= 1 && TELEMT_PORT <= 65535 )) || die "TELEMT_PORT вне диапазона"
  [[ "$TELEMT_RAW_SECRET" =~ ^[0-9a-fA-F]{32}$ ]] || die "TELEMT_RAW_SECRET должен быть 32 hex"
  [[ "$TELEMT_DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || die "TELEMT_DOMAIN выглядит некорректно"
  [[ "$TELEMT_SSH_PORT" =~ ^[0-9]+$ ]] || die "TELEMT_SSH_PORT должен быть числом"
}

port_in_use(){
  local p="$1"
  ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -qE "(^|:|\\])${p}$" && return 0
  return 1
}

check_supported_os(){
  [[ -f /etc/os-release ]] || die "Система не поддерживается: нет /etc/os-release"
  . /etc/os-release
  local id="${ID:-}" ver="${VERSION_ID:-}" arch
  arch="$(uname -m)"
  command -v systemctl >/dev/null 2>&1 || die "Система не поддерживается: нужен systemd/systemctl"
  case "$arch" in x86_64|amd64|aarch64|arm64) ;; *) die "Система не поддерживается: архитектура $arch" ;; esac
  case "$id:$ver" in
    debian:11|debian:12|debian:13|ubuntu:20.04|ubuntu:22.04|ubuntu:24.04) ;;
    *) die "Система не поддерживается: ID=$id VERSION_ID=$ver. Поддерживаются: Debian 11/12/13, Ubuntu 20.04/22.04/24.04." ;;
  esac
  ok "ОС поддерживается: ${PRETTY_NAME:-$id $ver}, arch=$arch"
}

choose_target(){
  mkdir -p /etc/telemt /opt/telemt "$TELEMT_GUI_DIR/bin" "$TELEMT_GUI_STATE_DIR"
  if [[ -n "$TELEMT_REPLACE_INSTANCE" ]]; then
    [[ "$TELEMT_REPLACE_INSTANCE" =~ ^telemt[0-9]*$ ]] || die "Некорректный TELEMT_REPLACE_INSTANCE: $TELEMT_REPLACE_INSTANCE"
    TARGET_NAME="$TELEMT_REPLACE_INSTANCE"
    ok "Режим замены существующего telemt-конфига: ${TARGET_NAME}"
  elif [[ "$TELEMT_ACTION" == "install" ]]; then
    TARGET_NAME="telemt1"
  elif [[ "$TELEMT_ACTION" == "add_instance" ]]; then
    local i=2
    while [[ -e "/etc/telemt/telemt${i}.toml" || -e "/etc/systemd/system/telemt${i}.service" ]]; do i=$((i+1)); done
    TARGET_NAME="telemt${i}"
  else
    die "Неизвестный TELEMT_ACTION: $TELEMT_ACTION"
  fi
  CONFIG_PATH="/etc/telemt/${TARGET_NAME}.toml"
  SERVICE_PATH="/etc/systemd/system/${TARGET_NAME}.service"
  [[ -f "$CONFIG_PATH" ]] && HAD_CONFIG=1 || true
  [[ -f "$SERVICE_PATH" ]] && HAD_SERVICE=1 || true
}

stop_target_if_exists(){ systemctl stop "${TARGET_NAME}.service" 2>/dev/null || true; }

choose_api_port(){
  local p=9091
  while true; do
    if ! port_in_use "$p"; then API_PORT="$p"; return; fi
    p=$((p+1)); (( p <= 9199 )) || die "Не удалось найти свободный API-порт 9091..9199"
  done
}

backup_existing(){
  if [[ -f "$CONFIG_PATH" ]]; then CFG_BAK="${CONFIG_PATH}.bak.${BACKUP_TAG}"; cp -a "$CONFIG_PATH" "$CFG_BAK"; ok "Бэкап конфига: $CFG_BAK"; fi
  if [[ -f "$SERVICE_PATH" ]]; then SVC_BAK="${SERVICE_PATH}.bak.${BACKUP_TAG}"; cp -a "$SERVICE_PATH" "$SVC_BAK"; ok "Бэкап сервиса: $SVC_BAK"; fi
}

rollback(){
  local code=$?
  if [[ $code -eq 0 ]]; then return; fi
  warn "Ошибка деплоя, выполняю откат config/service..."
  systemctl stop "${TARGET_NAME}.service" 2>/dev/null || true
  if [[ -n "$CFG_BAK" && -f "$CFG_BAK" ]]; then cp -a "$CFG_BAK" "$CONFIG_PATH"; elif [[ $HAD_CONFIG -eq 0 ]]; then rm -f "$CONFIG_PATH"; fi
  if [[ -n "$SVC_BAK" && -f "$SVC_BAK" ]]; then cp -a "$SVC_BAK" "$SERVICE_PATH"; elif [[ $HAD_SERVICE -eq 0 ]]; then rm -f "$SERVICE_PATH"; fi
  systemctl daemon-reload 2>/dev/null || true
  if [[ $HAD_SERVICE -eq 1 ]]; then systemctl restart "${TARGET_NAME}.service" 2>/dev/null || true; fi
  warn "Откат config/service завершён. UFW-разрешения, если были добавлены, не удалялись автоматически."
  exit "$code"
}
trap rollback ERR

detect_os_family(){
  . /etc/os-release
  case "${ID:-}" in debian|ubuntu) OS_FAMILY="debian" ;; *) die "Система не поддерживается этим деплой-скриптом" ;; esac
}

pkg_update(){ DEBIAN_FRONTEND=noninteractive apt-get update -qq; }
pkg_install(){ DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"; }

ensure_deps(){
  info "Устанавливаю/проверяю зависимости..."
  pkg_update
  pkg_install curl wget tar gzip openssl jq python3 iptables ufw kmod ca-certificates libcap2-bin
  if [[ "$TELEMT_TUNE_MODE" == "mtpr" || ( "$TELEMT_TUNE_MODE" == "native" && "$TELEMT_NATIVE_SYNLIMIT" == "1" && "$TELEMT_NATIVE_BACKEND" == "nftables" ) ]]; then
    pkg_install nftables
  fi
}

telemt_detect_arch(){
  local m; m="$(uname -m)"
  case "$m" in
    x86_64|amd64) if grep -qE 'avx2.*bmi2|bmi2.*avx2' /proc/cpuinfo 2>/dev/null; then echo "x86_64-v3"; else echo "x86_64"; fi ;;
    aarch64|arm64) echo "aarch64" ;;
    *) die "Неподдерживаемая архитектура: $m" ;;
  esac
}

telemt_detect_libc(){
  for f in /lib/ld-musl-*.so.* /lib64/ld-musl-*.so.*; do [[ -e "$f" ]] && { echo musl; return; }; done
  echo gnu
}

glibc_version(){ getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}' || true; }

select_telemt_libc(){
  local libc gv
  libc="$(telemt_detect_libc)"
  if [[ "$libc" == "gnu" ]]; then
    gv="$(glibc_version)"
    if [[ -n "$gv" ]] && ! version_ge "$gv" "2.32"; then
      warn "Обнаружен glibc $gv: будет использована musl-сборка telemt."
      echo musl; return
    fi
  fi
  echo "$libc"
}

try_download_asset(){
  local latest="$1" arch="$2" libc="$3" outdir="$4" fn url
  fn="telemt-${arch}-linux-${libc}.tar.gz"
  url="https://github.com/telemt/telemt/releases/download/${latest}/${fn}"
  if curl -fsSL "$url" -o "${outdir}/${fn}" 2>/dev/null; then printf '%s' "${outdir}/${fn}"; return 0; fi
  return 1
}

download_telemt(){
  local arch libc latest tmpd archive bin candidate ca cl
  arch="$(telemt_detect_arch)"; libc="$(select_telemt_libc)"
  info "Архитектура: $arch, выбранная libc-сборка: $libc"
  latest="$(curl -fsI 'https://github.com/telemt/telemt/releases/latest' 2>/dev/null | grep -i '^location:' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
  [[ -n "$latest" ]] || die "Не удалось определить последнюю стабильную версию telemt"
  info "Последняя стабильная версия telemt: $latest"
  tmpd="$(mktemp -d)"; archive=""
  for candidate in "${arch}:${libc}" "x86_64:${libc}" "${arch}:musl" "x86_64:musl" "${arch}:gnu" "x86_64:gnu"; do
    ca="${candidate%%:*}"; cl="${candidate#*:}"
    if archive="$(try_download_asset "$latest" "$ca" "$cl" "$tmpd")"; then info "Скачан asset: $(basename "$archive")"; break; fi
  done
  [[ -n "$archive" && -f "$archive" ]] || die "Не удалось скачать подходящую сборку telemt"
  tar -xf "$archive" -C "$tmpd"
  bin="$(find "$tmpd" -type f -name telemt | head -1)"
  [[ -n "$bin" ]] || die "Бинарник telemt не найден"
  mkdir -p "$(dirname "$TELEMT_BIN")"
  install -m 0755 "$bin" "$TELEMT_BIN"
  command -v setcap >/dev/null 2>&1 && setcap cap_net_bind_service,cap_net_admin=+ep "$TELEMT_BIN" 2>/dev/null || true
  rm -rf "$tmpd"
  local version_out
  if ! version_out="$($TELEMT_BIN --version 2>&1)"; then
    echo "$version_out" >&2
    die "telemt установлен, но не запускается на этой системе"
  fi
  ok "telemt установлен: $(printf '%s\n' "$version_out" | head -1)"
  echo "TELEMT_BIN=${TELEMT_BIN}"
}

ensure_user(){
  local nologin; nologin="$(command -v nologin 2>/dev/null || echo /bin/false)"
  getent group telemt >/dev/null 2>&1 || groupadd -r telemt 2>/dev/null || true
  getent passwd telemt >/dev/null 2>&1 || useradd -r -g telemt -d /opt/telemt -s "$nologin" -c "Telemt" telemt 2>/dev/null || true
  mkdir -p /opt/telemt /etc/telemt
  chown telemt:telemt /opt/telemt /etc/telemt 2>/dev/null || true
  chmod 750 /opt/telemt /etc/telemt 2>/dev/null || true
}

write_config(){
  local native_seconds="1" native_hitcount="1" native_burst="1"
  case "${TELEMT_NATIVE_PRESET:-hard}" in
    medium) native_seconds="1"; native_hitcount="1"; native_burst="3" ;;
    soft) native_seconds="1"; native_hitcount="2"; native_burst="5" ;;
    *) native_seconds="1"; native_hitcount="1"; native_burst="1" ;;
  esac
  [[ "${TELEMT_NATIVE_BACKEND:-nftables}" == "iptables" || "${TELEMT_NATIVE_BACKEND:-nftables}" == "nftables" ]] || TELEMT_NATIVE_BACKEND="nftables"
  if [[ -n "${TELEMT_CUSTOM_TOML_B64:-}" ]]; then
    TELEMT_CUSTOM_TOML_B64="$TELEMT_CUSTOM_TOML_B64" \
    TELEMT_PORT="$TELEMT_PORT" TELEMT_DOMAIN="$TELEMT_DOMAIN" TELEMT_RAW_SECRET="$TELEMT_RAW_SECRET" \
    API_PORT="$API_PORT" TARGET_NAME="$TARGET_NAME" TELEMT_BIN="$TELEMT_BIN" CONFIG_PATH="$CONFIG_PATH" \
    python3 - <<'PYEOF'
import base64, os
text = base64.b64decode(os.environ['TELEMT_CUSTOM_TOML_B64']).decode('utf-8', errors='replace')
repl = {
    '__TELEMT_PORT__': os.environ['TELEMT_PORT'],
    '__TELEMT_DOMAIN__': os.environ['TELEMT_DOMAIN'],
    '__TELEMT_RAW_SECRET__': os.environ['TELEMT_RAW_SECRET'],
    '__API_PORT__': os.environ['API_PORT'],
    '__TARGET_NAME__': os.environ['TARGET_NAME'],
    '__TELEMT_BIN__': os.environ['TELEMT_BIN'],
}
for k, v in repl.items():
    text = text.replace(k, v)
with open(os.environ['CONFIG_PATH'], 'w', encoding='utf-8', newline='\n') as f:
    f.write(text.rstrip() + '\n')
PYEOF
    chown root:telemt "$CONFIG_PATH" 2>/dev/null || true
    chmod 640 "$CONFIG_PATH"
    ok "Записан custom TOML как $CONFIG_PATH"
    return 0
  fi
  cat > "$CONFIG_PATH" <<EOF
[general]
fast_mode = true
use_middle_proxy = false
tg_connect = 30

[general.modes]
classic = false
secure  = false
tls     = true

[timeouts]
client_handshake = 120
client_keepalive = 90

[network]
ipv4 = true
ipv6 = false
prefer = 4

[server]
port = ${TELEMT_PORT}
listen_addr_ipv4 = "0.0.0.0"
client_mss = "tspu"
EOF

  if [[ "$TELEMT_TUNE_MODE" == "native" && "${TELEMT_NATIVE_SYNLIMIT:-0}" == "1" ]]; then
    cat >> "$CONFIG_PATH" <<EOF

[[server.listeners]]
ip = "0.0.0.0"
synlimit = "${TELEMT_NATIVE_BACKEND}"
synlimit_seconds = ${native_seconds}
synlimit_hitcount = ${native_hitcount}
synlimit_burst = ${native_burst}
EOF
    ok "Telemt native SYN limiter включён: backend=${TELEMT_NATIVE_BACKEND}, seconds=${native_seconds}, hitcount=${native_hitcount}, burst=${native_burst}"
  fi

  cat >> "$CONFIG_PATH" <<EOF

[server.api]
enabled   = true
listen    = "127.0.0.1:${API_PORT}"
whitelist = ["127.0.0.1/32"]

[censorship]
tls_domain         = "${TELEMT_DOMAIN}"
mask               = true
mask_port          = 443
tls_emulation      = true
unknown_sni_action = "reject_handshake"
fake_cert_len      = 2048

[access]
replay_check_len = 65536
ignore_time_skew = false

[access.users]
${TARGET_NAME} = "${TELEMT_RAW_SECRET}"

[[upstreams]]
type = "direct"
weight = 1
enabled = true
EOF
  chown root:telemt "$CONFIG_PATH" 2>/dev/null || true
  chmod 640 "$CONFIG_PATH"
  ok "Записан $CONFIG_PATH"
}
write_service(){
  cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=Telemt MTProto Proxy (${TELEMT_DOMAIN})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=telemt
Group=telemt
WorkingDirectory=/opt/telemt
ExecStart=${TELEMT_BIN} ${CONFIG_PATH}
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
  chmod 644 "$SERVICE_PATH"
  systemctl daemon-reload
  systemctl enable "${TARGET_NAME}.service" >/dev/null 2>&1 || true
  ok "Создан/обновлён ${TARGET_NAME}.service"
}

add_rate_limit_rule(){
  local rules="/etc/ufw/before.rules" p="$TELEMT_PORT"
  [[ -f "$rules" ]] || return 0
  cp "$rules" "${rules}.bak.${BACKUP_TAG}" 2>/dev/null || true
  TELEMT_RL_PORT="$p" python3 - "$rules" <<'PYEOF'
import os, sys, tempfile
path = sys.argv[1]
port = os.environ['TELEMT_RL_PORT']
with open(path, encoding='utf-8', errors='replace') as f:
    text = f.read()
tag = f"MTProto rate-limit port {port}"
if tag in text:
    print(f"  rate-limit для {port} уже есть")
    raise SystemExit
lines = text.splitlines(True)
idx = None
for i, line in enumerate(lines):
    if "ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" in line:
        idx = i + 1
        break
if idx is None:
    for i, line in enumerate(lines):
        if "ufw-before-input -i lo -j ACCEPT" in line:
            idx = i + 1
            break
if idx is None:
    print("  точка вставки для rate-limit не найдена")
    raise SystemExit
block = [
    f"\n# === {tag} ===\n",
    f"-A ufw-before-input -p tcp --dport {port} --syn -m recent --name mtp{port} --rcheck --seconds 1 -j DROP\n",
    f"-A ufw-before-input -p tcp --dport {port} --syn -m recent --name mtp{port} --set -j ACCEPT\n",
    f"# === end {tag} ===\n",
]
lines[idx:idx] = block
fd, tmp = tempfile.mkstemp(prefix='.before.rules.', dir=os.path.dirname(path) or '.')
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.writelines(lines)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, os.stat(path).st_mode & 0o777)
    os.replace(tmp, path)
finally:
    try:
        if os.path.exists(tmp):
            os.unlink(tmp)
    except Exception:
        pass
print(f"  rate-limit вставлен для порта {port}")
PYEOF
}

base_ufw_allow(){
  command -v ufw >/dev/null 2>&1 || { warn "ufw не найден — автоматическое открытие TCP-портов пропущено"; return 0; }
  local rules="${TELEMT_SSH_PORT}/tcp ${TELEMT_PORT}/tcp ${TELEMT_ALLOW_RULES}" r seen=""
  if [[ "$TELEMT_TUNE_MODE" == "mtpr" ]]; then
    local p
    for p in $MTPR_EXTRA_PORTS; do
      [[ -n "$p" ]] && rules="$rules ${p}/tcp"
    done
  fi
  info "Добавляю базовые UFW allow без принудительного включения UFW: $rules"
  for r in $rules; do
    [[ -z "$r" ]] && continue
    [[ " $seen " == *" $r "* ]] && continue
    seen="$seen $r"
    ufw allow "$r" >/dev/null 2>&1 || warn "Не удалось добавить UFW allow $r"
  done
  ufw reload >/dev/null 2>&1 || true
  if ufw status 2>/dev/null | grep -qi '^Status: active'; then
    ok "UFW активен; базовые allow-правила применены"
  else
    warn "UFW сейчас не активен; allow-правила сохранены и сработают после включения UFW"
  fi
}

apply_ufw(){
  [[ "$TELEMT_TUNE_MODE" == "ufw" ]] || return 0
  [[ "$TELEMT_UFW_ENABLE" == "1" ]] || { warn "UFW не включён по выбору пользователя"; return; }
  local rules="${TELEMT_SSH_PORT}/tcp ${TELEMT_PORT}/tcp ${ALLOW_RULES}"
  local seen="" r
  info "Разрешаю UFW-порты: $rules"
  for r in $rules; do
    [[ -z "$r" ]] && continue
    [[ " $seen " == *" $r "* ]] && continue
    seen="$seen $r"
    ufw allow "$r" >/dev/null 2>&1 || warn "Не удалось добавить UFW allow $r"
  done
  if modprobe xt_recent 2>/dev/null && grep -q '^xt_recent ' /proc/modules 2>/dev/null; then
    echo xt_recent > /etc/modules-load.d/xt_recent.conf 2>/dev/null || true
    add_rate_limit_rule || true
  else
    warn "xt_recent не загружен — rate-limit пропущен"
  fi
  ufw --force enable >/dev/null
  ufw reload >/dev/null 2>&1 || true
  ok "UFW активен"
  ufw status verbose || true
}

ufw_allow_for_mtpr(){
  [[ "$TELEMT_TUNE_MODE" == "mtpr" ]] || return 0
  command -v ufw >/dev/null 2>&1 || { warn "ufw не найден — UFW allow для MTproxy-reanimation пропущен"; return 0; }
  local rules="${TELEMT_SSH_PORT}/tcp ${TELEMT_PORT}/tcp" r p seen=""
  for p in $MTPR_EXTRA_PORTS; do
    [[ -n "$p" ]] && rules="$rules ${p}/tcp"
  done
  # iOS MSS+redirect external port is read from upstream mtpr.sh later and allowed there.
  info "Добавляю UFW allow для MTproxy-reanimation без принудительного включения UFW: $rules"
  for r in $rules; do
    [[ -z "$r" ]] && continue
    [[ " $seen " == *" $r "* ]] && continue
    seen="$seen $r"
    ufw allow "$r" >/dev/null 2>&1 || warn "Не удалось добавить UFW allow $r"
  done
  ufw reload >/dev/null 2>&1 || true
  if ufw status 2>/dev/null | grep -qi '^Status: active'; then
    ok "UFW активен; allow-правила для выбранных TCP-портов добавлены"
  else
    warn "UFW сейчас не активен; allow-правила добавлены, но применятся только после включения UFW"
  fi
}

apply_mtpr(){
  [[ "$TELEMT_TUNE_MODE" == "mtpr" ]] || return 0
  info "Настройка MTproxy-reanimation / nftables..."
  ufw_allow_for_mtpr
  command -v nft >/dev/null 2>&1 || pkg_install nftables
  mkdir -p /opt/mtproxy-reanimation
  local mtpr_url="https://raw.githubusercontent.com/Liafanx/MTproxy-reanimation/main/mtpr.sh"
  curl -fsSL "$mtpr_url" -o /opt/mtproxy-reanimation/mtpr.sh || die "Не удалось скачать актуальный mtpr.sh из MTproxy-reanimation"
  chmod +x /opt/mtproxy-reanimation/mtpr.sh 2>/dev/null || true
  ln -sf /opt/mtproxy-reanimation/mtpr.sh /usr/local/bin/mtpr 2>/dev/null || true
  local mtpr_version mtpr_sha
  mtpr_version="$(grep -oE '^VERSION="[^"]+"' /opt/mtproxy-reanimation/mtpr.sh | head -1 | cut -d'"' -f2 || true)"
  mtpr_sha="$(sha256sum /opt/mtproxy-reanimation/mtpr.sh | awk '{print $1}')"
  cat > /opt/mtproxy-reanimation/upstream-info.txt <<EOF
url=${mtpr_url}
version=${mtpr_version:-unknown}
sha256=${mtpr_sha}
fetched_utc=$(date -u '+%Y-%m-%d %H:%M:%S')
EOF
  ok "MTproxy-reanimation upstream: version=${mtpr_version:-unknown}, sha256=${mtpr_sha}"

  local upstream_tg upstream_hs upstream_ka upstream_ios_ext upstream_ios_mss
  upstream_tg="$(grep -oE '^TUNING_TG_CONNECT="[^"]+"' /opt/mtproxy-reanimation/mtpr.sh | head -1 | cut -d'"' -f2 || true)"
  upstream_hs="$(grep -oE '^TUNING_CLIENT_HANDSHAKE="[^"]+"' /opt/mtproxy-reanimation/mtpr.sh | head -1 | cut -d'"' -f2 || true)"
  upstream_ka="$(grep -oE '^TUNING_CLIENT_KEEPALIVE="[^"]+"' /opt/mtproxy-reanimation/mtpr.sh | head -1 | cut -d'"' -f2 || true)"
  upstream_ios_ext="$(grep -oE '^IOS2_EXTERNAL_PORT="[^"]+"' /opt/mtproxy-reanimation/mtpr.sh | head -1 | cut -d'"' -f2 || true)"
  upstream_ios_mss="$(grep -oE '^IOS2_MSS="[^"]+"' /opt/mtproxy-reanimation/mtpr.sh | head -1 | cut -d'"' -f2 || true)"
  upstream_tg="${upstream_tg:-10}"; upstream_hs="${upstream_hs:-15}"; upstream_ka="${upstream_ka:-60}"
  upstream_ios_ext="${upstream_ios_ext:-4443}"; upstream_ios_mss="${upstream_ios_mss:-92}"

  local rate="1/second" burst="1"
  case "$MTPR_PRESET" in
    medium)
      rate="1/second"; burst="3" ;;
    soft)
      rate="2/second"; burst="5" ;;
    forum-test)
      rate="2/second"; burst="3"; MTPR_METER_TIMEOUT="60s"
      upstream_tg="30"; upstream_hs="7"; upstream_ka="45" ;;
    upstream-default)
      # Non-interactive equivalent of MTproxy-reanimation defaults:
      # NFT limiter 1/second burst 1, meter timeout 60s, Telemt tuning 10/15/60.
      rate="1/second"; burst="1"; MTPR_METER_TIMEOUT="60s"
      upstream_tg="10"; upstream_hs="15"; upstream_ka="60" ;;
    custom-nft)
      [[ "$MTPR_CUSTOM_RATE" =~ ^[0-9]+$ ]] || MTPR_CUSTOM_RATE="1"
      [[ "$MTPR_CUSTOM_BURST" =~ ^[0-9]+$ ]] || MTPR_CUSTOM_BURST="1"
      [[ "$MTPR_CUSTOM_TG_CONNECT" =~ ^[0-9]+$ ]] || MTPR_CUSTOM_TG_CONNECT="10"
      [[ "$MTPR_CUSTOM_HANDSHAKE" =~ ^[0-9]+$ ]] || MTPR_CUSTOM_HANDSHAKE="15"
      [[ "$MTPR_CUSTOM_KEEPALIVE" =~ ^[0-9]+$ ]] || MTPR_CUSTOM_KEEPALIVE="60"
      rate="${MTPR_CUSTOM_RATE}/second"; burst="$MTPR_CUSTOM_BURST"
      upstream_tg="$MTPR_CUSTOM_TG_CONNECT"; upstream_hs="$MTPR_CUSTOM_HANDSHAKE"; upstream_ka="$MTPR_CUSTOM_KEEPALIVE" ;;
    *)
      rate="1/second"; burst="1" ;;
  esac
  [[ "$MTPR_METER_TIMEOUT" =~ ^[0-9]+s$ ]] || MTPR_METER_TIMEOUT="60s"

  cat > /opt/mtproxy-reanimation/settings.conf <<EOF
# MTproxy-reanimation compatible settings generated by Telemt GUI
SERVER_IP=''
SERVER_PORT='${TELEMT_PORT}'
NFT_RATE='${rate}'
NFT_BURST='${burst}'
NFT_METER_TIMEOUT='${MTPR_METER_TIMEOUT}'
NFT_TABLE='telemt_limit'
NFT_HOOK='input'
TUNING_TG_CONNECT='${upstream_tg}'
TUNING_CLIENT_HANDSHAKE='${upstream_hs}'
TUNING_CLIENT_KEEPALIVE='${upstream_ka}'
TUNING_APPLIED='false'
NFT_SERVICE_ENABLED='false'
IOS_FIX_APPLIED='false'
IOS2_FIX_APPLIED='false'
IOS2_EXTERNAL_PORT='${upstream_ios_ext}'
IOS2_TARGET_PORT='${TELEMT_PORT}'
IOS2_MSS='${upstream_ios_mss}'
IOS2_TABLE='mtpr_ios2_fix'
EXTRA_RULES_COUNT='0'
EOF
  chmod 600 /opt/mtproxy-reanimation/settings.conf 2>/dev/null || true

  cat > /usr/local/sbin/mtpr-syn-limit.sh <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
PORT="${SERVER_PORT:-__TELEMT_PORT__}"
RATE="${NFT_RATE:-__RATE__}"
BURST="${NFT_BURST:-__BURST__}"
TIMEOUT="${NFT_METER_TIMEOUT:-__TIMEOUT__}"
EXTRA="${MTPR_EXTRA_PORTS_RUNTIME:-__EXTRA_PORTS__}"
nft delete table inet telemt_limit 2>/dev/null || true
nft add table inet telemt_limit
nft add chain inet telemt_limit input '{ type filter hook input priority 0; policy accept; }'
add_rule(){
  local p="$1"
  [ -n "$p" ] || return 0
  nft add rule inet telemt_limit input tcp dport "$p" tcp flags '&' '(' syn '|' ack ')' '==' syn meter mtpr_${p} '{ ip saddr timeout' "$TIMEOUT" 'limit rate over' "$RATE" 'burst' "$BURST" 'packets }' counter drop
}
add_rule "$PORT"
for p in $EXTRA; do add_rule "$p"; done
EOS
  sed -i "s/__TELEMT_PORT__/${TELEMT_PORT}/g; s#__RATE__#${rate}#g; s/__BURST__/${burst}/g; s/__TIMEOUT__/${MTPR_METER_TIMEOUT}/g; s/__EXTRA_PORTS__/${MTPR_EXTRA_PORTS}/g" /usr/local/sbin/mtpr-syn-limit.sh
  chmod +x /usr/local/sbin/mtpr-syn-limit.sh

  if [[ "$MTPR_ENABLE_NFT" == "1" ]]; then
    /usr/local/sbin/mtpr-syn-limit.sh
    ok "NFT SYN limiter применён: port=${TELEMT_PORT}, rate=${rate}, burst=${burst}, timeout=${MTPR_METER_TIMEOUT}"
  fi

  if [[ "$MTPR_ENABLE_SERVICE" == "1" ]]; then
    cat > /etc/systemd/system/mtpr-syn-limit.service <<'EOF'
[Unit]
Description=MTproxy-reanimation SYN limiter
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/mtpr-syn-limit.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now mtpr-syn-limit.service >/dev/null 2>&1 || true
    ok "mtpr-syn-limit.service включён"
  fi

  if [[ "$MTPR_APPLY_TUNING" == "1" ]]; then
    cp -a "$CONFIG_PATH" "${CONFIG_PATH}.mtpr-backup-${BACKUP_TAG}" 2>/dev/null || true
    sed -i -E "s/^[[:space:]]*tg_connect[[:space:]]*=.*/tg_connect = ${upstream_tg}/" "$CONFIG_PATH" || true
    sed -i -E "s/^[[:space:]]*client_handshake[[:space:]]*=.*/client_handshake = ${upstream_hs}/" "$CONFIG_PATH" || true
    sed -i -E "s/^[[:space:]]*client_keepalive[[:space:]]*=.*/client_keepalive = ${upstream_ka}/" "$CONFIG_PATH" || true
    systemctl restart "${TARGET_NAME}.service"
    ok "Базовый тюнинг Telemt применён: tg_connect=${upstream_tg}, client_handshake=${upstream_hs}, client_keepalive=${upstream_ka}"
  fi

  if [[ "$MTPR_IOS_KEEPALIVE" == "1" ]]; then
    cat > /etc/sysctl.d/99-tg-keepalive.conf <<'EOF'
# MTproxy-reanimation: iOS TCP keepalive
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 3
EOF
    sysctl --system >/dev/null 2>&1 || true
    ok "iOS TCP keepalive применён"
  fi

  if [[ "$MTPR_IOS2_FIX" == "1" ]]; then
    local ext_port="${upstream_ios_ext}" target_port="${TELEMT_PORT}" mss="${upstream_ios_mss}"
    iptables -t nat -C PREROUTING -p tcp --dport "$ext_port" -j REDIRECT --to-ports "$target_port" 2>/dev/null || \
      iptables -t nat -A PREROUTING -p tcp --dport "$ext_port" -j REDIRECT --to-ports "$target_port" 2>/dev/null || true
    iptables -t mangle -C PREROUTING -p tcp --dport "$ext_port" --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss" 2>/dev/null || \
      iptables -t mangle -A PREROUTING -p tcp --dport "$ext_port" --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss" 2>/dev/null || true
    if command -v ufw >/dev/null 2>&1; then ufw allow "${ext_port}/tcp" >/dev/null 2>&1 || true; fi
    ok "ОПАСНАЯ опция iOS MSS+redirect применена: ${ext_port}/tcp -> ${target_port}/tcp, MSS=${mss}"
  fi
}

start_and_verify(){
  if port_in_use "$TELEMT_PORT"; then
    local line; line="$(ss -H -ltnp 2>/dev/null | awk -v p=":${TELEMT_PORT}" '$4 ~ p"$" {print; exit}')"
    die "Порт ${TELEMT_PORT}/tcp занят: $line"
  fi
  systemctl restart "${TARGET_NAME}.service"
  local i active_ok=0 listen_ok=0
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if systemctl is-active --quiet "${TARGET_NAME}.service"; then active_ok=1; fi
    if ss -H -ltn 2>/dev/null | awk -v p=":${TELEMT_PORT}" '$4 ~ p"$" {found=1} END{exit found?0:1}'; then listen_ok=1; break; fi
    sleep 1
  done
  if [[ "$active_ok" -ne 1 || "$listen_ok" -ne 1 ]]; then
    warn "Сервис ${TARGET_NAME} не запустился или порт не начал слушаться. Диагностика:"
    systemctl status "${TARGET_NAME}.service" --no-pager || true
    echo ""
    journalctl -u "${TARGET_NAME}.service" -n 80 --no-pager || true
    echo ""
    warn "Пробный запуск ${TELEMT_BIN} для вывода ошибки:"
    timeout 8 "$TELEMT_BIN" "$CONFIG_PATH" || true
    die "Сервис ${TARGET_NAME} не запустился или порт ${TELEMT_PORT}/tcp не слушается"
  fi
  ok "${TARGET_NAME} слушает ${TELEMT_PORT}/tcp"
}


record_managed_instance(){
  mkdir -p "$TELEMT_GUI_STATE_DIR"
  touch "$MANAGED_FILE"
  local tmp="${MANAGED_FILE}.tmp"
  grep -vE "^${TARGET_NAME}[[:space:]]" "$MANAGED_FILE" > "$tmp" 2>/dev/null || true
  printf '%s %s %s %s %s\n' "$TARGET_NAME" "$TELEMT_PORT" "$TELEMT_DOMAIN" "$CONFIG_PATH" "$SERVICE_PATH" >> "$tmp"
  mv "$tmp" "$MANAGED_FILE"
  chmod 600 "$MANAGED_FILE" 2>/dev/null || true
  ok "Записан managed-state: $MANAGED_FILE"
}

print_result(){
  local ip link hexdom
  ip="$(curl -s4 -m 4 ifconfig.me 2>/dev/null || curl -s4 -m 4 api.ipify.org 2>/dev/null || echo '<SERVER_IP>')"
  hexdom="$(printf '%s' "$TELEMT_DOMAIN" | xxd -p 2>/dev/null | tr -d '\n' || printf '%s' "$TELEMT_DOMAIN" | od -A n -t x1 | tr -d ' \n')"
  link="tg://proxy?server=${ip}&port=${TELEMT_PORT}&secret=ee${TELEMT_RAW_SECRET}${hexdom}"
  echo ""
  ok "Готово"
  echo "INSTANCE=${TARGET_NAME}"
  echo "API_URL=http://127.0.0.1:${API_PORT}"
  echo "Ссылка для Telegram:"
  echo "${link}"
  echo "LINK=${link}"
}

validate_inputs
check_supported_os
detect_os_family
choose_target
stop_target_if_exists
choose_api_port
backup_existing
ensure_deps
download_telemt
ensure_user
write_config
write_service
start_and_verify
base_ufw_allow
apply_ufw
apply_mtpr
record_managed_instance
print_result
'''

REMOTE_CLEANUP_SCRIPT = r'''#!/usr/bin/env bash
set -euo pipefail
CLEANUP_SCOPE="${CLEANUP_SCOPE:-selected}"
CLEANUP_NAMES="${CLEANUP_NAMES:-}"
CLOSE_UFW="${CLOSE_UFW:-1}"
MANAGED_FILE="/etc/telemt-gui/managed-instances"
TELEMT_GUI_DIR="/opt/telemt-gui"
log(){ echo "$*"; }
[[ ${EUID} -eq 0 ]] || { echo "[ERROR] Нужны root-права" >&2; exit 1; }
close_port(){ local p="$1"; [[ -n "$p" ]] || return 0; if command -v ufw >/dev/null 2>&1; then ufw delete allow "${p}/tcp" >/dev/null 2>&1 || true; fi; }
remove_instance(){
  local name="$1"; [[ -n "$name" ]] || return 0
  case "$name" in *[!A-Za-z0-9_-]*) echo "[WARN] Пропуск некорректного имени: $name" >&2; return 0 ;; esac
  local cfg="/etc/telemt/${name}.toml" svc="/etc/systemd/system/${name}.service" port=""
  [[ -f "$cfg" ]] && port="$(awk -F= '/^[[:space:]]*port[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$cfg" || true)"
  systemctl disable --now "${name}.service" >/dev/null 2>&1 || true
  rm -f "$svc" "$svc".bak* "$cfg" "$cfg".bak*
  [[ "$CLOSE_UFW" == "1" && -n "$port" ]] && close_port "$port"
  if [[ -f "$MANAGED_FILE" ]]; then
    tmp="${MANAGED_FILE}.tmp"
    grep -vE "^${name}[[:space:]]" "$MANAGED_FILE" > "$tmp" 2>/dev/null || true
    mv "$tmp" "$MANAGED_FILE"
  fi
  log "Удалён ${name}${port:+, порт ${port}/tcp закрыт в UFW если был открыт}"
}
if [[ -n "$CLEANUP_NAMES" ]]; then for name in $CLEANUP_NAMES; do remove_instance "$name"; done; fi
if [[ "$CLEANUP_SCOPE" == "program" ]]; then
  if [[ -f "$MANAGED_FILE" ]]; then
    awk '{print $1}' "$MANAGED_FILE" | while read -r name; do remove_instance "$name"; done
    rm -f "$MANAGED_FILE"
  else
    # Backward compatibility: old GUI versions used telemtN naming without a marker file.
    for svc in /etc/systemd/system/telemt[0-9]*.service; do [[ -e "$svc" ]] || continue; remove_instance "$(basename "$svc" .service)"; done
    for cfg in /etc/telemt/telemt[0-9]*.toml; do [[ -e "$cfg" ]] || continue; remove_instance "$(basename "$cfg" .toml)"; done
  fi
fi
if [[ "$CLEANUP_SCOPE" == "all" ]]; then
  for cfg in /etc/telemt/*.toml; do [[ -e "$cfg" ]] || continue; remove_instance "$(basename "$cfg" .toml)"; done
fi
systemctl disable --now mtpr-syn-limit.service >/dev/null 2>&1 || true
nft delete table inet telemt_limit 2>/dev/null || true
nft delete table inet mtpr_ios2_fix 2>/dev/null || true
if [[ -f /opt/mtproxy-reanimation/settings.conf ]]; then
  ios_ext="$(awk -F= '/^IOS2_EXTERNAL_PORT=/{gsub(/\047|"/,"",$2); print $2; exit}' /opt/mtproxy-reanimation/settings.conf || true)"
  ios_target="$(awk -F= '/^IOS2_TARGET_PORT=/{gsub(/\047|"/,"",$2); print $2; exit}' /opt/mtproxy-reanimation/settings.conf || true)"
  ios_mss="$(awk -F= '/^IOS2_MSS=/{gsub(/\047|"/,"",$2); print $2; exit}' /opt/mtproxy-reanimation/settings.conf || true)"
  if [[ -n "${ios_ext:-}" && -n "${ios_target:-}" ]]; then
    iptables -t nat -D PREROUTING -p tcp --dport "$ios_ext" -j REDIRECT --to-ports "$ios_target" 2>/dev/null || true
  fi
  if [[ -n "${ios_ext:-}" && -n "${ios_mss:-}" ]]; then
    iptables -t mangle -D PREROUTING -p tcp --dport "$ios_ext" --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$ios_mss" 2>/dev/null || true
  fi
fi
rm -f /usr/local/sbin/mtpr-syn-limit.sh /etc/systemd/system/mtpr-syn-limit.service /usr/local/bin/mtpr
rm -rf /opt/mtproxy-reanimation
if [[ "$CLEANUP_SCOPE" == "all" ]]; then rm -rf "$TELEMT_GUI_DIR" /etc/telemt-gui; fi
log "Удалены настройки MTproxy-reanimation/nftables, если они были установлены."
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl reset-failed >/dev/null 2>&1 || true
log "Очистка завершена."
'''

def _new_single_instance_socket() -> socket.socket:
    """Create a socket that really enforces one app instance.

    Do not use SO_REUSEADDR here: on Windows it may allow the second GUI
    process to bind the same local port, so duplicate-instance detection is
    silently bypassed. SO_EXCLUSIVEADDRUSE is Windows-specific and gives the
    behavior we need; on Linux/macOS a plain bind is enough.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
    if exclusive is not None:
        try:
            sock.setsockopt(socket.SOL_SOCKET, exclusive, 1)
        except OSError:
            pass
    return sock


def _try_bind_single_instance_socket() -> Optional[socket.socket]:
    sock = _new_single_instance_socket()
    try:
        sock.bind(("127.0.0.1", SINGLE_INSTANCE_PORT))
        sock.listen(1)
        return sock
    except OSError:
        sock.close()
        return None


def acquire_single_instance_socket() -> Optional[socket.socket]:
    """Return a listening socket, or None if this new instance should exit."""
    sock = _try_bind_single_instance_socket()
    if sock is not None:
        return sock

    # Something is already listening. If it is another Telemt Deployer, offer to close it.
    try:
        with socket.create_connection(("127.0.0.1", SINGLE_INSTANCE_PORT), timeout=0.7) as c:
            c.sendall((SINGLE_INSTANCE_TOKEN + " PING\n").encode("utf-8"))
            reply = c.recv(64).decode("utf-8", "ignore")
            if "OK" not in reply:
                raise RuntimeError("unexpected control-port reply")
    except Exception:
        root = tk.Tk(); root.withdraw()
        messagebox.showerror(
            "Telemt Deployer",
            "Не удалось запустить приложение: локальный порт контроля уже занят другим процессом."
        )
        root.destroy()
        return None

    root = tk.Tk(); root.withdraw()
    close_old = messagebox.askyesno(
        "Telemt Deployer уже запущен",
        "Одна копия Telemt Deployer уже запущена.\n\nЗакрыть открытую копию и запустить новую?"
    )
    root.destroy()
    if not close_old:
        return None
    try:
        with socket.create_connection(("127.0.0.1", SINGLE_INSTANCE_PORT), timeout=1.0) as c:
            c.sendall((SINGLE_INSTANCE_TOKEN + " CLOSE\n").encode("utf-8"))
            _ = c.recv(64)
    except Exception:
        pass
    for _ in range(50):
        time.sleep(0.1)
        sock = _try_bind_single_instance_socket()
        if sock is not None:
            return sock
    root = tk.Tk(); root.withdraw()
    messagebox.showerror("Telemt Deployer", "Старая копия не закрылась. Новый запуск отменён.")
    root.destroy()
    return None


class App(tk.Tk):
    def __init__(self, single_instance_socket: Optional[socket.socket] = None) -> None:
        super().__init__()
        self._single_instance_socket = single_instance_socket
        self.title("Telemt Deployer")
        self.geometry("1100x760")
        self.minsize(980, 680)
        self.session: Optional[SSHSession] = None
        self.state = RemoteState()
        self.worker_q: queue.Queue = queue.Queue()
        self.ssh_config_entries = parse_ssh_config()
        self.custom_rules: List[str] = []
        self.tune_mode = tk.StringVar(value="native")  # native | ufw | mtpr
        self.native_mode = tk.StringVar(value="clean")  # clean | synlimit
        self.native_backend = tk.StringVar(value="nftables")
        self.native_preset = tk.StringVar(value="hard")
        self.mtpr_nft_enable = tk.BooleanVar(value=True)
        self.mtpr_service_enable = tk.BooleanVar(value=True)
        self.mtpr_tuning_enable = tk.BooleanVar(value=True)
        self.mtpr_ios_keepalive = tk.BooleanVar(value=False)
        self.mtpr_ios2_fix = tk.BooleanVar(value=False)
        self._ios2_confirmed = False
        self.mtpr_extra_ports_enable = tk.BooleanVar(value=False)
        self.mtpr_preset = tk.StringVar(value="hard")
        self.mtpr_meter_timeout = tk.StringVar(value="60s")
        # Separate expert-only test modes. They intentionally live outside the
        # main MTproxy-reanimation controls, so experimental recipes do not
        # clutter the normal deploy path.
        self.test_mode = tk.StringVar(value="upstream-default")
        self.test_toml_path = tk.StringVar(value="")
        self.test_nft_enable = tk.BooleanVar(value=True)
        self.test_service_enable = tk.BooleanVar(value=True)
        self.test_apply_tuning = tk.BooleanVar(value=True)
        self.test_ios_keepalive = tk.BooleanVar(value=True)
        self.test_nft_rate = tk.StringVar(value="1")
        self.test_nft_burst = tk.StringVar(value="1")
        self.test_meter_timeout = tk.StringVar(value="60s")
        self.test_tg_connect = tk.StringVar(value="10")
        self.test_client_handshake = tk.StringVar(value="15")
        self.test_client_keepalive = tk.StringVar(value="60")
        self.params_valid = False
        self.validated_params: Optional[Dict[str, str]] = None
        self.validated_snapshot: Optional[DeployParams] = None
        self.dark = tk.BooleanVar(value=True)
        self.expert_mode = tk.BooleanVar(value=False)
        self._ping_inflight = False
        self._disconnect_notified = False
        self.deploying = False
        self._cards: List[RoundedCard] = []
        self._build_ui()
        self._start_single_instance_server()
        self.after(100, self._drain_queue)
        self.after(5000, self._poll_connection)

    # ---------- UI ----------
    def _build_ui(self) -> None:
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass
        self._apply_theme()

        main = ttk.Frame(self)
        main.pack(fill=tk.BOTH, expand=True)
        main.rowconfigure(1, weight=1)
        main.columnconfigure(0, weight=1)

        header = ttk.Frame(main)
        header.grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 2))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text=SUPPORTED_OS_TEXT, font=("Segoe UI", 9), foreground="#8892a4").grid(row=0, column=0, sticky="w")
        theme_box = ttk.Frame(header)
        theme_box.grid(row=0, column=1, sticky="e")
        ttk.Label(theme_box, text="Экспертный режим").grid(row=0, column=0, padx=(0, 6))
        self.expert_switch = ToggleSwitch(theme_box, self.expert_mode, command=self._toggle_expert_mode)
        self.expert_switch.grid(row=0, column=1, padx=(0, 16))
        ttk.Label(theme_box, text="Тёмная тема").grid(row=0, column=2, padx=(0, 6))
        self.theme_switch = ToggleSwitch(theme_box, self.dark, command=self._apply_theme)
        self.theme_switch.grid(row=0, column=3)

        self.body = ttk.Frame(main)
        self.body.grid(row=1, column=0, sticky="nsew", padx=10, pady=6)
        self.body.columnconfigure(0, weight=1)
        self.body.rowconfigure(4, weight=1)

        self._build_connection_block()
        self._build_easy_block()
        self._build_params_block()
        self._build_ufw_block()
        self._build_action_block()
        self._build_log_block()

        self._show_initial_state()
        self._toggle_expert_mode()

    def _make_card(self, title: str) -> RoundedCard:
        card = RoundedCard(self.body, title, theme=getattr(self, "_theme", {}))
        self._cards.append(card)
        return card

    def _apply_theme(self) -> None:
        dark = self.dark.get() if hasattr(self, "dark") else False
        if dark:
            # Dark palette — deep navy base, elevated cards
            bg       = "#141820"   # window background
            card     = "#1e2330"   # LabelFrame / card surface (elevated)
            card_top = "#252c3d"   # slightly lighter top edge for bevel illusion
            fg       = "#e2e8f0"
            field    = "#2a3146"   # input background
            accent   = "#333d54"   # hover / pressed
            muted    = "#8892a4"
            warn     = "#f87171"
            ok_col   = "#34d399"
            border   = "#3a4460"   # frame border
            btn_bg   = "#2a3146"
            btn_fg   = "#e2e8f0"
            acc_bg   = "#3b82f6"   # accent button bg
            acc_fg   = "#ffffff"
            acc_act  = "#2563eb"
        else:
            # Light palette — white cards on light-grey base
            bg       = "#eef0f5"
            card     = "#ffffff"
            card_top = "#f8f9fc"
            fg       = "#1a1f2e"
            field    = "#f4f6fb"
            accent   = "#e2e6f0"
            muted    = "#6b7280"
            warn     = "#dc2626"
            ok_col   = "#059669"
            border   = "#d1d8e8"
            btn_bg   = "#ffffff"
            btn_fg   = "#1a1f2e"
            acc_bg   = "#3b82f6"
            acc_fg   = "#ffffff"
            acc_act  = "#2563eb"

        self._theme = {
            "bg": bg, "card": card, "fg": fg, "field": field,
            "accent": accent, "muted": muted, "warn": warn,
            "border": border, "acc_bg": acc_bg,
        }
        # Keep legacy key so cleanup_telemt dialog doesn't break
        self._theme["bg"] = bg

        try:
            self.configure(bg=bg)

            # --- Base frames ---
            self.style.configure("TFrame", background=bg)
            self.style.configure("TLabel", background=bg, foreground=fg, font=("Segoe UI", 9))
            self.style.configure("Muted.TLabel",  background=bg, foreground=muted, font=("Segoe UI", 9))
            self.style.configure("CardMuted.TLabel",  background=card, foreground=muted, font=("Segoe UI", 9))
            self.style.configure("Warn.TLabel",   background=bg, foreground=warn,  font=("Segoe UI", 9))
            self.style.configure("Ok.TLabel",     background=bg, foreground=ok_col, font=("Segoe UI", 9))
            self.style.configure("CardWarn.TLabel", background=card, foreground=warn, font=("Segoe UI", 9))
            self.style.configure("CardOk.TLabel",   background=card, foreground=ok_col, font=("Segoe UI", 9))

            # --- LabelFrame as a card with visible border + subtle padding ---
            self.style.configure(
                "TLabelframe",
                background=card,
                foreground=fg,
                bordercolor=border,
                relief="groove",
                borderwidth=1,
                padding=(10, 6, 10, 10),
            )
            self.style.configure(
                "TLabelframe.Label",
                background=card,
                foreground=muted,
                font=("Segoe UI", 9, "bold"),
                padding=(4, 0),
            )
            # Inner frames inside cards need card background
            self.style.configure("Card.TFrame", background=card)

            # --- Checkbutton / Radiobutton ---
            self.style.configure(
                "TCheckbutton", background=card, foreground=fg, font=("Segoe UI", 9)
            )
            self.style.map(
                "TCheckbutton",
                background=[("active", card), ("selected", card), ("disabled", card)],
                foreground=[("disabled", muted), ("active", fg), ("selected", fg)],
            )
            self.style.configure(
                "TRadiobutton", background=card, foreground=fg, font=("Segoe UI", 9)
            )
            self.style.map(
                "TRadiobutton",
                background=[("active", card), ("selected", card), ("disabled", card)],
                foreground=[("disabled", muted), ("active", fg), ("selected", fg)],
            )

            # --- Standard button — slightly raised look ---
            self.style.configure(
                "TButton",
                padding=(10, 5),
                background=btn_bg,
                foreground=btn_fg,
                borderwidth=1,
                relief="flat",
                font=("Segoe UI", 9),
            )
            self.style.map(
                "TButton",
                background=[("active", accent), ("pressed", accent), ("disabled", bg)],
                foreground=[("disabled", muted)],
                relief=[("pressed", "flat"), ("active", "flat")],
            )

            # --- Accent button (blue) for primary actions ---
            self.style.configure(
                "Accent.TButton",
                padding=(12, 6),
                background=acc_bg,
                foreground=acc_fg,
                borderwidth=0,
                relief="flat",
                font=("Segoe UI", 9, "bold"),
            )
            self.style.map(
                "Accent.TButton",
                background=[("active", acc_act), ("pressed", acc_act), ("disabled", accent)],
                foreground=[("disabled", muted)],
            )

            # --- Entry / Combobox ---
            self.style.configure(
                "TEntry",
                fieldbackground=field,
                foreground=fg,
                insertcolor=fg,
                borderwidth=1,
                relief="flat",
                padding=(4, 3),
            )
            self.style.map(
                "TEntry",
                fieldbackground=[("disabled", accent), ("readonly", field)],
                foreground=[("disabled", muted)],
            )
            self.style.configure(
                "TCombobox",
                fieldbackground=field,
                foreground=fg,
                arrowcolor=muted,
                borderwidth=1,
                relief="flat",
            )
            self.style.map(
                "TCombobox",
                fieldbackground=[("readonly", field), ("disabled", accent)],
                foreground=[("disabled", muted), ("readonly", fg)],
                selectbackground=[("readonly", acc_bg)],
                selectforeground=[("readonly", acc_fg)],
            )

            # --- ScrolledText log ---
            if hasattr(self, "log"):
                self.log.configure(
                    bg=field, fg=fg, insertbackground=fg,
                    selectbackground=acc_bg, selectforeground=acc_fg,
                    font=("Consolas", 9),
                    relief="flat", borderwidth=0,
                )

            # --- ToggleSwitch ---
            for sw_name in ("theme_switch", "expert_switch"):
                if hasattr(self, sw_name):
                    sw = getattr(self, sw_name)
                    sw.app_bg = bg
                    sw.draw()

            # --- Custom SSH config picker arrow ---
            if hasattr(self, "config_picker"):
                try:
                    self.config_picker.apply_theme(self._theme)
                except Exception:
                    pass

            # --- Rounded cards ---
            for card_widget in getattr(self, "_cards", []):
                try:
                    card_widget.set_theme(self._theme)
                except Exception:
                    pass

            # --- Propagate card bg to inner frames ---
            self._repaint_card_frames()

        except Exception:
            pass

    def _repaint_card_frames(self) -> None:
        """Make ttk children placed inside rounded cards use card background."""
        card = self._theme.get("card", "#ffffff") if hasattr(self, "_theme") else "#ffffff"

        def repaint(widget, in_card: bool = False):
            now_in_card = in_card or bool(getattr(widget, "_rounded_card_content", False))
            wclass = widget.winfo_class()

            if now_in_card:
                try:
                    if wclass in ("Frame", "Label", "TFrame", "TLabel"):
                        widget.configure(background=card)
                except Exception:
                    pass

            for child in widget.winfo_children():
                repaint(child, now_in_card)

        try:
            repaint(self)
        except Exception:
            pass

    def _build_connection_block(self) -> None:
        pad = {"padx": 6, "pady": 5}
        self.conn = self._make_card("1. Подключение")
        conn = self.conn.content
        self.conn.grid(row=0, column=0, sticky="ew", padx=6, pady=7)
        for c in range(10):
            conn.columnconfigure(c, weight=1 if c in (1, 4) else 0)

        self.config_choice_var = tk.StringVar(value="")
        ttk.Label(conn, text="SSH config:").grid(row=0, column=0, sticky="w", **pad)
        self.config_picker = SearchableSSHConfigPicker(conn, self.config_choice_var, command=self._apply_ssh_config_choice)
        self.config_picker.grid(row=0, column=1, columnspan=2, sticky="ew", **pad)
        add_tooltip(ttk.Label(conn, text="?", style="CardMuted.TLabel"), "Можно выбрать запись из ~/.ssh/config. Пусто = ручной ввод. Поиск находится внутри выпадающего списка.").grid(row=0, column=3, sticky="w", **pad)

        ttk.Label(conn, text="IP сервера:").grid(row=0, column=4, sticky="e", **pad)
        self.host_var = tk.StringVar()
        self.ip_entry = ttk.Entry(conn, textvariable=self.host_var, width=16)
        self.ip_entry.grid(row=0, column=5, sticky="w", **pad)
        self.ip_entry.bind("<Return>", lambda e: self._advance_ip())
        add_tooltip(ttk.Label(conn, text="?", style="CardMuted.TLabel"), "Введите IPv4 полностью, например 185.197.74.59, и нажмите Enter.").grid(row=0, column=6, sticky="w", **pad)

        ttk.Label(conn, text="SSH-порт:").grid(row=0, column=7, sticky="e", **pad)
        self.ssh_port_var = tk.StringVar(value="22")
        self.ssh_port_entry = ttk.Entry(conn, textvariable=self.ssh_port_var, width=7)
        self.ssh_port_entry.grid(row=0, column=8, sticky="w", **pad)
        self.ssh_port_entry.bind("<Return>", lambda e: self._advance_port())
        add_tooltip(ttk.Label(conn, text="?", style="CardMuted.TLabel"), "Если порт SSH не задан, используется 22. Этот порт автоматически добавляется в UFW allow и не удаляется из списка.").grid(row=0, column=9, sticky="w", **pad)

        self.auth_frame = ttk.Frame(conn, style="Card.TFrame")
        self.auth_frame.grid(row=1, column=0, columnspan=10, sticky="ew", **pad)
        for c in range(12):
            self.auth_frame.columnconfigure(c, weight=1 if c in (1,) else 0)

        self.auth_mode = tk.StringVar(value="password")
        ttk.Radiobutton(self.auth_frame, text="Логин/пароль", variable=self.auth_mode, value="password", command=self._toggle_auth_mode).grid(row=0, column=0, sticky="w", **pad)
        ttk.Radiobutton(self.auth_frame, text="Логин/SSH-ключ", variable=self.auth_mode, value="key", command=self._toggle_auth_mode).grid(row=0, column=1, sticky="w", **pad)

        ttk.Label(self.auth_frame, text="User:").grid(row=1, column=0, sticky="w", **pad)
        self.user_var = tk.StringVar(value="root")
        self.user_entry = ttk.Entry(self.auth_frame, textvariable=self.user_var, width=20)
        self.user_entry.grid(row=1, column=1, sticky="ew", **pad)

        ttk.Label(self.auth_frame, text="Password:").grid(row=1, column=2, sticky="w", **pad)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(self.auth_frame, textvariable=self.password_var, show="•", width=16)
        self.password_entry.grid(row=1, column=3, sticky="ew", **pad)
        add_tooltip(ttk.Label(self.auth_frame, text="?", style="CardMuted.TLabel"), "Пароль SSH. Поле отключается, если выбран вход по SSH-ключу.").grid(row=1, column=4, sticky="w", **pad)

        self.key_label = ttk.Label(self.auth_frame, text="SSH key:")
        self.key_label.grid(row=2, column=0, sticky="w", **pad)
        self.key_path_var = tk.StringVar()
        self.key_entry = ttk.Entry(self.auth_frame, textvariable=self.key_path_var, width=30)
        self.key_entry.grid(row=2, column=1, sticky="ew", **pad)
        self.key_button = ttk.Button(self.auth_frame, text="Ключ…", command=self._choose_key)
        self.key_button.grid(row=2, column=2, sticky="w", **pad)
        self.key_ext_hint = add_tooltip(ttk.Label(self.auth_frame, text="?", style="CardMuted.TLabel"), "Выберите OpenSSH private key: id_rsa, id_ed25519 или .pem. .ppk может не подойти.")
        self.key_ext_hint.grid(row=2, column=3, sticky="w", **pad)

        self.passphrase_label = ttk.Label(self.auth_frame, text="Passphrase:")
        self.passphrase_label.grid(row=2, column=4, sticky="e", **pad)
        self.key_pass_var = tk.StringVar()
        self.key_pass_entry = ttk.Entry(self.auth_frame, textvariable=self.key_pass_var, show="•", width=12)
        self.key_pass_entry.grid(row=2, column=5, sticky="w", **pad)
        self.passphrase_hint = add_tooltip(ttk.Label(self.auth_frame, text="?", style="CardMuted.TLabel"), "Пароль, которым зашифрован private key. Это не пароль от сервера.")
        self.passphrase_hint.grid(row=2, column=6, sticky="w", **pad)

        self.sudo_label = ttk.Label(self.auth_frame, text="Sudo:")
        self.sudo_label.grid(row=2, column=7, sticky="e", **pad)
        self.sudo_pass_var = tk.StringVar()
        self.sudo_pass_entry = ttk.Entry(self.auth_frame, textvariable=self.sudo_pass_var, show="•", width=12)
        self.sudo_pass_entry.grid(row=2, column=8, sticky="w", **pad)
        self.sudo_hint = add_tooltip(ttk.Label(self.auth_frame, text="?", style="CardMuted.TLabel"), "Нужен только если пользователь не root и sudo требует пароль.")
        self.sudo_hint.grid(row=2, column=9, sticky="w", **pad)

        self.check_frame = ttk.Frame(conn, style="Card.TFrame")
        self.check_frame.grid(row=4, column=0, columnspan=10, sticky="ew", **pad)
        self.check_frame.columnconfigure(0, weight=1)
        self.conn_status_var = tk.StringVar(value="● Не подключено")
        self.conn_status = ttk.Label(self.check_frame, textvariable=self.conn_status_var, style="CardWarn.TLabel")
        self.conn_status.grid(row=0, column=0, sticky="w", **pad)
        self.reconnect_btn = ttk.Button(self.check_frame, text="Переподключиться", command=self.connect_and_scan)
        self.reconnect_btn.grid(row=0, column=1, sticky="e", **pad)
        self.connect_btn = ttk.Button(self.check_frame, text="Проверить подключение и права",
                                      command=self.connect_and_scan, style="Accent.TButton")
        self.connect_btn.grid(row=0, column=2, sticky="e", **pad)

        self._refresh_ssh_config_combo()
        self._toggle_auth_mode()

    def _build_easy_block(self) -> None:
        pad = {"padx": 6, "pady": 5}
        self.easy_frame = self._make_card("Быстрый режим")
        easy = self.easy_frame.content
        self.easy_frame.grid(row=1, column=0, sticky="ew", padx=6, pady=7)
        easy.columnconfigure(1, weight=1)
        self.easy_status_var = tk.StringVar(value="Выберите сервер и нажмите Deploy. Приложение само выберет 443/5223/8530.")
        ttk.Label(easy, textvariable=self.easy_status_var, style="CardMuted.TLabel", wraplength=760, justify="left").grid(row=0, column=0, columnspan=3, sticky="w", **pad)
        self.easy_deploy_btn = ttk.Button(easy, text="Deploy", command=self.easy_deploy_clicked, style="Accent.TButton")
        self.easy_deploy_btn.grid(row=1, column=0, sticky="w", **pad)
        self.easy_link_var = tk.StringVar(value="")
        self.easy_link_entry = self._make_link_entry(easy, self.easy_link_var, width=90)
        self.easy_link_entry.grid(row=2, column=0, columnspan=2, sticky="ew", **pad)
        self.easy_copy_btn = ttk.Button(easy, text="Копировать", command=self.copy_easy_link)
        self.easy_copy_btn.grid(row=2, column=2, sticky="w", **pad)
        self.easy_link_entry.grid_remove()
        self.easy_copy_btn.grid_remove()

    def _toggle_expert_mode(self) -> None:
        expert = self.expert_mode.get() if hasattr(self, "expert_mode") else True
        try:
            if expert:
                self.easy_frame.grid_remove()
                self.params_frame.grid()
                self.ufw_outer.grid()
                self.actions.grid()
                self.log_frame.grid()
                self._show_after_connect() if self.state.connected else None
                self.geometry("1100x760")
                self.minsize(980, 680)
            else:
                self.params_frame.grid_remove()
                self.ufw_outer.grid_remove()
                self.actions.grid_remove()
                self.log_frame.grid_remove()
                self.easy_frame.grid()
                self.geometry("1000x420")
                self.minsize(860, 380)
        except Exception:
            pass

    def _build_params_block(self) -> None:
        pad = {"padx": 6, "pady": 4}
        self.params_frame = self._make_card("2. Набор параметров telemt")
        params = self.params_frame.content
        self.params_frame.grid(row=1, column=0, sticky="ew", padx=6, pady=7)
        for c in range(10):
            params.columnconfigure(c, weight=1 if c in (3, 7) else 0)

        ttk.Label(params, text="Действие:").grid(row=0, column=0, sticky="w", **pad)
        self.action_var = tk.StringVar(value="install")
        self.action_combo = ttk.Combobox(params, textvariable=self.action_var, values=["install", "add_instance"], state="readonly", width=13)
        self.action_combo.grid(row=0, column=1, sticky="w", **pad)

        ttk.Label(params, text="Набор параметров:").grid(row=0, column=2, sticky="w", **pad)
        self.param_set_var = tk.StringVar(value=self._pair_label(DEFAULT_PAIRS[0]))
        self.param_set_combo = ttk.Combobox(params, textvariable=self.param_set_var, state="readonly", width=28)
        self.param_set_combo.grid(row=0, column=3, sticky="w", **pad)
        self.param_set_combo.bind("<<ComboboxSelected>>", lambda e: self._on_param_set_changed())
        self.free_default_button = ttk.Button(params, text="Свободный дефолт", command=self._choose_free_default)
        self.free_default_button.grid(row=0, column=4, sticky="w", **pad)

        self.params_warning = ttk.Label(
            params,
            style="CardWarn.TLabel",
            text="Рекомендуется правдоподобная связка порт+домен: 443+www.cloudflare.com, 5223+www.apple.com, 8530+www.microsoft.com.",
            wraplength=520,
            justify="left",
        )
        self.params_warning.grid(row=0, column=5, columnspan=5, sticky="w", **pad)

        self.custom_frame = ttk.Frame(params, style="Card.TFrame")
        self.custom_frame.grid(row=1, column=0, columnspan=10, sticky="ew", **pad)
        for c in range(12):
            self.custom_frame.columnconfigure(c, weight=1 if c in (3, 7, 11) else 0)
        ttk.Label(self.custom_frame, text="Порт:").grid(row=0, column=0, sticky="w", **pad)
        self.telemt_port_var = tk.StringVar(value="443")
        ttk.Entry(self.custom_frame, textvariable=self.telemt_port_var, width=8).grid(row=0, column=1, sticky="w", **pad)
        ttk.Label(self.custom_frame, text="Домен:").grid(row=0, column=2, sticky="w", **pad)
        self.domain_var = tk.StringVar(value="www.cloudflare.com")
        ttk.Entry(self.custom_frame, textvariable=self.domain_var, width=30).grid(row=0, column=3, sticky="ew", **pad)

        self.secret_enabled = tk.BooleanVar(value=False)
        self.secret_check = ttk.Checkbutton(self.custom_frame, text="Свой secret", variable=self.secret_enabled, command=self._toggle_secret)
        self.secret_check.grid(row=0, column=4, sticky="w", **pad)
        self.secret_help = add_tooltip(ttk.Label(self.custom_frame, text="?", style="CardMuted.TLabel"), "Можно ввести raw secret: 32 hex-символа, или полный ee... secret. Если не указать, будет создан случайный.")
        self.secret_help.grid(row=0, column=5, sticky="w", **pad)
        self.secret_var = tk.StringVar()
        self.secret_entry = ttk.Entry(self.custom_frame, textvariable=self.secret_var, width=46)
        self.secret_entry.grid(row=0, column=6, columnspan=6, sticky="ew", **pad)

        self.existing_warning_var = tk.StringVar()
        self.existing_warning = ttk.Label(params, style="CardWarn.TLabel", textvariable=self.existing_warning_var, wraplength=900, justify="left")
        self.existing_warning.grid(row=2, column=0, columnspan=10, sticky="w", **pad)

        self._toggle_secret()
        self._refresh_param_sets()
        self._on_param_set_changed()

    def _build_ufw_block(self) -> None:
        pad = {"padx": 6, "pady": 5}
        self.ufw_outer = self._make_card("3. Сетевой тюнинг / firewall")
        ufw_container = self.ufw_outer.content
        self.ufw_outer.grid(row=2, column=0, sticky="ew", padx=6, pady=7)
        ufw_container.columnconfigure(0, weight=1)

        self.tuning_notebook = ttk.Notebook(ufw_container)
        self.tuning_notebook.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        self.tuning_main_tab = ttk.Frame(self.tuning_notebook, style="Card.TFrame")
        self.tuning_test_tab = ttk.Frame(self.tuning_notebook, style="Card.TFrame")
        self.tuning_notebook.add(self.tuning_main_tab, text="Основные")
        self.tuning_notebook.add(self.tuning_test_tab, text="Тестовые режимы")
        self.tuning_notebook.bind("<<NotebookTabChanged>>", lambda _e: self._on_tuning_tab_changed())

        ufw = self.tuning_main_tab
        ufw.columnconfigure(0, weight=1)

        mode_row = ttk.Frame(ufw, style="Card.TFrame")
        mode_row.grid(row=0, column=0, sticky="ew", **pad)
        ttk.Label(mode_row, text="Режим:").pack(side=tk.LEFT, padx=(0, 8))
        ttk.Radiobutton(mode_row, text="Telemt native", variable=self.tune_mode, value="native", command=self._toggle_tune_mode).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(mode_row, text="UFW + xt_recent", variable=self.tune_mode, value="ufw", command=self._toggle_tune_mode).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(mode_row, text="MTproxy-reanimation / nftables", variable=self.tune_mode, value="mtpr", command=self._toggle_tune_mode).pack(side=tk.LEFT, padx=(0, 10))
        add_tooltip(ttk.Label(mode_row, text="?", style="CardMuted.TLabel"), "Telemt native — чистая установка или встроенный SYN limiter telemt 3.4.17+. UFW/xt_recent и MTproxy-reanimation оставлены как альтернативы.").pack(side=tk.LEFT)

        self.native_inner = ttk.Frame(ufw, style="Card.TFrame")
        self.native_inner.grid(row=1, column=0, sticky="ew", **pad)
        self.native_inner.columnconfigure(9, weight=1)

        ttk.Radiobutton(self.native_inner, text="Чистая установка", variable=self.native_mode, value="clean").grid(row=0, column=0, sticky="w", **pad)
        ttk.Radiobutton(self.native_inner, text="Native SYN limiter", variable=self.native_mode, value="synlimit").grid(row=0, column=1, sticky="w", **pad)
        add_tooltip(ttk.Label(self.native_inner, text="?", style="CardMuted.TLabel"), "Встроенный SYN limiter telemt. В конфиг добавляются synlimit, synlimit_seconds, synlimit_hitcount, synlimit_burst в [[server.listeners]].").grid(row=0, column=2, sticky="w", **pad)
        ttk.Label(self.native_inner, text="backend:").grid(row=0, column=3, sticky="e", **pad)
        self.native_backend_combo = ttk.Combobox(self.native_inner, textvariable=self.native_backend, state="readonly", width=9, values=["nftables", "iptables"])
        self.native_backend_combo.grid(row=0, column=4, sticky="w", **pad)
        ttk.Label(self.native_inner, text="preset:").grid(row=0, column=5, sticky="e", **pad)
        self.native_preset_combo = ttk.Combobox(self.native_inner, textvariable=self.native_preset, state="readonly", width=8, values=["hard", "medium", "soft"])
        self.native_preset_combo.grid(row=0, column=6, sticky="w", **pad)

        self.ufw_inner = ttk.Frame(ufw, style="Card.TFrame")
        self.ufw_inner.grid(row=2, column=0, sticky="ew", **pad)
        self.ufw_inner.columnconfigure(2, weight=1)
        self.ufw_enable = tk.BooleanVar(value=False)
        self.keep_current_ports = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.ufw_inner, text="Включить/обновить UFW", variable=self.ufw_enable).grid(row=0, column=0, sticky="w", **pad)
        ttk.Checkbutton(self.ufw_inner, text="Добавить текущие публичные порты", variable=self.keep_current_ports).grid(row=0, column=1, sticky="w", **pad)
        add_tooltip(ttk.Label(self.ufw_inner, text="?", style="CardMuted.TLabel"), "Скрипт добавит в UFW allow публично слушающие порты, найденные на сервере в момент сканирования.").grid(row=0, column=2, sticky="w", **pad)
        ttk.Button(self.ufw_inner, text="Пересканировать порты", command=self.scan_ports).grid(row=0, column=3, sticky="w", **pad)
        ttk.Button(self.ufw_inner, text="Порты…", command=self.open_ports_window).grid(row=0, column=4, sticky="w", **pad)

        self.mtpr_inner = ttk.Frame(ufw, style="Card.TFrame")
        self.mtpr_inner.grid(row=3, column=0, sticky="ew", **pad)
        self.mtpr_inner.columnconfigure(0, weight=1)

        # Верхняя строка: все опции reanimation в одну компактную линию.
        self.mtpr_options_row = ttk.Frame(self.mtpr_inner, style="Card.TFrame")
        self.mtpr_options_row.grid(row=0, column=0, sticky="ew")

        def add_mtpr_option(text: str, var: tk.BooleanVar, tip: str, command=None) -> None:
            # Use the card background for the small per-option containers too.
            # Without this, ttk uses the default TFrame background and the help
            # labels look like dark square patches inside the rounded card.
            item = ttk.Frame(self.mtpr_options_row, style="Card.TFrame")
            item.pack(side=tk.LEFT, padx=(0, 14), pady=3)
            ttk.Checkbutton(item, text=text, variable=var, command=command).pack(side=tk.LEFT)
            add_tooltip(ttk.Label(item, text="?", style="CardMuted.TLabel"), tip).pack(side=tk.LEFT, padx=(3, 0))

        add_mtpr_option(
            "NFT SYN limiter",
            self.mtpr_nft_enable,
            "Лимитирует новые TCP SYN на порт telemt через nftables.",
            self._sync_mtpr_deps,
        )
        add_mtpr_option(
            "systemd автозапуск",
            self.mtpr_service_enable,
            "Создаёт службу, чтобы nft-правила переживали перезагрузку.",
            self._sync_mtpr_deps,
        )
        add_mtpr_option(
            "тюнинг Telemt",
            self.mtpr_tuning_enable,
            "Подкручивает tg_connect, handshake и keepalive в telemt-конфиге.",
        )
        add_mtpr_option(
            "iOS keepalive",
            self.mtpr_ios_keepalive,
            "sysctl keepalive для более стабильной работы iOS-клиентов.",
        )
        add_mtpr_option(
            "iOS MSS+redirect",
            self.mtpr_ios2_fix,
            "Опасная экспериментальная опция: redirect + MSS-правила.",
            self._confirm_ios2_option,
        )
        add_mtpr_option(
            "доп. TCP-порты",
            self.mtpr_extra_ports_enable,
            "Дополнительные TCP-порты telemt для nft limiter/UFW allow. Не SSH/VPN/панели.",
            self._sync_mtpr_deps,
        )

        # Нижняя строка: параметры limiter'а и кнопка портов. Подсказки стоят у названий параметров.
        self.mtpr_controls_row = ttk.Frame(self.mtpr_inner, style="Card.TFrame")
        self.mtpr_controls_row.grid(row=1, column=0, sticky="w", pady=(2, 0))

        ttk.Label(self.mtpr_controls_row, text="Пресет:").pack(side=tk.LEFT, padx=(0, 4))
        add_tooltip(ttk.Label(self.mtpr_controls_row, text="?", style="CardMuted.TLabel"), "hard/medium/soft — стандартные пресеты. forum-test — 2/3/60 + timeouts 30/7/45. upstream-default — максимально близко к дефолту MTproxy-reanimation: 1/1/60 + timeouts 10/15/60 + iOS keepalive.").pack(side=tk.LEFT, padx=(0, 4))
        self.mtpr_preset_combo = ttk.Combobox(
            self.mtpr_controls_row,
            textvariable=self.mtpr_preset,
            state="readonly",
            width=16,
            values=["hard", "medium", "soft"],
        )
        self.mtpr_preset_combo.pack(side=tk.LEFT, padx=(0, 16))
        self.mtpr_preset_combo.bind("<<ComboboxSelected>>", lambda _e: self._sync_mtpr_preset_options())

        ttk.Label(self.mtpr_controls_row, text="meter timeout:").pack(side=tk.LEFT, padx=(0, 4))
        add_tooltip(ttk.Label(self.mtpr_controls_row, text="?", style="CardMuted.TLabel"), "Как долго nftables помнит IP в meter после SYN.").pack(side=tk.LEFT, padx=(0, 4))
        self.mtpr_timeout_combo = ttk.Combobox(
            self.mtpr_controls_row,
            textvariable=self.mtpr_meter_timeout,
            state="readonly",
            width=7,
            values=["30s", "60s", "120s"],
        )
        self.mtpr_timeout_combo.pack(side=tk.LEFT, padx=(0, 16))
        ttk.Button(self.mtpr_controls_row, text="Порты…", command=self.open_ports_window).pack(side=tk.LEFT)

        self._build_test_tuning_tab(self.tuning_test_tab)
        self._toggle_tune_mode()

    def _build_test_tuning_tab(self, parent: ttk.Frame) -> None:
        pad = {"padx": 6, "pady": 5}
        parent.columnconfigure(1, weight=1)

        ttk.Label(parent, text="Тестовый режим:").grid(row=0, column=0, sticky="w", **pad)
        self.test_mode_combo = ttk.Combobox(
            parent,
            textvariable=self.test_mode,
            state="readonly",
            width=22,
            values=["upstream-default", "forum-test", "custom-nft", "custom-toml"],
        )
        self.test_mode_combo.grid(row=0, column=1, sticky="w", **pad)
        self.test_mode_combo.bind("<<ComboboxSelected>>", lambda _e: self._sync_test_mode_options())
        add_tooltip(
            ttk.Label(parent, text="?", style="CardMuted.TLabel"),
            "Здесь только экспериментальные рецепты. Основные режимы остаются на вкладке «Основные».",
        ).grid(row=0, column=2, sticky="w", **pad)

        self.test_flags_row = ttk.Frame(parent, style="Card.TFrame")
        self.test_flags_row.grid(row=1, column=0, columnspan=6, sticky="ew", **pad)
        ttk.Checkbutton(self.test_flags_row, text="NFT limiter", variable=self.test_nft_enable).pack(side=tk.LEFT, padx=(0, 14))
        ttk.Checkbutton(self.test_flags_row, text="systemd", variable=self.test_service_enable).pack(side=tk.LEFT, padx=(0, 14))
        ttk.Checkbutton(self.test_flags_row, text="timeouts", variable=self.test_apply_tuning).pack(side=tk.LEFT, padx=(0, 14))
        ttk.Checkbutton(self.test_flags_row, text="iOS keepalive", variable=self.test_ios_keepalive).pack(side=tk.LEFT, padx=(0, 14))
        ttk.Button(self.test_flags_row, text="Порты…", command=self.open_ports_window).pack(side=tk.LEFT)

        self.test_nft_row = ttk.Frame(parent, style="Card.TFrame")
        self.test_nft_row.grid(row=2, column=0, columnspan=6, sticky="ew", **pad)
        ttk.Label(self.test_nft_row, text="NFT rate:").pack(side=tk.LEFT, padx=(0, 4))
        ttk.Entry(self.test_nft_row, textvariable=self.test_nft_rate, width=5).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(self.test_nft_row, text="/second   burst:").pack(side=tk.LEFT, padx=(0, 4))
        ttk.Entry(self.test_nft_row, textvariable=self.test_nft_burst, width=5).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(self.test_nft_row, text="meter timeout:").pack(side=tk.LEFT, padx=(0, 4))
        ttk.Entry(self.test_nft_row, textvariable=self.test_meter_timeout, width=7).pack(side=tk.LEFT, padx=(0, 10))
        add_tooltip(
            ttk.Label(self.test_nft_row, text="?", style="CardMuted.TLabel"),
            "Поля нужны для быстрой проверки рецептов с форумов: например rate=1 burst=1 timeout=60s или rate=2 burst=3 timeout=60s.",
        ).pack(side=tk.LEFT)

        self.test_timeout_row = ttk.Frame(parent, style="Card.TFrame")
        self.test_timeout_row.grid(row=3, column=0, columnspan=6, sticky="ew", **pad)
        ttk.Label(self.test_timeout_row, text="tg_connect:").pack(side=tk.LEFT, padx=(0, 4))
        ttk.Entry(self.test_timeout_row, textvariable=self.test_tg_connect, width=5).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(self.test_timeout_row, text="handshake:").pack(side=tk.LEFT, padx=(0, 4))
        ttk.Entry(self.test_timeout_row, textvariable=self.test_client_handshake, width=5).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(self.test_timeout_row, text="keepalive:").pack(side=tk.LEFT, padx=(0, 4))
        ttk.Entry(self.test_timeout_row, textvariable=self.test_client_keepalive, width=5).pack(side=tk.LEFT, padx=(0, 10))
        add_tooltip(
            ttk.Label(self.test_timeout_row, text="?", style="CardMuted.TLabel"),
            "Эти значения записываются/правятся в telemt-конфиге через MTproxy-reanimation tuning.",
        ).pack(side=tk.LEFT)

        self.test_toml_row = ttk.Frame(parent, style="Card.TFrame")
        self.test_toml_row.grid(row=4, column=0, columnspan=6, sticky="ew", **pad)
        self.test_toml_row.columnconfigure(1, weight=1)
        ttk.Label(self.test_toml_row, text="Готовый TOML:").grid(row=0, column=0, sticky="w", padx=(0, 6))
        ttk.Entry(self.test_toml_row, textvariable=self.test_toml_path).grid(row=0, column=1, sticky="ew", padx=(0, 6))
        ttk.Button(self.test_toml_row, text="Выбрать…", command=self._choose_test_toml).grid(row=0, column=2, sticky="w")
        add_tooltip(
            ttk.Label(self.test_toml_row, text="?", style="CardMuted.TLabel"),
            "Файл будет записан как telemt-конфиг. Поддерживаются плейсхолдеры: __TELEMT_PORT__, __TELEMT_DOMAIN__, __TELEMT_RAW_SECRET__, __API_PORT__, __TARGET_NAME__.",
        ).grid(row=0, column=3, sticky="w", padx=(6, 0))

        self.test_hint_var = tk.StringVar(value="")
        ttk.Label(parent, textvariable=self.test_hint_var, style="CardMuted.TLabel", wraplength=980, justify="left").grid(row=5, column=0, columnspan=6, sticky="ew", **pad)
        self._sync_test_mode_options()

    def _is_test_tab_active(self) -> bool:
        try:
            return bool(self.expert_mode.get()) and hasattr(self, "tuning_notebook") and self.tuning_notebook.index("current") == 1
        except Exception:
            return False

    def _on_tuning_tab_changed(self) -> None:
        # The test tab is an explicit deploy recipe selector. While it is active,
        # validation/deploy use test controls and ignore normal tuning controls.
        self._invalidate_params()
        if self._is_test_tab_active():
            self.tune_mode.set("mtpr")
            self._sync_test_mode_options()
        else:
            self._toggle_tune_mode()

    def _choose_test_toml(self) -> None:
        path = filedialog.askopenfilename(
            title="Выберите telemt TOML",
            filetypes=[("TOML", "*.toml"), ("All files", "*.*")],
        )
        if path:
            self.test_toml_path.set(path)
            self.test_mode.set("custom-toml")
            self._sync_test_mode_options()

    def _sync_test_mode_options(self) -> None:
        mode = self.test_mode.get()
        if mode == "upstream-default":
            self.test_nft_enable.set(True)
            self.test_service_enable.set(True)
            self.test_apply_tuning.set(True)
            self.test_ios_keepalive.set(True)
            self.test_nft_rate.set("1")
            self.test_nft_burst.set("1")
            self.test_meter_timeout.set("60s")
            self.test_tg_connect.set("10")
            self.test_client_handshake.set("15")
            self.test_client_keepalive.set("60")
            self.test_hint_var.set("Повторяет ручной вариант: telemt latest + client_mss=tspu + MTproxy-reanimation defaults: 1/sec, burst 1, timeout 60s, timeouts 10/15/60, iOS keepalive.")
        elif mode == "forum-test":
            self.test_nft_enable.set(True)
            self.test_service_enable.set(True)
            self.test_apply_tuning.set(True)
            self.test_ios_keepalive.set(False)
            self.test_nft_rate.set("2")
            self.test_nft_burst.set("3")
            self.test_meter_timeout.set("60s")
            self.test_tg_connect.set("30")
            self.test_client_handshake.set("7")
            self.test_client_keepalive.set("45")
            self.test_hint_var.set("Форумный тест: 2/sec, burst 3, timeout 60s, timeouts 30/7/45. Удобно сравнить с upstream-default.")
        elif mode == "custom-toml":
            self.test_nft_enable.set(True)
            self.test_service_enable.set(True)
            self.test_apply_tuning.set(False)
            self.test_hint_var.set("Custom TOML: файл будет загружен как telemt-конфиг. NFT-поля ниже всё равно можно применить как внешний limiter.")
        else:
            self.test_nft_enable.set(True)
            self.test_service_enable.set(True)
            self.test_apply_tuning.set(True)
            self.test_hint_var.set("Custom NFT: вручную задаются rate/burst/meter timeout и timeouts telemt. TOML не обязателен.")
        self._invalidate_params()

    def _test_int(self, var: tk.StringVar, name: str, min_value: int = 0, max_value: int = 86400) -> str:
        value = var.get().strip()
        if not re.fullmatch(r"[0-9]+", value):
            raise ValueError(f"{name} должен быть целым числом")
        iv = int(value)
        if iv < min_value or iv > max_value:
            raise ValueError(f"{name} вне диапазона {min_value}..{max_value}")
        return str(iv)

    def _test_timeout_value(self) -> str:
        value = self.test_meter_timeout.get().strip()
        if re.fullmatch(r"[0-9]+", value):
            value += "s"
        if not re.fullmatch(r"[0-9]+s", value):
            raise ValueError("meter timeout должен быть в формате 60s или числом секунд")
        return value

    def _toggle_tune_mode(self) -> None:
        mode = self.tune_mode.get()
        if mode == "ufw":
            self.ufw_enable.set(True)
            self.native_inner.grid_remove()
            self.ufw_inner.grid()
            self.mtpr_inner.grid_remove()
        elif mode == "mtpr":
            self.ufw_enable.set(False)
            self.native_inner.grid_remove()
            self.ufw_inner.grid_remove()
            self.mtpr_inner.grid()
            self._sync_mtpr_preset_options()
        else:
            self.ufw_enable.set(False)
            self.native_inner.grid()
            self.ufw_inner.grid_remove()
            self.mtpr_inner.grid_remove()

    def _sync_mtpr_preset_options(self) -> None:
        preset = self.mtpr_preset.get()
        if preset == "upstream-default":
            # Максимально близко к ручной схеме: свежий telemt + дефолтный MTproxy-reanimation.
            self.mtpr_nft_enable.set(True)
            self.mtpr_service_enable.set(True)
            self.mtpr_tuning_enable.set(True)
            self.mtpr_ios_keepalive.set(True)
            self.mtpr_ios2_fix.set(False)
            self.mtpr_extra_ports_enable.set(False)
            self.mtpr_meter_timeout.set("60s")
            self._ios2_confirmed = False
        elif preset == "forum-test":
            self.mtpr_nft_enable.set(True)
            self.mtpr_service_enable.set(True)
            self.mtpr_tuning_enable.set(True)
            self.mtpr_ios_keepalive.set(False)
            self.mtpr_ios2_fix.set(False)
            self.mtpr_meter_timeout.set("60s")
            self._ios2_confirmed = False
        self._sync_mtpr_deps()

    def _confirm_ios2_option(self) -> None:
        if not self.mtpr_ios2_fix.get():
            self._ios2_confirmed = False
            return
        msg = (
            "Это опасная экспериментальная опция: она добавляет redirect/MSS-правила для отдельного TCP-порта.\n\n"
            "Она может повлиять на сетевое поведение сервера. Включайте только если понимаете последствия.\n\n"
            "Включить iOS MSS+redirect?"
        )
        if not messagebox.askyesno("Опасная опция", msg):
            self.mtpr_ios2_fix.set(False)
            self._ios2_confirmed = False
        else:
            self._ios2_confirmed = True
            self.mtpr_nft_enable.set(True)

    def _sync_mtpr_deps(self) -> None:
        # systemd service and extra-port rules only make sense together with the NFT limiter.
        if self.mtpr_service_enable.get() or self.mtpr_extra_ports_enable.get() or self.mtpr_ios2_fix.get():
            self.mtpr_nft_enable.set(True)
        try:
            if not self.mtpr_nft_enable.get():
                self.mtpr_service_enable.set(False)
                self.mtpr_extra_ports_enable.set(False)
        except Exception:
            pass

    def _build_action_block(self) -> None:
        pad = {"padx": 6, "pady": 5}
        self.actions = ttk.Frame(self.body)
        self.actions.grid(row=3, column=0, sticky="ew", padx=4, pady=6)
        self.validate_btn = ttk.Button(self.actions, text="Проверить параметры", command=self.validate_params_clicked, style="Accent.TButton")
        self.validate_btn.pack(side=tk.LEFT, **pad)
        self.plan_btn = ttk.Button(self.actions, text="Показать план", state="disabled", command=self.show_plan)
        self.plan_btn.pack(side=tk.LEFT, **pad)
        ttk.Button(self.actions, text="Очистить telemt…", command=self.cleanup_telemt).pack(side=tk.LEFT, **pad)
        ttk.Button(self.actions, text="Очистить лог", command=lambda: self.log.delete("1.0", tk.END)).pack(side=tk.RIGHT, **pad)

    def _build_log_block(self) -> None:
        self.log_frame = self._make_card("Лог")
        self.log_frame.grid(row=4, column=0, sticky="nsew", padx=6, pady=7)
        self.log = scrolledtext.ScrolledText(self.log_frame.content, wrap=tk.WORD, height=15)
        self.log.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self._log_wheel_bound = False
        self._bind_log_wheel()
        self._apply_theme()

    def _bind_log_wheel(self) -> None:
        """Route mouse-wheel events to the log while the pointer is over it.

        On Windows/Tk the wheel is often delivered to the focused widget, not
        necessarily to the widget under the cursor. That made the log look
        "stuck" until the user clicked inside it. Binding globally only while
        the pointer is over the log keeps scrolling predictable without stealing
        keyboard focus from entries/comboboxes.
        """
        def enable(_event=None):
            if getattr(self, "_log_wheel_bound", False):
                return
            self._log_wheel_bound = True
            try:
                self.bind_all("<MouseWheel>", self._on_log_mousewheel, add="+")
                self.bind_all("<Button-4>", self._on_log_mousewheel, add="+")
                self.bind_all("<Button-5>", self._on_log_mousewheel, add="+")
            except Exception:
                pass

        def disable(_event=None):
            if not getattr(self, "_log_wheel_bound", False):
                return
            self._log_wheel_bound = False
            try:
                # There are no other app-wide wheel bindings in this GUI; using
                # unbind_all avoids accumulating duplicate handlers after hover.
                self.unbind_all("<MouseWheel>")
                self.unbind_all("<Button-4>")
                self.unbind_all("<Button-5>")
            except Exception:
                pass

        self.log.bind("<Enter>", enable, add="+")
        self.log.bind("<Leave>", disable, add="+")

    def _on_log_mousewheel(self, event) -> str:
        if not hasattr(self, "log"):
            return "break"
        try:
            if getattr(event, "num", None) == 4:
                units = -3
            elif getattr(event, "num", None) == 5:
                units = 3
            else:
                delta = getattr(event, "delta", 0)
                if delta == 0:
                    return "break"
                # Windows usually sends multiples of 120; touchpads can send
                # smaller deltas, so keep at least one unit per wheel event.
                units = -int(delta / 120) if abs(delta) >= 120 else (-1 if delta > 0 else 1)
            self.log.yview_scroll(units, "units")
        except Exception:
            pass
        return "break"

    def _show_initial_state(self) -> None:
        self.auth_frame.grid_remove()
        self.check_frame.grid_remove()
        self.params_frame.grid_remove()
        self.ufw_outer.grid_remove()
        self.actions.grid_remove()
        self.log_frame.grid(row=4, column=0, sticky="nsew", padx=4, pady=6)
        self._log("Введите IPv4 сервера и нажмите Enter.")
        try:
            self.conn_status_var.set("● Не подключено")
        except Exception:
            pass

    def _show_port_step(self) -> None:
        self.ssh_port_entry.focus_set()
        self.ssh_port_entry.selection_range(0, tk.END)

    def _show_auth_step(self) -> None:
        self.auth_frame.grid()
        self.check_frame.grid()
        self.user_entry.focus_set()

    def _show_after_connect(self) -> None:
        if self.expert_mode.get():
            self.params_frame.grid()
            self.ufw_outer.grid()
            self.actions.grid()
            self._toggle_tune_mode()
        else:
            self.easy_frame.grid()
        self._refresh_param_sets()
        self._update_existing_warning()

    # ---------- progressive connection ----------
    def _advance_ip(self) -> None:
        ip = self.host_var.get().strip()
        if not is_valid_ipv4(ip):
            messagebox.showerror("IP", "Введите корректный IPv4: четыре октета от 0 до 255")
            return
        self._show_port_step()

    def _ssh_port(self) -> int:
        v = self.ssh_port_var.get().strip() or "22"
        if not v.isdigit() or not (1 <= int(v) <= 65535):
            raise ValueError("SSH-порт должен быть числом 1..65535")
        return int(v)

    def _advance_port(self) -> None:
        try:
            self._ssh_port()
        except Exception as e:
            messagebox.showerror("SSH-порт", str(e))
            return
        self._show_auth_step()

    def _toggle_auth_mode(self) -> None:
        key = self.auth_mode.get() == "key"
        for w in (self.key_label, self.key_entry, self.key_button, self.key_ext_hint, self.passphrase_label, self.key_pass_entry, getattr(self, "passphrase_hint", None)):
            if w is None:
                continue
            if key:
                try: w.grid()
                except Exception: pass
            else:
                try: w.grid_remove()
                except Exception: pass
        try:
            self.password_entry.configure(state=("disabled" if key else "normal"))
            self.key_entry.configure(state=("normal" if key else "disabled"))
            self.key_pass_entry.configure(state=("normal" if key else "disabled"))
            self.key_button.configure(state=("normal" if key else "disabled"))
        except Exception:
            pass

    def _toggle_secret(self) -> None:
        enabled = self.secret_enabled.get()
        try:
            if enabled:
                self.secret_entry.grid()
                self.secret_entry.configure(state="normal")
            else:
                self.secret_var.set("")
                self.secret_entry.configure(state="disabled")
                self.secret_entry.grid_remove()
        except Exception:
            pass

    def _toggle_ufw(self) -> None:
        self._toggle_tune_mode()

    def _choose_key(self) -> None:
        filetypes = [
            ("OpenSSH private keys", "*"),
            ("PEM files", "*.pem"),
            ("All files", "*.*"),
        ]
        path = filedialog.askopenfilename(title="Выберите OpenSSH private key: id_rsa, id_ed25519 или .pem", filetypes=filetypes)
        if path:
            self.key_path_var.set(path)

    # ---------- SSH config ----------
    def _refresh_ssh_config_combo(self) -> None:
        vals = [""]
        self.ssh_config_label_map = {}
        for e in self.ssh_config_entries:
            host = e.get("hostname", "") or e.get("alias", "")
            user = e.get("user", "")
            port = e.get("port", "")
            label = f"{e.get('alias','')}  →  {host}"
            if user: label += f"  ({user})"
            if port: label += f":{port}"
            vals.append(label)
            self.ssh_config_label_map[label] = e
        if hasattr(self, "config_picker"):
            self.config_picker.set_values(vals)

    def _apply_ssh_config_choice(self) -> None:
        choice = self.config_choice_var.get().strip()
        if not choice:
            return
        alias = choice.split("  →  ", 1)[0].strip()
        item = next((e for e in self.ssh_config_entries if e.get("alias") == alias), None)
        if not item:
            return
        host = item.get("hostname", "") or item.get("alias", "")
        if is_valid_ipv4(host):
            self.host_var.set(host)
            self._show_port_step()
        else:
            self._log(f"SSH config выбран: {alias}, HostName={host}. В поле IP нужен IPv4; при необходимости введите IP вручную.")
        if item.get("port"):
            self.ssh_port_var.set(item["port"])
        if item.get("user"):
            self.user_var.set(item["user"])
        if item.get("identityfile"):
            key = self._expand_identity_file(item["identityfile"], item)
            self.key_path_var.set(key)
            self.auth_mode.set("key")
            self._toggle_auth_mode()
        self._show_auth_step()
        if not self.user_var.get().strip():
            self.user_entry.focus_set()
        elif self.auth_mode.get() == "key" and not self.key_path_var.get().strip():
            self.key_entry.focus_set()
        elif self.auth_mode.get() == "password" and not self.password_var.get():
            self.password_entry.focus_set()
        else:
            self.connect_btn.focus_set()

    def _expand_identity_file(self, value: str, item: Optional[Dict[str, str]] = None) -> str:
        v = (value or "").strip().strip('"').strip("'")
        host = (item or {}).get("hostname", (item or {}).get("alias", ""))
        user = (item or {}).get("user", self.user_var.get().strip())
        v = v.replace("%h", host).replace("%r", user).replace("%p", (item or {}).get("port", self.ssh_port_var.get().strip() or "22"))
        v = os.path.expandvars(v)
        v = os.path.expanduser(v)
        # В OpenSSH относительный IdentityFile обычно ищут относительно ~/.ssh.
        if v and not os.path.isabs(v):
            v = str(Path.home() / ".ssh" / v)
        # На Windows os.path.expanduser("~/.ssh/id_rsa") может дать смешанный
        # вид C:\Users\Name/.ssh/id_rsa. Это рабочий путь, но выглядит странно.
        return os.path.normpath(v) if v else v


    # ---------- logging/thread ----------
    def _log(self, text: str) -> None:
        if not hasattr(self, "log"):
            return
        self.log.insert(tk.END, strip_ansi(str(text)).rstrip() + "\n")
        self.log.see(tk.END)

    def _run_thread(self, fn) -> None:
        threading.Thread(target=fn, daemon=True).start()

    def _start_single_instance_server(self) -> None:
        sock = getattr(self, "_single_instance_socket", None)
        if sock is None:
            return
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        def server() -> None:
            while True:
                try:
                    conn, _addr = sock.accept()
                except OSError:
                    break
                with conn:
                    try:
                        data = conn.recv(256).decode("utf-8", "ignore").strip()
                        if not data.startswith(SINGLE_INSTANCE_TOKEN):
                            conn.sendall(b"ERR\n")
                            continue
                        if data.endswith("CLOSE"):
                            conn.sendall(b"OK\n")
                            self.after(0, self._on_close)
                            break
                        conn.sendall(b"OK\n")
                    except Exception:
                        pass
        threading.Thread(target=server, daemon=True).start()

    def _on_close(self) -> None:
        try:
            if self.session:
                self.session.close()
        except Exception:
            pass
        try:
            sock = getattr(self, "_single_instance_socket", None)
            if sock is not None:
                sock.close()
        except Exception:
            pass
        self.destroy()

    def _drain_queue(self) -> None:
        try:
            while True:
                kind, payload = self.worker_q.get_nowait()
                if kind == "log":
                    self._log(payload)
                elif kind == "error":
                    try:
                        self.easy_deploy_btn.configure(state="normal")
                    except Exception:
                        pass
                    self._log("[ERROR] " + str(payload))
                    # Сетевые ошибки часто означают потерю SSH-сессии.
                    if any(x in str(payload).lower() for x in ("ssh", "socket", "connection", "timed out", "not connected")):
                        self._mark_disconnected(str(payload), notify=False)
                    messagebox.showerror("Ошибка", str(payload))
                elif kind == "state":
                    self.state = payload
                    self._mark_connected()
                    self._show_after_connect()
                    self._log("Подключение и проверки OK")
                elif kind == "ping":
                    self._ping_inflight = False
                    if payload is True:
                        self._mark_connected(log=False)
                    else:
                        self._mark_disconnected("SSH-соединение потеряно", notify=True)
                elif kind == "validate_after_scan":
                    self.state = payload
                    self._mark_connected(log=False)
                    self._update_existing_warning()
                    self.validate_params()
                elif kind == "easy_status":
                    if hasattr(self, "easy_status_var"):
                        self.easy_status_var.set(str(payload))
                elif kind == "easy_link":
                    if hasattr(self, "easy_link_var"):
                        self.easy_link_var.set(str(payload))
                        self.easy_link_entry.grid()
                        self.easy_copy_btn.grid()
                        self.easy_status_var.set("Готово. Ссылка создана.")
                elif kind == "deploy_done":
                    self.deploying = False
                    try:
                        self.easy_deploy_btn.configure(state="normal")
                    except Exception:
                        pass
                    if isinstance(payload, dict):
                        msg = str(payload.get("message", "Deploy OK"))
                        link = str(payload.get("link", "")).strip()
                        is_easy = payload.get("easy") == "1"
                    else:
                        msg = str(payload)
                        link = ""
                        is_easy = False
                    self._log(msg)
                    if link and not is_easy:
                        self._show_deploy_result_window(link, msg)
                    elif not is_easy:
                        messagebox.showinfo("Deploy", msg)
        except queue.Empty:
            pass
        self.after(100, self._drain_queue)

    def _mark_connected(self, log: bool = False) -> None:
        self.state.connected = True
        self._disconnect_notified = False
        if hasattr(self, "conn_status_var"):
            self.conn_status_var.set("● Подключено")
            try:
                self.conn_status.configure(style="CardOk.TLabel")
            except Exception:
                pass
        if log:
            self._log("SSH-соединение активно")

    def _mark_disconnected(self, reason: str = "", notify: bool = True) -> None:
        self.state.connected = False
        self.params_valid = False
        self.validated_params = None
        try:
            self.plan_btn.configure(state="disabled")
        except Exception:
            pass
        if hasattr(self, "conn_status_var"):
            self.conn_status_var.set("● Соединение потеряно")
            try:
                self.conn_status.configure(style="CardWarn.TLabel")
            except Exception:
                pass
        if self.session:
            try:
                self.session.close()
            except Exception:
                pass
            self.session = None
        if notify and not self._disconnect_notified:
            self._disconnect_notified = True
            msg = reason or "SSH-соединение потеряно. Нажмите «Переподключиться»."
            self._log("[WARN] " + msg)
            try:
                messagebox.showwarning("SSH", msg)
            except Exception:
                pass

    def _poll_connection(self) -> None:
        if self.session and self.state.connected and not self._ping_inflight and not self.deploying:
            self._ping_inflight = True
            sess = self.session
            def work():
                try:
                    ok = sess.is_alive(timeout=5)
                except Exception:
                    ok = False
                self.worker_q.put(("ping", ok))
            self._run_thread(work)
        self.after(7000, self._poll_connection)

    def _confirm_ssh_fingerprint(self, host: str, port: int, key) -> None:
        key_id = known_host_id(host, port)
        fp = ssh_key_fingerprint_sha256(key)
        key_type = key.get_name()
        trusted = load_trusted_hosts()
        old = trusted.get(key_id)
        if old == fp:
            self.worker_q.put(("log", f"SSH fingerprint подтверждён: {key_type} {fp}"))
            return
        title = "SSH fingerprint"
        if old:
            msg = (
                f"ВНИМАНИЕ: SSH fingerprint сервера изменился.\n\n"
                f"Сервер: {key_id}\n"
                f"Было: {old}\n"
                f"Сейчас: {key_type} {fp}\n\n"
                "Это может быть переустановка сервера или MITM-атака. Доверять новому ключу?"
            )
        else:
            msg = (
                f"Первое подключение к SSH-серверу.\n\n"
                f"Сервер: {key_id}\n"
                f"Ключ: {key_type} {fp}\n\n"
                "Сверьте fingerprint с данными VPS/SSH и подтвердите доверие."
            )
        if not self._ask_yes_no_threadsafe(title, msg):
            raise RuntimeError("SSH fingerprint не подтверждён пользователем")
        trusted[key_id] = fp
        save_trusted_hosts(trusted)
        self.worker_q.put(("log", f"SSH fingerprint сохранён: {key_type} {fp}"))

    def _ask_yes_no_threadsafe(self, title: str, message: str) -> bool:
        event = threading.Event()
        result = {"value": False}
        def ask() -> None:
            try:
                result["value"] = bool(messagebox.askyesno(title, message))
            finally:
                event.set()
        self.after(0, ask)
        event.wait()
        return result["value"]

    # ---------- remote scan ----------
    def _connect_and_scan_sync(self) -> RemoteState:
        if not is_valid_ipv4(self.host_var.get().strip()):
            raise ValueError("Сначала введите корректный IPv4 сервера")
        ssh_port = self._ssh_port()
        user = self.user_var.get().strip()
        if not user:
            raise ValueError("Введите User")
        if self.auth_mode.get() == "password" and not self.password_var.get():
            raise ValueError("Введите пароль или выберите SSH-ключ")
        if self.auth_mode.get() == "key" and not self.key_path_var.get().strip():
            raise ValueError("Выберите SSH private key")

        if self.session and self.state.connected:
            try:
                if self.session.is_alive(timeout=5):
                    st = self._scan_state(self.session)
                    st.connected = True
                    st.root_mode = self.session.root_mode
                    return st
            except Exception:
                try:
                    self.session.close()
                except Exception:
                    pass
                self.session = None

        if self.session:
            self.session.close()
        host = self.host_var.get().strip()
        self.worker_q.put(("log", "Получаю SSH fingerprint сервера..."))
        self.worker_q.put(("easy_status", "Получаю SSH fingerprint сервера..."))
        host_key = probe_ssh_server_key(host, ssh_port)
        self._confirm_ssh_fingerprint(host, ssh_port, host_key)
        sess = SSHSession(
            host=host, port=ssh_port, user=user,
            password=self.password_var.get() if self.auth_mode.get() == "password" else "",
            key_path=self.key_path_var.get().strip() if self.auth_mode.get() == "key" else "",
            key_passphrase=self.key_pass_var.get(), sudo_password=self.sudo_pass_var.get(),
            host_key=host_key,
        )
        self.worker_q.put(("log", "Подключаюсь по SSH..."))
        self.worker_q.put(("easy_status", "Подключаюсь по SSH..."))
        sess.connect()
        rights = sess.detect_rights()
        self.worker_q.put(("log", f"Права: {rights}"))
        state = self._scan_state(sess)
        state.connected = True
        state.root_mode = rights
        self.session = sess
        return state

    def connect_and_scan(self) -> None:
        try:
            # Fast local validation so obvious errors are shown immediately.
            if not is_valid_ipv4(self.host_var.get().strip()):
                messagebox.showerror("IP", "Сначала введите корректный IPv4 сервера")
                return
            self._ssh_port()
            if not self.user_var.get().strip():
                messagebox.showerror("SSH", "Введите User")
                return
            if self.auth_mode.get() == "password" and not self.password_var.get():
                messagebox.showerror("SSH", "Введите пароль или выберите SSH-ключ")
                return
            if self.auth_mode.get() == "key" and not self.key_path_var.get().strip():
                messagebox.showerror("SSH", "Выберите SSH private key")
                return
        except Exception as e:
            messagebox.showerror("SSH", str(e))
            return

        def work():
            try:
                state = self._connect_and_scan_sync()
                self.worker_q.put(("state", state))
            except Exception as e:
                self.deploying = False
                self.worker_q.put(("error", str(e)))
        self._run_thread(work)

    def _scan_state(self, sess: SSHSession) -> RemoteState:
        st = RemoteState()
        # OS/system check
        cmd = r'''
set -e
. /etc/os-release
ARCH=$(uname -m)
GLIBC=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}' || true)
SYSTEMD=0; command -v systemctl >/dev/null 2>&1 && SYSTEMD=1
printf 'ID=%s\nVERSION_ID=%s\nPRETTY_NAME=%s\nARCH=%s\nGLIBC=%s\nSYSTEMD=%s\n' "${ID:-}" "${VERSION_ID:-}" "${PRETTY_NAME:-}" "$ARCH" "$GLIBC" "$SYSTEMD"
'''
        code, out, err = sess.run(cmd, timeout=20)
        if code != 0:
            raise RuntimeError("Не удалось проверить систему: " + (err.strip() or out.strip()))
        info: Dict[str, str] = {}
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                info[k] = v
        st.os_id = info.get("ID", "")
        st.os_version = info.get("VERSION_ID", "")
        st.pretty_name = info.get("PRETTY_NAME", "")
        st.arch = info.get("ARCH", "")
        st.glibc = info.get("GLIBC", "")
        st.systemd = info.get("SYSTEMD") == "1"
        supported = self._is_supported_system(st)
        st.supported = supported
        if not supported:
            raise RuntimeError(f"Система не поддерживается: ID={st.os_id}, VERSION_ID={st.os_version}, ARCH={st.arch}, systemd={st.systemd}. {SUPPORTED_OS_TEXT}")
        self.worker_q.put(("log", f"Система поддерживается: {st.pretty_name}, arch={st.arch}, glibc={st.glibc or '?'}"))

        # ports
        code, out, err = sess.run("ss -H -tulnp 2>/dev/null || true", timeout=20, sudo=True)
        st.raw_ss = out
        st.public_ports = []
        st.public_ports_keep = []
        st.used_tcp_ports = []
        st.port_owners = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0].lower()
            local = parts[4]
            if local.startswith("127.0.0.1:") or local.startswith("[::1]:"):
                continue
            m = re.search(r":(\d+)$", local)
            if not m:
                continue
            p = int(m.group(1))
            if proto.startswith("tcp"):
                st.used_tcp_ports.append(p)
                owner = describe_ss_owner(line)
                if owner not in st.port_owners.setdefault(p, []):
                    st.port_owners[p].append(owner)
                rule = f"{p}/tcp"
            elif proto.startswith("udp"):
                rule = f"{p}/udp"
            else:
                continue
            if rule not in st.public_ports:
                st.public_ports.append(rule)
            # preserve public non-telemt ports; exact process name "telemt" only
            if not re.search(r'users:\(\("telemt"', line):
                if rule not in st.public_ports_keep:
                    st.public_ports_keep.append(rule)

        # configs
        config_cmd = r'''
for f in /etc/telemt/telemt*.toml /etc/telemt/telemt.toml; do
  [ -f "$f" ] || continue
  name=$(basename "$f" .toml)
  port=$(awk -F= '/^[[:space:]]*port[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$f")
  domain=$(awk -F= '/^[[:space:]]*tls_domain[[:space:]]*=/{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); gsub(/"/,"",$2); print $2; exit}' "$f")
  api=$(awk -F= '/^[[:space:]]*listen[[:space:]]*=/{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); gsub(/"/,"",$2); print $2; exit}' "$f")
  raw=$(awk -F= '/^[[:space:]]*[A-Za-z0-9_-]+[[:space:]]*=[[:space:]]*"[0-9a-fA-F]{32}"/{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); gsub(/"/,"",$2); print $2; exit}' "$f")
  printf 'CFG|%s|%s|%s|%s|%s|%s\n' "$name" "$port" "$domain" "$raw" "$api" "$f"
done
'''
        code, out, err = sess.run(config_cmd, timeout=20, sudo=True)
        for line in out.splitlines():
            if not line.startswith("CFG|"):
                continue
            _, name, port_s, domain, raw, api, path = (line.split("|", 6) + [""] * 7)[:7]
            cfg = TelemtConfig(name=name, domain=domain, raw=raw, api=api, path=path)
            if port_s.isdigit():
                cfg.port = int(port_s)
                if cfg.port not in st.used_tcp_ports:
                    st.used_tcp_ports.append(cfg.port)
            st.telemt_configs[name] = cfg
        used_pairs = {(cfg.port, cfg.domain) for cfg in st.telemt_configs.values() if cfg.port and cfg.domain}
        used_ports = set(st.used_tcp_ports)
        st.default_available = [(p, d) for p, d in DEFAULT_PAIRS if p not in used_ports and (p, d) not in used_pairs]
        return st

    def _is_supported_system(self, st: RemoteState) -> bool:
        if not st.systemd:
            return False
        if st.arch not in {"x86_64", "amd64", "aarch64", "arm64"}:
            return False
        if st.os_id == "debian" and st.os_version in {"11", "12", "13"}:
            return True
        if st.os_id == "ubuntu" and st.os_version in {"20.04", "22.04", "24.04"}:
            return True
        return False

    def scan_ports(self) -> None:
        if not self.session:
            messagebox.showwarning("SSH", "Сначала подключитесь к серверу")
            return
        def work():
            try:
                st = self._scan_state(self.session)  # type: ignore[arg-type]
                st.connected = True
                st.root_mode = self.session.root_mode if self.session else ""
                self.worker_q.put(("state", st))
                self.worker_q.put(("log", "Порты пересканированы."))
            except Exception as e:
                self.deploying = False
                self.worker_q.put(("error", str(e)))
        self._run_thread(work)

    # ---------- params/defaults ----------
    def _pair_label(self, pair: Tuple[int, str]) -> str:
        return f"{pair[0]} + {pair[1]}"

    def _refresh_param_sets(self) -> None:
        values = [self._pair_label(p) for p in DEFAULT_PAIRS] + ["custom"]
        self.param_set_combo.configure(values=values)
        # free-default button only if free defaults exist
        if self.state.connected and not self.state.default_available:
            self.free_default_button.grid_remove()
        else:
            self.free_default_button.grid()

    def _choose_free_default(self) -> None:
        if self.state.default_available:
            pair = self.state.default_available[0]
        else:
            messagebox.showwarning("Дефолт", "Свободных дефолтных наборов параметров нет")
            return
        self.param_set_var.set(self._pair_label(pair))
        self._on_param_set_changed()

    def _on_param_set_changed(self) -> None:
        val = self.param_set_var.get()
        if val == "custom":
            self.custom_frame.grid()
            return
        self.custom_frame.grid_remove()
        m = re.match(r"(\d+) \+ (.+)", val)
        if m:
            self.telemt_port_var.set(m.group(1))
            self.domain_var.set(m.group(2))

    def _selected_port_domain(self) -> Tuple[int, str]:
        if self.param_set_var.get() != "custom":
            m = re.match(r"(\d+) \+ (.+)", self.param_set_var.get())
            if not m:
                raise ValueError("Некорректный дефолтный набор параметров")
            return int(m.group(1)), m.group(2).strip()
        port_s = self.telemt_port_var.get().strip()
        domain = self.domain_var.get().strip()
        if not port_s.isdigit() or not (1 <= int(port_s) <= 65535):
            raise ValueError("Порт telemt должен быть числом 1..65535")
        if not domain or not re.fullmatch(r"[A-Za-z0-9.-]+", domain):
            raise ValueError("Домен маскировки выглядит некорректно")
        return int(port_s), domain

    def _telemt_config_for_port(self, port: int) -> Optional[TelemtConfig]:
        for cfg in self.state.telemt_configs.values():
            if cfg.port == port:
                return cfg
        return None

    def _port_owner_text(self, port: int) -> str:
        owners = self.state.port_owners.get(port) or []
        if owners:
            return "; ".join(owners)
        return "процесс не определён; проверьте `ss -ltnp` на сервере"

    def _choose_easy_default(self) -> Tuple[int, str, Optional[TelemtConfig]]:
        """Choose port/domain for Easy mode. Returns port, domain, config_to_replace."""
        occupied_by_other: List[str] = []
        replace_candidates: List[Tuple[int, str, TelemtConfig]] = []
        used = set(self.state.used_tcp_ports)
        for port, domain in DEFAULT_PAIRS:
            cfg = self._telemt_config_for_port(port)
            if port not in used and cfg is None:
                return port, domain, None
            if cfg is not None:
                replace_candidates.append((port, domain, cfg))
            else:
                occupied_by_other.append(f"{port}/tcp — {self._port_owner_text(port)}")
        if replace_candidates:
            port, domain, cfg = replace_candidates[0]
            return port, domain, cfg
        detail = "\n".join(occupied_by_other) if occupied_by_other else "443/5223/8530 заняты сторонними процессами"
        raise ValueError("Все дефолтные порты заняты сторонними приложениями:\n" + detail)

    def _update_existing_warning(self) -> None:
        if not self.state.telemt_configs:
            self.existing_warning_var.set("")
            return
        parts = []
        for name, cfg in sorted(self.state.telemt_configs.items()):
            if cfg.port or cfg.domain:
                parts.append(f"{name}: {cfg.port or '?'} + {cfg.domain or '?'}")
        self.existing_warning_var.set("Найдены существующие telemt-конфиги: " + "; ".join(parts))
        if "telemt1" in self.state.telemt_configs:
            self.action_var.set("add_instance")

    # ---------- UFW ports window ----------
    def open_ports_window(self) -> None:
        win = tk.Toplevel(self)
        win.title("Разрешённые порты")
        win.geometry("620x460")
        win.minsize(480, 340)
        frm = ttk.Frame(win)
        frm.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        frm.rowconfigure(1, weight=1)
        frm.columnconfigure(0, weight=1)
        ttk.Label(frm, text="Порты для firewall/limiter. Формат: 51820/udp, 8443/tcp. Без протокола — tcp.").grid(row=0, column=0, columnspan=3, sticky="w", pady=4)
        lb = tk.Listbox(frm)
        try:
            lb.configure(bg=self._theme.get("field", "white"), fg=self._theme.get("fg", "black"), selectbackground="#3b82f6", selectforeground="white")
        except Exception:
            pass
        lb.grid(row=1, column=0, columnspan=3, sticky="nsew", pady=4)
        entry_var = tk.StringVar()
        ent = ttk.Entry(frm, textvariable=entry_var)
        ent.grid(row=2, column=0, sticky="ew", padx=(0, 6), pady=4)

        def current_items() -> List[Tuple[str, str]]:
            items: List[Tuple[str, str]] = []
            try:
                items.append((f"{self._ssh_port()}/tcp", "обязательный SSH"))
            except Exception:
                pass
            try:
                p, _ = self._selected_port_domain()
                items.append((f"{p}/tcp", "обязательный telemt"))
            except Exception:
                pass
            if self.ufw_enable.get() and self.keep_current_ports.get():
                for r in self.state.public_ports_keep:
                    items.append((r, "текущий публичный"))
            custom_kind = "custom"
            if self.tune_mode.get() == "mtpr" and self.mtpr_extra_ports_enable.get():
                custom_kind = "custom / доп. telemt"
            elif self.tune_mode.get() in {"ufw", "native"}:
                custom_kind = "custom / firewall"
            for r in self.custom_rules:
                items.append((r, custom_kind))
            seen = set(); out=[]
            for r, kind in items:
                if r in seen:
                    continue
                seen.add(r); out.append((r, kind))
            return sorted(out, key=lambda x: (int(x[0].split('/')[0]), x[0].split('/')[1], x[1]))

        def refresh() -> None:
            lb.delete(0, tk.END)
            for r, kind in current_items():
                lb.insert(tk.END, f"{r} [{kind}]")

        def add() -> None:
            try:
                r = parse_port_rule(entry_var.get())
                if r not in self.custom_rules:
                    self.custom_rules.append(r)
                entry_var.set("")
                refresh()
            except Exception as e:
                messagebox.showerror("Порт", str(e), parent=win)

        def delete() -> None:
            sel = list(lb.curselection())
            deleted = False
            for idx in reversed(sel):
                line = lb.get(idx)
                m = re.match(r"([^ ]+) \[custom", line)
                if m and m.group(1) in self.custom_rules:
                    self.custom_rules.remove(m.group(1)); deleted = True
            if not deleted and sel:
                messagebox.showinfo("Порты", "Удалять можно только custom-порты. SSH, основной telemt и автонайденные публичные порты защищены.", parent=win)
            refresh()

        ttk.Button(frm, text="Добавить", command=add).grid(row=2, column=1, padx=4, pady=4)
        ttk.Button(frm, text="Удалить custom", command=delete).grid(row=2, column=2, padx=4, pady=4)
        ttk.Button(frm, text="Закрыть", command=win.destroy).grid(row=3, column=2, sticky="e", pady=6)
        ent.bind("<Return>", lambda e: add())
        refresh()

    def _computed_allow_rules(self, params: Optional[Dict[str, str]] = None) -> List[str]:
        rules: List[str] = []
        if params is not None:
            ssh_port = params.get("ssh_port", "").strip()
            telemt_port = params.get("port", "").strip()
            if ssh_port:
                rules.append(f"{ssh_port}/tcp")
            if telemt_port:
                rules.append(f"{telemt_port}/tcp")
            if params.get("ufw") == "1" and params.get("keep_current") == "1":
                rules.extend(params.get("public_ports_keep", "").split())
            rules.extend(params.get("custom_rules", "").split())
        else:
            try:
                ssh = self._ssh_port()
                rules.append(f"{ssh}/tcp")
            except Exception:
                pass
            try:
                port, _ = self._selected_port_domain()
                rules.append(f"{port}/tcp")
            except Exception:
                pass
            if self.ufw_enable.get() and self.keep_current_ports.get():
                rules.extend(self.state.public_ports_keep)
            rules.extend(self.custom_rules)
        dedup: List[str] = []
        for r in rules:
            if r and r not in dedup:
                dedup.append(r)
        return sorted(dedup, key=lambda x: (int(x.split('/')[0]), x.split('/')[1]))

    def _computed_mtpr_extra_ports(self, params: Optional[Dict[str, str]] = None) -> List[str]:
        """Return TCP port numbers as strings for additional reanimator limiter rules."""
        if params is not None:
            if params.get("mtpr_extra_ports_enabled") != "1":
                return []
            custom_rules = params.get("custom_rules", "").split()
            base_ports = set()
            for key in ("port", "ssh_port"):
                try:
                    base_ports.add(int(params.get(key, "")))
                except Exception:
                    pass
        else:
            if not self.mtpr_extra_ports_enable.get():
                return []
            custom_rules = list(self.custom_rules)
            base_ports = set()
            try:
                base_ports.add(self._selected_port_domain()[0])
            except Exception:
                pass
            try:
                base_ports.add(self._ssh_port())
            except Exception:
                pass
        ports: List[str] = []
        for rule in custom_rules:
            try:
                port_s, proto = rule.split("/", 1)
            except ValueError:
                continue
            if proto != "tcp":
                continue
            p = int(port_s)
            if p in base_ports:
                continue
            if str(p) not in ports:
                ports.append(str(p))
        return ports

    def _validation_fingerprint(self) -> str:
        """Return a stable fingerprint for current user inputs relevant to deploy.

        The generated random secret is intentionally not included when the secret
        checkbox is off: it is generated once and then kept in DeployParams.
        """
        try:
            port, domain = self._selected_port_domain()
            port_domain = f"{port}:{domain}"
        except Exception:
            port_domain = f"invalid:{self.telemt_port_var.get()}:{self.domain_var.get()}:{self.param_set_var.get()}"
        parts = [
            self.host_var.get().strip(),
            str(self._ssh_port()) if self.ssh_port_var.get().strip().isdigit() else self.ssh_port_var.get().strip(),
            self.action_var.get(),
            self.param_set_var.get(),
            port_domain,
            "secret-on" if self.secret_enabled.get() else "secret-off",
            self.secret_var.get().strip() if self.secret_enabled.get() else "",
            self.tune_mode.get(),
            self.native_mode.get(),
            self.native_backend.get(),
            self.native_preset.get(),
            str(self.ufw_enable.get()),
            str(self.keep_current_ports.get()),
            ",".join(sorted(self.custom_rules)),
            str(self.mtpr_nft_enable.get()),
            str(self.mtpr_service_enable.get()),
            str(self.mtpr_tuning_enable.get()),
            str(self.mtpr_ios_keepalive.get()),
            str(self.mtpr_ios2_fix.get()),
            str(self.mtpr_extra_ports_enable.get()),
            self.mtpr_preset.get(),
            self.mtpr_meter_timeout.get(),
            "test-tab" if self._is_test_tab_active() else "main-tab",
            self.test_mode.get(),
            self.test_toml_path.get().strip(),
            str(self.test_nft_enable.get()),
            str(self.test_service_enable.get()),
            str(self.test_apply_tuning.get()),
            str(self.test_ios_keepalive.get()),
            self.test_nft_rate.get().strip(),
            self.test_nft_burst.get().strip(),
            self.test_meter_timeout.get().strip(),
            self.test_tg_connect.get().strip(),
            self.test_client_handshake.get().strip(),
            self.test_client_keepalive.get().strip(),
        ]
        return "|".join(parts)

    def _invalidate_params(self) -> None:
        self.params_valid = False
        self.validated_params = None
        self.validated_snapshot = None
        if hasattr(self, "plan_btn"):
            self.plan_btn.configure(state="disabled")

    # ---------- validation/plan/deploy ----------
    def validate_params_clicked(self) -> None:
        if not self.session or not self.state.connected:
            self._mark_disconnected("Нет активного SSH-соединения. Нажмите «Переподключиться».", notify=True)
            return
        def work():
            try:
                st = self._scan_state(self.session)  # type: ignore[arg-type]
                st.connected = True
                st.root_mode = self.session.root_mode if self.session else ""
                self.worker_q.put(("validate_after_scan", st))
            except Exception as e:
                self.worker_q.put(("error", "Не удалось обновить состояние сервера перед проверкой параметров: " + str(e)))
        self._run_thread(work)

    def validate_params(self, quiet: bool = False) -> Optional[Dict[str, str]]:
        try:
            if not self.state.connected or not self.session:
                raise ValueError("Сначала нужно проверить подключение и права")
            if not is_valid_ipv4(self.host_var.get().strip()):
                raise ValueError("IP сервера некорректен")
            ssh_port = self._ssh_port()
            action = self.action_var.get()
            if action not in {"install", "add_instance"}:
                raise ValueError("Некорректное действие")
            port, domain = self._selected_port_domain()
            # Port conflict checks. A port occupied by an existing telemt config can be replaced after confirmation.
            replace_cfg = self._telemt_config_for_port(port)
            replace_instance = ""
            if port in self.state.used_tcp_ports:
                if replace_cfg is not None:
                    replace_instance = replace_cfg.name
                    if not quiet:
                        msg = (
                            f"Порт {port}/tcp уже занят telemt-конфигом {replace_cfg.name}: "
                            f"domain={replace_cfg.domain or '?'}.\n\n"
                            "Можно заменить этот конфиг новым. Старый config/service будет сохранён как .bak. Продолжить?"
                        )
                        if not messagebox.askyesno("Порт занят telemt", msg):
                            raise ValueError("Деплой на занятый telemt-порт отменён")
                else:
                    raise ValueError(f"Порт {port}/tcp уже занят не telemt: {self._port_owner_text(port)}")
            if self.mtpr_ios2_fix.get() and not quiet and not getattr(self, "_ios2_confirmed", False):
                msg = (
                    "Выбрана опасная опция iOS MSS+redirect. Она добавит redirect/MSS-правила и может повлиять на сетевое поведение сервера.\n\n"
                    "Продолжить?"
                )
                if not messagebox.askyesno("Опасная опция", msg):
                    self.mtpr_ios2_fix.set(False)
                    self._ios2_confirmed = False
            fp = self._validation_fingerprint()
            if self.secret_enabled.get():
                raw = normalize_secret(self.secret_var.get())
            elif self.validated_snapshot and self.validated_snapshot.fingerprint == fp:
                raw = self.validated_snapshot.data.get("raw", "")
            else:
                raw = secrets.token_hex(16)
            test_active = self._is_test_tab_active()
            tune_mode_value = self.tune_mode.get()
            mtpr_preset = self.mtpr_preset.get()
            mtpr_nft = self.mtpr_nft_enable.get()
            mtpr_service = self.mtpr_service_enable.get()
            mtpr_tuning = self.mtpr_tuning_enable.get()
            mtpr_ios = self.mtpr_ios_keepalive.get()
            mtpr_ios2 = self.mtpr_ios2_fix.get()
            mtpr_extra_enabled = self.mtpr_extra_ports_enable.get()
            mtpr_timeout = self.mtpr_meter_timeout.get()
            mtpr_custom_rate = ""
            mtpr_custom_burst = ""
            mtpr_custom_tg = ""
            mtpr_custom_hs = ""
            mtpr_custom_ka = ""
            custom_toml_b64 = ""
            custom_toml_path = ""
            test_mode_value = ""

            if test_active:
                tune_mode_value = "mtpr"
                test_mode_value = self.test_mode.get()
                if test_mode_value not in {"upstream-default", "forum-test", "custom-nft", "custom-toml"}:
                    raise ValueError("Некорректный тестовый режим")
                mtpr_preset = test_mode_value if test_mode_value in {"upstream-default", "forum-test"} else "custom-nft"
                mtpr_nft = self.test_nft_enable.get()
                mtpr_service = self.test_service_enable.get()
                mtpr_tuning = self.test_apply_tuning.get()
                mtpr_ios = self.test_ios_keepalive.get()
                mtpr_ios2 = False
                mtpr_extra_enabled = False
                mtpr_timeout = self._test_timeout_value()
                mtpr_custom_rate = self._test_int(self.test_nft_rate, "NFT rate", 1, 1000)
                mtpr_custom_burst = self._test_int(self.test_nft_burst, "NFT burst", 1, 10000)
                mtpr_custom_tg = self._test_int(self.test_tg_connect, "tg_connect", 1, 86400)
                mtpr_custom_hs = self._test_int(self.test_client_handshake, "client_handshake", 1, 86400)
                mtpr_custom_ka = self._test_int(self.test_client_keepalive, "client_keepalive", 1, 86400)
                if test_mode_value == "custom-toml":
                    custom_toml_path = self.test_toml_path.get().strip()
                    if not custom_toml_path:
                        raise ValueError("Для custom-toml выберите TOML-файл")
                    toml_file = Path(custom_toml_path)
                    if not toml_file.is_file():
                        raise ValueError("TOML-файл не найден")
                    data = toml_file.read_bytes()
                    if len(data) > 256 * 1024:
                        raise ValueError("TOML-файл слишком большой: максимум 256 KiB")
                    custom_toml_b64 = base64.b64encode(data).decode("ascii")
            else:
                if self.tune_mode.get() == "mtpr" and mtpr_preset == "upstream-default":
                    mtpr_nft = True
                    mtpr_service = True
                    mtpr_tuning = True
                    mtpr_ios = True
                    mtpr_ios2 = False
                    mtpr_extra_enabled = False
                    mtpr_timeout = "60s"
                elif self.tune_mode.get() == "mtpr" and mtpr_preset == "forum-test":
                    mtpr_nft = True
                    mtpr_service = True
                    mtpr_tuning = True
                    mtpr_ios = False
                    mtpr_ios2 = False
                    mtpr_timeout = "60s"

            params = {
                "action": action,
                "host": self.host_var.get().strip(),
                "user": self.user_var.get().strip(),
                "ssh_port": str(ssh_port),
                "port": str(port),
                "domain": domain,
                "raw": raw,
                "full": full_secret(raw, domain),
                "replace_instance": replace_instance,
                "replace_existing": bool01(bool(replace_instance)),
                "keep_current": bool01(self.keep_current_ports.get()),
                "custom_rules": " ".join(self.custom_rules),
                "public_ports_keep": " ".join(self.state.public_ports_keep),
                "mtpr_extra_ports_enabled": bool01(mtpr_extra_enabled),
                "ufw": bool01(self.ufw_enable.get()),
                "tune_mode": tune_mode_value,
                "native_synlimit": bool01(tune_mode_value == "native" and self.native_mode.get() == "synlimit"),
                "native_backend": self.native_backend.get(),
                "native_preset": self.native_preset.get(),
                "mtpr_nft": bool01(mtpr_nft),
                "mtpr_service": bool01(mtpr_service),
                "mtpr_tuning": bool01(mtpr_tuning),
                "mtpr_ios": bool01(mtpr_ios),
                "mtpr_ios2": bool01(mtpr_ios2),
                "mtpr_preset": mtpr_preset,
                "mtpr_meter_timeout": mtpr_timeout,
                "mtpr_custom_rate": mtpr_custom_rate,
                "mtpr_custom_burst": mtpr_custom_burst,
                "mtpr_custom_tg": mtpr_custom_tg,
                "mtpr_custom_hs": mtpr_custom_hs,
                "mtpr_custom_ka": mtpr_custom_ka,
                "test_mode": test_mode_value,
                "custom_toml_b64": custom_toml_b64,
                "custom_toml_path": custom_toml_path,
                "mtpr_extra_ports": "",
            }
            params["mtpr_extra_ports"] = " ".join(self._computed_mtpr_extra_ports(params))
            if not quiet:
                self.params_valid = True
                self.validated_params = params
                self.validated_snapshot = DeployParams(data=dict(params), fingerprint=fp)
                self.plan_btn.configure(state="normal")
                self._log("Проверка параметров OK. Теперь можно показать план.")
                if not self.secret_enabled.get():
                    self._log("Secret не указан: будет использован сгенерированный raw secret, показанный в плане.")
                messagebox.showinfo("Проверка", "Критичные параметры корректны. Можно открыть план деплоя.")
            return params
        except Exception as e:
            if not quiet:
                self.params_valid = False
                self.validated_params = None
                self.plan_btn.configure(state="disabled")
                messagebox.showerror("Проверка", str(e))
            return None

    def _current_link(self, cfg: TelemtConfig) -> Optional[str]:
        if cfg.port and cfg.domain and re.fullmatch(r"[0-9a-fA-F]{32}", cfg.raw or ""):
            return f"tg://proxy?server={self.host_var.get().strip()}&port={cfg.port}&secret={full_secret(cfg.raw.lower(), cfg.domain)}"
        return None

    def _build_plan_text(self, params: Dict[str, str]) -> Tuple[str, List[str]]:
        allow_rules = self._computed_allow_rules(params)
        if params.get("replace_instance"):
            target = f"замена {params.get('replace_instance')}"
        else:
            target = "telemt1" if params["action"] == "install" else "следующий свободный telemtN"
        lines = [
            "План деплоя",
            "=" * 64,
            f"Сервер: {params['host']}:{params['ssh_port']}",
            f"Система: {self.state.pretty_name}, arch={self.state.arch}, glibc={self.state.glibc or '?'}",
            f"Действие: {params['action']}",
            f"Целевой инстанс: {target}",
            f"Порт telemt: {params['port']}/tcp",
            f"Домен маскировки: {params['domain']}",
            f"Raw secret: {params['raw']}",
            f"Full secret: {params['full']}",
            f"Предварительная ссылка: tg://proxy?server={params['host']}&port={params['port']}&secret={params['full']}",
            f"Сетевой режим: {params.get('tune_mode', 'native')}",
            f"UFW: {'будет включён/обновлён' if params['ufw'] == '1' else 'будет добавлен allow для SSH/telemt/custom-портов без принудительного включения UFW'}",
        ]
        if params["ufw"] == "1":
            lines.append("Разрешённые UFW-порты:")
            for r in allow_rules:
                lines.append(f"  - {r}")
        if params.get("tune_mode", "native") == "native":
            lines.append("Telemt native:")
            if params.get("native_synlimit") == "1":
                lines.append(f"  - встроенный SYN limiter: да, backend={params.get('native_backend')}, preset={params.get('native_preset')}")
                lines.append("  - параметры будут записаны в [[server.listeners]]: synlimit, synlimit_seconds, synlimit_hitcount, synlimit_burst")
            else:
                lines.append("  - чистая установка: без встроенного SYN limiter")
            lines.append(f"  - UFW allow: будет добавлен для {params['port']}/tcp и SSH-порта без принудительного включения UFW")
        if params.get("tune_mode") == "mtpr":
            lines.append("MTproxy-reanimation / nftables:")
            lines.append("  - upstream mtpr.sh будет скачан заново; версия/hash будут сохранены на сервере")
            lines.append(f"  - NFT SYN limiter: {'да' if params.get('mtpr_nft') == '1' else 'нет'}")
            lines.append(f"  - systemd автозапуск: {'да' if params.get('mtpr_service') == '1' else 'нет'}")
            lines.append(f"  - тюнинг Telemt: {'да' if params.get('mtpr_tuning') == '1' else 'нет'}")
            lines.append(f"  - iOS keepalive: {'да' if params.get('mtpr_ios') == '1' else 'нет'}")
            lines.append(f"  - iOS MSS+redirect: {'да (ОПАСНАЯ опция)' if params.get('mtpr_ios2') == '1' else 'нет'}")
            if params.get('test_mode'):
                lines.append(f"  - вкладка тестовых режимов: {params.get('test_mode')}")
            lines.append(f"  - preset: {params.get('mtpr_preset')} / timeout {params.get('mtpr_meter_timeout')}")
            if params.get('mtpr_preset') == 'upstream-default':
                lines.append("  - upstream-default: повторяет ручную схему: свежий telemt, client_mss=tspu, [general] tg_connect=10, [timeouts] handshake=15/keepalive=60")
                lines.append("  - MTproxy-reanimation default: NFT rate=1/second, burst=1, meter timeout=60s, iOS keepalive включён")
            elif params.get('mtpr_preset') == 'forum-test':
                lines.append("  - forum-test: NFT rate=2/second, burst=3, timeout=60s, tg_connect=30, handshake=7, keepalive=45")
            elif params.get('mtpr_preset') == 'custom-nft':
                lines.append(f"  - custom NFT: rate={params.get('mtpr_custom_rate')}/second, burst={params.get('mtpr_custom_burst')}, timeout={params.get('mtpr_meter_timeout')}, tg_connect={params.get('mtpr_custom_tg')}, handshake={params.get('mtpr_custom_hs')}, keepalive={params.get('mtpr_custom_ka')}")
            if params.get('custom_toml_path'):
                lines.append(f"  - custom TOML: будет загружен файл {params.get('custom_toml_path')}")
                lines.append("  - поддерживаются плейсхолдеры: __TELEMT_PORT__, __TELEMT_DOMAIN__, __TELEMT_RAW_SECRET__, __API_PORT__, __TARGET_NAME__")
            lines.append(f"  - UFW allow: будет добавлен для {params['port']}/tcp и SSH-порта без принудительного включения UFW")
            if params.get('mtpr_extra_ports'):
                lines.append(f"  - доп. TCP-порты telemt для nft limiter/UFW allow: {params.get('mtpr_extra_ports')}")
        if params.get("replace_instance"):
            cfg = self.state.telemt_configs.get(params["replace_instance"])
            lines.append("")
            lines.append(f"ВНИМАНИЕ: порт занят telemt-конфигом {params['replace_instance']}. Он будет заменён новым конфигом.")
            if cfg:
                lines.append(f"Текущие параметры {cfg.name}: port={cfg.port or '?'}, domain={cfg.domain or '?'}")
                link = self._current_link(cfg)
                if link:
                    lines.append(f"Текущая ссылка {cfg.name}:")
                    lines.append(link)
        elif params["action"] == "install" and "telemt1" in self.state.telemt_configs:
            cfg = self.state.telemt_configs["telemt1"]
            lines.append("")
            lines.append("ВНИМАНИЕ: telemt1 уже существует. Его настройки будут пересозданы, старые файлы будут сохранены как .bak.<timestamp>.")
            lines.append(f"Текущие параметры telemt1: port={cfg.port or '?'}, domain={cfg.domain or '?'}")
            link = self._current_link(cfg)
            if link:
                lines.append("Текущая ссылка telemt1:")
                lines.append(link)
        if not self.state.default_available:
            lines.append("")
            lines.append("Свободных дефолтных наборов параметров нет. Для новых инстансов используйте custom.")
        lines.extend([
            "",
            "Будет выполнено:",
            "  - жёсткая проверка поддерживаемой ОС/архитектуры/systemd",
            "  - установка зависимостей",
            "  - загрузка последней стабильной версии telemt с совместимой libc-сборкой",
            "  - установка бинарника в /opt/telemt-gui/bin/telemt без подмены чужого /bin или /usr/bin telemt",
            "  - создание/обновление /etc/telemt/<instance>.toml",
            "  - создание/обновление systemd service",
            "  - запуск сервиса и проверка LISTEN-порта",
            "  - UFW allow для SSH/telemt/custom-портов в любом сетевом режиме",
            "  - опционально: Telemt native SYN limiter, UFW + xt_recent или MTproxy-reanimation/nftables",
            "  - rollback config/service при ошибке",
            "  - запись managed-state в /etc/telemt-gui/managed-instances",
            "  - вывод итоговой tg://proxy ссылки в лог",
        ])
        return "\n".join(lines), allow_rules

    def show_plan(self) -> None:
        if not self.params_valid or not self.validated_snapshot:
            messagebox.showerror("План", "Сначала нажмите «Проверить параметры».")
            return
        if self.validated_snapshot.fingerprint != self._validation_fingerprint():
            self._invalidate_params()
            messagebox.showerror("План", "Параметры изменились после проверки. Повторите проверку.")
            return
        params = dict(self.validated_snapshot.data)
        text, _ = self._build_plan_text(params)
        win = tk.Toplevel(self)
        win.title("План деплоя")
        win.geometry("880x660")
        win.minsize(640, 420)
        win.rowconfigure(0, weight=1)
        win.columnconfigure(0, weight=1)
        txt = scrolledtext.ScrolledText(win, wrap=tk.WORD)
        txt.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        txt.insert(tk.END, text)
        txt.configure(state="disabled")
        btns = ttk.Frame(win)
        btns.grid(row=1, column=0, sticky="ew", padx=8, pady=8)
        btns.columnconfigure(0, weight=1)
        ttk.Button(btns, text="Отмена", command=win.destroy).grid(row=0, column=1, padx=4)
        ttk.Button(btns, text="Deploy", command=lambda: self.deploy_with_params(params, win)).grid(row=0, column=2, padx=4)

    def deploy_with_params(self, params: Dict[str, str], plan_window: Optional[tk.Toplevel]) -> None:
        if not self.session:
            messagebox.showerror("SSH", "Нет активной SSH-сессии")
            return
        if params.get("replace_instance") and params.get("_easy") != "1":
            cfg = self.state.telemt_configs.get(params["replace_instance"])
            msg = f"Порт {params['port']}/tcp уже занят telemt-конфигом {params['replace_instance']}.\nНовый deploy заменит этот конфиг. Продолжить?"
            if cfg:
                link = self._current_link(cfg)
                if link:
                    msg += "\n\nТекущая ссылка:\n" + link
            if not messagebox.askyesno("Подтверждение замены", msg):
                return
        elif params["action"] == "install" and "telemt1" in self.state.telemt_configs and params.get("_easy") != "1":
            cfg = self.state.telemt_configs["telemt1"]
            msg = f"telemt1 уже существует: port={cfg.port or '?'}, domain={cfg.domain or '?'}\nНастройки будут пересозданы. Продолжить?"
            link = self._current_link(cfg)
            if link:
                msg += "\n\nТекущая ссылка:\n" + link
            if not messagebox.askyesno("Подтверждение", msg):
                return
        if params.get("_easy") != "1" and not messagebox.askyesno("Deploy", "Применить конфигурацию на сервере?"):
            return
        if plan_window and plan_window.winfo_exists():
            plan_window.destroy()
        self.deploying = True

        def work():
            remote_path = ""
            remote_env_path = ""
            try:
                sess = self.session
                if sess is None:
                    raise RuntimeError("SSH-сессия не активна")
                remote_path = f"/tmp/telemt-gui-deploy-{int(time.time())}.sh"
                remote_env_path = f"/tmp/telemt-gui-deploy-{int(time.time())}.env"
                sess.upload_text(remote_path, REMOTE_DEPLOY_SCRIPT, 0o700)
                allow_rules = self._computed_allow_rules(params)
                base = {f"{params['ssh_port']}/tcp", f"{params['port']}/tcp"}
                extra = " ".join([r for r in allow_rules if r not in base])
                env_values = {
                    "TELEMT_ACTION": params["action"],
                    "TELEMT_PORT": params["port"],
                    "TELEMT_DOMAIN": params["domain"],
                    "TELEMT_RAW_SECRET": params["raw"],
                    "TELEMT_UFW_ENABLE": params["ufw"],
                    "TELEMT_SSH_PORT": params["ssh_port"],
                    "TELEMT_ALLOW_RULES": extra,
                    "TELEMT_REPLACE_INSTANCE": params.get("replace_instance", ""),
                    "TELEMT_TUNE_MODE": params.get("tune_mode", "native"),
                    "TELEMT_NATIVE_SYNLIMIT": params.get("native_synlimit", "0"),
                    "TELEMT_NATIVE_BACKEND": params.get("native_backend", "nftables"),
                    "TELEMT_NATIVE_PRESET": params.get("native_preset", "hard"),
                    "MTPR_ENABLE_NFT": params.get("mtpr_nft", "0"),
                    "MTPR_ENABLE_SERVICE": params.get("mtpr_service", "0"),
                    "MTPR_APPLY_TUNING": params.get("mtpr_tuning", "0"),
                    "MTPR_IOS_KEEPALIVE": params.get("mtpr_ios", "0"),
                    "MTPR_IOS2_FIX": params.get("mtpr_ios2", "0"),
                    "MTPR_PRESET": params.get("mtpr_preset", "hard"),
                    "MTPR_METER_TIMEOUT": params.get("mtpr_meter_timeout", "60s"),
                    "MTPR_EXTRA_PORTS": params.get("mtpr_extra_ports", ""),
                    "MTPR_CUSTOM_RATE": params.get("mtpr_custom_rate", ""),
                    "MTPR_CUSTOM_BURST": params.get("mtpr_custom_burst", ""),
                    "MTPR_CUSTOM_TG_CONNECT": params.get("mtpr_custom_tg", ""),
                    "MTPR_CUSTOM_HANDSHAKE": params.get("mtpr_custom_hs", ""),
                    "MTPR_CUSTOM_KEEPALIVE": params.get("mtpr_custom_ka", ""),
                    "TELEMT_CUSTOM_TOML_B64": params.get("custom_toml_b64", ""),
                }
                sess.upload_text(remote_env_path, shell_env_text(env_values), 0o600)
                self.worker_q.put(("log", "Запускаю deploy на сервере..."))
                stream_buf: List[str] = []
                def on_chunk(chunk: str) -> None:
                    text = strip_ansi(chunk)
                    stream_buf.append(text)
                    if text.strip():
                        self.worker_q.put(("log", text.rstrip()))
                remote_cmd = (
                    f"set -a; . {q(remote_env_path)}; set +a; "
                    f"timeout 900s bash {q(remote_path)}; rc=$?; "
                    f"rm -f {q(remote_env_path)} {q(remote_path)}; exit $rc"
                )
                code, out, err = sess.run_stream(remote_cmd, timeout=930, sudo=True, on_output=on_chunk)
                clean = strip_ansi("".join(stream_buf) + out)
                clean_err = strip_ansi(err)
                if clean_err.strip():
                    self.worker_q.put(("log", clean_err.strip()))
                deploy_link = ""
                m = re.search(r"LINK=(tg://proxy\?\S+)", clean)
                if m:
                    deploy_link = m.group(1)
                    self.worker_q.put(("log", "Итоговая ссылка для Telegram: " + deploy_link))
                    if params.get("_easy") == "1":
                        self.worker_q.put(("easy_link", deploy_link))
                if code != 0:
                    raise RuntimeError(f"Deploy завершился с кодом {code}")
                st = self._scan_state(sess)
                st.connected = True
                st.root_mode = sess.root_mode
                self.worker_q.put(("state", st))
                self._check_external_tcp_port(params["host"], int(params["port"]))
                self.worker_q.put(("deploy_done", {"message": "Deploy OK", "link": deploy_link, "easy": params.get("_easy", "0")}))
            except Exception as e:
                try:
                    sess = self.session
                    if sess is not None and (remote_path or remote_env_path):
                        sess.run(f"rm -f {q(remote_path)} {q(remote_env_path)}", timeout=10, sudo=True)
                except Exception:
                    pass
                self.worker_q.put(("error", str(e)))
            finally:
                self.deploying = False
        self._run_thread(work)


    def _build_easy_params_from_state(self) -> Dict[str, str]:
        port, domain, replace_cfg = self._choose_easy_default()
        raw = secrets.token_hex(16)
        replace_name = replace_cfg.name if replace_cfg else ""
        return {
            "action": "add_instance" if not replace_name else "install",
            "host": self.host_var.get().strip(),
            "user": self.user_var.get().strip(),
            "ssh_port": str(self._ssh_port()),
            "port": str(port),
            "domain": domain,
            "raw": raw,
            "full": full_secret(raw, domain),
            "replace_instance": replace_name,
            "replace_existing": bool01(bool(replace_name)),
            "keep_current": "0",
            "custom_rules": "",
            "public_ports_keep": "",
            "mtpr_extra_ports_enabled": "0",
            "ufw": "0",
            "tune_mode": "native",
            "native_synlimit": "1",
            "native_backend": "nftables",
            "native_preset": "medium",
            "mtpr_nft": "0",
            "mtpr_service": "0",
            "mtpr_tuning": "0",
            "mtpr_ios": "0",
            "mtpr_ios2": "0",
            "mtpr_preset": "hard",
            "mtpr_meter_timeout": "60s",
            "mtpr_extra_ports": "",
            "_easy": "1",
        }

    def _copy_text_to_clipboard(self, text: str, status_var: Optional[tk.StringVar] = None) -> None:
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        if status_var is not None:
            status_var.set("Ссылка скопирована в буфер обмена.")

    def _make_link_entry(self, parent: tk.Widget, textvariable: tk.StringVar, width: int = 88) -> tk.Entry:
        """Create a link field with explicit colors.

        ttk.Entry in readonly state can render text invisibly on some Windows
        themes after our dark-theme style maps. A plain tk.Entry is more
        predictable here and still allows normal Ctrl+C / selection.
        """
        theme = getattr(self, "_theme", {})
        bg = theme.get("field", "#ffffff")
        fg = theme.get("fg", "#111111")
        border = theme.get("border", "#888888")
        select_bg = theme.get("accent_bg", "#2f80ed")
        select_fg = theme.get("accent_fg", "#ffffff")
        ent = tk.Entry(
            parent,
            textvariable=textvariable,
            width=width,
            bg=bg,
            fg=fg,
            insertbackground=fg,
            selectbackground=select_bg,
            selectforeground=select_fg,
            readonlybackground=bg,
            disabledbackground=bg,
            disabledforeground=fg,
            relief="solid",
            bd=1,
            highlightthickness=1,
            highlightbackground=border,
            highlightcolor=select_bg,
            exportselection=False,
        )
        return ent

    def _show_deploy_result_window(self, link: str, message: str = "Deploy OK") -> None:
        win = tk.Toplevel(self)
        win.title("Deploy OK")
        win.transient(self)
        win.grab_set()
        win.configure(bg=self._theme.get("bg", "#f5f5f5"))
        win.columnconfigure(0, weight=1)

        card = RoundedCard(win, "Готово", theme=getattr(self, "_theme", {}))
        card.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)
        content = card.content
        content.columnconfigure(0, weight=1)

        status_var = tk.StringVar(value="Deploy завершён. Скопируйте ссылку и добавьте её в Telegram.")
        ttk.Label(content, text=message, style="CardOk.TLabel").grid(row=0, column=0, sticky="w", padx=10, pady=(8, 2))
        ttk.Label(content, textvariable=status_var, style="CardMuted.TLabel", wraplength=620).grid(row=1, column=0, sticky="w", padx=10, pady=(0, 8))

        link_var = tk.StringVar(value=link)
        ent = self._make_link_entry(content, link_var, width=88)
        ent.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 8))
        try:
            ent.focus_set()
            ent.selection_range(0, tk.END)
        except Exception:
            pass

        btns = ttk.Frame(content, style="Card.TFrame")
        btns.grid(row=3, column=0, sticky="e", padx=10, pady=(0, 10))
        ttk.Button(btns, text="Копировать", style="Accent.TButton", command=lambda: self._copy_text_to_clipboard(link, status_var)).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(btns, text="Закрыть", command=win.destroy).grid(row=0, column=1)

        win.bind("<Escape>", lambda _e: win.destroy())
        win.update_idletasks()
        w = min(max(win.winfo_reqwidth(), 700), max(self.winfo_width() - 80, 700))
        h = win.winfo_reqheight()
        x = self.winfo_rootx() + max((self.winfo_width() - w) // 2, 20)
        y = self.winfo_rooty() + max((self.winfo_height() - h) // 2, 20)
        win.geometry(f"{w}x{h}+{x}+{y}")

    def copy_easy_link(self) -> None:
        link = self.easy_link_var.get().strip() if hasattr(self, "easy_link_var") else ""
        self._copy_text_to_clipboard(link, self.easy_status_var if hasattr(self, "easy_status_var") else None)

    def easy_deploy_clicked(self) -> None:
        if self.deploying:
            messagebox.showinfo("Deploy", "Deploy уже выполняется")
            return
        self.easy_link_var.set("")
        try:
            self.easy_link_entry.grid_remove()
            self.easy_copy_btn.grid_remove()
        except Exception:
            pass
        self.deploying = True
        self.easy_deploy_btn.configure(state="disabled")
        self.easy_status_var.set("Подключаюсь и проверяю сервер...")

        def work():
            try:
                st = self._connect_and_scan_sync()
                self.state = st
                self.worker_q.put(("state", st))
                params = self._build_easy_params_from_state()
                replace_name = params.get("replace_instance", "")
                if replace_name:
                    cfg = self.state.telemt_configs.get(replace_name)
                    msg = (
                        f"Свободных дефолтных портов нет. Будет заменён существующий telemt-конфиг {replace_name} "
                        f"на порту {params['port']}/tcp.\n\n"
                        f"Старый домен: {(cfg.domain if cfg else '?')}\n"
                        f"Новый домен: {params['domain']}\n\nПродолжить?"
                    )
                    if not self._ask_yes_no_threadsafe("Быстрый deploy", msg):
                        self.worker_q.put(("easy_status", "Deploy отменён."))
                        self.deploying = False
                        self.after(0, lambda: self.easy_deploy_btn.configure(state="normal"))
                        return
                else:
                    msg = (
                        f"Будет установлен telemt на первый свободный дефолтный порт:\n\n"
                        f"{params['port']}/tcp + {params['domain']}\n"
                        "Режим: Telemt native + Native SYN limiter, preset medium.\n\nПродолжить?"
                    )
                    if not self._ask_yes_no_threadsafe("Быстрый deploy", msg):
                        self.worker_q.put(("easy_status", "Deploy отменён."))
                        self.deploying = False
                        self.after(0, lambda: self.easy_deploy_btn.configure(state="normal"))
                        return
                self.worker_q.put(("easy_status", "Запускаю deploy..."))
                # Directly reuse the normal deploy path, but skip an extra plan window.
                self.after(0, lambda: self.deploy_with_params(params, None))
            except Exception as e:
                self.worker_q.put(("error", str(e)))
                self.deploying = False
        self._run_thread(work)

    def _check_external_tcp_port(self, host: str, port: int) -> None:
        """Best-effort external TCP check from the local machine. Never raises.

        With nft/iptables SYN limiters a single immediate connect can be a false negative:
        the deploy itself, Telegram client, browser checks, or repeated UI probes may compete
        with the limiter. Therefore the check waits a little and retries with pauses.
        """
        initial_delay = 5.0
        attempts = 5
        timeout = 7.0
        pause = 2.0
        last_error = None

        self.worker_q.put((
            "log",
            f"Проверяю внешний TCP-доступ к {host}:{port}: ожидание {int(initial_delay)} сек, "
            f"до {attempts} попыток..."
        ))
        time.sleep(initial_delay)

        for i in range(1, attempts + 1):
            try:
                with socket.create_connection((host, int(port)), timeout=timeout):
                    self.worker_q.put((
                        "log",
                        f"[OK] Внешняя проверка TCP-порта: {host}:{port} доступен "
                        f"с этого компьютера (попытка {i}/{attempts})."
                    ))
                    return
            except Exception as e:
                last_error = e
                self.worker_q.put((
                    "log",
                    f"[INFO] Внешняя проверка TCP-порта: попытка {i}/{attempts} не удалась ({e})."
                ))
                if i < attempts:
                    time.sleep(pause)

        self.worker_q.put((
            "log",
            f"[WARN] Не удалось подтвердить внешний TCP-доступ к {host}:{port} "
            f"после {attempts} попыток (последняя ошибка: {last_error}). "
            "Установка НЕ откатывается. Это может быть firewall, rate-limit или временная задержка после настройки. "
            "Если proxy уже работает — предупреждение можно игнорировать; иначе проверьте UFW/iptables/nftables "
            "и firewall у VPS-провайдера."
        ))


    # ---------- cleanup ----------
    def cleanup_telemt(self) -> None:
        if not self.session or not self.state.connected:
            messagebox.showwarning("SSH", "Сначала подключитесь к серверу")
            return
        if not self.state.telemt_configs:
            messagebox.showinfo("Очистка", "Telemt-конфиги не найдены")
            return
        win = tk.Toplevel(self)
        win.title("Очистка telemt")
        win.geometry("680x520")
        win.minsize(560, 420)
        win.transient(self)
        win.columnconfigure(0, weight=1)
        win.rowconfigure(1, weight=1)
        ttk.Label(win, text="Выберите telemt-конфиги для удаления. Для каждого показаны порт и домен маскировки.").grid(row=0, column=0, sticky="w", padx=10, pady=8)
        frame = ttk.Frame(win)
        frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=4)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        theme = getattr(self, "_theme", {"bg": "#f5f5f5", "fg": "#111111", "field": "#ffffff", "accent": "#e9e9e9"})
        canvas = tk.Canvas(frame, highlightthickness=0, bg=theme.get("bg", "#f5f5f5"))
        scroll = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas, bg=theme.get("bg", "#f5f5f5"))
        inner.columnconfigure(0, weight=1)
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        vars_by_name = {}
        for i, (name, cfg) in enumerate(sorted(self.state.telemt_configs.items(), key=lambda kv: kv[0])):
            var = tk.BooleanVar(value=name.startswith("telemt") and name[6:].isdigit())
            vars_by_name[name] = var
            text = f"{name}: port={cfg.port or '?'}, domain={cfg.domain or '?'}, api={cfg.api or '?'}"
            tk.Checkbutton(
                inner, text=text, variable=var, anchor="w",
                bg=theme.get("bg", "#f5f5f5"), fg=theme.get("fg", "#111111"),
                activebackground=theme.get("bg", "#f5f5f5"), activeforeground=theme.get("fg", "#111111"),
                selectcolor=theme.get("field", "#ffffff"),
                highlightthickness=0, bd=0
            ).grid(row=i, column=0, sticky="w", padx=6, pady=4)
        close_ufw_var = tk.BooleanVar(value=True)
        remove_all_var = tk.BooleanVar(value=False)
        opts = ttk.Frame(win)
        opts.grid(row=2, column=0, sticky="ew", padx=10, pady=6)
        ttk.Checkbutton(opts, text="Закрыть использованные TCP-порты в UFW", variable=close_ufw_var).pack(anchor="w")
        ttk.Checkbutton(opts, text="Дополнительно удалить ВСЕ telemt-конфиги, включая не созданные программой", variable=remove_all_var).pack(anchor="w")
        btns = ttk.Frame(win)
        btns.grid(row=3, column=0, sticky="ew", padx=10, pady=10)
        btns.columnconfigure(0, weight=1)
        ttk.Button(btns, text="Отмена", command=win.destroy).grid(row=0, column=1, padx=4)
        def do_cleanup():
            selected = [name for name, var in vars_by_name.items() if var.get()]
            if remove_all_var.get():
                if not messagebox.askyesno("Опасное удаление", "Будут удалены ВСЕ telemt-конфиги и service-файлы. Продолжить?"):
                    return
                scope = "all"
            else:
                scope = "selected"
                if not selected:
                    messagebox.showwarning("Очистка", "Не выбран ни один конфиг")
                    return
            msg = "Удалить выбранные telemt-конфиги?"
            if selected:
                msg += "\n\n" + "\n".join(selected)
            if not messagebox.askyesno("Подтверждение", msg):
                return
            win.destroy()
            self.deploying = True
            def work():
                try:
                    sess = self.session
                    if sess is None:
                        raise RuntimeError("SSH-сессия не активна")
                    remote_path = f"/tmp/telemt-gui-cleanup-{int(time.time())}.sh"
                    sess.upload_text(remote_path, REMOTE_CLEANUP_SCRIPT, 0o700)
                    self.worker_q.put(("log", "Запускаю очистку telemt на сервере..."))
                    names = " ".join(selected)
                    cmd = f"CLEANUP_SCOPE={q(scope)} CLEANUP_NAMES={q(names)} CLOSE_UFW={q('1' if close_ufw_var.get() else '0')} bash {q(remote_path)}"
                    code, out, err = sess.run(cmd, timeout=300, sudo=True)
                    clean = strip_ansi(out)
                    clean_err = strip_ansi(err)
                    if clean.strip(): self.worker_q.put(("log", clean.strip()))
                    if clean_err.strip(): self.worker_q.put(("log", clean_err.strip()))
                    sess.run(f"rm -f {q(remote_path)}", timeout=10, sudo=True)
                    if code != 0:
                        raise RuntimeError(f"Очистка завершилась с кодом {code}")
                    st = self._scan_state(sess)
                    st.connected = True
                    st.root_mode = sess.root_mode
                    self.worker_q.put(("state", st))
                    self.worker_q.put(("log", "Очистка завершена."))
                except Exception as e:
                    self.worker_q.put(("error", str(e)))
                finally:
                    self.deploying = False
            self._run_thread(work)
        ttk.Button(btns, text="Удалить выбранное", command=do_cleanup).grid(row=0, column=2, padx=4)


def main() -> None:
    single_sock = acquire_single_instance_socket()
    if single_sock is None:
        return
    app = App(single_sock)
    app.mainloop()


if __name__ == "__main__":
    main()
