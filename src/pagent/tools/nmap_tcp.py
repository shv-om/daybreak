"""Light infrastructure adapter: ONE fixed nmap TCP connect scan of explicit ports.
The command is built here from validated values. No shell, no scripts, no version probing, no OS detection."""
from __future__ import annotations
import re, shutil, subprocess
from ..policy import ToolSpec

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")


def _ports_ok(v: list) -> bool:
    return 1 <= len(v) <= 20 and len(set(v)) == len(v) and all(type(p) is int and 1 <= p <= 65535 for p in v)


def build_command(nmap_path: str, host: str, ports: list) -> list:
    return [nmap_path, "-sT", "-Pn", "-n", "--open", "--max-retries", "1", "--host-timeout", "60s",
            "-p", ",".join(str(p) for p in sorted(ports)), "-oX", "-", host]


def _default_runner(cmd: list, timeout: float) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)
    if proc.returncode != 0:
        raise RuntimeError(f"nmap exit {proc.returncode}")
    return proc.stdout


def make_nmap_tcp(runner=_default_runner, nmap_path=None) -> ToolSpec:
    path = nmap_path if nmap_path is not None else shutil.which("nmap")

    def handler(host: str, ports: list, timeout: float) -> str:
        if not path:
            raise FileNotFoundError("nmap not found on PATH")
        return runner(build_command(path, host, ports), timeout)

    return ToolSpec(name="nmap_tcp", read_only=True,
                    arg_schema={"host": (str, lambda h: bool(_HOST_RE.match(h.lower()))), "ports": (list, _ports_ok)},
                    max_calls=10, timeout_s=90.0, max_output_bytes=65536, handler=handler)
