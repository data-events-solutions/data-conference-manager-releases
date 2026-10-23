"""Remote access to Android phones with ADB wireless debugging + scrcpy.

This only works on phones where the owner has turned on Developer options ->
Wireless debugging and paired with this machine using the code the phone shows.
Android keeps a persistent "Wireless debugging connected" notification while a
session is active, so the person using the phone can always see it.
"""
import re
import shutil
import subprocess

ADDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$")


def _addr(addr):
    addr = addr.strip()
    if not ADDR_RE.match(addr):
        raise ValueError("expected ip:port, e.g. 192.168.1.23:37165")
    return addr


def pair(runner, addr, code):
    if not re.fullmatch(r"\d{6}", code.strip()):
        raise ValueError("pairing code is 6 digits")
    return runner.run(["adb", "pair", _addr(addr), code.strip()])


def connect(runner, addr):
    return runner.run(["adb", "connect", _addr(addr)])


def disconnect(runner, addr):
    return runner.run(["adb", "disconnect", _addr(addr)], check=False)


def connected(runner):
    out = runner.run(["adb", "devices"], check=False)
    return [line.split()[0] for line in out.splitlines()[1:] if line.strip().endswith("device")]


def open_screen(runner, addr):
    """Start a scrcpy window (screen mirroring + control) on this machine's display."""
    addr = _addr(addr)
    if runner.dry_run:
        runner.run(["scrcpy", "-s", addr])
        return
    if not shutil.which("scrcpy"):
        raise RuntimeError("scrcpy is not installed on this machine")
    subprocess.Popen(["scrcpy", "-s", addr, "--window-title", f"famctl {addr}"])
