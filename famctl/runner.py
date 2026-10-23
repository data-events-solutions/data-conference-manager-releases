import logging
import shlex
import subprocess

log = logging.getLogger(__name__)


class Runner:
    """Runs system commands, or records them when dry_run is on."""

    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.history = []

    def run(self, cmd, check=True, input_text=None):
        if isinstance(cmd, str):
            cmd = shlex.split(cmd)
        self.history.append(" ".join(cmd))
        if self.dry_run:
            log.info("[dry-run] %s", " ".join(cmd))
            return ""
        result = subprocess.run(cmd, input=input_text, capture_output=True, text=True)
        if check and result.returncode != 0:
            raise RuntimeError(f"{' '.join(cmd)} failed: {result.stderr.strip()}")
        return result.stdout
