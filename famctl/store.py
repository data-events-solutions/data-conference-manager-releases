import json
import os
import re
import threading

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")


def normalize_mac(mac):
    mac = mac.strip().lower().replace("-", ":")
    if not MAC_RE.match(mac):
        raise ValueError(f"invalid MAC address: {mac}")
    return mac


def normalize_domain(domain):
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    if not DOMAIN_RE.match(domain):
        raise ValueError(f"invalid domain: {domain}")
    return domain


class Store:
    """Persists per-device settings (keyed by MAC) and the global blocklist."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.data = {"devices": {}, "global_blocked": []}
        if os.path.exists(path):
            with open(path) as f:
                self.data.update(json.load(f))

    def save(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, self.path)

    def device(self, mac):
        mac = normalize_mac(mac)
        return self.data["devices"].setdefault(mac, {
            "name": "",
            "paused": False,
            "down_mbit": 0,  # 0 = no limit
            "up_mbit": 0,
            "blocked": [],
            "adb": "",  # ip:port of wireless debugging, if paired
        })

    def update_device(self, mac, **fields):
        with self.lock:
            dev = self.device(mac)
            for key, value in fields.items():
                if key not in dev:
                    raise KeyError(key)
                dev[key] = value
            self.save()
            return dev

    def set_global_blocked(self, domains):
        with self.lock:
            self.data["global_blocked"] = sorted({normalize_domain(d) for d in domains})
            self.save()
