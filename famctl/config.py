import os
from dataclasses import dataclass, field


def _bool(name, default=False):
    return os.environ.get(name, str(default)).lower() in ("1", "true", "yes")


@dataclass
class Config:
    # LAN interface the phones connect through (Wi-Fi bridge on most routers).
    lan_iface: str = field(default_factory=lambda: os.environ.get("FAMCTL_LAN_IFACE", "br-lan"))
    # Interface used to shape upload traffic (mirrored from LAN ingress).
    ifb_iface: str = field(default_factory=lambda: os.environ.get("FAMCTL_IFB_IFACE", "ifb0"))
    # Total internet speed in Mbit/s, used as the ceiling for all devices.
    total_mbit: int = field(default_factory=lambda: int(os.environ.get("FAMCTL_TOTAL_MBIT", "100")))
    state_file: str = field(default_factory=lambda: os.environ.get("FAMCTL_STATE", "/etc/famctl/state.json"))
    leases_file: str = field(default_factory=lambda: os.environ.get("FAMCTL_LEASES", "/tmp/dhcp.leases"))
    arp_file: str = field(default_factory=lambda: os.environ.get("FAMCTL_ARP", "/proc/net/arp"))
    dnsmasq_conf: str = field(default_factory=lambda: os.environ.get("FAMCTL_DNSMASQ_CONF", "/tmp/dnsmasq.d/famctl.conf"))
    dnsmasq_restart: str = field(default_factory=lambda: os.environ.get("FAMCTL_DNSMASQ_RESTART", "/etc/init.d/dnsmasq restart"))
    router_ip: str = field(default_factory=lambda: os.environ.get("FAMCTL_ROUTER_IP", "192.168.1.1"))
    # Redirect all DNS traffic to the router so blocking can't be bypassed by changing DNS.
    force_dns: bool = field(default_factory=lambda: _bool("FAMCTL_FORCE_DNS", True))
    # Print commands instead of running them (for testing on a normal PC).
    dry_run: bool = field(default_factory=lambda: _bool("FAMCTL_DRY_RUN"))
    password: str = field(default_factory=lambda: os.environ.get("FAMCTL_PASSWORD", ""))
    secret_key: str = field(default_factory=lambda: os.environ.get("FAMCTL_SECRET", os.urandom(24).hex()))
