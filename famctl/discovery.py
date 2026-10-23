"""Find devices connected to the router from the ARP table and DHCP leases."""


def read_arp(path="/proc/net/arp"):
    """Return {mac: ip} for reachable neighbours."""
    devices = {}
    try:
        with open(path) as f:
            next(f, None)  # header
            for line in f:
                parts = line.split()
                if len(parts) < 6:
                    continue
                ip, flags, mac = parts[0], parts[2], parts[3].lower()
                if flags == "0x0" or mac == "00:00:00:00:00:00":
                    continue
                devices[mac] = ip
    except FileNotFoundError:
        pass
    return devices


def read_leases(path):
    """Parse a dnsmasq leases file: '<expiry> <mac> <ip> <hostname> <client-id>'."""
    leases = {}
    try:
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                mac = parts[1].lower()
                leases[mac] = {"ip": parts[2], "hostname": "" if parts[3] == "*" else parts[3]}
    except FileNotFoundError:
        pass
    return leases


def is_randomized_mac(mac):
    """Phones use a random 'private' MAC per network; bit 2 of the first octet marks it."""
    return bool(int(mac.split(":")[0], 16) & 0x02)


def discover(leases_path, arp_path="/proc/net/arp"):
    arp = read_arp(arp_path)
    leases = read_leases(leases_path)
    result = {}
    for mac in set(arp) | set(leases):
        lease = leases.get(mac, {})
        result[mac] = {
            "mac": mac,
            "ip": arp.get(mac) or lease.get("ip", ""),
            "hostname": lease.get("hostname", ""),
            "online": mac in arp,
            "random_mac": is_randomized_mac(mac),
        }
    return result
