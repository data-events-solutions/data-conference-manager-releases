"""Per-device bandwidth limits with tc HTB.

Download is shaped on the LAN interface's egress (traffic going to the phone).
Upload is shaped by mirroring LAN ingress to an IFB device and shaping its egress.
"""


def build_commands(lan, ifb, total_mbit, limits):
    """limits: list of (ip, down_mbit, up_mbit). 0 means unlimited in that direction."""
    cmds = [
        f"tc qdisc del dev {lan} root",
        f"tc qdisc del dev {lan} ingress",
        f"tc qdisc del dev {ifb} root",
    ]
    active = [(ip, d, u) for ip, d, u in limits if ip and (d or u)]
    if not active:
        return cmds, []

    setup = [
        f"ip link add {ifb} type ifb",
        f"ip link set {ifb} up",
        f"tc qdisc add dev {lan} handle ffff: ingress",
        f"tc filter add dev {lan} parent ffff: protocol ip u32 match u32 0 0 "
        f"action mirred egress redirect dev {ifb}",
    ]
    for dev, field_name in ((lan, "dst"), (ifb, "src")):
        setup += [
            f"tc qdisc add dev {dev} root handle 1: htb default 9999",
            f"tc class add dev {dev} parent 1: classid 1:1 htb rate {total_mbit}mbit",
            f"tc class add dev {dev} parent 1:1 classid 1:9999 htb rate {total_mbit}mbit",
        ]
        for n, (ip, down, up) in enumerate(active, start=10):
            rate = down if dev == lan else up
            if not rate:
                continue
            setup += [
                f"tc class add dev {dev} parent 1:1 classid 1:{n} htb rate {rate}mbit ceil {rate}mbit",
                f"tc qdisc add dev {dev} parent 1:{n} fq_codel",
                f"tc filter add dev {dev} protocol ip parent 1:0 prio 1 u32 "
                f"match ip {field_name} {ip}/32 flowid 1:{n}",
            ]
    return cmds, setup


def apply(runner, lan, ifb, total_mbit, limits):
    cleanup, setup = build_commands(lan, ifb, total_mbit, limits)
    for cmd in cleanup:
        runner.run(cmd, check=False)  # fine if nothing existed yet
    for i, cmd in enumerate(setup):
        runner.run(cmd, check=i != 0)  # the ifb link may already exist
