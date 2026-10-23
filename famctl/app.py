import hmac
import os
import logging
from functools import wraps

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

from . import discovery, filtering, remote, shaping
from .config import Config
from .runner import Runner
from .store import Store, normalize_domain, normalize_mac


def create_app(cfg=None):
    cfg = cfg or Config()
    if not cfg.password:
        raise SystemExit("Set FAMCTL_PASSWORD - this dashboard controls your whole network.")

    app = Flask(__name__)
    app.secret_key = cfg.secret_key
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
    app.cfg = cfg
    app.runner = Runner(dry_run=cfg.dry_run)
    app.store = Store(cfg.state_file)

    def login_required(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not session.get("ok"):
                if request.path.startswith("/api/"):
                    return jsonify(error="login required"), 401
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapper

    def apply_all():
        devices = app.store.data["devices"]
        live = discovery.discover(cfg.leases_file, cfg.arp_file)
        limits = [
            (live.get(mac, {}).get("ip", ""), d["down_mbit"], d["up_mbit"])
            for mac, d in devices.items()
        ]
        shaping.apply(app.runner, cfg.lan_iface, cfg.ifb_iface, cfg.total_mbit, limits)
        filtering.apply(app.runner, cfg, devices, app.store.data["global_blocked"])

    app.apply_all = apply_all

    @app.errorhandler(ValueError)
    @app.errorhandler(RuntimeError)
    def bad_request(err):
        return jsonify(error=str(err)), 400

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            if hmac.compare_digest(request.form.get("password", ""), cfg.password):
                session["ok"] = True
                return redirect(url_for("index"))
            error = "كلمة السر غلط"
        return render_template("login.html", error=error)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def index():
        return render_template("index.html", dry_run=cfg.dry_run)

    @app.get("/api/devices")
    @login_required
    def list_devices():
        live = discovery.discover(cfg.leases_file, cfg.arp_file)
        saved = app.store.data["devices"]
        out = []
        for mac in sorted(set(live) | set(saved)):
            info = live.get(mac, {"mac": mac, "ip": "", "hostname": "", "online": False,
                                  "random_mac": discovery.is_randomized_mac(mac)})
            out.append({**info, **app.store.device(mac)})
        return jsonify(devices=out, global_blocked=app.store.data["global_blocked"])

    @app.post("/api/devices/<mac>")
    @login_required
    def update_device(mac):
        body = request.get_json(force=True)
        fields = {}
        if "name" in body:
            fields["name"] = str(body["name"])[:60]
        if "paused" in body:
            fields["paused"] = bool(body["paused"])
        for key in ("down_mbit", "up_mbit"):
            if key in body:
                value = int(body[key] or 0)
                if not 0 <= value <= cfg.total_mbit:
                    raise ValueError(f"{key} must be between 0 and {cfg.total_mbit}")
                fields[key] = value
        if "blocked" in body:
            fields["blocked"] = sorted({normalize_domain(d) for d in body["blocked"] if d.strip()})
        dev = app.store.update_device(normalize_mac(mac), **fields)
        apply_all()
        return jsonify(device=dev)

    @app.post("/api/global-blocklist")
    @login_required
    def global_blocklist():
        domains = [d for d in request.get_json(force=True).get("domains", []) if d.strip()]
        app.store.set_global_blocked(domains)
        apply_all()
        return jsonify(global_blocked=app.store.data["global_blocked"])

    @app.post("/api/apply")
    @login_required
    def apply_now():
        apply_all()
        return jsonify(ok=True, commands=app.runner.history[-50:] if cfg.dry_run else [])

    @app.post("/api/remote/<mac>/<action>")
    @login_required
    def remote_action(mac, action):
        mac = normalize_mac(mac)
        body = request.get_json(force=True) or {}
        addr = body.get("addr") or app.store.device(mac)["adb"]
        if action == "pair":
            out = remote.pair(app.runner, addr, body.get("code", ""))
        elif action == "connect":
            out = remote.connect(app.runner, addr)
            app.store.update_device(mac, adb=addr)
        elif action == "screen":
            out = remote.open_screen(app.runner, addr)
        elif action == "disconnect":
            out = remote.disconnect(app.runner, addr)
        else:
            return jsonify(error="unknown action"), 404
        return jsonify(ok=True, output=out or "")

    return app


def main():
    logging.basicConfig(level=logging.INFO)
    app = create_app()
    app.apply_all()  # restore rules after a reboot
    app.run(host=os.environ.get("FAMCTL_HOST", "0.0.0.0"), port=int(os.environ.get("FAMCTL_PORT", "8080")))


if __name__ == "__main__":
    main()
