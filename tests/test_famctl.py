import pytest

from famctl import discovery, filtering, shaping
from famctl.app import create_app
from famctl.config import Config
from famctl.store import normalize_domain

MAC = "a4:5e:60:11:22:33"


@pytest.fixture
def client(tmp_path):
    (tmp_path / "leases").write_text(f"1700000000 {MAC} 192.168.1.50 Ahmed-Phone *\n")
    (tmp_path / "arp").write_text("IP address HW type Flags HW address Mask Device\n"
                                  f"192.168.1.50 0x1 0x2 {MAC} * br-lan\n")
    cfg = Config(state_file=str(tmp_path / "state.json"), leases_file=str(tmp_path / "leases"),
                 arp_file=str(tmp_path / "arp"),
                 dry_run=True, password="pw", secret_key="test")
    app = create_app(cfg)
    c = app.test_client()
    c.post("/login", data={"password": "pw"})
    c.app = app
    return c


def test_requires_login(client):
    client.post("/logout")
    assert client.get("/api/devices").status_code == 401


def test_wrong_password_rejected(client):
    client.post("/logout")
    client.post("/login", data={"password": "nope"})
    assert client.get("/api/devices").status_code == 401


def test_lists_leased_device(client):
    devices = client.get("/api/devices").get_json()["devices"]
    assert devices[0]["hostname"] == "Ahmed-Phone"
    assert devices[0]["ip"] == "192.168.1.50"
    assert devices[0]["online"]


def test_limit_and_block_generate_rules(client):
    r = client.post(f"/api/devices/{MAC}", json={"down_mbit": 5, "up_mbit": 2,
                                                  "blocked": ["https://www.TikTok.com/foo"]})
    assert r.status_code == 200
    assert r.get_json()["device"]["blocked"] == ["tiktok.com"]
    history = "\n".join(client.app.runner.history)
    assert "htb rate 5mbit ceil 5mbit" in history
    assert "match ip dst 192.168.1.50/32" in history
    assert "match ip src 192.168.1.50/32" in history


def test_rejects_bad_input(client):
    assert client.post(f"/api/devices/{MAC}", json={"blocked": ["not a domain"]}).status_code == 400
    assert client.post(f"/api/devices/{MAC}", json={"down_mbit": 99999}).status_code == 400
    assert client.post("/api/devices/zz", json={}).status_code == 400
    assert client.post(f"/api/remote/{MAC}/connect", json={"addr": "1.2.3.4; rm -rf /"}).status_code == 400


def test_nft_rules():
    devices = {MAC: {"paused": True, "blocked": ["youtube.com"]}}
    nft = filtering.build_nft(devices, "192.168.1.1", force_dns=True)
    assert f"ether saddr {MAC} drop" in nft
    assert "ip daddr @blk_a45e60112233_v4 reject" in nft
    assert "dnat ip to 192.168.1.1" in nft


def test_dnsmasq_conf():
    conf = filtering.build_dnsmasq({MAC: {"blocked": ["youtube.com"]}}, ["tiktok.com"])
    assert "address=/tiktok.com/0.0.0.0" in conf
    assert "nftset=/youtube.com/4#inet#famctl#blk_a45e60112233_v4" in conf


def test_no_limits_only_cleans_up():
    cleanup, setup = shaping.build_commands("br-lan", "ifb0", 100, [("192.168.1.5", 0, 0)])
    assert setup == [] and cleanup


def test_random_mac_detection():
    assert discovery.is_randomized_mac("da:a1:19:00:00:01")
    assert not discovery.is_randomized_mac(MAC)


def test_normalize_domain():
    assert normalize_domain("http://www.facebook.com/x") == "facebook.com"


def test_refuses_to_start_without_password(tmp_path):
    with pytest.raises(SystemExit):
        create_app(Config(state_file=str(tmp_path / "s.json"), password=""))
