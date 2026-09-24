"""Temporary iwd AP with DHCP and a forwarding kill switch."""

import getpass
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time


RUN = Path("/run/routevpn-hotspot.json")
AP_PROFILE = Path("/var/lib/iwd/ap")
HOSTAPD_CONFIG = Path("/run/routevpn-hostapd.conf")
HOSTAPD_LOG = Path("/run/routevpn-hostapd.log")
GATEWAY = "10.77.0.1"


def command(*argv, input_text=None):
    result = subprocess.run(argv, input=input_text, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f'{" ".join(argv[:3])}: {(result.stderr or result.stdout).strip()}')
    return result.stdout


def check_binary(name):
    if not shutil.which(name):
        raise RuntimeError(f"Не найден {name}; установите его перед запуском точки доступа")


def profile(ssid, password, channel=None):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", ssid):
        raise RuntimeError("SSID: 1–32 символа A-Z, a-z, 0-9, _ или -")
    if not 8 <= len(password) <= 63 or not password.isascii():
        raise RuntimeError("Пароль Wi-Fi: 8–63 ASCII-символа")
    lines = ["[General]"]
    if channel:
        lines.append(f"Channel={channel}")
    lines += ["", "[Security]", f"Passphrase={password}", ""]
    AP_PROFILE.mkdir(parents=True, exist_ok=True)
    target = AP_PROFILE / f"{ssid}.ap"
    if target.exists():
        raise RuntimeError(f"Профиль {target} уже существует; выберите другое имя сети")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write("\n".join(lines))
    return target


def hostapd_config(iface, ssid, password, channel):
    if HOSTAPD_CONFIG.exists():
        raise RuntimeError(f"Файл {HOSTAPD_CONFIG} уже существует")
    lines = [
        f"interface={iface}", "driver=nl80211", "country_code=RU", "ieee80211d=1", f"ssid={ssid}",
        "hw_mode=a" if channel >= 36 else "hw_mode=g", f"channel={channel}",
        "ieee80211n=0", "ieee80211ac=0", "ieee80211ax=0", "wmm_enabled=0", "auth_algs=1", "ignore_broadcast_ssid=0", "ap_isolate=0",
        "wpa=2", f"wpa_passphrase={password}", "wpa_key_mgmt=WPA-PSK", "rsn_pairwise=CCMP", "",
    ]
    fd = os.open(HOSTAPD_CONFIG, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write("\n".join(lines))
    return HOSTAPD_CONFIG


def guard_rules(iface):
    return f'''table inet routevpn {{
  chain forward {{
    type filter hook forward priority -50; policy accept;
    iifname "{iface}" oifname != "rvpn0" drop
  }}
}}
'''


def nft_guard(iface):
    # A dedicated table avoids changing existing firewall tables.
    exists = subprocess.run(["nft", "list", "table", "inet", "routevpn"], capture_output=True)
    if exists.returncode == 0:
        raise RuntimeError("Таблица nft routevpn уже существует")
    command("nft", "-f", "-", input_text=guard_rules(iface))


def cleanup():
    if not RUN.exists():
        return
    info = json.loads(RUN.read_text())
    iface = info["iface"]
    if info.get("hostapd_pid"):
        try:
            comm = Path(f'/proc/{info["hostapd_pid"]}/comm').read_text().strip()
            if comm == "hostapd":
                os.kill(info["hostapd_pid"], signal.SIGTERM)
                time.sleep(0.4)
        except (ProcessLookupError, FileNotFoundError):
            pass
    if info.get("dnsmasq_pid"):
        try:
            comm = Path(f'/proc/{info["dnsmasq_pid"]}/comm').read_text().strip()
            if comm == "dnsmasq":
                os.kill(info["dnsmasq_pid"], signal.SIGTERM)
        except ProcessLookupError:
            pass
        except FileNotFoundError:
            pass
    if not info.get("virtual"):
        subprocess.run(["iwctl", "ap", iface, "stop"], capture_output=True)
    if info.get("nft_guard"):
        subprocess.run(["nft", "delete", "table", "inet", "routevpn"], capture_output=True)
    subprocess.run(["ip", "addr", "del", GATEWAY + "/24", "dev", iface], capture_output=True)
    if info.get("virtual"):
        subprocess.run(["iw", "dev", iface, "del"], capture_output=True)
    if info.get("profile"):
        Path(info["profile"]).unlink(missing_ok=True)
    if info.get("hostapd_config"):
        Path(info["hostapd_config"]).unlink(missing_ok=True)
        HOSTAPD_LOG.unlink(missing_ok=True)
    if "previous_forward" in info:
        Path("/proc/sys/net/ipv4/ip_forward").write_text(info["previous_forward"])
    RUN.unlink(missing_ok=True)


def start(iface, ssid, virtual_from=None, password_file=None):
    if os.geteuid() != 0:
        raise RuntimeError("Точка доступа требует root: sudo routevpn hotspot run ...")
    for binary in ("iw", "iwctl", "nft", "ip", "dnsmasq"):
        check_binary(binary)
    if virtual_from:
        check_binary("hostapd")
    if RUN.exists():
        raise RuntimeError("Точка доступа уже запущена; выполните hotspot stop, если запись устарела")
    if not Path("/sys/class/net/rvpn0").exists():
        raise RuntimeError("Сначала запустите routevpn run и дождитесь интерфейса rvpn0")
    for name in (iface, virtual_from):
        if name and not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name):
            raise RuntimeError("Недопустимое имя интерфейса")
    if not virtual_from and not Path("/sys/class/net", iface).exists():
        raise RuntimeError(f"Интерфейс {iface} не найден")
    route = command("ip", "route", "get", "1.1.1.1")
    upstream = re.search(r"\bdev\s+(\S+)", route)
    if not virtual_from and upstream and upstream.group(1) == iface:
        raise RuntimeError("Указан интерфейс текущего подключения; используйте второй адаптер или --virtual-from")
    if not virtual_from:
        link = subprocess.run(["iw", "dev", iface, "link"], capture_output=True, text=True)
        if link.returncode == 0 and "Connected to" in link.stdout:
            raise RuntimeError("Этот Wi-Fi интерфейс сейчас подключён к сети; используйте --virtual-from")
    if virtual_from and iface == virtual_from:
        raise RuntimeError("Виртуальный AP должен иметь отдельное имя интерфейса")

    if password_file:
        source = Path(password_file)
        if source.stat().st_mode & 0o077:
            raise RuntimeError("Файл с паролем должен иметь права 0600")
        password = source.read_text().rstrip("\n")
    else:
        password = getpass.getpass("Пароль новой Wi-Fi сети: ")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", ssid):
        raise RuntimeError("SSID: 1–32 символа A-Z, a-z, 0-9, _ или -")
    if not 8 <= len(password) <= 63 or not password.isascii() or "\n" in password or "\r" in password:
        raise RuntimeError("Пароль Wi-Fi: 8–63 ASCII-символа без переноса строки")
    channel = None
    if virtual_from:
        if not Path("/sys/class/net", virtual_from).exists():
            raise RuntimeError(f"Интерфейс {virtual_from} не найден")
        info = command("iw", "dev", virtual_from, "info")
        match = re.search(r"\bchannel\s+(\d+)", info)
        if not match:
            raise RuntimeError("Не удалось определить канал текущей Wi-Fi сети")
        channel = int(match.group(1))
        original = bytes.fromhex(Path("/sys/class/net", virtual_from, "address").read_text().strip().replace(":", ""))
        mac = bytearray(original)
        mac[0] = (mac[0] | 0x02) & 0xFE
        if bytes(mac) == original:
            mac[-1] ^= 0x01
        address = ":".join(f"{part:02x}" for part in mac)
        command("iw", "dev", virtual_from, "interface", "add", iface, "type", "__ap", "addr", address)
        time.sleep(1)

    current = {"iface": iface, "virtual": bool(virtual_from)}
    RUN.write_text(json.dumps(current))
    try:
        if virtual_from:
            current["hostapd_config"] = str(hostapd_config(iface, ssid, password, channel))
            RUN.write_text(json.dumps(current))
            log_fd = os.open(HOSTAPD_LOG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(log_fd, "w") as log:
                hostapd = subprocess.Popen(["hostapd", str(HOSTAPD_CONFIG)], stdout=log, stderr=subprocess.STDOUT)
            current["hostapd_pid"] = hostapd.pid
            RUN.write_text(json.dumps(current))
            time.sleep(2)
            if hostapd.poll() is not None:
                raise RuntimeError("hostapd не запустился: " + HOSTAPD_LOG.read_text()[-1500:])
        else:
            current["profile"] = str(profile(ssid, password, channel))
            RUN.write_text(json.dumps(current))
            command("iwctl", "ap", iface, "start-profile", ssid)
        command("ip", "addr", "add", GATEWAY + "/24", "dev", iface)
        command("ip", "link", "set", iface, "up")
        nft_guard(iface)
        current["nft_guard"] = True
        RUN.write_text(json.dumps(current))
        previous = Path("/proc/sys/net/ipv4/ip_forward").read_text()
        current["previous_forward"] = previous
        RUN.write_text(json.dumps(current))
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")
        dnsmasq = subprocess.Popen([
            "dnsmasq", "--no-daemon", "--port=0", "--bind-interfaces", "--interface=" + iface,
            "--except-interface=lo", "--dhcp-range=10.77.0.50,10.77.0.200,255.255.255.0,12h",
            "--dhcp-authoritative", "--dhcp-rapid-commit",
            "--dhcp-option=option:router," + GATEWAY,
            "--dhcp-option=option:dns-server,1.1.1.1",
        ])
        current["dnsmasq_pid"] = dnsmasq.pid
        RUN.write_text(json.dumps(current))
        time.sleep(1)
        if dnsmasq.poll() is not None:
            raise RuntimeError("dnsmasq завершился сразу после запуска")
        print(f"Точка доступа {ssid} запущена на {iface}; Ctrl+C остановит её", flush=True)
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
        while True:
            if not RUN.exists():
                break
            if dnsmasq.poll() is not None:
                raise RuntimeError("dnsmasq остановился; точка доступа выключена")
            if virtual_from and hostapd.poll() is not None:
                raise RuntimeError("hostapd остановился; точка доступа выключена")
            time.sleep(1)
    finally:
        cleanup()


def stop():
    if os.geteuid() != 0:
        raise RuntimeError("Остановка точки доступа требует root")
    if not RUN.exists():
        raise RuntimeError("Точка доступа не запущена")
    cleanup()
