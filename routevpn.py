#!/usr/bin/env python3
"""Small Linux CLI around mihomo. State lives in the invoking user's home."""

import argparse
import base64
import binascii
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import time
import signal
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))


NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$")
IFACE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
KINDS = {"domain": "DOMAIN", "suffix": "DOMAIN-SUFFIX", "cidr": "IP-CIDR",
         "src-cidr": "SRC-IP-CIDR", "dst-port": "DST-PORT", "process": "PROCESS-NAME"}
ACTIONS = {"vpn": "VPN", "direct": "DIRECT", "block": "REJECT"}
API = "http://127.0.0.1:19090"


class Error(Exception):
    pass


def state_dir():
    owner = os.environ.get("SUDO_USER") if os.geteuid() == 0 else None
    home = Path(pwd.getpwnam(owner).pw_dir) if owner and owner != "root" else Path.home()
    return home / ".config" / "routevpn"


def load(root):
    path = root / "state.json"
    if not path.exists():
        return {"subscriptions": {}, "active": None, "routes": [], "ports": [], "uplink": None}
    return json.loads(path.read_text())


def atomic_write(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".routevpn-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as stream:
            stream.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def save(root, state):
    atomic_write(root / "state.json", json.dumps(state, ensure_ascii=False, indent=2) + "\n")


def valid_name(value):
    if not NAME.fullmatch(value):
        raise Error("Имя: 1–40 символов A-Z, a-z, 0-9, _ или -; первый символ — буква или цифра")
    return value


def valid_port(value):
    port = int(value)
    if not 1 <= port <= 65535:
        raise Error("Порт должен быть в диапазоне 1–65535")
    return port


def host_port(value):
    try:
        parts = urllib.parse.urlsplit("//" + value)
        host, port = parts.hostname, parts.port
    except ValueError as exc:
        raise Error(f"Неверный адрес {value}: {exc}") from exc
    if not host or port is None or not 1 <= port <= 65535 or parts.path or parts.query or parts.fragment or parts.username or parts.password:
        raise Error("Адрес назначения должен иметь вид host:port или [IPv6]:port")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", host):
        raise Error("Недопустимое имя хоста")
    return value


def rule(kind, value, action):
    if "," in value or "\n" in value or not value:
        raise Error("Недопустимый шаблон маршрута")
    if kind in ("cidr", "src-cidr"):
        network = ipaddress.ip_network(value, strict=False)
        if network.version != 4:
            raise Error("Сейчас правила CIDR поддерживают только IPv4")
        value = str(network)
    elif kind in ("domain", "suffix"):
        if not re.fullmatch(r"[A-Za-z0-9.-]+", value) or ".." in value:
            raise Error("Недопустимое доменное имя")
    elif kind == "dst-port":
        bounds = value.split("-", 1)
        if len(bounds) > 2 or not all(part.isdecimal() and 1 <= int(part) <= 65535 for part in bounds):
            raise Error("Порт: число 1–65535 или диапазон начало-конец")
        if len(bounds) == 2 and int(bounds[0]) > int(bounds[1]):
            raise Error("Начало диапазона портов больше конца")
    return {"kind": kind, "value": value, "action": action}


def render(state, tun=True):
    active = state["active"]
    if not active or active not in state["subscriptions"]:
        raise Error("Сначала добавьте и выберите подписку: sub add, sub use")
    sub = state["subscriptions"][active]
    provider = {"type": sub["type"], "path": f"providers/{active}.yaml"}
    if sub["type"] == "http":
        provider.update(url=sub["source"], interval=3600)
    provider["health-check"] = {"enable": True, "url": "https://cp.cloudflare.com/generate_204", "interval": 600}

    cfg = {
        "mode": "rule", "log-level": "warning", "ipv6": False,
        "allow-lan": False, "mixed-port": 17890,
        "external-controller": "127.0.0.1:19090",
        "secret": state["secret"],
        "profile": {"store-selected": False},
        "dns": {
            "enable": True, "listen": "127.0.0.1:15353", "ipv6": False,
            "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
            "nameserver": ["https://1.1.1.1/dns-query#VPN"],
            "proxy-server-nameserver": ["1.1.1.1"],
        },
        "proxy-providers": {active: provider},
        "proxy-groups": [
            {"name": "AUTO", "type": "url-test", "use": [active],
             "url": "https://cp.cloudflare.com/generate_204", "interval": 300,
             "empty-fallback": "REJECT"},
            {"name": "VPN", "type": "select", "proxies": ["AUTO", "REJECT"],
             "use": [active], "default-selected": "AUTO"},
        ],
        "rules": [f'{KINDS[r["kind"]]},{r["value"]},{ACTIONS[r["action"]]}' for r in state["routes"]]
                 + ["MATCH,VPN"],
    }
    if state.get("uplink"):
        cfg["interface-name"] = state["uplink"]
    if tun:
        cfg["tun"] = {
            "enable": True, "stack": "mixed", "device": "rvpn0",
            "auto-route": True, "auto-redirect": True,
            "auto-detect-interface": not bool(state.get("uplink")), "strict-route": True,
            "dns-hijack": ["any:53", "tcp://any:53"],
        }
    if state["ports"]:
        cfg["listeners"] = [
            {"name": "forward-" + p["name"], "type": "tunnel", "listen": p["listen"],
             "port": p["port"], "network": p["network"], "target": p["target"],
             "proxy": "VPN"}
            for p in state["ports"]
        ]
    return yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False)


def api(method, path, secret, payload=None, timeout=8):
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(API + path, data=body, method=method,
                                 headers={"Authorization": "Bearer " + secret,
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = response.read()
        return json.loads(data) if data else None
    except (urllib.error.URLError, TimeoutError) as exc:
        raise Error(f"Нет ответа от mihomo: {exc}") from exc


def find_mihomo():
    local = Path(__file__).resolve().with_name("mihomo")
    return str(local) if local.is_file() and os.access(local, os.X_OK) else shutil.which("mihomo")


def require_mihomo():
    binary = find_mihomo()
    if not binary:
        raise Error("mihomo не найден в PATH. Установите официальный бинарник mihomo.")
    return binary


def select_fastest(secret):
    api("PUT", "/proxies/VPN", secret, {"name": "AUTO"})
    delays = api("GET", "/group/AUTO/delay?url=https://cp.cloudflare.com/generate_204&timeout=5000",
                 secret, timeout=12)
    reachable = {name: delay for name, delay in delays.items()
                 if isinstance(delay, (int, float)) and delay > 0}
    if not reachable:
        raise Error("Ни один сервер подписки не прошёл проверку. VPN остановлен, чтобы восстановить обычный интернет")
    selected = api("GET", "/proxies/AUTO", secret).get("now")
    print(f"Выбран сервер: {selected} ({reachable.get(selected, '?')} мс; доступно {len(reachable)})", flush=True)


def validate_provider_content(raw):
    try:
        content = raw.decode("utf-8-sig").strip()
    except UnicodeDecodeError as exc:
        raise Error("Подписка не в UTF-8") from exc
    if not content:
        raise Error("Подписка пуста")
    try:
        parsed = yaml.safe_load(content)
    except yaml.YAMLError:
        parsed = None
    if isinstance(parsed, dict) and isinstance(parsed.get("proxies"), list):
        proxies = parsed["proxies"]
        if proxies and all(isinstance(p, dict) and p.get("name") and p.get("type") for p in proxies):
            return len(proxies), "yaml"
        raise Error("В YAML нет корректного списка proxies")
    if isinstance(parsed, dict):
        raise Error("В YAML подписке нет списка proxies")

    def uri_count(value):
        lines = [line.strip() for line in value.splitlines() if line.strip()]
        return len(lines) if lines and all(re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*://\S+", line) for line in lines) else 0

    count = uri_count(content)
    if count:
        return count, "uri"
    try:
        decoded = base64.b64decode(content + "=" * (-len(content) % 4), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        raise Error("Неизвестный формат подписки: нужен YAML, URI или base64 с URI") from None
    count = uri_count(decoded)
    if not count:
        raise Error("После декодирования base64 не найдено URI узлов")
    return count, "base64"


def fetch_remote(root, name, url, secret):
    if not shutil.which("curl"):
        raise Error("Для HTTPS-подписок нужен curl")
    provider_dir = root / "providers"
    provider_dir.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{name}-download-", dir=provider_dir)
    os.fchmod(fd, 0o600)
    os.close(fd)
    try:
        result = subprocess.run([
            "curl", "--fail", "--location", "--silent", "--show-error",
            "--max-time", "30", "--max-filesize", "10000000",
            "--proto", "=https", "--proto-redir", "=https",
            "--output", temporary, url,
        ], capture_output=True, text=True)
        if result.returncode:
            raise Error("Не удалось скачать подписку: " + result.stderr.strip())
        if not 0 < Path(temporary).stat().st_size <= 10_000_000:
            raise Error("Подписка пуста или больше 10 МБ")
        validate_provider_content(Path(temporary).read_bytes())
        binary = require_mihomo()
        with tempfile.TemporaryDirectory(prefix="probe-", dir=root) as probe_name:
            probe = Path(probe_name)
            (probe / "providers").mkdir()
            shutil.copyfile(temporary, probe / "providers" / f"{name}.yaml")
            check_state = {"secret": secret, "active": name,
                           "subscriptions": {name: {"type": "file"}}, "routes": [], "ports": []}
            config = probe / "config.yaml"
            config.write_text(render(check_state, tun=False))
            check = subprocess.run([binary, "-t", "-d", str(probe), "-f", str(config)],
                                   capture_output=True, text=True, timeout=20)
            if check.returncode:
                raise Error("Неверный формат подписки: " + (check.stderr or check.stdout).strip())
        os.replace(temporary, provider_dir / f"{name}.yaml")
    finally:
        Path(temporary).unlink(missing_ok=True)


def sync(root, state, tun=True, reload=False):
    config = root / "config.yaml"
    atomic_write(config, render(state, tun))
    if find_mihomo():
        check = subprocess.run([find_mihomo(), "-t", "-d", str(root), "-f", str(config)],
                               capture_output=True, text=True)
        if check.returncode:
            raise Error("mihomo не принял конфигурацию: " + (check.stderr or check.stdout).strip())
    if reload:
        api("PUT", "/configs?force=true", state["secret"], {"path": str(config)})
    return config


def main(argv=None):
    parser = argparse.ArgumentParser(description="Консольный VPN-клиент на базе mihomo")
    parser.add_argument("--state-dir", type=Path, default=state_dir())
    top = parser.add_subparsers(dest="cmd", required=True)
    sub = top.add_parser("sub", help="подписки")
    sp = sub.add_subparsers(dest="op", required=True)
    a = sp.add_parser("add"); a.add_argument("name"); a.add_argument("source")
    a = sp.add_parser("use"); a.add_argument("name")
    a = sp.add_parser("remove"); a.add_argument("name")
    sp.add_parser("list")
    a = top.add_parser("route", help="правила маршрутизации")
    rp = a.add_subparsers(dest="op", required=True)
    b = rp.add_parser("add"); b.add_argument("kind", choices=KINDS); b.add_argument("value"); b.add_argument("action", choices=ACTIONS)
    b = rp.add_parser("remove"); b.add_argument("index", type=int)
    rp.add_parser("list")
    a = top.add_parser("port", help="локальные пробросы портов через VPN")
    pp = a.add_subparsers(dest="op", required=True)
    b = pp.add_parser("add"); b.add_argument("name"); b.add_argument("port", type=int); b.add_argument("target")
    b.add_argument("--listen", default="127.0.0.1"); b.add_argument("--network", choices=["tcp", "udp", "both"], default="tcp")
    b = pp.add_parser("remove"); b.add_argument("name")
    pp.add_parser("list")
    a = top.add_parser("render", help="создать конфиг mihomo"); a.add_argument("--proxy-only", action="store_true")
    a = top.add_parser("run", help="запустить mihomo в текущем терминале"); a.add_argument("--proxy-only", action="store_true")
    a = top.add_parser("uplink", help="физический интерфейс для VPN-соединения")
    a.add_argument("iface", nargs="?", help="например wlan0; без аргумента показать выбор, auto — автоопределение")
    a = top.add_parser("hotspot", help="раздача VPN через Wi-Fi")
    hp = a.add_subparsers(dest="op", required=True)
    b = hp.add_parser("run"); b.add_argument("--iface", required=True); b.add_argument("--ssid", required=True)
    b.add_argument("--virtual-from", help="создать AP на том же адаптере, что и Wi-Fi-клиент")
    b.add_argument("--password-file", type=Path, help="файл с паролем Wi-Fi, права 0600")
    hp.add_parser("stop")
    top.add_parser("reload", help="обновить конфиг работающего mihomo")
    top.add_parser("status", help="статус ядра и выбранного узла")
    top.add_parser("nodes", help="список узлов активной подписки")
    a = top.add_parser("node", help="выбрать узел"); a.add_argument("name")
    top.add_parser("update", help="обновить активную подписку")
    args = parser.parse_args(argv)
    root = args.state_dir.expanduser().resolve()
    state = load(root)
    if "secret" not in state:
        import secrets
        state["secret"] = secrets.token_urlsafe(32)

    if args.cmd == "sub":
        if args.op == "list":
            for name, item in state["subscriptions"].items():
                source_type = "https" if item.get("managed") else item["type"]
                print(("* " if name == state["active"] else "  ") + name + " (" + source_type + ")")
            return
        name = valid_name(args.name)
        if args.op == "add":
            if name in state["subscriptions"]:
                raise Error("Подписка с таким именем уже есть")
            if args.source.startswith("https://"):
                parsed = urllib.parse.urlsplit(args.source)
                if not parsed.hostname or not parsed.netloc or any(c in args.source for c in "\r\n"):
                    raise Error("Неверная HTTPS-ссылка")
                fetch_remote(root, name, args.source, state["secret"])
                item = {"type": "file", "source": args.source, "managed": True}
            elif args.source.startswith(("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")):
                dest = root / "providers" / f"{name}.yaml"
                atomic_write(dest, args.source + "\n")
                item = {"type": "file", "source": str(dest)}
            else:
                source = Path(args.source).expanduser().resolve()
                if not source.is_file() or source.stat().st_size > 10_000_000:
                    raise Error("Нужен существующий файл подписки размером до 10 МБ или HTTPS-ссылка")
                dest = root / "providers" / f"{name}.yaml"
                atomic_write(dest, source.read_text())
                item = {"type": "file", "source": str(dest)}
            state["subscriptions"][name] = item
            state["active"] = name if state["active"] is None else state["active"]
        elif args.op == "use":
            if name not in state["subscriptions"]:
                raise Error("Подписка не найдена")
            state["active"] = name
        else:
            if name not in state["subscriptions"]:
                raise Error("Подписка не найдена")
            del state["subscriptions"][name]
            if state["active"] == name:
                state["active"] = next(iter(state["subscriptions"]), None)
            (root / "providers" / f"{name}.yaml").unlink(missing_ok=True)
        save(root, state)
        print("Готово. Обновите работающее ядро командой reload (с sudo для TUN).")
    elif args.cmd == "route":
        if args.op == "list":
            for index, item in enumerate(state["routes"], 1):
                print(index, item["kind"], item["value"], item["action"])
            return
        if args.op == "add":
            state["routes"].append(rule(args.kind, args.value, args.action))
        else:
            if not 1 <= args.index <= len(state["routes"]):
                raise Error("Номер правила не найден")
            state["routes"].pop(args.index - 1)
        save(root, state)
        print("Готово. Обновите работающее ядро командой reload (с sudo для TUN).")
    elif args.cmd == "port":
        if args.op == "list":
            for p in state["ports"]:
                print(f'{p["name"]}: {p["listen"]}:{p["port"]} -> {p["target"]} ({",".join(p["network"])})')
            return
        if args.op == "add":
            valid_name(args.name)
            valid_port(args.port)
            host_port(args.target)
            try:
                ipaddress.ip_address(args.listen)
            except ValueError as exc:
                raise Error("--listen должен быть IP-адресом") from exc
            if any(p["name"] == args.name or (p["listen"] == args.listen and p["port"] == args.port) for p in state["ports"]):
                raise Error("Имя или локальный порт уже занят в настройках")
            state["ports"].append({"name": args.name, "port": args.port, "target": args.target,
                                   "listen": args.listen, "network": ["tcp", "udp"] if args.network == "both" else [args.network]})
        else:
            old = len(state["ports"])
            state["ports"] = [p for p in state["ports"] if p["name"] != args.name]
            if len(state["ports"]) == old:
                raise Error("Проброс не найден")
        save(root, state)
        print("Готово. Обновите работающее ядро командой reload (с sudo для TUN).")
    elif args.cmd == "render":
        print(sync(root, state, tun=not args.proxy_only))
    elif args.cmd == "uplink":
        if args.iface is not None:
            if args.iface != "auto" and not IFACE.fullmatch(args.iface):
                raise Error("Недопустимое имя интерфейса")
            state["uplink"] = None if args.iface == "auto" else args.iface
            save(root, state)
            print("Готово. Обновите работающее ядро командой reload (с sudo для TUN).")
        print(state.get("uplink") or "auto")
    elif args.cmd == "run":
        binary = require_mihomo()
        tun = not args.proxy_only
        if tun and os.geteuid() != 0:
            raise Error("TUN требует root: sudo rvpn run (или запустите rvpn run --proxy-only)")
        try:
            with socket.create_connection(("127.0.0.1", 19090), timeout=0.3):
                raise Error("mihomo уже работает на 127.0.0.1:19090; сначала остановите прежний запуск")
        except (ConnectionRefusedError, TimeoutError, OSError) as exc:
            if isinstance(exc, PermissionError):
                raise Error("Нет доступа к локальному сокету API") from exc
        config = sync(root, state, tun=tun)
        process = subprocess.Popen([binary, "-d", str(root), "-f", str(config)])
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise Error("mihomo завершился сразу после запуска")
                try:
                    api("GET", "/version", state["secret"], timeout=1)
                    break
                except Error:
                    time.sleep(0.25)
            else:
                raise Error("Контроллер mihomo не запустился за 10 секунд")
            select_fastest(state["secret"])
            if process.wait():
                raise Error("mihomo завершился с ошибкой")
        except KeyboardInterrupt:
            pass
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait()
    elif args.cmd == "hotspot":
        from hotspot import start, stop
        if args.op == "run":
            config = api("GET", "/configs", state["secret"])
            if not config.get("tun", {}).get("enable"):
                raise Error("Работающий mihomo должен быть запущен с TUN")
            try:
                start(args.iface, args.ssid, args.virtual_from, args.password_file)
            except KeyboardInterrupt:
                pass
        else:
            stop()
    elif args.cmd == "reload":
        current = api("GET", "/configs", state["secret"])
        tun_enabled = bool(current.get("tun", {}).get("enable"))
        if tun_enabled and os.geteuid() != 0:
            raise Error(f"Для обновления TUN запустите sudo {Path(__file__).resolve()} reload")
        print(sync(root, state, tun=tun_enabled, reload=True))
    elif args.cmd == "status":
        print("Подписка:", state["active"] or "нет")
        info = api("GET", "/proxies/VPN", state["secret"])
        selected = info.get("now")
        if selected == "AUTO":
            selected = api("GET", "/proxies/AUTO", state["secret"]).get("now")
        print("Узел:", selected, "| доступные:", len(info.get("all", [])))
    elif args.cmd == "nodes":
        active = state["active"]
        if not active:
            raise Error("Нет активной подписки")
        info = api("GET", "/providers/proxies/" + urllib.parse.quote(active), state["secret"])
        for p in info.get("proxies", []):
            print(p.get("name", "?"))
    elif args.cmd == "node":
        api("PUT", "/proxies/VPN", state["secret"], {"name": args.name})
        print("Выбран:", args.name)
    elif args.cmd == "update":
        if not state["active"]:
            raise Error("Нет активной подписки")
        item = state["subscriptions"][state["active"]]
        if item.get("managed"):
            fetch_remote(root, state["active"], item["source"], state["secret"])
        try:
            api("GET", "/version", state["secret"])
        except Error:
            print("Файл обновлён; ядро сейчас не запущено")
            return
        api("PUT", "/providers/proxies/" + urllib.parse.quote(state["active"]), state["secret"])
        print("Подписка обновлена")


if __name__ == "__main__":
    try:
        main()
    except (Error, OSError, RuntimeError, ValueError, yaml.YAMLError) as exc:
        print("Ошибка:", exc, file=sys.stderr)
        sys.exit(1)
