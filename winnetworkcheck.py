#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetworkCheck - 网络检查 + 确认式修复
检测只读；修复只关代理，且必须先确认。
支持 Windows（主）/ macOS / Linux。
"""

import os
import re
import sys
import json
import time
import socket
import platform
import subprocess
from pathlib import Path

# ============ 颜色 ============
if sys.platform == "win32":
    os.system("")
    GREEN = "\033[92m"; YELLOW = "\033[93m"; RED = "\033[91m"
    CYAN = "\033[96m"; RESET = "\033[0m"; BOLD = "\033[1m"
else:
    GREEN = "\033[92m"; YELLOW = "\033[93m"; RED = "\033[91m"
    CYAN = "\033[96m"; RESET = "\033[0m"; BOLD = "\033[1m"

IS_WIN = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

PASS = WARN = FAIL = 0
HAS_SYSTEM_PROXY = False
PROXY_SERVICES = []  # macOS: 需要关闭代理的服务名列表


def ok(msg):
    global PASS
    print(f"{GREEN}[OK]   {msg}{RESET}")
    PASS += 1


def wn(msg):
    global WARN
    print(f"{YELLOW}[WARN] {msg}{RESET}")
    WARN += 1


def bad(msg):
    global FAIL
    print(f"{RED}[FAIL] {msg}{RESET}")
    FAIL += 1


def section(msg):
    print(f"\n{CYAN}-------- {msg} --------{RESET}")


def run(cmd, shell=True, timeout=20):
    """执行命令，返回 (returncode, stdout, stderr)"""
    try:
        if isinstance(cmd, str) and not shell:
            cmd = cmd.split()
        r = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="ignore"
        )
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def is_admin():
    try:
        if IS_WIN:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


# ============================================================
# Windows 检测
# ============================================================

def check_win_system_proxy():
    global HAS_SYSTEM_PROXY
    section("1. 系统代理（WinINET）")
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        )
        try:
            proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
        except FileNotFoundError:
            proxy_enable = 0
        try:
            proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
        except FileNotFoundError:
            proxy_server = ""
        try:
            auto_config, _ = winreg.QueryValueEx(key, "AutoConfigURL")
        except FileNotFoundError:
            auto_config = ""
        winreg.CloseKey(key)

        if proxy_enable == 1 or auto_config:
            HAS_SYSTEM_PROXY = True
            bad("系统代理开启")
            print(f"    ProxyEnable: {proxy_enable}")
            print(f"    ProxyServer: {proxy_server}")
            if auto_config:
                print(f"    AutoConfigURL: {auto_config}")
        else:
            ok("系统代理未开启")
    except Exception as e:
        wn(f"读取系统代理失败：{e}")


def check_win_winhttp():
    section("2. WinHTTP 代理")
    code, out, _ = run("netsh winhttp show proxy")
    if not out.strip():
        wn("无法查询 WinHTTP 代理")
        return
    for line in out.splitlines():
        if line.strip():
            print(f"    {line.strip()}")
    low = out.lower()
    if "direct access" in low or "直接访问" in out:
        ok("WinHTTP 未使用代理")
    elif "proxy server" in low or "代理服务器" in out:
        wn("WinHTTP 使用了代理，请查看上方输出")
    else:
        wn("无法判断 WinHTTP 代理状态")


def check_win_env_proxy():
    section("3. 环境变量代理")
    found = []
    for name in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                 "http_proxy", "https_proxy", "all_proxy"]:
        for scope in ["User", "Machine"]:
            code, out, _ = run(
                f'powershell -NoProfile -Command '
                f'"[Environment]::GetEnvironmentVariable(\'{name}\',\'{scope}\')"'
            )
            v = out.strip()
            if v and v.lower() != "none":
                found.append(f"{name} [{scope}] = {v}")
                break
    if not found:
        ok("没有代理环境变量")
    else:
        wn("发现代理环境变量：")
        for f in found:
            print(f"    {f}")


def check_win_vpn():
    section("4. VPN 连接")
    ps = (
        "Get-VpnConnection -ErrorAction SilentlyContinue | "
        "Select-Object Name,ServerAddress,ConnectionStatus | ConvertTo-Json -Compress"
    )
    code, out, _ = run(f'powershell -NoProfile -Command "{ps}"')
    items = []
    if out.strip():
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            items = data
        except Exception:
            pass

    ps2 = (
        "Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue | "
        "Select-Object Name,ServerAddress,ConnectionStatus | ConvertTo-Json -Compress"
    )
    code, out2, _ = run(f'powershell -NoProfile -Command "{ps2}"')
    if out2.strip():
        try:
            data = json.loads(out2)
            if isinstance(data, dict):
                data = [data]
            items.extend(data)
        except Exception:
            pass

    if not items:
        ok("没有任何 VPN 配置")
        return
    connected = [x for x in items if x.get("ConnectionStatus") == "Connected"]
    if connected:
        bad("有 VPN 处于已连接状态：")
        for x in connected:
            print(f"    {x.get('Name')} - {x.get('ServerAddress')}")
    else:
        wn("存在 VPN 配置（当前未连接）：")
        for x in items:
            print(f"    {x.get('Name')} - {x.get('ServerAddress')}")


VIRTUAL_KEYWORDS = re.compile(
    r"TAP|TUN|WireGuard|OpenVPN|VPN|Clash|Mihomo|Surge|Proxy|Hyper-V|utun",
    re.IGNORECASE,
)


def check_win_route():
    section("5. 默认路由")
    ps = (
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
        "Sort-Object RouteMetric | Select-Object -First 3 "
        "InterfaceIndex,NextHop,RouteMetric | ConvertTo-Json -Compress"
    )
    code, out, _ = run(f'powershell -NoProfile -Command "{ps}"')
    routes = []
    if out.strip():
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            routes = data
        except Exception:
            pass
    if not routes:
        bad("没有默认路由（可能断网或加速器抢了路由）")
        return
    primary = routes[0]
    idx = primary.get("InterfaceIndex")
    ps2 = (
        f"Get-NetAdapter -InterfaceIndex {idx} -ErrorAction SilentlyContinue | "
        "Select-Object Name,InterfaceDescription,Status | ConvertTo-Json -Compress"
    )
    code, out2, _ = run(f'powershell -NoProfile -Command "{ps2}"')
    name = desc = "未知"
    if out2.strip():
        try:
            ad = json.loads(out2)
            name = ad.get("Name", "未知")
            desc = ad.get("InterfaceDescription", "未知")
        except Exception:
            pass
    print(f"    默认接口：{name}    下一跳：{primary.get('NextHop')}")
    print(f"    网卡描述：{desc}")
    if VIRTUAL_KEYWORDS.search(desc or "") or VIRTUAL_KEYWORDS.search(name or ""):
        bad("默认路由走虚拟网卡 —— 典型的加速器/VPN 接管网络")
    else:
        ok("默认路由走物理网卡（正常）")


def check_win_adapters():
    section("6. 虚拟网卡 (TAP/TUN/WireGuard/OpenVPN)")
    ps = (
        "Get-NetAdapter -ErrorAction SilentlyContinue | "
        "Select-Object Name,InterfaceDescription,Status | ConvertTo-Json -Compress"
    )
    code, out, _ = run(f'powershell -NoProfile -Command "{ps}"')
    adapters = []
    if out.strip():
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            adapters = data
        except Exception:
            pass
    virtual = [
        a for a in adapters
        if VIRTUAL_KEYWORDS.search(a.get("InterfaceDescription", "") or "")
        or VIRTUAL_KEYWORDS.search(a.get("Name", "") or "")
    ]
    if not virtual:
        ok("没有发现虚拟网卡")
        return
    up = [a for a in virtual if a.get("Status") == "Up"]
    if up:
        wn("以下虚拟网卡处于启用状态：")
        for a in up:
            print(f"    {a.get('Name')} - {a.get('InterfaceDescription')} [{a.get('Status')}]")
    else:
        ok("虚拟网卡存在但未启用：")
        for a in virtual:
            print(f"    {a.get('Name')} - {a.get('InterfaceDescription')} [{a.get('Status')}]")


def check_win_dns():
    section("7. DNS")
    ps = (
        "Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.ServerAddresses.Count -gt 0 } | "
        "Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress"
    )
    code, out, _ = run(f'powershell -NoProfile -Command "{ps}"')
    items = []
    if out.strip():
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            items = data
        except Exception:
            pass
    if not items:
        wn("没有检测到 DNS 设置")
        return
    bad_flag = False
    for d in items:
        alias = d.get("InterfaceAlias", "?")
        addrs = d.get("ServerAddresses") or []
        if isinstance(addrs, str):
            addrs = [addrs]
        joined = ", ".join(addrs)
        print(f"    [{alias}] {joined}")
        for a in addrs:
            if a.startswith("127.0.0.1") or a.startswith("198.18.") or a == "0.0.0.0":
                bad_flag = True
    if bad_flag:
        bad("DNS 指向本地/保留地址 —— 加速器/DNS 代理可能正在接管")
    else:
        ok("DNS 看起来是正常的地址")


PROXY_PORTS = [7890, 7891, 7897, 1080, 1087, 10808, 10809,
               8888, 9090, 8080, 8118, 6152, 6153, 20171, 20172]


def check_win_ports():
    section("8. 常见代理端口监听")
    ps = (
        "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
        "Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress"
    )
    code, out, _ = run(f'powershell -NoProfile -Command "{ps}"')
    items = []
    if out.strip():
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            items = data
        except Exception:
            pass
    listening = [x for x in items if x.get("LocalPort") in PROXY_PORTS]
    if not listening:
        ok("没有常见代理端口在监听")
        return
    bad("检测到代理端口在监听：")
    for x in listening:
        pid = x.get("OwningProcess")
        pname = "?"
        ps2 = f"(Get-Process -Id {pid} -ErrorAction SilentlyContinue).ProcessName"
        _, out2, _ = run(f'powershell -NoProfile -Command "{ps2}"')
        if out2.strip():
            pname = out2.strip()
        print(f"    {x.get('LocalAddress')}:{x.get('LocalPort')}  PID={pid}  {pname}")


PROC_PATTERN = re.compile(
    r"clash|mihomo|surge|v2ray|xray|sing-box|trojan|shadowsocks|ss-local|"
    r"ssr|quantumult|stash|loon|tun2socks|gost|hysteria|naive|tuic|"
    r"wireguard|openvpn|tailscale|zerotier|迅游|腾讯加速器|雷神加速|"
    r"uu加速|uubooster|加速器|proxifier|netch",
    re.IGNORECASE,
)


def check_win_processes():
    section("9. 加速器/VPN 相关进程")
    ps = (
        "Get-Process -ErrorAction SilentlyContinue | "
        "Select-Object Id,ProcessName,Path | ConvertTo-Json -Compress"
    )
    code, out, _ = run(f'powershell -NoProfile -Command "{ps}"')
    items = []
    if out.strip():
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            items = data
        except Exception:
            pass
    hits = []
    for p in items:
        name = p.get("ProcessName", "")
        path = p.get("Path", "") or ""
        if PROC_PATTERN.search(name) or PROC_PATTERN.search(path):
            hits.append(p)
    if not hits:
        ok("没有发现加速器/VPN 相关进程")
    else:
        wn("发现以下相关进程：")
        for p in hits:
            print(f"    PID {p.get('Id')}  {p.get('ProcessName')}")


def check_win_hosts():
    section("10. hosts 文件")
    hosts = Path(os.environ.get("SystemRoot", r"C:\Windows")) / \
        "System32" / "drivers" / "etc" / "hosts"
    if not hosts.exists():
        wn("找不到 hosts 文件")
        return
    try:
        lines = hosts.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception as e:
        wn(f"读取 hosts 失败：{e}")
        return
    extras = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if re.match(r"^127\.0\.0\.1\s+localhost", s):
            continue
        if re.match(r"^::1\s+localhost", s):
            continue
        if re.match(r"^255\.255\.255\.255\s+broadcasthost", s):
            continue
        extras.append(s)
    if not extras:
        ok("hosts 只有默认条目")
    else:
        wn("hosts 里有额外条目：")
        for e in extras:
            print(f"    {e}")


def check_win_startup():
    section("11. 启动项（Run 键）")
    try:
        import winreg
        found = []
        for hive, path in [
            (winreg.HKEY_CURRENT_USER,
             r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ]:
            try:
                key = winreg.OpenKey(hive, path)
            except FileNotFoundError:
                continue
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                except OSError:
                    break
                i += 1
                if PROC_PATTERN.search(name) or PROC_PATTERN.search(str(value)):
                    found.append(f"{path}\\{name} = {value}")
            winreg.CloseKey(key)
        if not found:
            ok("启动项里没有加速器/VPN 相关条目")
        else:
            wn("启动项里发现相关条目：")
            for f in found:
                print(f"    {f}")
    except Exception as e:
        wn(f"读取启动项失败：{e}")


# ============================================================
# macOS 检测（简要）
# ============================================================

def check_mac_system_proxy():
    global HAS_SYSTEM_PROXY, PROXY_SERVICES
    section("1. 系统代理")
    _, out, _ = run("scutil --proxy")
    if re.search(r"HTTPEnable\s*:\s*1|HTTPSEnable\s*:\s*1|SOCKSEnable\s*:\s*1", out):
        HAS_SYSTEM_PROXY = True
        bad("检测到系统代理开启")
        for line in out.splitlines():
            print(f"    {line}")
    else:
        ok("系统代理未开启")

    section("2. 各网络服务代理")
    _, svcs, _ = run("networksetup -listallnetworkservices")
    found = False
    for svc in svcs.splitlines()[1:]:
        svc = svc.strip().lstrip("*")
        if not svc:
            continue
        for t in ["webproxy", "securewebproxy", "socksfirewallproxy"]:
            _, o, _ = run(f'networksetup -get{t} "{svc}"')
            if "Enabled: Yes" in o:
                bad(f"服务 [{svc}] 的 {t} 已开启")
                for line in o.splitlines():
                    print(f"    {line}")
                PROXY_SERVICES.append(svc)
                found = True
    if not found:
        ok("所有网络服务的代理均为关闭状态")


def check_mac_vpn():
    section("3. VPN 配置")
    _, out, _ = run("scutil --nc list")
    lines = [l for l in out.splitlines()
             if l.strip() and "Available network" not in l]
    if not lines:
        ok("没有任何 VPN 配置")
    elif any("(Connected)" in l for l in lines):
        bad("有 VPN 处于已连接状态：")
        for l in lines:
            print(f"    {l}")
    else:
        wn("存在 VPN 配置（当前未连接）：")
        for l in lines:
            print(f"    {l}")


def check_mac_route():
    section("4. 默认路由")
    _, out, _ = run("route -n get default")
    m_if = re.search(r"interface:\s*(\S+)", out)
    m_gw = re.search(r"gateway:\s*(\S+)", out)
    if not m_if:
        bad("没有默认路由")
        return
    iface = m_if.group(1)
    gw = m_gw.group(1) if m_gw else "无"
    print(f"    默认接口：{iface}    网关：{gw}")
    if re.match(r"utun|tun|tap|ppp|ipsec", iface):
        bad(f"默认路由走虚拟接口 {iface}")
    elif re.match(r"en|bridge", iface):
        ok(f"默认路由走物理接口 {iface}（正常）")
    else:
        wn(f"默认路由走未知接口 {iface}")


def check_mac_vif():
    section("5. 虚拟接口")
    _, out, _ = run("ifconfig")
    vifs = re.findall(r"^(utun\d+|tun\d+|tap\d+|ppp\d+|ipsec\d+):",
                      out, re.MULTILINE)
    if not vifs:
        ok("没有虚拟接口")
        return
    has_ipv4 = False
    for v in vifs:
        _, o, _ = run(f"ifconfig {v}")
        if "inet " in o:
            has_ipv4 = True
            bad(f"{v} 上有 IPv4 地址（很可能是加速器/VPN）")
            for line in o.splitlines():
                if "inet " in line:
                    print(f"    {line.strip()}")
    if not has_ipv4:
        ok("虚拟接口存在，但只有 IPv6 link-local（系统自带）")
        print(f"    {' '.join(vifs)}")


def check_mac_dns():
    section("6. DNS")
    _, out, _ = run("scutil --dns")
    m = re.search(r"nameserver\[0\]\s*:\s*(\S+)", out)
    ns = m.group(1) if m else "未检测到"
    print(f"    主 DNS：{ns}")
    if ns.startswith("127.0.0.1"):
        bad("DNS 指向 127.0.0.1")
    elif ns.startswith("198.18."):
        bad("DNS 落在 198.18.0.0/15")
    else:
        ok("DNS 看起来正常")


def check_mac_ports():
    section("7. 常见代理端口监听")
    code, out, _ = run("lsof -nP -iTCP -sTCP:LISTEN")
    pat = re.compile(r":(" + "|".join(str(p) for p in PROXY_PORTS) + r")\b")
    hits = [l for l in out.splitlines() if pat.search(l)]
    if not hits:
        ok("没有常见代理端口在监听")
    else:
        bad("检测到代理端口在监听：")
        for h in hits:
            print(f"    {h}")


def check_mac_processes():
    section("8. 加速器/VPN 相关进程")
    _, out, _ = run("ps aux")
    hits = [l for l in out.splitlines() if PROC_PATTERN.search(l)]
    if not hits:
        ok("没有发现加速器/VPN 相关进程")
    else:
        wn("发现以下相关进程：")
        for l in hits:
            parts = l.split(None, 10)
            if len(parts) > 10:
                print(f"    PID {parts[1]}  {parts[10][:80]}")


def check_mac_hosts():
    section("9. /etc/hosts")
    p = Path("/etc/hosts")
    if not p.exists():
        wn("找不到 /etc/hosts")
        return
    try:
        lines = p.read_text(errors="ignore").splitlines()
    except Exception as e:
        wn(f"读取失败：{e}")
        return
    extras = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if re.match(r"^127\.0\.0\.1\s+localhost", s):
            continue
        if re.match(r"^255\.255\.255\.255\s+broadcasthost", s):
            continue
        if re.match(r"^::1\s+localhost", s):
            continue
        extras.append(s)
    if not extras:
        ok("/etc/hosts 只有默认条目")
    else:
        wn("/etc/hosts 里有额外条目：")
        for e in extras:
            print(f"    {e}")


# ============================================================
# 统一入口
# ============================================================

def run_check():
    global PASS, WARN, FAIL, HAS_SYSTEM_PROXY, PROXY_SERVICES
    PASS = WARN = FAIL = 0
    HAS_SYSTEM_PROXY = False
    PROXY_SERVICES = []

    os.system("cls" if IS_WIN else "clear")
    print("=" * 50)
    print("  NetworkCheck - 网络检查（加速器/VPN/代理残留）")
    print(f"  平台：{platform.system()} {platform.release()}")
    print(f"  时间：{time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)
    print()
    print("提示：检测只读，不改任何东西。修复需你确认。")

    if IS_WIN:
        check_win_system_proxy()
        check_win_winhttp()
        check_win_env_proxy()
        check_win_vpn()
        check_win_route()
        check_win_adapters()
        check_win_dns()
        check_win_ports()
        check_win_processes()
        check_win_hosts()
        check_win_startup()
    elif IS_MAC:
        check_mac_system_proxy()
        check_mac_vpn()
        check_mac_route()
        check_mac_vif()
        check_mac_dns()
        check_mac_ports()
        check_mac_processes()
        check_mac_hosts()
    else:
        bad("暂不支持该平台")
        return

    print()
    print("=" * 50)
    print(f" 检测完成：OK {PASS} 项   WARN {WARN} 项   FAIL {FAIL} 项")
    print("=" * 50)
    if FAIL > 0:
        print()
        print(f"{RED}结论：检测到疑似加速器/VPN/代理残留，可尝试修复。{RESET}")
    elif WARN > 0:
        print()
        print(f"{YELLOW}结论：未发现严重残留，但有几项提醒。{RESET}")
    else:
        print()
        print(f"{GREEN}结论：网络配置干净，未发现残留。{RESET}")


# ============================================================
# 修复
# ============================================================

def do_fix():
    os.system("cls" if IS_WIN else "clear")
    print("=" * 50)
    print("  修复预览（尚未执行）")
    print("=" * 50)
    print()

    if IS_WIN:
        if not HAS_SYSTEM_PROXY:
            print("本次检测没有发现可自动修复的代理残留。")
            print()
            print("如果你仍然遇到网络问题，可以手动检查：")
            print("  - 完全退出加速器（含托盘图标）")
            print("  - 浏览器扩展（SwitchyOmega / Proxy Switchy 之类）")
            print("  - App 内部代理（Telegram、Steam、Docker 等）")
            print("  - 重启电脑，清掉 TUN/路由残留")
            print()
            input("按回车返回菜单...")
            return

        admin = is_admin()
        print("将要执行以下动作：")
        print()
        print("  1) 关闭系统代理（ProxyEnable -> 0）")
        print("  2) 清除 ProxyServer")
        print("  3) 清除 AutoConfigURL")
        print("  4) 重置 WinHTTP 代理（netsh winhttp reset proxy）")
        print("  5) 通知系统刷新代理设置")
        print()
        print("说明：")
        print("  - 只关闭代理开关。不动 DNS、路由、hosts、扩展、进程。")
        print("  - 可逆：需要时在加速器里重新开启即可。")
        if not admin:
            print()
            print(f"{YELLOW}  注意：当前不是管理员，第 4 步会失败。{RESET}")
            print(f"{YELLOW}  前 3 步不需要管理员，仍会执行。{RESET}")
        print()
        ans = input("确认执行？(y/N): ").strip()
        if ans.lower() != "y":
            print()
            print("已取消，未做任何修改。")
            input("按回车返回菜单...")
            return

        print()
        print("开始执行...")
        print()
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                0, winreg.KEY_ALL_ACCESS,
            )
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            print(f"{GREEN}[OK]{RESET} 已关闭系统代理（ProxyEnable = 0）")
            for name in ["ProxyServer", "AutoConfigURL"]:
                try:
                    winreg.DeleteValue(key, name)
                    print(f"{GREEN}[OK]{RESET} 已清除 {name}")
                except FileNotFoundError:
                    pass
                except Exception as e:
                    print(f"{YELLOW}[WARN]{RESET} 清除 {name} 失败：{e}")
            winreg.CloseKey(key)
        except Exception as e:
            print(f"{RED}[FAIL]{RESET} 修改注册表失败：{e}")

        print()
        if admin:
            code, out, err = run("netsh winhttp reset proxy")
            if code == 0:
                print(f"{GREEN}[OK]{RESET} 已重置 WinHTTP 代理")
            else:
                print(f"{RED}[FAIL]{RESET} WinHTTP 重置失败：{err or out}")
        else:
            print(f"{YELLOW}[SKIP]{RESET} 跳过 WinHTTP 重置（需要管理员权限）")

        print()
        try:
            import ctypes
            wininet = ctypes.WinDLL("wininet.dll")
            wininet.InternetSetOptionW(0, 39, 0, 0)  # SETTINGS_CHANGED
            wininet.InternetSetOptionW(0, 37, 0, 0)  # REFRESH
            print(f"{GREEN}[OK]{RESET} 已通知系统刷新代理设置")
        except Exception as e:
            print(f"{YELLOW}[WARN]{RESET} 通知系统刷新失败：{e}")

    elif IS_MAC:
        svcs = []
        for s in PROXY_SERVICES:
            if s not in svcs:
                svcs.append(s)
        if not svcs:
            print("本次检测没有发现可自动修复的代理残留。")
            print()
            input("按回车返回菜单...")
            return

        print("将要执行以下动作：")
        print()
        cmds = []
        for s in svcs:
            cmds.append(f'sudo networksetup -setwebproxystate "{s}" off')
            cmds.append(f'sudo networksetup -setsecurewebproxystate "{s}" off')
            cmds.append(f'sudo networksetup -setsocksfirewallproxystate "{s}" off')
        for c in cmds:
            print(f"  {c}")
        print()
        print("说明：")
        print("  - 只关闭代理开关。不动 DNS、路由、hosts、扩展、进程。")
        print()
        ans = input("确认执行？(y/N): ").strip()
        if ans.lower() != "y":
            print()
            print("已取消，未做任何修改。")
            input("按回车返回菜单...")
            return

        print()
        for s in svcs:
            for t in ["webproxystate", "securewebproxystate", "socksfirewallproxystate"]:
                code, _, err = run(
                    f'networksetup -set{t} "{s}" off', shell=True
                )
                # 需要 sudo，改用 os.system 直接提权
        print("提示：macOS 修复需要 sudo 密码。")
        for s in svcs:
            print(f"→ 服务: {s}")
            os.system(f'networksetup -setwebproxystate "{s}" off')
            os.system(f'networksetup -setsecurewebproxystate "{s}" off')
            os.system(f'networksetup -setsocksfirewallproxystate "{s}" off')

    else:
        print("该平台暂不支持修复。")

    print()
    print("修复完成。")
    print()
    input("按回车返回菜单（将重新检测）...")


# ============================================================
# 主循环
# ============================================================

def main():
    while True:
        run_check()
        print()
        print("-" * 50)
        print(" 请选择操作：")
        print("   1) 再次检测")
        print("   2) 修复（先展示动作，确认后才执行）")
        print("   3) 退出")
        print("-" * 50)
        try:
            choice = input("请选择 [1/2/3]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n已退出。")
            sys.exit(0)

        if choice == "1":
            continue
        elif choice == "2":
            do_fix()
        elif choice == "3":
            print("已退出。")
            sys.exit(0)
        else:
            print("无效选择，请重新输入。")
            time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n已退出。")
        sys.exit(0)