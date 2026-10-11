#!/usr/bin/env bash
# macOS 网络检查 + 确认式修复
# 检测只读；修复只关代理，且必须先确认

RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"
CYAN="\033[1;36m"; RESET="\033[0m"

have() { command -v "$1" >/dev/null 2>&1; }
section() { printf "\n${CYAN}──────── %s ────────${RESET}\n" "$1"; }

PASS=0; WARN=0; FAIL=0
ok()  { printf "${GREEN}✅ %s${RESET}\n" "$1"; PASS=$((PASS+1)); }
wn()  { printf "${YELLOW}⚠️  %s${RESET}\n" "$1"; WARN=$((WARN+1)); }
bad() { printf "${RED}❌ %s${RESET}\n" "$1"; FAIL=$((FAIL+1)); }

SERVICES_WITH_PROXY=""

run_check() {
  PASS=0; WARN=0; FAIL=0
  SERVICES_WITH_PROXY=""

  clear
  echo "================================================"
  echo "  macOS 网络检查（加速器/VPN/代理残留）"
  echo "  时间：$(date)"
  echo "================================================"
  echo
  echo "提示：检测只读，不改任何东西。修复需你确认。"

  # 1 系统代理
  section "1. 系统代理"
  local proxy_out
  proxy_out="$(scutil --proxy 2>/dev/null || true)"
  if echo "$proxy_out" | grep -qE 'HTTPEnable *: *1|HTTPSEnable *: *1|SOCKSEnable *: *1'; then
    bad "检测到系统代理开启（HTTP/HTTPS/SOCKS 至少一个为 1）"
    echo "$proxy_out" | sed 's/^/    /'
  else
    ok "系统代理未开启（无 HTTP/HTTPS/SOCKS 代理）"
  fi

  # 2 各服务代理
  section "2. 各网络服务代理"
  if have networksetup; then
    local found=0
    while IFS= read -r svc; do
      [ -z "$svc" ] && continue
      svc="${svc#\*}"
      for t in webproxy securewebproxy socksfirewallproxy; do
        out="$(networksetup -get${t} "$svc" 2>/dev/null || true)"
        if echo "$out" | grep -q 'Enabled: Yes'; then
          printf "${RED}❌ 服务 [%s] 的 %s 已开启${RESET}\n" "$svc" "$t"
          echo "$out" | sed 's/^/    /'
          SERVICES_WITH_PROXY="${SERVICES_WITH_PROXY}${svc}"$'\n'
          found=1
        fi
      done
    done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)
    if [ "$found" = "0" ]; then
      ok "所有网络服务的代理均为关闭状态"
    fi
  fi

  # 3 VPN
  section "3. VPN 配置"
  local vpn_lines
  vpn_lines="$(scutil --nc list 2>/dev/null | grep -E '\*|\(Connected\)|\(Disconnected\)' | grep -v 'Available network' || true)"
  if [ -z "$vpn_lines" ]; then
    ok "没有任何 VPN 配置"
  elif echo "$vpn_lines" | grep -q '(Connected)'; then
    bad "有 VPN 处于已连接状态："
    echo "$vpn_lines" | sed 's/^/    /'
  else
    wn "存在 VPN 配置（当前未连接）："
    echo "$vpn_lines" | sed 's/^/    /'
  fi

  # 4 默认路由
  section "4. 默认路由"
  local def_if def_gw
  def_if="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
  def_gw="$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}')"
  if [ -z "${def_if:-}" ]; then
    bad "没有默认路由（可能断网或加速器抢了路由）"
  else
    echo "    默认接口：$def_if    网关：${def_gw:-无}"
    case "$def_if" in
      utun*|tun*|tap*|ppp*|ipsec*)
        bad "默认路由走虚拟接口 $def_if —— 典型的加速器/VPN 接管网络" ;;
      en*|bridge*)
        ok "默认路由走物理接口 $def_if（正常）" ;;
      *)
        wn "默认路由走未知接口 $def_if，建议人工看一眼" ;;
    esac
  fi

  # 5 虚拟接口
  section "5. 虚拟接口 (utun/tun/tap/ppp)"
  local vif
  vif="$(ifconfig 2>/dev/null | grep -E '^(utun|tun|tap|ppp|ipsec)' | awk -F: '{print $1}')"
  if [ -z "${vif:-}" ]; then
    ok "没有虚拟接口"
  else
    local has_ipv4=0
    for i in $vif; do
      if ifconfig "$i" 2>/dev/null | grep -q 'inet '; then
        has_ipv4=1
        printf "${RED}❌ %s 上有 IPv4 地址（很可能是加速器/VPN 的接口）${RESET}\n" "$i"
        ifconfig "$i" 2>/dev/null | grep 'inet ' | sed 's/^/    /'
      fi
    done
    if [ "$has_ipv4" = "0" ]; then
      ok "虚拟接口存在，但只有 IPv6 link-local（系统自带，非加速器）"
      echo "    $vif" | sed 's/^/    /'
    fi
  fi

  # 6 DNS
  section "6. DNS"
  local dns_out ns
  dns_out="$(scutil --dns 2>/dev/null || true)"
  ns="$(echo "$dns_out" | grep -E 'nameserver\[0\]' | head -n 1 | awk '{print $3}')"
  echo "    主 DNS：${ns:-未检测到}"
  if echo "$dns_out" | grep -qE 'nameserver\[0\] : 127\.0\.0\.1'; then
    bad "DNS 指向 127.0.0.1 —— 加速器/DNS 代理正在接管"
  elif echo "$dns_out" | grep -qE 'nameserver\[0\] : 198\.18\.'; then
    bad "DNS 落在 198.18.0.0/15 —— Clash/Surge 之类工具的 fake-ip 段"
  else
    ok "DNS 看起来是正常的下发地址"
  fi

  # 7 代理端口
  section "7. 常见代理端口监听"
  if have lsof; then
    local port_out
    port_out="$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | grep -E ':(7890|7891|7897|1080|1087|10808|10809|8888|9090|8080|8118|6152|6153|20171|20172)\b' || true)"
    if [ -z "$port_out" ]; then
      ok "没有常见代理端口在监听"
    else
      bad "检测到代理端口在监听："
      echo "$port_out" | sed 's/^/    /'
    fi
  else
    wn "没有 lsof，跳过端口检查"
  fi

  # 8 进程
  section "8. 加速器/VPN 相关进程"
  local ps_out
  ps_out="$(ps aux 2>/dev/null | grep -Ei 'clash|mihomo|surge|v2ray|xray|sing-box|trojan|shadowsocks|ss-local|ssr|quantumult|stash|loon|tun2socks|gost|hysteria|naive|tuic|wireguard|openvpn|tailscale|zerotier|迅游|xunyou|qiyou|奇游|腾讯加速器|雷神加速|uu加速|uumac|uubooster|加速器' | grep -v grep || true)"
  if [ -z "$ps_out" ]; then
    ok "没有发现加速器/VPN 相关进程"
  else
    wn "发现以下相关进程（在跑不代表有问题）："
    echo "$ps_out" | awk '{printf "    PID %-7s %s\n", $2, $11" "$12" "$13}' | sort -u
  fi

  # 9 网易UU
  section "9. 网易 UU 守护项"
  local uu
  uu="$(ls /Library/LaunchDaemons /Library/LaunchAgents "$HOME/Library/LaunchAgents" 2>/dev/null | grep -iE 'netease|uu(mac|remote|booster)' || true)"
  if [ -z "$uu" ]; then
    ok "没有发现网易 UU 相关守护项"
  else
    wn "发现网易 UU 相关 plist（装了但未必在跑）："
    echo "$uu" | sed 's/^/    /'
  fi

  # 10 hosts
  section "10. /etc/hosts"
  local hosts_extra
  hosts_extra="$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/hosts 2>/dev/null | grep -vE '^\s*(127\.0\.0\.1|255\.255\.255\.255|::1|fe80::1%lo0)\s+(localhost|broadcasthost|ip6-localhost|ip6-loopback)' || true)"
  if [ -z "$hosts_extra" ]; then
    ok "/etc/hosts 只有系统默认条目"
  else
    wn "/etc/hosts 里有额外条目："
    echo "$hosts_extra" | sed 's/^/    /'
  fi

  # 11 扩展
  section "11. 系统扩展 / 网络扩展"
  local ext ne
  ext="$(systemextensionsctl list 2>/dev/null | grep -E '^\s*[0-9]+ extension' | head -n1)"
  ne="$(pluginkit -m -p com.apple.networkextension 2>/dev/null || true)"
  if echo "$ext" | grep -q '^0 extension'; then
    ok "没有第三方系统扩展"
  else
    wn "存在系统扩展：${ext:-未知}"
  fi
  if [ -z "$ne" ]; then
    ok "没有网络扩展插件"
  else
    wn "存在网络扩展插件："
    echo "$ne" | sed 's/^/    /'
  fi

  echo
  echo "================================================"
  printf " 检测完成：${GREEN}✅ %d 项通过${RESET}   ${YELLOW}⚠️  %d 项提醒${RESET}   ${RED}❌ %d 项异常${RESET}\n" "$PASS" "$WARN" "$FAIL"
  echo "================================================"
  if [ "$FAIL" -gt 0 ]; then
    echo
    echo "👉 结论：检测到疑似加速器/VPN/代理残留，可尝试修复。"
  elif [ "$WARN" -gt 0 ]; then
    echo
    echo "👉 结论：未发现严重残留，但有几项提醒。"
  else
    echo
    echo "👉 结论：网络配置干净，未发现残留。"
  fi
}

do_fix() {
  clear
  echo "================================================"
  echo "  修复预览（尚未执行）"
  echo "================================================"
  echo

  # 解析要修复的服务
  local -a svc_list=()
  if [ -n "$SERVICES_WITH_PROXY" ]; then
    while IFS= read -r s; do
      [ -z "$s" ] && continue
      local dup=0
      for x in "${svc_list[@]:-}"; do
        [ "$x" = "$s" ] && dup=1 && break
      done
      [ "$dup" = "0" ] && svc_list+=("$s")
    done <<< "$SERVICES_WITH_PROXY"
  fi

  if [ ${#svc_list[@]} -eq 0 ]; then
    echo "本次检测没有发现可自动修复的代理残留。"
    echo
    echo "如果你仍然遇到网络问题，可以手动检查："
    echo "  - 完全退出加速器（含菜单栏图标）"
    echo "  - 浏览器扩展（SwitchyOmega / Proxy Switchy 之类）"
    echo "  - App 内部代理（Telegram、Steam、Docker 等）"
    echo "  - 重启 Mac，清掉 TUN/路由残留"
    echo
    read -n 1 -s -r -p "按任意键返回菜单..."
    return
  fi

  echo "将要执行以下动作："
  echo
  local i=1
  for s in "${svc_list[@]}"; do
    echo "  $i) 关闭网络服务 [$s] 的 Web 代理"
    i=$((i+1))
    echo "  $i) 关闭网络服务 [$s] 的 HTTPS 代理"
    i=$((i+1))
    echo "  $i) 关闭网络服务 [$s] 的 SOCKS 代理"
    i=$((i+1))
  done
  echo
  echo "对应命令（需要管理员密码）："
  echo
  for s in "${svc_list[@]}"; do
    echo "  sudo networksetup -setwebproxystate \"$s\" off"
    echo "  sudo networksetup -setsecurewebproxystate \"$s\" off"
    echo "  sudo networksetup -setsocksfirewallproxystate \"$s\" off"
  done
  echo
  echo "说明："
  echo "  - 只关闭代理开关。不动 DNS、路由、hosts、扩展、进程。"
  echo "  - 可逆：下次需要时在加速器里重新开启即可。"
  echo

  local ans
  read -rp "确认执行？(y/N): " ans
  if [[ ! "$ans" =~ ^[Yy]$ ]]; then
    echo
    echo "已取消，未做任何修改。"
    read -n 1 -s -r -p "按任意键返回菜单..."
    return
  fi

  echo
  echo "需要管理员权限，请输入密码："
  if ! sudo -v; then
    echo
    echo "❌ 获取管理员权限失败，已取消。"
    read -n 1 -s -r -p "按任意键返回菜单..."
    return
  fi

  echo
  echo "开始执行..."
  echo
  for s in "${svc_list[@]}"; do
    echo "→ 服务: $s"
    sudo networksetup -setwebproxystate "$s" off 2>/dev/null && echo "  ✅ Web 代理已关闭" || echo "  ❌ Web 代理关闭失败"
    sudo networksetup -setsecurewebproxystate "$s" off 2>/dev/null && echo "  ✅ HTTPS 代理已关闭" || echo "  ❌ HTTPS 代理关闭失败"
    sudo networksetup -setsocksfirewallproxystate "$s" off 2>/dev/null && echo "  ✅ SOCKS 代理已关闭" || echo "  ❌ SOCKS 代理关闭失败"
    echo
  done

  echo "修复完成。"
  echo
  read -n 1 -s -r -p "按任意键返回菜单（将重新检测）..."
}

show_menu() {
  echo
  echo "────────────────────────────────────────────────"
  echo " 请选择操作："
  echo "   1) 再次检测"
  echo "   2) 修复（先展示动作，确认后才执行）"
  echo "   3) 退出"
  echo "────────────────────────────────────────────────"
}

while true; do
  run_check
  show_menu
  read -rp "请选择 [1/2/3]: " choice
  case "$choice" in
    1) continue ;;
    2) do_fix ;;
    3) echo "已退出。"; exit 0 ;;
    *) echo "无效选择，请重新输入。"; sleep 1 ;;
  esac
done
