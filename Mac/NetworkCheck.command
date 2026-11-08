#!/usr/bin/env bash
RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"
CYAN="\033[1;36m"; RESET="\033[0m"

have() { command -v "$1" >/dev/null 2>&1; }
section() { printf "\n${CYAN}──────── %s ────────${RESET}\n" "$1"; }

PASS=0; WARN=0; FAIL=0
ok()  { printf "${GREEN}✅ %s${RESET}\n" "$1"; PASS=$((PASS+1)); }
wn()  { printf "${YELLOW}⚠️  %s${RESET}\n" "$1"; WARN=$((WARN+1)); }
bad() { printf "${RED}❌ %s${RESET}\n" "$1"; FAIL=$((FAIL+1)); }

SERVICES_WITH_PROXY=""
PROXY_PIDS=""

PROXY_PATTERN='clash|mihomo|surge|v2ray|xray|sing-box|trojan|shadowsocks|ss-local|quantumult|stash|loon|tun2socks|gost|hysteria|naive|tuic|wireguard|openvpn|tailscale|zerotier|迅游|xunyou|qiyou|奇游|腾讯加速器|雷神加速|uu加速|uumac|uubooster|proxifier|netch'
SYSTEM_PATH_RE='/System/|/usr/|/sbin/|/bin/|/Library/Apple/'

run_check() {
  PASS=0; WARN=0; FAIL=0
  SERVICES_WITH_PROXY=""
  PROXY_PIDS=""

  clear
  echo "================================================"
  echo "  macOS 网络检查（加速器/VPN/代理）"
  echo "  时间：$(date)"
  echo "================================================"
  echo
  echo "提示：检测只读。修复会关闭代理并终止加速器进程。"

  section "1. 系统代理"
  local proxy_out
  proxy_out="$(scutil --proxy 2>/dev/null || true)"
  if echo "$proxy_out" | grep -qE 'HTTPEnable *: *1|HTTPSEnable *: *1|SOCKSEnable *: *1'; then
    bad "系统代理已开启"
    echo "$proxy_out" | sed 's/^/    /'
  else
    ok "系统代理未开启"
  fi

  section "2. 各网络服务代理"
  if have networksetup; then
    local found=0
    while IFS= read -r svc; do
      [ -z "$svc" ] && continue
      svc="${svc#\*}"
      for t in webproxy securewebproxy socksfirewallproxy; do
        out="$(networksetup -get${t} "$svc" 2>/dev/null || true)"
        if echo "$out" | grep -q 'Enabled: Yes'; then
          bad "服务 [$svc] 的 $t 已开启"
          echo "$out" | sed 's/^/    /'
          SERVICES_WITH_PROXY="${SERVICES_WITH_PROXY}${svc}"$'\n'
          found=1
        fi
      done
    done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)
    [ "$found" = "0" ] && ok "所有网络服务的代理均为关闭状态"
  fi

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

  section "4. 默认路由"
  local def_if def_gw
  def_if="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
  def_gw="$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}')"
  if [ -z "${def_if:-}" ]; then
    bad "没有默认路由"
  else
    echo "    默认接口：$def_if    网关：${def_gw:-无}"
    case "$def_if" in
      utun*|tun*|tap*|ppp*|ipsec*) bad "默认路由走虚拟接口 $def_if" ;;
      en*|bridge*) ok "默认路由走物理接口 $def_if" ;;
      *) wn "默认路由走未知接口 $def_if" ;;
    esac
  fi

  section "5. 虚拟接口"
  local vif
  vif="$(ifconfig 2>/dev/null | grep -E '^(utun|tun|tap|ppp|ipsec)' | awk -F: '{print $1}')"
  if [ -z "${vif:-}" ]; then
    ok "没有虚拟接口"
  else
    local has_ipv4=0
    for i in $vif; do
      if ifconfig "$i" 2>/dev/null | grep -q 'inet '; then
        has_ipv4=1
        bad "$i 上有 IPv4 地址"
        ifconfig "$i" 2>/dev/null | grep 'inet ' | sed 's/^/    /'
      fi
    done
    [ "$has_ipv4" = "0" ] && { ok "虚拟接口只有 IPv6 link-local（系统自带）"; echo "    $vif" | sed 's/^/    /'; }
  fi

  section "6. DNS"
  local dns_out ns
  dns_out="$(scutil --dns 2>/dev/null || true)"
  ns="$(echo "$dns_out" | grep -E 'nameserver\[0\]' | head -n 1 | awk '{print $3}')"
  echo "    主 DNS：${ns:-未检测到}"
  if echo "$dns_out" | grep -qE 'nameserver\[0\] : 127\.0\.0\.1'; then
    bad "DNS 指向 127.0.0.1"
  elif echo "$dns_out" | grep -qE 'nameserver\[0\] : 198\.18\.'; then
    bad "DNS 落在 198.18.0.0/15（fake-ip）"
  else
    ok "DNS 正常"
  fi

  section "7. 代理端口监听"
  if have lsof; then
    local port_out
    port_out="$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | grep -E ':(7890|7891|7897|1080|1087|10808|10809|8888|9090|8080|8118|6152|6153|20171|20172)\b' || true)"
    if [ -z "$port_out" ]; then
      ok "没有常见代理端口在监听"
    else
      bad "检测到常见代理端口在监听："
      echo "$port_out" | sed 's/^/    /'
    fi
  else
    wn "没有 lsof，跳过端口检查"
  fi

  section "8. 加速器/代理进程"
  local ps_out
  ps_out="$(ps -axo pid=,args= 2>/dev/null | grep -Ei "$PROXY_PATTERN" | grep -Ev "$SYSTEM_PATH_RE" | grep -v grep || true)"
  if [ -z "$ps_out" ]; then
    ok "没有发现加速器/代理进程"
  else
    bad "检测到加速器/代理进程："
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      local pid args
      pid="$(echo "$line" | awk '{print $1}')"
      args="$(echo "$line" | cut -d' ' -f2-)"
      echo "    PID $pid  $args"
      PROXY_PIDS="${PROXY_PIDS}${pid} "
    done <<< "$ps_out"

    # 补充：这些进程监听的任意端口（不只常见端口，不漏自定义端口）
    if have lsof; then
      for pid in $PROXY_PIDS; do
        local pout
        pout="$(lsof -nP -a -p "$pid" -iTCP -sTCP:LISTEN 2>/dev/null || true)"
        if [ -n "$pout" ]; then
          echo "    代理进程 PID $pid 监听："
          echo "$pout" | awk '{print "      " $(NF-1)}' | sort -u
        fi
      done
    fi
  fi

  section "9. 其他可疑进程"
  local other_ps
  other_ps="$(ps -axo pid=,args= 2>/dev/null | grep -Ei 'proxifier|netch' | grep -Ev "$SYSTEM_PATH_RE" | grep -v grep || true)"
  if [ -z "$other_ps" ]; then
    ok "没有其他代理相关进程"
  else
    wn "发现："
    echo "$other_ps" | sed 's/^/    /'
  fi

  section "10. 网易 UU 守护项"
  local uu
  uu="$(ls /Library/LaunchDaemons /Library/LaunchAgents "$HOME/Library/LaunchAgents" 2>/dev/null | grep -iE 'netease|uu(mac|remote|booster)' || true)"
  if [ -z "$uu" ]; then
    ok "没有网易 UU 相关 plist"
  else
    wn "发现网易 UU 相关 plist（未必在跑）："
    echo "$uu" | sed 's/^/    /'
  fi

  section "11. /etc/hosts"
  local hosts_extra
  hosts_extra="$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/hosts 2>/dev/null | grep -vE '^\s*(127\.0\.0\.1|255\.255\.255\.255|::1|fe80::1%lo0)\s+(localhost|broadcasthost|ip6-localhost|ip6-loopback)' || true)"
  if [ -z "$hosts_extra" ]; then
    ok "/etc/hosts 只有系统默认条目"
  else
    wn "/etc/hosts 有额外条目："
    echo "$hosts_extra" | sed 's/^/    /'
  fi

  section "12. 系统扩展 / 网络扩展"
  local ext ne
  ext="$(systemextensionsctl list 2>/dev/null | grep -E '^\s*[0-9]+ extension' | head -n1)"
  ne="$(pluginkit -m -p com.apple.networkextension 2>/dev/null || true)"
  if echo "$ext" | grep -q '^0 extension'; then
    ok "没有第三方系统扩展"
  else
    wn "系统扩展：${ext:-未知}"
  fi
  if [ -z "$ne" ]; then
    ok "没有网络扩展插件"
  else
    wn "网络扩展插件："
    echo "$ne" | sed 's/^/    /'
  fi

  echo
  echo "================================================"
  printf " 检测完成：${GREEN}✅ %d 项通过${RESET}   ${YELLOW}⚠️  %d 项提醒${RESET}   ${RED}❌ %d 项异常${RESET}\n" "$PASS" "$WARN" "$FAIL"
  echo "================================================"
  if [ "$FAIL" -gt 0 ]; then
    echo
    echo "👉 结论：检测到加速器/代理正在运行或存在残留，可执行修复。"
  elif [ "$WARN" -gt 0 ]; then
    echo
    echo "👉 结论：未发现严重残留，但有几项提醒。"
  else
    echo
    echo "👉 结论：网络配置干净。"
  fi
}

do_fix() {
  clear
  echo "================================================"
  echo "  修复预览（尚未执行）"
  echo "================================================"
  echo

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

  local has_procs=0
  [ -n "$PROXY_PIDS" ] && has_procs=1

  if [ ${#svc_list[@]} -eq 0 ] && [ "$has_procs" = "0" ]; then
    echo "本次检测没有发现可修复的代理残留或代理进程。"
    echo
    read -n 1 -s -r -p "按任意键返回菜单..."
    return
  fi

  echo "将要执行以下动作："
  echo

  local step=1
  if [ "$has_procs" = "1" ]; then
    echo "  $step) 终止以下加速器/代理进程："
    step=$((step+1))
    for p in $PROXY_PIDS; do
      local c
      c="$(ps -p "$p" -o args= 2>/dev/null || echo "?")"
      echo "     PID $p  $c"
    done
    echo "     命令：kill $PROXY_PIDS"
    echo
  fi

  for s in "${svc_list[@]}"; do
    echo "  $step) 关闭网络服务 [$s] 的代理"
    step=$((step+1))
  done

  if [ ${#svc_list[@]} -gt 0 ]; then
    echo
    echo "关闭代理的命令（需要管理员密码）："
    for s in "${svc_list[@]}"; do
      echo "  sudo networksetup -setwebproxystate \"$s\" off"
      echo "  sudo networksetup -setsecurewebproxystate \"$s\" off"
      echo "  sudo networksetup -setsocksfirewallproxystate \"$s\" off"
    done
  fi

  echo
  echo "说明："
  echo "  - 会终止所有匹配到的代理/加速器进程（系统进程自动跳过）。"
  echo "  - 未保存的加速器配置可能丢失。"
  echo "  - 可逆：下次需要时重新打开加速器即可。"
  echo

  local ans
  read -rp "确认执行？(y/N): " ans
  if [[ ! "$ans" =~ ^[Yy]$ ]]; then
    echo
    echo "已取消。"
    read -n 1 -s -r -p "按任意键返回菜单..."
    return
  fi

  if [ ${#svc_list[@]} -gt 0 ]; then
    echo
    echo "需要管理员权限："
    if ! sudo -v; then
      echo "❌ 获取管理员权限失败，已取消。"
      read -n 1 -s -r -p "按任意键返回菜单..."
      return
    fi
  fi

  echo
  echo "开始执行..."
  echo

  if [ "$has_procs" = "1" ]; then
    for pid in $PROXY_PIDS; do
      local args
      args="$(ps -p "$pid" -o args= 2>/dev/null || true)"
      if [ -z "$args" ]; then
        echo "  ⏭  PID $pid 已退出"
        continue
      fi
      if echo "$args" | grep -Eq "$SYSTEM_PATH_RE"; then
        echo "  ⏭  PID $pid 是系统进程，跳过"
        continue
      fi
      echo "→ 终止 PID $pid"
      kill "$pid" 2>/dev/null && echo "  ✅ 已终止" || {
        echo "  ⚠️  普通终止失败，尝试强制终止..."
        kill -9 "$pid" 2>/dev/null && echo "  ✅ 已强制终止" || echo "  ❌ 终止失败"
      }
    done
    sleep 1

    local remain=""
    for pid in $PROXY_PIDS; do
      ps -p "$pid" >/dev/null 2>&1 && remain="${remain}${pid} "
    done
    if [ -n "$remain" ]; then
      echo "  仍有进程存活：$remain"
      for pid in $remain; do
        kill -9 "$pid" 2>/dev/null && echo "  ✅ PID $pid 已强制终止" || echo "  ❌ PID $pid 仍无法终止"
      done
    fi
    echo
  fi

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
