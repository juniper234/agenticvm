#!/bin/sh
export DISPLAY=:0 HOME=/workspace XAUTHORITY=/workspace/.Xauthority
export XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
export XDG_CURRENT_DESKTOP=XFCE XDG_SESSION_DESKTOP=xfce XDG_SESSION_TYPE=x11
umask 077
mkdir -p "$HOME/.config/xfce4/xfconf/xfce-perchannel-xml" "$HOME/.config/agenticvm-browser"
cp /etc/agenticvm/browser-user.js "$HOME/.config/agenticvm-browser/user.js"
# Reapply required low-memory settings, preserving unrelated user preferences.
cp /etc/agenticvm/xfwm4.xml "$HOME/.config/xfce4/xfconf/xfce-perchannel-xml/xfwm4.xml"
dbus-daemon --session --address="$DBUS_SESSION_BUS_ADDRESS" --fork
xfce4-session >"$HOME/.cache/xfce-session.log" 2>&1 &
count=0
while ! xprop -root _NET_SUPPORTING_WM_CHECK 2>/dev/null | grep -q 'window id'; do
    count=$((count + 1)); [ "$count" -lt 100 ] || exit 1
    sleep 0.1
done
/usr/local/bin/agenticvm-browser http://127.0.0.1:8080/ >"$HOME/.cache/browser.log" 2>&1 &
count=0
while ! xdotool search --onlyvisible --class 'firefox' >/dev/null 2>&1; do
    count=$((count + 1)); [ "$count" -lt 200 ] || { cat "$HOME/.cache/browser.log"; exit 1; }
    sleep 0.1
done
# A window that appears during an immediate GTK/GPU crash is not readiness.
# Require the full session to survive and the fixture to be loaded by Firefox.
sleep 2
/usr/bin/pgrep -u 1000 -x xfce4-panel >/dev/null || { cat "$HOME/.cache/xfce-session.log"; exit 1; }
/usr/bin/pgrep -u 1000 -x xfwm4 >/dev/null || exit 1
xdotool search --onlyvisible --name 'AgenticVM Desktop Ready' >/dev/null || { cat "$HOME/.cache/browser.log"; exit 1; }
/usr/bin/curl --fail --silent --noproxy '*' --max-time 2 http://127.0.0.1:8080/ >/dev/null || exit 1
touch "$XDG_RUNTIME_DIR/agenticvm-desktop-ready"
wait
