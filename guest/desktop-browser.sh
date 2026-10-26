#!/bin/sh
# Fixed managed browser entry point. URL is always an argv value, never code.
set -eu
if [ "$#" -gt 1 ]; then echo 'Usage: agenticvm-browser [http(s) URL]' >&2; exit 2; fi
url=${1:-http://127.0.0.1:8080/}
case "$url" in http://*|https://*|about:blank) ;; *) echo 'Unsupported browser URL scheme' >&2; exit 2 ;; esac
export MOZ_ENABLE_WAYLAND=0
profile=/workspace/.config/agenticvm-browser
mkdir -p "$profile"
/usr/bin/firefox-esr --no-remote --profile "$profile" --new-window "$url" &
browser_pid=$!
trap 'kill -TERM "$browser_pid" 2>/dev/null || true' TERM INT
count=0
while kill -0 "$browser_pid" 2>/dev/null; do
    window=$(xdotool search --onlyvisible --class firefox 2>/dev/null | head -n 1 || true)
    if [ -n "$window" ]; then
        wmctrl -i -r "$window" -b add,maximized_vert,maximized_horz
        break
    fi
    count=$((count + 1)); [ "$count" -lt 200 ] || break
    sleep 0.1
done
wait "$browser_pid"
