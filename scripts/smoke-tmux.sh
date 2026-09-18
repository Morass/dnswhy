#!/bin/bash
# Drives the real binary in a real terminal: a model test cannot see a mangled
# layout, a swallowed newline or a colour code that leaks when output is piped.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
bin=${DNSWHY_BIN:-}
if [ -z "$bin" ]; then
	bin=$(mktemp -d)/dnswhy
	go build -o "$bin" ./cmd/dnswhy
fi

# A short socket path: unix sockets cap at about 104 characters.
sock=$(mktemp -d /tmp/dw.XXXX)/s
session=dnswhy-smoke
fixtures="--scutil-file $root/testdata/vpn.scutil --resolver-dir $root/testdata/resolver-dir --hosts-file $root/testdata/hosts --offline"

cleanup() { tmux -S "$sock" kill-server 2>/dev/null || true; }
trap cleanup EXIT

tmux -S "$sock" new-session -d -s "$session" -x 100 -y 40
tmux -S "$sock" send-keys "PS1='$ ' ; clear" Enter
sleep 0.5

fail=0
check() { # check <description> <pattern>
	if tmux -S "$sock" capture-pane -p -t "$session" | grep -qF "$2"; then
		echo "  ok    $1"
	else
		echo "  FAIL  $1 (expected to see: $2)"
		fail=1
	fi
}

echo "explain a scoped name"
tmux -S "$sock" send-keys "$bin files.corp.internal $fixtures" Enter
sleep 1.5
check "the question is shown" "Question  files.corp.internal"
check "the winning scope is named" "resolver #3  corp.internal"
check "the winner is marked" "wins"
check "the command to reproduce it is given" "dig @198.51.100.53"

echo "colour reaches a terminal"
tmux -S "$sock" send-keys "clear; $bin printer.local $fixtures" Enter
sleep 1.5
# -e keeps the escape sequences in the capture, which is the only way to see
# that the binary really colours a terminal.
if tmux -S "$sock" capture-pane -p -e -t "$session" | grep -q $'\033\[1m'; then
	echo "  ok    escape sequences reach a terminal"
else
	echo "  FAIL  escape sequences reach a terminal"
	fail=1
fi

echo "colour stays out of a pipe"
tmux -S "$sock" send-keys "clear; $bin files.corp.internal $fixtures > /tmp/dw-piped.txt; grep -c $'\\033' /tmp/dw-piped.txt" Enter
sleep 1.5
check "a redirected run is plain text" "0"

echo "doctor"
tmux -S "$sock" send-keys "clear; $bin doctor $fixtures" Enter
sleep 1.5
check "the summary line is shown" "worth fixing"

echo "help"
tmux -S "$sock" send-keys "clear; $bin --help" Enter
sleep 1
check "usage is shown" "dnswhy <name>"

rm -f /tmp/dw-piped.txt
if [ "$fail" -eq 0 ]; then
	echo "smoke: all checks passed"
else
	echo "smoke: FAILED"
fi
exit "$fail"
