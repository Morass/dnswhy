#!/bin/bash
# Regenerate the README screenshots by driving the real binary in a real
# terminal against a captured example configuration, never this machine's own.
set -eu
TOOL=dnswhy
REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT="$REPO/docs/images"
W=$(mktemp -d /tmp/shots.XXXXXX)
SOCK="$W/tmux.sock"
TMUX_BIN=$(command -v tmux)
T="$TMUX_BIN -S $SOCK"
DEMO_HOME=/tmp/${TOOL}demo
cleanup() { $T kill-server 2>/dev/null || true; rm -rf "$W" "$DEMO_HOME"; }
trap cleanup EXIT
rm -rf "$DEMO_HOME"
mkdir -p "$OUT" "$W/bin" "$DEMO_HOME"

(cd "$REPO" && go build -o "$W/real-$TOOL" ./cmd/$TOOL && go build -o "$W/ansi2svg" ./scripts/ansi2svg)

# The example machine: a laptop with a VPN scope, a Bonjour scope and a couple
# of resolver files. Wrapping the flags keeps the typed command readable.
cp -R "$REPO/testdata" "$W/state"
cat >"$W/bin/$TOOL" <<WRAP
#!/bin/bash
exec "$W/real-$TOOL" "\$@" \\
  --scutil-file "$W/state/vpn.scutil" \\
  --resolver-dir "$W/state/resolver-dir" \\
  --hosts-file "$W/state/hosts" \\
  --offline
WRAP
chmod +x "$W/bin/$TOOL"

nap() { perl -e "select(undef,undef,undef,$1)"; }
ENV=(env -i HOME="$DEMO_HOME" PATH="$W/bin:/usr/bin:/bin" TERM=xterm-256color LANG=en_US.UTF-8 BASH_SILENCE_DEPRECATION_WARNING=1)
COLS=100 ROWS=30
"${ENV[@]}" "$TMUX_BIN" -S "$SOCK" -f /dev/null new-session -d -s t -x $COLS -y $ROWS \
	"PS1='\[\e[1;32m\]\$\[\e[0m\] ' bash --noprofile --norc"
$T set -g status off
nap 0.5

type_() { $T send-keys -t t -l "$1"; $T send-keys -t t Enter; }
wait_for() {
	for _ in $(seq 1 80); do
		$T capture-pane -p -t t | grep -qF -- "$1" && { nap 0.4; return 0; }
		nap 0.25
	done
	echo "screenshots: timed out waiting for: $1" >&2
	$T capture-pane -p -t t >&2
	exit 1
}
shot() { # shot NAME "window title"
	$T capture-pane -e -p -t t |
		sed -e "s#$W/state/resolver-dir#/etc/resolver#g" -e "s#$W/state#/etc#g" |
		"$W/ansi2svg" -title "$2" -cols $COLS >"$OUT/$1.svg"
	echo "  docs/images/$1.svg"
}

type_ "clear; $TOOL files.corp.internal"
wait_for "wins"
shot explain "dnswhy files.corp.internal"

type_ "clear; $TOOL printer.local"
wait_for "Bonjour"
shot bonjour "dnswhy printer.local"

type_ "clear; $TOOL doctor"
wait_for "worth fixing"
shot doctor "dnswhy doctor"

echo done
