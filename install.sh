#!/bin/sh
# SudoWhizzy agent installer: curl -fsSL __HUB__/install.sh | sh -s <token>
# As root (or with sudo): a system service that manages the whole server.
# As an ordinary user: manages that user's own sites and files, no root needed
# (shared hosting, a jailed account). Each agent is one server on your plan.
set -eu
HUB="__HUB__"
TOKEN="${1:?usage: install.sh <token>}"

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac

download() { # dest url
  if command -v curl >/dev/null; then curl -fsSL "$2" -o "$1"
  elif command -v wget >/dev/null; then wget -qO "$1" "$2"
  else echo "Needs curl or wget." >&2; exit 1; fi
}

if [ "$(id -u)" = 0 ]; then
  # ---- root: system service ----
  command -v systemctl >/dev/null || { echo "This server has no systemd. Install as an ordinary user instead (run this without sudo), or set up systemd." >&2; exit 1; }
  BIN=/usr/local/bin/sudowhizzy-agent
  download "$BIN.new" "$HUB/dl/sudowhizzy-agent-linux-$ARCH"
  chmod 755 "$BIN.new" && mv -f "$BIN.new" "$BIN"
  "$BIN" enroll "$HUB" "$TOKEN"
  cat > /etc/systemd/system/sudowhizzy-agent.service <<UNIT
[Unit]
Description=SudoWhizzy agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN
Restart=always
RestartSec=5
# 3 = the hub revoked this server; stay stopped.
RestartPreventExitStatus=3

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable sudowhizzy-agent >/dev/null 2>&1
  systemctl restart sudowhizzy-agent
  echo "SudoWhizzy agent installed as root and connected."
  echo "To disconnect at any time: systemctl disable --now sudowhizzy-agent"
  exit 0
fi

# ---- ordinary user: no root ----
echo "Installing SudoWhizzy for user '$(id -un)' (no root): it will manage this user's own sites and files only."
BINDIR="$HOME/.local/bin"
BIN="$BINDIR/sudowhizzy-agent"
CONFDIR="$HOME/.config/sudowhizzy"
mkdir -p "$BINDIR" "$CONFDIR"
download "$BIN.new" "$HUB/dl/sudowhizzy-agent-linux-$ARCH"
chmod 755 "$BIN.new" && mv -f "$BIN.new" "$BIN"
"$BIN" enroll "$HUB" "$TOKEN"

STARTED=""
# Prefer a per-user systemd service when the user has a working systemd instance.
if command -v systemctl >/dev/null && systemctl --user show-environment >/dev/null 2>&1; then
  mkdir -p "$HOME/.config/systemd/user"
  cat > "$HOME/.config/systemd/user/sudowhizzy-agent.service" <<UNIT
[Unit]
Description=SudoWhizzy agent (user)
After=network-online.target

[Service]
ExecStart=$BIN
Restart=always
RestartSec=5
RestartPreventExitStatus=3

[Install]
WantedBy=default.target
UNIT
  systemctl --user daemon-reload
  systemctl --user enable sudowhizzy-agent >/dev/null 2>&1 || true
  systemctl --user restart sudowhizzy-agent >/dev/null 2>&1 && STARTED="systemd --user"
  # So it keeps running after you log out (may be denied on some hosts; harmless if so).
  command -v loginctl >/dev/null && loginctl enable-linger "$(id -un)" >/dev/null 2>&1 || true
fi

# Fallback for jailed accounts without user systemd: a crontab watchdog.
# The agent runs AS the cron job and keeps running; the next minute's tick exits
# at once because flock cannot take the held lock. If it dies, the next tick
# starts it again. This needs no detaching, so systemd never cleans it up.
# A single-file lock (flock) if available, else a pid check.
if [ -z "$STARTED" ]; then
  LOCK="$CONFDIR/agent.lock"
  LOG="$CONFDIR/agent.log"
  rm -f "$CONFDIR/stopped"
  if command -v flock >/dev/null; then
    RUN="flock -n $LOCK $BIN >> $LOG 2>&1"
  else
    RUN="[ -e $CONFDIR/agent.pid ] && kill -0 \$(cat $CONFDIR/agent.pid) 2>/dev/null || $BIN >> $LOG 2>&1"
  fi
  if command -v crontab >/dev/null; then
    LINE="* * * * * [ -e $CONFDIR/stopped ] || $RUN # sudowhizzy-agent"
    REBOOT="@reboot [ -e $CONFDIR/stopped ] || $RUN # sudowhizzy-agent"
    ( crontab -l 2>/dev/null | grep -v '# sudowhizzy-agent$' || true; echo "$LINE"; echo "$REBOOT" ) | crontab -
    STARTED="crontab watchdog (every minute)"
  fi
  # Start now in the background so there is no wait for the first tick.
  if command -v flock >/dev/null; then ( flock -n "$LOCK" "$BIN" >> "$LOG" 2>&1 & )
  else ( setsid "$BIN" >> "$LOG" 2>&1 & ) || nohup "$BIN" >> "$LOG" 2>&1 & fi
fi

if [ -z "$STARTED" ]; then
  echo "SudoWhizzy agent enrolled, but this account has neither user systemd nor crontab, so it cannot keep itself running."
  echo "Start it yourself (for example in a persistent session or your host's startup):"
  echo "  $BIN"
else
  echo "SudoWhizzy agent installed for your user and connected (kept running by: $STARTED)."
  echo "To disconnect: disconnect this server in the SudoWhizzy dashboard. To remove locally: rm -rf $CONFDIR $BIN, and remove the sudowhizzy-agent crontab lines if any."
fi
