import pyshark
import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
from queue import Queue
import time
import subprocess
import re
from datetime import datetime
import threading
import asyncio
import traceback

asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())  # Changed to Proactor for subprocess support on Windows

devices = {}  # {mac: {'protocol': str, 'timestamp': str, 'device_name': str, 'platform': str, 'port': str, 'ip': str, 'capabilities': str}}

stop_event = threading.Event()

def update_gui():
    cdp_text = "CDP Devices:\n"
    lldp_text = "LLDP Devices:\n"
    for mac, info in sorted(devices.items()):
        device_str = f"MAC: {mac}\nTimestamp: {info.get('timestamp', 'N/A')}\nName: {info.get('device_name', 'N/A')}\nPlatform: {info.get('platform', 'N/A')}\nPort: {info.get('port', 'N/A')}\nIP: {info.get('ip', 'N/A')}\nCapabilities: {info.get('capabilities', 'N/A')}\n\n"
        if info.get('protocol') == 'CDP':
            cdp_text += device_str
        elif info.get('protocol') == 'LLDP':
            lldp_text += device_str
    
    CDP_text.config(text=cdp_text)
    LLDP_text.config(text=lldp_text)

def sniff_cdp_lldp(interfaces):
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        capture = pyshark.LiveCapture(interface=interfaces, display_filter='cdp or lldp', eventloop=loop, use_json=True)  # use_json for better parsing
        for packet in capture.sniff_continuously():
            if stop_event.is_set():
                break
            now = datetime.now().strftime('%H:%M:%S')
            mac = packet.eth.src.lower() if hasattr(packet, 'eth') else None
            if not mac:
                continue

            if mac not in devices:
                devices[mac] = {'timestamp': now}
            else:
                devices[mac]['timestamp'] = now

            if 'cdp' in packet:
                devices[mac]['protocol'] = 'CDP'
                devices[mac]['device_name'] = getattr(packet.cdp, 'deviceid', 'N/A')
                devices[mac]['platform'] = getattr(packet.cdp, 'platform', 'N/A')
                devices[mac]['port'] = getattr(packet.cdp, 'portid', 'N/A')
                devices[mac]['ip'] = getattr(packet.cdp, 'nrgyz_ip_address', 'N/A')
                caps = []
                if getattr(packet.cdp, 'capabilities_router', '0') == '1':
                    caps.append('Router')
                if getattr(packet.cdp, 'capabilities_switch', '0') == '1':
                    caps.append('Switch')
                if getattr(packet.cdp, 'capabilities_host', '0') == '1':
                    caps.append('Host')
                devices[mac]['capabilities'] = ', '.join(caps)
            elif 'lldp' in packet:
                devices[mac]['protocol'] = 'LLDP'
                devices[mac]['device_name'] = getattr(packet.lldp, 'system_name', 'N/A')
                devices[mac]['platform'] = getattr(packet.lldp, 'system_desc', 'N/A')
                devices[mac]['port'] = getattr(packet.lldp, 'port_desc', 'N/A')
                devices[mac]['ip'] = getattr(packet.lldp, 'mgn_addr_ip4', 'N/A')
                caps = []
                if getattr(packet.lldp, 'capabilities_router', '0') == '1':
                    caps.append('Router')
                if getattr(packet.lldp, 'capabilities_mac_bridge', '0') == '1':
                    caps.append('Bridge')
                if getattr(packet.lldp, 'capabilities_station', '0') == '1':
                    caps.append('Station')
                devices[mac]['capabilities'] = ', '.join(caps)

            root.after(0, update_gui)
    except Exception as e:
        traceback.print_exc()  # Full stack trace
        print(f"Error type: {type(e).__name__}, Message: {str(e)}")

def get_interfaces():
    try:
        output = subprocess.check_output(['tshark', '-D']).decode('utf-8', errors='ignore').splitlines()
        interfaces = [line.split('.', 1)[1].strip() if '.' in line else line.strip() for line in output]
        print("Available interfaces:", interfaces)  # Debug print
        return interfaces
    except Exception as e:
        print("Interface list error:", str(e))
        traceback.print_exc()
        return []

def update_display():
    # Update IP Config Info
    infoE = ipConfig_Get("Ethernet adapter Ethernet")
    ipConfig_E_label.config(text=f"ipconfig Ether\n\nIP: {infoE['IP']}\nMAC: {infoE['MAC']}\nNetwork Name: {infoE['Network Name']}\nDefault Gateway: {infoE['Default Gateway']}\nDNS Server: {infoE['DNS Server']}")

    infoW = ipConfig_Get("Wireless LAN adapter Wi-Fi")
    ipConfig_W_label.config(text=f"ipconfig WIFI\n\nIP: {infoW['IP']}\nMAC: {infoW['MAC']}\nNetwork Name: {infoW['Network Name']}\nDefault Gateway: {infoW['Default Gateway']}\nDNS Server: {infoW['DNS Server']}")

    root.after(1000, update_display)  # Update every 1 seconds

def ipConfig_Get(interface):
    try:
        output = subprocess.check_output('ipconfig /all', shell=True).decode('utf-8', errors='ignore')
        # Regex patterns for various fields (target specific interface)
        ip_pattern = re.compile(rf'{interface}.*?IPv4 Address.*?:\s*([\d\.]+)', re.DOTALL | re.IGNORECASE)
        mac_pattern = re.compile(rf'{interface}.*?Physical Address.*?:\s*([0-9A-Fa-f:-]+)', re.DOTALL | re.IGNORECASE)
        gateway_pattern = re.compile(rf'{interface}.*?Default Gateway.*?:\s*([\d\.]+)', re.DOTALL | re.IGNORECASE)
        dns_pattern = re.compile(rf'{interface}.*?DNS Servers.*?:\s*([\d\.]+)', re.DOTALL | re.IGNORECASE) # Grabs first DNS; adjust for multiple
        network_name_pattern = re.compile(rf'{interface} adapter\s*(.*):', re.DOTALL | re.IGNORECASE) # Adapter description as "network name"
       
        ip_match = ip_pattern.search(output)
        mac_match = mac_pattern.search(output)
        gateway_match = gateway_pattern.search(output)
        dns_match = dns_pattern.search(output)
        network_name_match = network_name_pattern.search(output)
       
        ip = ip_match.group(1) if ip_match else 'Not Found'
        mac = mac_match.group(1) if mac_match else 'Not Found'
        gateway = gateway_match.group(1) if gateway_match else 'Not Found'
        dns = dns_match.group(1) if dns_match else 'Not Found' # First DNS; can extend to find all
        network_name = network_name_match.group(1).strip() if network_name_match else 'Not Found'
       
        return {
            'IP': ip,
            'MAC': mac,
            'Network Name': network_name,
            'Default Gateway': gateway,
            'DNS Server': dns
        }
    except Exception as e:
        return {'Error': str(e)}

#********************************** UI ***********************************
#create UI Main Window
root = tk.Tk()
root.title("Network Packet Sniffer")
root.attributes('-fullscreen', True)
root.bind('<Escape>', lambda e: root.quit())

#create IPconfig display area
ipConfig_frame = tk.Frame(root, bg='white')
ipConfig_frame.place(relx=0, rely=0, relwidth=.33, relheight=0.3)  # Increased height for better display

#create IPconfig ETHER display label
ipConfig_E_label = tk.Label(ipConfig_frame, bg='white', font=('Arial', 12, 'bold'), anchor='nw', justify='left')
ipConfig_E_label.pack(side='left', fill='both', expand=True)

#create IPconfig WIFI display label
ipConfig_W_label = tk.Label(ipConfig_frame, bg='white', font=('Arial', 12, 'bold'), anchor='nw', justify='left')
ipConfig_W_label.pack(side='right', fill='both', expand=True)

#create CDP/LLDP display area
CDP_LLDP_frame = tk.Frame(root, bg='grey')
CDP_LLDP_frame.place(relx=0, rely=0.3, relwidth=.33, relheight=0.7)  # Adjusted for fullscreen tablet

#create CDP label
CDP_text = tk.Label(CDP_LLDP_frame, bg='white', font=('Arial', 12, 'bold'), anchor='nw', justify='left', wraplength=300)
CDP_text.pack(side='right', fill='both', expand=True)

#create LLDP label
LLDP_text = tk.Label(CDP_LLDP_frame, bg='white', font=('Arial', 12, 'bold'), anchor='nw', justify='left', wraplength=300)
LLDP_text.pack(side='left', fill='both', expand=True)

# Get interfaces dynamically
interfaces = get_interfaces()

# Start sniffing
sniff_thread = threading.Thread(target=sniff_cdp_lldp, args=(interfaces,), daemon=True)
sniff_thread.start()

#*************************************** Main Loop **************************************
#update loop
update_display()

#initiate main loop
root.mainloop()