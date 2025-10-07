import pyshark
import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
from queue import Queue
import time
import subprocess
import re



def update_display():
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
    

#create UI Main Window
root = tk.Tk()
root.title("Network Packet Sniffer")
root.attributes('-fullscreen', True)
root.bind('<Escape>', lambda e: root.quit())

#create IPconfig display area
ipConfig_frame = tk.Frame(root, bg='white')
ipConfig_frame.place(relx=0, rely=0, relwidth=.33, relheight=0.2)

#create IPconfig ETHER display label
ipConfig_E_label = tk.Label(ipConfig_frame, text="ipConfig ETHER", bg='white', fg='black', font=('Arial', 12, 'bold'))
ipConfig_E_label.pack(side='left', fill='both', expand=True)

#create IPconfig WIFI display label
ipConfig_W_label = tk.Label(ipConfig_frame, text="ipConfig WIFI", bg='white', fg='black', font=('Arial', 12, 'bold'))
ipConfig_W_label.pack(side='right', fill='both', expand=True)



#create Arp display area
arp_frame = tk.Frame(root, bg='grey')
arp_frame.place(relx=0, rely=0.2, relwidth=.33, relheight=0.8)




#update loop
update_display()

#initiate main loop
root.mainloop()