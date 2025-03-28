import tkinter as tk
from tkinter import scrolledtext, messagebox
import nmap
import threading
import subprocess
import socket

# Function to get NetBIOS name using nbtscan
def get_netbios_name(ip):
    try:
        result = subprocess.run(["nbtscan", "-v", ip], capture_output=True, text=True)
        for line in result.stdout.split("\n"):
            if "Name" in line:
                return line.split()[1]  # Extract the NetBIOS hostname
    except Exception:
        return None
    return None

# Function to resolve hostname using Reverse DNS lookup
def get_reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]  # Get hostname from DNS
    except socket.herror:
        return None

# Function to scan for online hosts
def scan_hosts():
    network_range = ip_entry.get().strip()

    if not network_range:
        messagebox.showwarning("Input Error", "Please enter a valid network range (e.g., 192.168.1.0/24).")
        return

    scanner = nmap.PortScanner()

    try:
        result_text.delete("1.0", tk.END)  # Clear previous results
        result_text.insert(tk.END, f"🔍 Scanning network: {network_range}...\n")

        # Run Nmap Ping Scan (-sn) with Reverse DNS (-R)
        scanner.scan(hosts=network_range, arguments="-sn -R")

        live_hosts = [host for host in scanner.all_hosts() if scanner[host].state() == "up"]

        if live_hosts:
            result_text.insert(tk.END, "\n✅ Online Hosts Found:\n")
            for host in live_hosts:
                hostname = scanner[host].hostname()

                # Try Reverse DNS if no hostname found
                if not hostname:
                    hostname = get_reverse_dns(host)

                # Try NetBIOS scan as last option
                if not hostname:
                    hostname = get_netbios_name(host)

                # If still unknown, mark it
                if not hostname:
                    hostname = "Unknown"

                result_text.insert(tk.END, f"📡 {host} ➝ {hostname}\n")
        else:
            result_text.insert(tk.END, "\n❌ No online hosts detected.\n")

    except Exception as e:
        messagebox.showerror("Error", f"Scan failed: {str(e)}")

# GUI Setup
root = tk.Tk()
root.title("Nmap Live Host Scanner - Windows 11")
root.geometry("600x400")  # Set window size

tk.Label(root, text="Network Range (e.g., 192.168.1.0/24):").grid(row=0, column=0, padx=5, pady=5)
ip_entry = tk.Entry(root, width=30)
ip_entry.grid(row=0, column=1, padx=5, pady=5)

scan_button = tk.Button(root, text="Start Scan", command=lambda: threading.Thread(target=scan_hosts).start())
scan_button.grid(row=1, columnspan=2, pady=10)

result_text = scrolledtext.ScrolledText(root, width=70, height=18)
result_text.grid(row=2, columnspan=2, padx=5, pady=5)

root.mainloop()