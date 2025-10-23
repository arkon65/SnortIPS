# ------------------------------------------------------------
# DESCRIPTION:
# This script integrates Snort IDS with iptables to simulate a
# basic Intrusion Prevention System (IPS). It monitors Snort’s
# live console output, detects specific alerts (ICMP, TCP, Nmap),
# and optionally applies iptables rules to block suspicious traffic.
#
# AUTHOR: Argyris Koudounas
# DATE: 2025/10/17
# LANGUAGE: Python 3
#
# USAGE:
# Run the script with administrator privileges:
#     sudo python3 SnortIPS.py
#
# The program will:
#   - Start Snort on a selected network interface
#   - Continuously read its real-time alerts
#   - Detect rule IDs (SIDs) for ping, TCP, and scan events
#   - Prompt the user to take IPS actions (block/ignore)
#   - Allow manual firewall rule management
#
# DEPENDENCIES:
#   - Snort (configured with local.rules and valid SIDs)
#   - iptables
#   - Python 3.x (standard library only)
#
# NOTE:
# This script is intended for educational and research purposes.
# It is not production-grade and should be used only in controlled
# environments such as labs or virtual networks.
# ============================================================

import subprocess
import time

def monitor_interface(iface):
    comm = f"sudo snort -i {iface} -A console -c /etc/snort/snort.conf"
    print(f"Starting Snort on interface {iface}...\n")

    # Detection flags and counters
    pingFlag = 0
    tcpFlag = 0
    nmapFlag = 0

    # Example rule lists (adjust SIDs as needed)
    tcpRules = ["[1:10000021:0]", "[1:10000022:0]", "[1:10000025:0]", "[1:10000926:0]", "[1:10000030:0]"]
    nmapRules = ["[1:10001136:1]", "[1:10001137:1]", "[1:10001138:1]", "[1:10001139:1]", "[1:10001140:1]", "[1:10001141:1]"]

    # Launch Snort as subprocess and capture output line by line
    process = subprocess.Popen(
        comm,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        text=True
    )

    # Live Snort output visible
    for line in process.stdout:
        line = line.strip()
        if not line:
            continue
        print(line)  

        # --- Single rule ICMP Ping Detection ---
        if "[1:10000005:0]" in line:
            pingFlag += 1
            print(f"[+] ICMP alert detected ({pingFlag})")

            if pingFlag > 5:
                print("\nSuspicious ICMP traffic detected!")
                action = input("Action [0 = ignore, 1 = block ICMP traffic]: ").strip()
                if action == "1":
                    reject_cmd = f"sudo iptables -A INPUT -p icmp -i {iface} -j DROP"
                    subprocess.run(reject_cmd, shell=True)
                    print("[IPS] ICMP traffic blocked.")
                else:
                    print("No action taken.")
                pingFlag = 0

        # --- TCP Rule Detection example with multiple rule corellaction ---
        for sid in tcpRules:
            if sid in line:
                tcpFlag += 1
                print(f"[+] TCP alert {sid} ({tcpFlag})")

                if tcpFlag > 20000:
                    print("Suspicious TCP traffic detected!")
                    action = input("Action [0 = ignore, 1 = block TCP traffic]: ").strip()
                    if action == "1":
                        reject_cmd = f"sudo iptables -A INPUT -p tcp -i {iface} -j DROP"
                        subprocess.run(reject_cmd, shell=True)
                        print("[IPS] TCP traffic blocked.")
                    else:
                        print("No action taken.")
                    tcpFlag = 0

        # --- Nmap Scan Detection example with multiple rule corellaction ---
        for sid in nmapRules:
            if sid in line:
                nmapFlag += 1
                print(f"[+] Nmap scan alert {sid} ({nmapFlag})")

                if nmapFlag > 3:
                    print("Possible Nmap XMAS scan detected!")
                    action = input("Action [0 = ignore, 1 = block scan]: ").strip()
                    if action == "1":
                        reject_cmd = f"sudo iptables -A INPUT -i {iface} -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP"
                        subprocess.run(reject_cmd, shell=True)
                        print("[IPS] Scan traffic blocked.")
                    else:
                        print("No action taken.")
                    nmapFlag = 0

        time.sleep(0.1)


# Function for Iptables management
def manage_iptables():
    while True:
        print("\n--- Manual iptables options ---")
        print("1 - Accept or block traffic on specific interface")
        print("2 - Accept/block traffic from address on interface")
        print("3 - Accept/block traffic from address on port")
        print("4 - Insert manual rule")
        print("5 - Print existing Iptable entries")
        print("6 - Return to main menu")
        choice = input("Select option: ").strip()

        if choice == "1":
            iface = input("Interface: ").strip()
            action = input("1 = Accept all, 2 = Drop all: ").strip()
            if action == "1":
                cmd = f"sudo iptables -A INPUT -i {iface} -j ACCEPT"
            else:
                cmd = f"sudo iptables -A INPUT -i {iface} -j DROP"
            subprocess.run(cmd, shell=True)
            print("Rule applied.")

        elif choice == "2":
            iface = input("Interface: ").strip()
            addr = input("Source address: ").strip()
            action = input("1 = Accept, 2 = Drop: ").strip()
            if action == "1":
                cmd = f"sudo iptables -A INPUT -i {iface} -s {addr} -j ACCEPT"
            else:
                cmd = f"sudo iptables -A INPUT -i {iface} -s {addr} -j DROP"
            subprocess.run(cmd, shell=True)
            print("Rule applied.")

        elif choice == "3":
            iface = input("Interface: ").strip()
            addr = input("Address: ").strip()
            port = input("Port: ").strip()
            action = input("1 = Accept, 2 = Drop: ").strip()
            if action == "1":
                cmd = f"sudo iptables -A INPUT -i {iface} -s {addr} -p tcp --dport {port} -j ACCEPT"
            else:
                cmd = f"sudo iptables -A INPUT -i {iface} -s {addr} -p tcp --dport {port} -j DROP"
            subprocess.run(cmd, shell=True)
            print("Rule applied.")

        elif choice == "4":
            cmd = input("Enter full iptables command: ").strip()
            subprocess.run(cmd, shell=True)
            print("Rule inserted manually.")

        elif choice == "5":
            cmd = f"sudo iptables --list --line-numbers"
            subprocess.run(cmd, shell=True)

        elif choice == "6":
            break

        else:
            print("Invalid option.")
        time.sleep(0.5)

#----------------------------------------------------------------------------------------------------------
def main():
    while True:
        print("\nWelcome to Simple Snort IPS (SSIPS)")
        print("1 - Interface monitor")
        print("2 - Manage iptables rules")
        print("Ctrl+C to exit\n")

        selection = input("Choose option: ").strip()

        if selection == "1":
            iface = input("Enter interface to monitor: ").strip()
            monitor_interface(iface)

        elif selection == "2":
            manage_iptables()

        else:
            print("Invalid choice.")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting SnortIPS...")
