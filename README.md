 🛡️ SnortIPS – Simple Intrusion Prevention System in Python

A practical and educational Python script that integrates Snort IDS and iptables to simulate a lightweight Intrusion Prevention System (IPS).  
It demonstrates how to monitor Snort alerts in real time, detect suspicious network activity (ex. ICMP, TCP, Nmap scans), and dynamically apply firewall rules to mitigate potential threats.

---

## ⚙️ Features

- Monitors a live Snort process and parses its console alerts in real time  
- Detects single alerts or a combination of alerts. 
- Interactively applies iptables rules to block malicious traffic  
- Provides a manual rule management interface  
- Displays continuous Snort output in the console  
- Gracefully handles interruptions and clean exits  
- Structured modular design for easy customization and debugging  

---

## 🧠 How It Works

1. The user launches the script and selects an option from the menu:
   - **1 – Monitor interface:** Runs Snort on the chosen network interface and reads alerts in real time.
   - **2 – Manage iptables:** Lets the user manually create, remove, or modify firewall rules.
2. The script spawns a Snort process using `subprocess.Popen()` and continuously reads its output stream.
3. It checks each line for known **Snort rule IDs (SIDs)** associated with ICMP, TCP, or Nmap events.
4. When a threshold (e.g., more than 5 ping alerts) is reached, it prompts the user to block the traffic automatically.
5. If confirmed, it applies an appropriate **iptables DROP rule** to block further packets.
6. The process runs interactively and prints alerts and IPS actions live in the console.

---

## 🚀 Usage

### Requirements

- **Python 3.x**  
- **Snort** installed and configured (`/etc/snort/snort.conf` and `local.rules`)  
- **iptables** and administrative privileges (run as `sudo`)  

### Run

```bash
sudo python3 SnortIPS.py
```

### Example Session

```
Welcome to Simple Snort IPS (SSIPS)
1 - Interface monitor
2 - Manage iptables rules
Ctrl+C to exit

> 1
Enter interface to monitor: eth0
Starting Snort on interface eth0...

[**] [1:10000005:0] ICMP Ping detected [**]
[+] ICMP alert detected (5)

Suspicious ICMP traffic detected!
Action [0 = ignore, 1 = block ICMP traffic]: 1

[IPS] ICMP traffic blocked.
```

---

## ⚙️ Configuration Guide

### 1. Add Custom Snort Rules

To detect ICMP (ping) traffic, edit `/etc/snort/rules/local.rules` and insert:

```bash
alert icmp any any -> any any (msg:"ICMP Ping detected"; itype:8; sid:10000005; rev:0;)
```

For simple TCP and Nmap detections, ensure your Snort rule set includes:
```bash
# Example TCP rules
alert tcp any any -> any any (msg:"Suspicious TCP connection"; sid:10000021; rev:0;)
alert tcp any any -> any any (msg:"TCP SYN flood"; sid:10000022; rev:0;)

# Example Nmap XMAS scan rule
alert tcp any any -> any any (msg:"Nmap XMAS Scan"; flags:FPU; sid:10001136; rev:1;)
```

Make sure `include $RULE_PATH/local.rules` is active in your `/etc/snort/snort.conf`.

### 2. Test the System

- **ICMP:** From another device, run  
  ```bash
  ping <target_IP>
  ```
- **Nmap scan:**  
  ```bash
  nmap -sX <target_IP>
  ```
- SnortIPS will detect and print alerts in the console. When thresholds are reached, it will offer to block traffic using iptables.

---

## ⚠️ Notes

- This project is designed for educational and testing purposes.  
  It is not production-grade and should not be deployed on critical systems.  
- You must have Snort configured and running with rule SIDs that match those in the script.  
- Modify the rule IDs and thresholds in the `tcpRules`, `nmapRules`, and ICMP detection sections to suit your Snort setup.  
- Run in a controlled environment such as a lab or VM.
- Missing features: proper input control & sanitization 
