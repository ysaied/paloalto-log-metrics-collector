import paramiko
import yaml
import csv
from datetime import datetime
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Load YAML inventory ---
with open("./firewalls.yaml") as f:
    config = yaml.safe_load(f)

# --- Output CSV file ---
csv_file = "fw_logcounters.csv"

# Ensure header only once
with open(csv_file, "a", newline="") as f:
    writer = csv.writer(f)
    if f.tell() == 0:
        writer.writerow(["fw_ip", "hostname", "model", "sn", "panos", "panorama_ip", "timestamp", "datetime", "last-second", "last-minute", "last-hour", "last-day", "last-week", "incoming_log-rate", "raw_log-rate", "written_log-rate", "config-size_KB", "sec-rules", "HA", "status"])

# --- Function to fetch log counters ---
def get_log_counters(host, username, password):
    print(f"[DEBUG] Starting connection to {host}")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password, timeout=10)
        print(f"[DEBUG] Connection successful to {host}")

        print(f"[DEBUG] Sending command to {host} using invoke_shell")
        chan = ssh.invoke_shell()
        buffer = ""
        # Wait until the prompt ">" appears
        while True:
            if chan.recv_ready():
                chunk = chan.recv(1024).decode()
                buffer += chunk
                if ">" in buffer:
                    print(f"[DEBUG] Prompt detected for {host}")
                    break
            time.sleep(0.2)
        chan.send("debug log-receiver log-flow counters | match \"incoming logs\"\n")
        time.sleep(2)
        output = ""
        while chan.recv_ready():
            output += chan.recv(65535).decode()
        print(f"[DEBUG] Received output from {host} via invoke_shell")

        print(f"[DEBUG] Sending second command to {host} for log rates")
        chan.send("debug log-receiver statistics | match \"Log incoming rate\\|Log written rate\"\n")
        time.sleep(2)
        stats_output = ""
        while chan.recv_ready():
            stats_output += chan.recv(65535).decode()

        # Get hostname, model, serial number, and panos version
        print(f"[DEBUG] Sending third command to {host} for hostname, model, serial, and sw-version")
        chan.send("show system info | match \"hostname\\|serial\\|model\\|sw-version\"\n")
        time.sleep(2)
        sysinfo_output = ""
        while chan.recv_ready():
            sysinfo_output += chan.recv(65535).decode()
        hostname = sn = model = panos = ""
        h_match = re.search(r"hostname:\s+(\S+)", sysinfo_output)
        s_match = re.search(r"serial:\s+(\S+)", sysinfo_output)
        m_match = re.search(r"model:\s+(\S+)", sysinfo_output)
        p_match = re.search(r"sw-version:\s+(\S+)", sysinfo_output)
        if h_match:
            hostname = h_match.group(1)
        if s_match:
            sn = s_match.group(1)
        if m_match:
            model = m_match.group(1)
        if p_match:
            panos = p_match.group(1)

        print(f"[DEBUG] Sending fourth command to {host} for panorama status")
        chan.send("show panorama-status | match \"Panorama Server 1\"\n")
        time.sleep(2)
        panorama_output = ""
        while chan.recv_ready():
            panorama_output += chan.recv(65535).decode()
        panorama_ip = ""
        p_match = re.search(r"Panorama Server 1\s*:\s*(\S+)", panorama_output)
        if p_match:
            panorama_ip = p_match.group(1)

        print(f"[DEBUG] Sending fifth command to {host} for config size")
        chan.send("show management-server last-committed config-size | match \"bytes\"\n")
        time.sleep(2)
        config_output = ""
        while chan.recv_ready():
            config_output += chan.recv(65535).decode()
        config_kb = ""
        c_match = re.search(r"(\d+)\s+bytes", config_output)
        if c_match:
            config_kb = str(int(c_match.group(1)) // 1024)

        print(f"[DEBUG] Sending sixth command to {host} for security rules")
        chan.send("show resource limit policies | match \"Security\"\n")
        time.sleep(2)
        sec_output = ""
        while chan.recv_ready():
            sec_output += chan.recv(65535).decode()
        sec_rules = ""
        s_match = re.search(r"Security\s+(\d+)", sec_output)
        if s_match:
            sec_rules = s_match.group(1)

        print(f"[DEBUG] Sending seventh command to {host} for raw log forwarding rate")
        chan.send('debug log-receiver rawlog_fwd stats global show | match "Total forwarding rate"\n')
        time.sleep(2)
        rawlog_output = ""
        while chan.recv_ready():
            rawlog_output += chan.recv(65535).decode()
        raw_log_rate = "0"
        r_match = re.search(r"Total forwarding rate\s*:\s*(\d+)\s+logs/sec", rawlog_output)
        if r_match:
            raw_log_rate = r_match.group(1)

        print(f"[DEBUG] Sending eighth command to {host} for HA state")
        chan.send('show high-availability state | match "Mode"\n')
        time.sleep(2)
        ha_output = ""
        while chan.recv_ready():
            ha_output += chan.recv(65535).decode()
        if "Active" in ha_output or "Passive" in ha_output:
            ha_state = "True"
        else:
            ha_state = "False"

        chan.close()
        ssh.close()

        print(f"[DEBUG] Raw output from {host}:\n{output}")
        print(f"[DEBUG] Parsing output from {host} using regex")
        match = re.search(r"incoming logs:\s+(\d+/\d+/\d+/\d+/\d+)", output)
        if match:
            parts = match.group(1).split("/")
            if len(parts) == 5:
                print(f"[DEBUG] Parsing stats output from {host}")
                rate_match = re.findall(r"(Log (?:incoming|written) rate):\s+(\d+)/sec", stats_output)
                incoming_rate = written_rate = "0"
                for name, value in rate_match:
                    if "incoming" in name:
                        incoming_rate = value
                    elif "written" in name:
                        written_rate = value
                return parts, incoming_rate, raw_log_rate, written_rate, hostname, model, sn, panos, panorama_ip, config_kb, sec_rules, ha_state, "success"
            else:
                print(f"[WARN] {host}: incoming logs did not have 5 fields: {parts}")
                # Return empty counters if fields are not 5
                rate_match = re.findall(r"(Log (?:incoming|written) rate):\s+(\d+)/sec", stats_output)
                incoming_rate = written_rate = "0"
                for name, value in rate_match:
                    if "incoming" in name:
                        incoming_rate = value
                    elif "written" in name:
                        written_rate = value
                return ["", "", "", "", ""], incoming_rate, raw_log_rate, written_rate, hostname, model, sn, panos, panorama_ip, config_kb, sec_rules, ha_state, "partial"
        else:
            print(f"[WARN] {host}: 'incoming logs' pattern not found in output")
            rate_match = re.findall(r"(Log (?:incoming|written) rate):\s+(\d+)/sec", stats_output)
            incoming_rate = written_rate = "0"
            for name, value in rate_match:
                if "incoming" in name:
                    incoming_rate = value
                elif "written" in name:
                    written_rate = value
            return ["", "", "", "", ""], incoming_rate, raw_log_rate, written_rate, hostname, model, sn, panos, panorama_ip, config_kb, sec_rules, ha_state, "partial"
    except Exception as e:
        print(f"[ERROR] {host}: {e}")
        return ["", "", "", "", ""], "0", "0", "0", "", "", "", "", "", "", "", f"error: {e}"

def process_firewall(host, username, password):
    print(f"[DEBUG] Processing host: {host}")
    result = get_log_counters(host, username, password)
    if result:
        counters, incoming_rate, raw_log_rate, written_rate, hostname, model, sn, panos, panorama_ip, config_kb, sec_rules, ha_state, status = result
        if not counters or len(counters) != 5:
            counters = ["", "", "", "", ""]
            if status == "success":
                status = "partial"
    else:
        counters = ["", "", "", "", ""]
        incoming_rate = "0"
        raw_log_rate = "0"
        written_rate = "0"
        hostname = ""
        model = ""
        sn = ""
        panos = ""
        panorama_ip = ""
        config_kb = ""
        sec_rules = ""
        ha_state = ""
        status = "failed"
    epoch = int(datetime.now().timestamp())
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[DEBUG] Writing results to CSV for {host}")
    with open(csv_file, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([host, hostname, model, sn, panos, panorama_ip, epoch, now] + counters + [incoming_rate, raw_log_rate, written_rate, config_kb, sec_rules, ha_state, status])
    if any(counters):
        print(f"[OK] {host}: {counters} incoming_log-rate: {incoming_rate} raw_log-rate: {raw_log_rate} written_log-rate: {written_rate}")
    else:
        print(f"[WARN] {host}: no counters retrieved")
    print(f"[DEBUG] Moving to next host...\n")

tasks = []
with ThreadPoolExecutor(max_workers=20) as executor:
    for group_name, group_data in config["groups"].items():
        username = group_data["username"]
        password = group_data["password"]
        for host in group_data["hosts"]:
            tasks.append(executor.submit(process_firewall, host, username, password))
    for future in as_completed(tasks):
        future.result()