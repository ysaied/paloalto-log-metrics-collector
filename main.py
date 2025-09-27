import paramiko
import yaml
import csv
from datetime import datetime
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

VERBOSE = False

def log(msg, level="info"):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if level == "info":
        print(f"[{now}] [info] {msg}")
    elif level == "verbose" and VERBOSE:
        print(f"[{now}] [verbose] {msg}")
    elif level == "warn":
        print(f"[{now}] [WARN] {msg}")
    elif level == "error":
        print(f"[{now}] [ERROR] {msg}")

# --- Load YAML inventories ---
with open("./firewalls.yaml") as f:
    config = yaml.safe_load(f)

with open("./panoramas.yaml") as f:
    panorama_config = yaml.safe_load(f)

# --- Output CSV files ---
csv_file = "fw_logcounters.csv"
panorama_csv_file = "panorama_logcounters.csv"

# Ensure header only once for firewalls
with open(csv_file, "a", newline="") as f:
    writer = csv.writer(f)
    if f.tell() == 0:
        writer.writerow(["fw_ip", "hostname", "model", "sn", "panos", "panorama_ip", "timestamp", "datetime", "last-second", "last-minute", "last-hour", "last-day", "last-week", "incoming_log-rate", "raw_log-rate", "written_log-rate", "config-size_KB", "sec-rules", "HA", "status"])

# Ensure header only once for panoramas
with open(panorama_csv_file, "a", newline="") as f:
    writer = csv.writer(f)
    if f.tell() == 0:
        writer.writerow([
            "panorama_ip", "hostname", "model", "sn", "panos", "timestamp", "datetime",
            "last-second", "last-minute", "last-hour", "last-day", "last-week", "incoming_log-rate",
            "config-size_MB", "config-size_PERCENT", "config-size_MAX", "status"
        ])

# --- Function to fetch log counters for firewalls ---
def get_log_counters(host, username, password):
    log(f"Starting connection to {host}", "info")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password, timeout=10, banner_timeout=30)
        log(f"Connection successful to {host}", "info")

        log(f"Sending command to {host} using invoke_shell", "verbose")
        chan = ssh.invoke_shell()
        buffer = ""
        # Wait until the prompt ">" appears
        while True:
            if chan.recv_ready():
                chunk = chan.recv(1024).decode()
                buffer += chunk
                if ">" in buffer:
                    log(f"Prompt detected for {host}", "verbose")
                    # Disable CLI pager after prompt detected
                    chan.send("set cli pager off\n")
                    time.sleep(1)
                    while chan.recv_ready():
                        chan.recv(65535).decode()
                    log(f"Disabled CLI pager on {host}", "verbose")
                    break
            time.sleep(0.2)
        chan.send("debug log-receiver log-flow counters | match \"incoming logs\"\n")
        time.sleep(2)
        output = ""
        while chan.recv_ready():
            output += chan.recv(65535).decode()
        log(f"Received output from {host} via invoke_shell", "verbose")

        log(f"Sending second command to {host} for log rates", "verbose")
        chan.send("debug log-receiver statistics | match \"Log incoming rate\\|Log written rate\"\n")
        time.sleep(2)
        stats_output = ""
        while chan.recv_ready():
            stats_output += chan.recv(65535).decode()

        log(f"Sending third command to {host} for raw log forwarding rate", "verbose")
        chan.send('debug log-receiver rawlog_fwd stats global show | match "Total forwarding rate"\n')
        time.sleep(2)
        rawlog_output = ""
        while chan.recv_ready():
            rawlog_output += chan.recv(65535).decode()
        raw_log_rate = "0"
        r_match = re.search(r"Total forwarding rate\s*:\s*(\d+)\s+logs/sec", rawlog_output)
        if r_match:
            raw_log_rate = r_match.group(1)

        log(f"Sending fourth command to {host} for hostname, model, serial, and sw-version", "verbose")
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

        log(f"Sending fifth command to {host} for panorama status", "verbose")
        chan.send("show panorama-status | match \"Panorama Server 1\"\n")
        time.sleep(2)
        panorama_output = ""
        while chan.recv_ready():
            panorama_output += chan.recv(65535).decode()
        panorama_ip = ""
        p_match = re.search(r"Panorama Server 1\s*:\s*(\S+)", panorama_output)
        if p_match:
            panorama_ip = p_match.group(1)

        log(f"Sending sixth command to {host} for config size", "verbose")
        chan.send("show management-server last-committed config-size | match \"bytes\"\n")
        time.sleep(2)
        config_output = ""
        while chan.recv_ready():
            config_output += chan.recv(65535).decode()
        config_kb = ""
        c_match = re.search(r"(\d+)\s+bytes", config_output)
        if c_match:
            config_kb = str(int(c_match.group(1)) // 1024)

        log(f"Sending seventh command to {host} for security rules", "verbose")
        chan.send("show resource limit policies | match \"Security\"\n")
        time.sleep(2)
        sec_output = ""
        while chan.recv_ready():
            sec_output += chan.recv(65535).decode()
        sec_rules = ""
        s_match = re.search(r"Security\s+(\d+)", sec_output)
        if s_match:
            sec_rules = s_match.group(1)

        log(f"Sending eighth command to {host} for HA state", "verbose")
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

        log(f"Raw output from {host}:\n{output}", "verbose")
        log(f"Parsing output from {host} using regex", "verbose")
        match = re.search(r"incoming logs:\s+(\d+/\d+/\d+/\d+/\d+)", output)
        if match:
            parts = match.group(1).split("/")
            if len(parts) == 5:
                log(f"Parsing stats output from {host}", "verbose")
                rate_match = re.findall(r"(Log (?:incoming|written) rate):\s+(\d+)/sec", stats_output)
                incoming_rate = written_rate = "0"
                for name, value in rate_match:
                    if "incoming" in name:
                        incoming_rate = value
                    elif "written" in name:
                        written_rate = value
                return parts, incoming_rate, raw_log_rate, written_rate, hostname, model, sn, panos, panorama_ip, config_kb, sec_rules, ha_state, "success"
            else:
                log(f"{host}: incoming logs did not have 5 fields: {parts}", "warn")
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
            log(f"{host}: 'incoming logs' pattern not found in output", "warn")
            rate_match = re.findall(r"(Log (?:incoming|written) rate):\s+(\d+)/sec", stats_output)
            incoming_rate = written_rate = "0"
            for name, value in rate_match:
                if "incoming" in name:
                    incoming_rate = value
                elif "written" in name:
                    written_rate = value
            return ["", "", "", "", ""], incoming_rate, raw_log_rate, written_rate, hostname, model, sn, panos, panorama_ip, config_kb, sec_rules, ha_state, "partial"
    except Exception as e:
        log(f"{host}: {e}", "error")
        return ["", "", "", "", ""], "0", "0", "0", "", "", "", "", "", "", "", "", f"error: {e}"

def process_firewall(host, username, password):
    log(f"Processing host: {host}", "verbose")
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
    log(f"Writing results to CSV for {host}", "info")
    with open(csv_file, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([host, hostname, model, sn, panos, panorama_ip, epoch, now] + counters + [incoming_rate, raw_log_rate, written_rate, config_kb, sec_rules, ha_state, status])
    if not any(counters):
        log(f"{host}: no counters retrieved", "warn")
    log(f"Moving to next host...\n", "verbose")

# --- Updated function to fetch panorama counters ---
def get_panorama_counters(host, username, password):
    log(f"Starting connection to Panorama {host}", "info")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password, timeout=10, banner_timeout=30)
        log(f"Connection successful to Panorama {host}", "info")

        chan = ssh.invoke_shell()
        buffer = ""
        # Wait until the prompt ">" appears
        while True:
            if chan.recv_ready():
                chunk = chan.recv(1024).decode()
                buffer += chunk
                if ">" in buffer:
                    log(f"Prompt detected for Panorama {host}", "verbose")
                    # Disable CLI pager after prompt detected
                    chan.send("set cli pager off\n")
                    time.sleep(1)
                    while chan.recv_ready():
                        chan.recv(65535).decode()
                    log(f"Disabled CLI pager on Panorama {host}", "verbose")
                    break
            time.sleep(0.2)

        # Run system info command
        chan.send('show system info | match "hostname\\|serial\\|model\\|sw-version"\n')
        time.sleep(2)
        sysinfo_output = ""
        while chan.recv_ready():
            sysinfo_output += chan.recv(65535).decode()
        hostname = model = sn = panos = ""
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

        # Run last commit info command
        chan.send('show system last-commit-info | match "Jobid\\|Size"\n')
        time.sleep(2)
        commit_output = ""
        while chan.recv_ready():
            commit_output += chan.recv(65535).decode()
        jobid = ""
        config_size_bytes = 0
        jobid_match = re.search(r"Jobid\s*:\s*(\d+)", commit_output)
        size_match = re.search(r"Committed Total Size\s*:\s*(\d+)", commit_output)
        if jobid_match:
            jobid = jobid_match.group(1)
        if size_match:
            try:
                config_size_bytes = int(size_match.group(1))
            except:
                config_size_bytes = 0
        config_size_MB = round(config_size_bytes / (1024*1024), 2)

        # Run job size command if jobid found
        config_size_MAX = ""
        config_size_PERCENT = ""
        if jobid:
            chan.send(f"show jobs id {jobid} | match \"size\"\n")
            time.sleep(2)
            job_output = ""
            while chan.recv_ready():
                job_output += chan.recv(65535).decode()
            max_match = re.search(r"Maximum recommended configuration size\s*:\s*(\d+)", job_output)
            percent_match = re.search(r"(\d+)%", job_output)
            if max_match:
                config_size_MAX = max_match.group(1)
            if percent_match:
                config_size_PERCENT = percent_match.group(1)

        # Run log-flow counters command
        chan.send('debug log-collector log-flow counters | match "inbound"\n')
        time.sleep(2)
        inbound_output = ""
        while chan.recv_ready():
            inbound_output += chan.recv(65535).decode()
        last_second = last_minute = last_hour = last_day = last_week = ""
        inbound_match = re.search(r"inbound logger:\s*(\d+)/(\d+)/(\d+)/(\d+)/(\d+)", inbound_output)
        if inbound_match:
            last_second = inbound_match.group(1)
            last_minute = inbound_match.group(2)
            last_hour = inbound_match.group(3)
            last_day = inbound_match.group(4)
            last_week = inbound_match.group(5)

        # Run incoming log rate command
        chan.send('debug log-collector log-collection-stats show incoming-logs | match "Incoming log rate"\n')
        time.sleep(2)
        incoming_output = ""
        while chan.recv_ready():
            incoming_output += chan.recv(65535).decode()
        incoming_log_rate = ""
        incoming_match = re.search(r"Incoming log rate\s*=\s*([0-9]*\.?[0-9]+)", incoming_output)
        if incoming_match:
            incoming_log_rate = incoming_match.group(1)

        chan.close()
        ssh.close()

        return host, hostname, model, sn, panos, str(config_size_MB), config_size_PERCENT, config_size_MAX, last_second, last_minute, last_hour, last_day, last_week, incoming_log_rate, int(datetime.now().timestamp()), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "success"
    except Exception as e:
        log(f"Panorama {host}: {e}", "error")
        # Return empty values with error status
        return host, "", "", "", "", "", "", "", "", "", "", "", "", "", int(datetime.now().timestamp()), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), f"error: {e}"

def process_panorama(host, username, password):
    log(f"Processing Panorama host: {host}", "verbose")
    result = get_panorama_counters(host, username, password)
    if result:
        (panorama_ip, hostname, model, sn, panos, config_size_MB, config_size_PERCENT, config_size_MAX, last_second, last_minute, last_hour, last_day, last_week, incoming_log_rate, epoch, now, status) = result
    else:
        panorama_ip = hostname = model = sn = panos = config_size_MB = config_size_PERCENT = config_size_MAX = ""
        last_second = last_minute = last_hour = last_day = last_week = incoming_log_rate = ""
        epoch = int(datetime.now().timestamp())
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = "failed"
    log(f"Writing Panorama results to CSV for {host}", "info")
    with open(panorama_csv_file, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            panorama_ip, hostname, model, sn, panos, epoch, now,
            last_second, last_minute, last_hour, last_day, last_week, incoming_log_rate,
            config_size_MB, config_size_PERCENT, config_size_MAX, status
        ])
    log(f"Moving to next Panorama host...\n", "verbose")

tasks = []
with ThreadPoolExecutor(max_workers=20) as executor:
    for group_name, group_data in config["groups"].items():
        username = group_data["username"]
        password = group_data["password"]
        for host in group_data["hosts"]:
            tasks.append(executor.submit(process_firewall, host, username, password))
    for future in as_completed(tasks):
        future.result()

# Process Panorama hosts similarly
panorama_tasks = []
with ThreadPoolExecutor(max_workers=20) as executor:
    for group_name, group_data in panorama_config["groups"].items():
        username = group_data["username"]
        password = group_data["password"]
        for host in group_data["hosts"]:
            panorama_tasks.append(executor.submit(process_panorama, host, username, password))
    for future in as_completed(panorama_tasks):
        future.result()