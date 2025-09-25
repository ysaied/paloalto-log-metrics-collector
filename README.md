# Palo Alto Firewall Log Counters Collector

This script connects to multiple Palo Alto firewalls over SSH, runs a set of operational and debug commands, and stores the results into a CSV file.  
It is designed for environments with many firewalls (e.g., 300+) and supports parallel execution.

---

## 🔹 What the Script Does

For each firewall, the script:
1. Connects via SSH (using credentials defined in `firewalls.yaml`).
2. Runs the following commands:
   - `debug log-receiver log-flow counters | match "incoming logs"`
   - `debug log-receiver statistics | match "Log incoming rate|Log written rate"`
   - `debug log-receiver rawlog_fwd stats global show | match "Total forwarding rate"`
   - `show system info | match "hostname|serial|model"`
   - `show panorama-status | match "Panorama Server 1"`
   - `show management-server last-committed config-size | match "bytes"`
   - `show resource limit policies | match "Security"`
3. Extracts:
   - Hostname, Model, Serial Number
   - Panorama IP (if configured)
   - Config size in KB
   - Number of security rules
   - Log counters (last second/minute/hour/day/week)
   - Log incoming rate, written rate, and raw log forwarding rate
4. Appends results into a CSV file `fw_logcounters.csv` with a timestamp.

---

## 🔹 CSV Output Format

The CSV file has the following columns:

```
fw_ip, hostname, model, sn, panorama_ip, timestamp, datetime,
last-second, last-minute, last-hour, last-day, last-week,
incoming_log-rate, raw_log-rate, written_log-rate,
config-size_KB, sec-rules
```

---

## 🔹 YAML Inventory Structure

Firewalls are grouped in `firewalls.yaml`. Each group defines credentials and a list of hosts.

Example:

```yaml
groups:
  group1:
    username: admin
    password: password123
    hosts:
      - 192.168.2.18
      - 192.168.2.35
  group2:
    username: another_admin
    password: secret456
    hosts:
      - 10.10.10.1
      - 10.10.10.2
```

This allows multiple groups of firewalls with different credentials to be managed in a single run.

---

## 🔹 Usage

Run the script:

```bash
python main.py
```

To schedule it every 30 minutes, add a cronjob:

```bash
*/30 * * * * /usr/bin/python3 /path/to/main.py >> /var/log/fw_logcounters.log 2>&1
```

---

## 🔹 Requirements

- Python 3.8+
- Dependencies:
  - `paramiko`
  - `pyyaml`
