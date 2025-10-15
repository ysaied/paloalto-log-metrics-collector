# Palo Alto Networks Automation Toolkit

## 🧩 Overview
This toolkit automates the collection of system information, health metrics, and configuration files from **Palo Alto Firewalls** and **Panorama** appliances.

It replaces the older SSH/Paramiko-based script with a **modern API- and SNMP-driven solution** built entirely in **Python 3**.
All operations are performed using Palo Alto XML APIs over HTTPS with optional SNMP polling, and tasks run in **parallel threads** for efficiency.

---

## 📂 File Descriptions

### 🟢 `panos_auth_to_key.py`
Handles authentication and API key generation.

**Purpose:**
Converts a YAML file containing usernames and passwords into another YAML containing API keys for each device.

**Functions:**
- `get_api_key(host, username, password)` → Fetches the API key from each device.
- Reads `firewalls_auth.yaml` and `panoramas_auth.yaml`.
- Generates `firewalls_apikey.yaml` and `panoramas_apikey.yaml`.

**Usage Example:**
```bash
python3 panos_auth_to_key.py
```
Creates API key YAMLs for use by other scripts.

---

### 🟢 `panos_actions.py`
Provides helper functions for communicating with PAN-OS APIs.

**Functions:**
- `panos_op_cmd(host, api_key, xml_cmd)` → Executes XML API commands and returns structured results.
- `panos_export_cfg(host, api_key)` → Exports the full configuration in XML format, with pretty printing.

**Features:**
- Secure HTTPS requests with timeouts.
- Built-in exception handling and XML-to-dict conversion.
- Reusable across both Firewalls and Panorama.

---

### 🟢 `info_collector.py`
Main information collector — combines API and SNMP data for **Firewalls** and **Panoramas**.

**Key Features:**
- Parallel collection using `ThreadPoolExecutor`.
- Collects data via XML API + SNMP.
- Generates `panos_nodes_data.csv` containing all results.
- Optional configuration export controlled by variable `EXPORT_CONFIG_ENABLED`.

**Collected Data:**
| Source | Category | Examples |
|---------|-----------|-----------|
| API (Firewalls) | System info, HA, Panorama connection, log collector preference, log status, rule count, etc. | `<show><system><info></info></system></show>` |
| API (Panorama) | Device groups, templates, log collectors, commit info, config size/percent, etc. | `<show><devicegroups/></show>`, `<show><log-collector><all/></log-collector></show>` |
| SNMP | Metrics | `.1.3.6.1.4.1.25461.2.1.2.7.1.1.0` (log in-rate), `.1.3.6.1.4.1.25461.2.1.2.6.1.1.0` (Panorama log-per-sec) |

**Output CSV Columns (sample):**
```
node_ip, timestamp, datetime, hostname, devicename, family, model, serial, sw-version,
ha, ha-peer, fw-prma_ip, fw-prma_conn, fw-secrules, config-file_MB, fw-log_status,
fw-log_fwd-rate, fw-log_in-rate, fw-log_wr-rate, fw-lc_count,
prma-dg_count, prma-tmp_count, prma-tstk_count, prma-device_total,
prma-device_connected, prma-device_unconnected, prma-lc_count,
prma-lcgrp_count, prma-lps_all, prma-lps_own, prma-loconfig_MB,
prma-toconfig_MB, prma-config_perc
```

**Parallel Execution Example:**
```bash
python3 info_collector.py
```
Automatically processes all devices listed in `firewalls_apikey.yaml` and `panoramas_apikey.yaml`.

---

### 🟢 `config_collector.py`
Dedicated lightweight script to **export configurations only** from Firewalls.

**Functionality:**
- Uses the same YAML API key input.
- Calls `panos_export_cfg()` for each firewall.
- Saves output under `config/` subdirectory (auto-created if missing).

**Output Format:**
```
config/<hostname>_<YYYYMMDD_HHMM>_cfg.xml
```

**Example:**
```
config/PA-VM-2_20251014_1737_cfg.xml
```

---

## ⚙️ Configuration

Inside `info_collector.py`:

```python
SNMP_COMMUNITY = 'public'          # SNMP community string
EXPORT_CONFIG_ENABLED = False      # Toggle config export on/off
INPUT_FILES = {
    'firewalls': ['firewalls_apikey.yaml'],
    'panoramas': ['panoramas_apikey.yaml']
}
```

---

## 🧮 Execution Flow

1. **Generate API keys**
   ```bash
   python3 panos_auth_to_key.py
   ```

2. **Collect full data (API + SNMP + optional config)**
   ```bash
   python3 info_collector.py
   ```

3. **(Optional) Export only configurations**
   ```bash
   python3 config_collector.py
   ```

---

## 🧰 Dependencies

Install via APT and pip:

```bash
sudo apt update
sudo apt install -y python3-yaml python3-pysnmp4 python3-pyasn1 python3-pyasn1-modules python3-pyasyncore
pip install requests xmltodict
```

---

## 🧾 Logging

- **INFO** → workflow events (collection progress, export success)
- **ERROR** → SNMP/API connection failures
- All logs include timestamps and severity levels.

---

## ⚡ Parallelism

- The collector runs concurrently using `ThreadPoolExecutor(max_workers=20)`.
- Handles hundreds of nodes simultaneously.
- Reduces overall execution time drastically.

---

## 📁 Output Summary

| File | Description |
|------|--------------|
| `panos_nodes_data.csv` | Combined operational data for all nodes |
| `config/*.xml` | Individual firewall configuration exports |
| `*_apikey.yaml` | API key credentials (generated from auth) |

---

**Last updated:** 2025-10-15 04:36:27
