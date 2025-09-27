# Palo Alto Log Metrics Collector

This repository provides Python scripts to collect log-related metrics from **Palo Alto Firewalls** and **Panorama appliances** using SSH (Paramiko).  
The collected data is exported into CSV files for further analysis and capacity planning.

---

## 🔹 Features

### Firewall Data Collection (`fw_logcounters.csv`)
For each firewall defined in `firewalls.yaml`, the script collects:

- **Basic Info**:  
  `fw_ip, hostname, model, sn, panos, panorama_ip, timestamp, datetime`
- **Log Counters**:  
  `last-second, last-minute, last-hour, last-day, last-week`
- **Log Rates**:  
  `incoming_log-rate, raw_log-rate, written_log-rate`
- **System / Config Info**:  
  `config-size_KB, sec-rules, HA, status`

### Panorama Data Collection (`panorama_logcounters.csv`)
For each Panorama defined in `panoramas.yaml`, the script collects:

- **Basic Info**:  
  `panorama_ip, hostname, model, sn, panos, timestamp, datetime`
- **Log Counters**:  
  `last-second, last-minute, last-hour, last-day, last-week`
- **Log Rates**:  
  `incoming_log-rate`
- **Config Sizes**:  
  `config-size_MB, config-size_PERCENT, config-size_MAX`
- **Status**

---

## 🔹 Enhancements Added

- Automatic **`set cli pager off`** after login to avoid paged CLI output.
- **Verbose and Info logging modes** (`VERBOSE` flag).  
  - `[info]` → basic connectivity and results  
  - `[verbose]` → detailed step-by-step command execution and parsing
- **Parallel SSH execution** with `ThreadPoolExecutor` to handle hundreds of firewalls efficiently.
- **Error handling** for unreachable devices or wrong credentials (recorded in CSV `status` column).
- **Improved HA detection** → checks for both `"Active"` and `"Passive"` in HA state.
- **Regex fixes for Panorama**:  
  - `inbound logger:` instead of `inbound logs`  
  - `Incoming log rate =` instead of `Incoming log rate`

---

## 🔹 YAML File Structures

### Firewalls (`firewalls.yaml`)
```yaml
groups:
  group1:
    username: admin
    password: password123
    hosts:
      - 192.168.2.18
      - 192.168.2.19
  group2:
    username: another_admin
    password: secret456
    hosts:
      - 192.168.2.20
```

### Panoramas (`panoramas.yaml`)
```yaml
groups:
  panorama_group1:
    username: admin
    password: password123
    hosts:
      - 192.168.2.30
      - 192.168.2.31
```

---

## 🔹 Usage

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the script:
   ```bash
   python main.py
   ```

3. Results:
   - Firewall data → `fw_logcounters.csv`
   - Panorama data → `panorama_logcounters.csv`

---

## 🔹 Example CSV Output

### Firewall
```
fw_ip,hostname,model,sn,panos,panorama_ip,timestamp,datetime,last-second,last-minute,last-hour,last-day,last-week,incoming_log-rate,raw_log-rate,written_log-rate,config-size_KB,sec-rules,HA,status
192.168.2.18,PA-VM-1,PA-VM,007900000507637,11.0.3,192.168.2.31,1695800000,2025-09-27 13:42:25,7,838,32544,64634,64634,0,1,3,66,3,False,success
```

### Panorama
```
panorama_ip,hostname,model,sn,panos,timestamp,datetime,last-second,last-minute,last-hour,last-day,last-week,incoming_log-rate,config-size_MB,config-size_PERCENT,config-size_MAX,status
192.168.2.30,Panorama-1,M-200,007900000112233,11.0.3,1695800010,2025-09-27 13:45:25,0,230,14763,119912,119912,4.33,20.2,16,120,error: auth failed
```

---

## 🔹 License
MIT License
