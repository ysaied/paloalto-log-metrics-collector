#!/usr/bin/env python3
# pip install PyYAML pysnmp==4.4.12 pyasn1==0.4.8 pyasn1-modules==0.2.8 pyasyncore
# sudo apt update
# sudo apt install -y python3-yaml python3-pysnmp4 python3-pyasn1 python3-pyasn1-modules python3-pyasyncore

import logging
from panos_actions import panos_op_cmd,panos_export_cfg
import requests
import yaml
import csv
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from pysnmp.hlapi import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd,
)

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# === CONFIGURATION VARIABLES ===
SNMP_COMMUNITY = "ysaied"  # SNMP community string
EXPORT_CONFIG_ENABLED = False  # Toggle configuration export for firewalls

# Default list of YAML files to load, now as dict by group type
INPUT_FILES = {
    "firewalls": ["firewalls_apikey.yaml"],
    "panoramas": ["panoramas_apikey.yaml"]
}

def snmp_pull_firewall(host, community):
    # Firewall-specific SNMP OIDs
    oids = [
        ".1.3.6.1.4.1.25461.2.1.2.7.1.1.0",
        ".1.3.6.1.4.1.25461.2.1.2.7.1.2.0"
    ]
    result = {
        "fw-log_in-rate": None,
        "fw-log_wr-rate": None
    }
    for oid in oids:
        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=1),  # SNMP v2c
                UdpTransportTarget((host, 161), timeout=2, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            if errorIndication:
                logging.error(f"SNMP error on {host} for {oid}: {errorIndication}")
            elif errorStatus:
                logging.error(f"SNMP error on {host} for {oid}: {errorStatus.prettyPrint()}")
            else:
                for varBind in varBinds:
                    if oid == ".1.3.6.1.4.1.25461.2.1.2.7.1.1.0":
                        try:
                            result["fw-log_in-rate"] = int(varBind[1])
                        except Exception:
                            result["fw-log_in-rate"] = None
                    elif oid == ".1.3.6.1.4.1.25461.2.1.2.7.1.2.0":
                        try:
                            result["fw-log_wr-rate"] = int(varBind[1])
                        except Exception:
                            result["fw-log_wr-rate"] = None
        except Exception as e:
            logging.error(f"SNMP exception on {host}: {e}")
    return result


# Panorama-specific SNMP pull for prma-lps_own
def snmp_pull_panorama(host, community):
    oid = ".1.3.6.1.4.1.25461.2.1.2.6.1.1.0"
    result = {"prma-lps_own": None}
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((host, 161), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        if errorIndication:
            logging.error(f"SNMP error on {host} for {oid}: {errorIndication}")
        elif errorStatus:
            logging.error(f"SNMP error on {host} for {oid}: {errorStatus.prettyPrint()}")
        else:
            for varBind in varBinds:
                try:
                    result["prma-lps_own"] = int(varBind[1])
                except Exception:
                    result["prma-lps_own"] = None
    except Exception as e:
        logging.error(f"SNMP exception on {host}: {e}")
    return result



def process_host(host, api_key, group_type):
    if not api_key or str(api_key).lower() == "null":
        return None

    # Define command groups
    fw_cmds = {
        "resource_limit_cmd": "<show><resource><limit><policies/></limit></resource></show>",
        "logging_status_cmd": "<show><logging-status></logging-status></show>",
        "log_receiver_counters_cmd": "<debug><log-receiver><rawlog_fwd><stats><global><show/></global></stats></rawlog_fwd></log-receiver></debug>",
        "log_receiver_statistics_cmd": "<debug><log-receiver><statistics/></log-receiver></debug>",
        "last_committed_cmd": "<show><management-server><last-committed><config-size/></last-committed></management-server></show>",
        "panorama_status_cmd": "<show><panorama-status></panorama-status></show>",
        "log_collector_preference_cmd": "<show><log-collector><preference-list></preference-list></log-collector></show>",
    }
    panorama_cmds = {
        "devicegroups_cmd": "<show><devicegroups/></show>",
        "templates_cmd": "<show><templates/></show>",
        "template_stack_cmd": "<show><template-stack/></show>",
        "devices_all_cmd": "<show><devices><all/></devices></show>",
        "last_commit_info_cmd": "<show><system><last-commit-info/></system></show>",
        "log_collectors_all_cmd": "<show><log-collector><all/></log-collector></show>",
        "log_collector_groups_all_cmd": "<show><log-collector-group><all/></log-collector-group></show>"
        # Removed "logging_status_all_cmd"
    }
    common_cmds = {
        "xml_cmd": "<show><system><info></info></system></show>",
        "ha_state_cmd": "<show><high-availability><state/></high-availability></show>"
    }

    api_groups = {
        "firewalls": fw_cmds,
        "panoramas": panorama_cmds,
        "common": common_cmds
    }

    # Always run common commands with error handling
    try:
        sysinfo_result = panos_op_cmd(host, api_key, common_cmds["xml_cmd"])
    except requests.exceptions.RequestException as e:
        logging.error(f"API error on {host}: {e}")
        sysinfo_result = None
    except Exception as e:
        logging.error(f"API error on {host}: {e}")
        sysinfo_result = None
    try:
        ha_state_result = panos_op_cmd(host, api_key, common_cmds["ha_state_cmd"])
    except requests.exceptions.RequestException as e:
        logging.error(f"API error on {host}: {e}")
        ha_state_result = None
    except Exception as e:
        logging.error(f"API error on {host}: {e}")
        ha_state_result = None

    # Run fw commands if group_type is firewalls
    if group_type == "firewalls":
        try:
            resource_limit_result = panos_op_cmd(host, api_key, fw_cmds["resource_limit_cmd"])
        except requests.exceptions.RequestException as e:
            logging.error(f"API error on {host}: {e}")
            resource_limit_result = None
        except Exception as e:
            logging.error(f"API error on {host}: {e}")
            resource_limit_result = None
        try:
            logging_status_result = panos_op_cmd(host, api_key, fw_cmds["logging_status_cmd"])
        except requests.exceptions.RequestException as e:
            logging.error(f"API error on {host}: {e}")
            logging_status_result = None
        except Exception as e:
            logging.error(f"API error on {host}: {e}")
            logging_status_result = None
        try:
            log_receiver_counters_result = panos_op_cmd(host, api_key, fw_cmds["log_receiver_counters_cmd"])
        except requests.exceptions.RequestException as e:
            logging.error(f"API error on {host}: {e}")
            log_receiver_counters_result = None
        except Exception as e:
            logging.error(f"API error on {host}: {e}")
            log_receiver_counters_result = None
        try:
            log_receiver_statistics_result = panos_op_cmd(host, api_key, fw_cmds["log_receiver_statistics_cmd"])
        except requests.exceptions.RequestException as e:
            logging.error(f"API error on {host}: {e}")
            log_receiver_statistics_result = None
        except Exception as e:
            logging.error(f"API error on {host}: {e}")
            log_receiver_statistics_result = None
        try:
            last_committed_result = panos_op_cmd(host, api_key, fw_cmds["last_committed_cmd"])
        except requests.exceptions.RequestException as e:
            logging.error(f"API error on {host}: {e}")
            last_committed_result = None
        except Exception as e:
            logging.error(f"API error on {host}: {e}")
            last_committed_result = None
        try:
            panorama_result = panos_op_cmd(host, api_key, fw_cmds["panorama_status_cmd"])
        except requests.exceptions.RequestException as e:
            logging.error(f"API error on {host}: {e}")
            panorama_result = None
        except Exception as e:
            logging.error(f"API error on {host}: {e}")
            panorama_result = None
        # Run log_collector_preference_cmd for firewalls only
        try:
            log_collector_preference_result = panos_op_cmd(host, api_key, fw_cmds["log_collector_preference_cmd"])
        except requests.exceptions.RequestException as e:
            logging.error(f"API error on {host}: {e}")
            log_collector_preference_result = None
        except Exception as e:
            logging.error(f"API error on {host}: {e}")
            log_collector_preference_result = None
        # Determine fw_lc_count after fetching log_collector_preference_result
        fw_lc_count = 0
        if isinstance(log_collector_preference_result, dict) and log_collector_preference_result.get('@status') == 'success':
            pref = log_collector_preference_result.get('result', {}).get('preference_list', {})
            # Handle if it's a dict with pref-list or status
            if isinstance(pref, dict):
                # Check for direct "status": "Log Collector Preference List does not exist"
                if pref.get('status') == 'Log Collector Preference List does not exist':
                    fw_lc_count = 0
                elif 'pref-list' in pref and isinstance(pref['pref-list'], dict):
                    if 'ipaddr' in pref['pref-list'] and isinstance(pref['pref-list']['ipaddr'], list):
                        fw_lc_count = len(pref['pref-list']['ipaddr'])
                    elif 'serial_number' in pref['pref-list'] and isinstance(pref['pref-list']['serial_number'], list):
                        fw_lc_count = len(pref['pref-list']['serial_number'])
                    else:
                        fw_lc_count = 1
            # Handle if it's a list with multiple entries
            elif isinstance(pref, list):
                for entry in pref:
                    if isinstance(entry, dict):
                        # If any entry has "status": "Log Collector Preference List does not exist", set to 0 and break
                        if entry.get('status') == 'Log Collector Preference List does not exist':
                            fw_lc_count = 0
                            break
                        if 'pref-list' in entry:
                            pl = entry['pref-list']
                            if isinstance(pl, dict):
                                if 'ipaddr' in pl and isinstance(pl['ipaddr'], list):
                                    fw_lc_count = len(pl['ipaddr'])
                                elif 'serial_number' in pl and isinstance(pl['serial_number'], list):
                                    fw_lc_count = len(pl['serial_number'])
                                else:
                                    fw_lc_count = 1

        # --- EXPORT CONFIGURATION LOGIC FOR FIREWALLS ---
        # Export configuration after all API calls for firewalls
        if EXPORT_CONFIG_ENABLED and group_type == "firewalls":
            try:
                xml_content = panos_export_cfg(host, api_key)
                # Get sysinfo for nodename (fall back to host if needed)
                try:
                    sysinfo = sysinfo_result.get('result', {}).get('system', {}) if isinstance(sysinfo_result, dict) else {}
                except Exception:
                    sysinfo = {}
                nodename = sysinfo.get('hostname', host)
                # Current date/time in YYYYMMDD_HHMM
                dt_str = datetime.now().strftime("%Y%m%d_%H%M")
                filename = f"{nodename}_{dt_str}_cfg.xml"
                # Save to 'config' subdirectory under script directory
                script_dir = os.path.dirname(os.path.abspath(__file__))
                config_dir = os.path.join(script_dir, "config")
                if not os.path.exists(config_dir):
                    os.makedirs(config_dir)
                filepath = os.path.join(config_dir, filename)
                if xml_content:
                    with open(filepath, "wb") as f:
                        f.write(xml_content)
                    logging.info(f"Config exported for {nodename} ({host}) to {filepath}")
                else:
                    logging.error(f"Failed to export config for {nodename} ({host}) - no content returned")
            except Exception as e:
                logging.error(f"Error exporting config for {host}: {e}")
    else:
        resource_limit_result = None
        logging_status_result = None
        log_receiver_counters_result = None
        log_receiver_statistics_result = None
        last_committed_result = None
        panorama_result = None

    # Run panorama commands if group_type is panoramas
    if group_type == "panoramas":
        panorama_result = None
        try:
            devicegroups_result = panos_op_cmd(host, api_key, panorama_cmds["devicegroups_cmd"])
        except requests.exceptions.RequestException as e:
            logging.error(f"API error on {host}: {e}")
            devicegroups_result = None
        except Exception as e:
            logging.error(f"API error on {host}: {e}")
            devicegroups_result = None
        try:
            templates_result = panos_op_cmd(host, api_key, panorama_cmds["templates_cmd"])
        except requests.exceptions.RequestException as e:
            logging.error(f"API error on {host}: {e}")
            templates_result = None
        except Exception as e:
            logging.error(f"API error on {host}: {e}")
            templates_result = None
        try:
            template_stack_result = panos_op_cmd(host, api_key, panorama_cmds["template_stack_cmd"])
        except requests.exceptions.RequestException as e:
            logging.error(f"API error on {host}: {e}")
            template_stack_result = None
        except Exception as e:
            logging.error(f"API error on {host}: {e}")
            template_stack_result = None
        try:
            devices_all_result = panos_op_cmd(host, api_key, panorama_cmds["devices_all_cmd"])
        except requests.exceptions.RequestException as e:
            logging.error(f"API error on {host}: {e}")
            devices_all_result = None
        except Exception as e:
            logging.error(f"API error on {host}: {e}")
            devices_all_result = None
        try:
            last_commit_info_result = panos_op_cmd(host, api_key, panorama_cmds["last_commit_info_cmd"])
        except requests.exceptions.RequestException as e:
            logging.error(f"API error on {host}: {e}")
            last_commit_info_result = None
        except Exception as e:
            logging.error(f"API error on {host}: {e}")
            last_commit_info_result = None

        # Fetch new Panorama commands (no debug prints)
        try:
            log_collectors_all_result = panos_op_cmd(host, api_key, panorama_cmds["log_collectors_all_cmd"])
        except requests.exceptions.RequestException as e:
            logging.error(f"API error on {host}: {e}")
            log_collectors_all_result = None
        except Exception as e:
            logging.error(f"API error on {host}: {e}")
            log_collectors_all_result = None

        try:
            log_collector_groups_all_result = panos_op_cmd(host, api_key, panorama_cmds["log_collector_groups_all_cmd"])
        except requests.exceptions.RequestException as e:
            logging.error(f"API error on {host}: {e}")
            log_collector_groups_all_result = None
        except Exception as e:
            logging.error(f"API error on {host}: {e}")
            log_collector_groups_all_result = None

        # Compute prma_lc_count and extract serial numbers for log collectors
        prma_lc_count = None
        log_collector_serials = []
        if isinstance(log_collectors_all_result, dict) and log_collectors_all_result.get('@status') == 'success':
            result = log_collectors_all_result.get('result')
            if result is None or result == "No collectors found":
                prma_lc_count = 0
            elif isinstance(result, dict) and 'log-collector' in result:
                lc = result['log-collector']
                if isinstance(lc, dict) and 'entry' in lc:
                    entry = lc['entry']
                    if isinstance(entry, list):
                        prma_lc_count = len(entry)
                        for e in entry:
                            serial = e.get('serial', None)
                            if serial:
                                log_collector_serials.append(serial)
                    elif isinstance(entry, dict):
                        prma_lc_count = 1
                        serial = entry.get('serial', None)
                        if serial:
                            log_collector_serials.append(serial)
                    else:
                        prma_lc_count = 0
                else:
                    prma_lc_count = 0
            else:
                prma_lc_count = 0
        else:
            prma_lc_count = None

        # For each log collector serial, run the log-collector show command and sum logs-per-sec
        prma_lps_all = 0
        for serial in log_collector_serials:
            try:
                lc_result = panos_op_cmd(host, api_key, f"<show><log-collector><serial-number>{serial}</serial-number></log-collector></show>")
                # Extract logs-per-sec value and sum it
                lps_val = None
                if (
                    isinstance(lc_result, dict)
                    and 'result' in lc_result
                    and 'log-collector' in lc_result['result']
                    and 'entry' in lc_result['result']['log-collector']
                ):
                    entry = lc_result['result']['log-collector']['entry']
                    # entry can be dict or list, but for single serial it's likely dict
                    if isinstance(entry, dict):
                        lps_str = entry.get('logs-per-sec')
                        try:
                            lps_val = int(lps_str)
                        except Exception:
                            lps_val = 0
                    elif isinstance(entry, list):
                        # Unlikely, but sum all
                        for ent in entry:
                            lps_str = ent.get('logs-per-sec')
                            try:
                                prma_lps_all += int(lps_str)
                            except Exception:
                                pass
                        lps_val = None  # already summed
                if lps_val is not None:
                    prma_lps_all += lps_val
            except requests.exceptions.RequestException as e:
                logging.error(f"API error on {host} for log collector serial {serial}: {e}")
            except Exception as e:
                logging.error(f"API error on {host} for log collector serial {serial}: {e}")

        # Compute prma_lcgrp_count
        prma_lcgrp_count = None
        if isinstance(log_collector_groups_all_result, dict) and log_collector_groups_all_result.get('@status') == 'success':
            result = log_collector_groups_all_result.get('result', {})
            lcgrp = result.get('log-collector-group')
            if lcgrp is None:
                prma_lcgrp_count = 0
            elif isinstance(lcgrp, dict) and 'entry' in lcgrp:
                entry = lcgrp['entry']
                if isinstance(entry, list):
                    prma_lcgrp_count = len(entry)
                elif isinstance(entry, dict):
                    prma_lcgrp_count = 1
                else:
                    prma_lcgrp_count = 0
            else:
                prma_lcgrp_count = 0
        else:
            prma_lcgrp_count = None

        # SNMP pull for Panorama-specific OID
        snmp_panorama_data = snmp_pull_panorama(host, SNMP_COMMUNITY)
        prma_lps_own = snmp_panorama_data.get("prma-lps_own")

    fw_log_fwd_rate = ""
    if group_type == "firewalls" and isinstance(log_receiver_counters_result, dict) and log_receiver_counters_result.get('@status') == 'success':
        res_text = log_receiver_counters_result.get('result', '')
        if isinstance(res_text, str):
            import re
            m = re.search(r'Total forwarding rate\s*:\s*(\d+)', res_text)
            if m:
                fw_log_fwd_rate = int(m.group(1))

    # Parse logging status
    fw_status = ""
    if group_type == "firewalls" and isinstance(logging_status_result, dict) and logging_status_result.get('@status') == 'success':
        log_res = logging_status_result.get('result', {}).get('show-logging-status', {})
        conn_info = log_res.get('Conn-Info', {})
        text_block = conn_info.get('#text', '')
        if isinstance(text_block, str):
            import re
            matches = re.findall(r'Connection Status\s*:\s*.*Active.*\nRate\s*:\s*(\d+)\s*logs/sec', text_block)
            if matches:
                fw_status = sum(int(m) for m in matches)

    ha_value = ""
    ha_peer = ""
    if isinstance(ha_state_result, dict) and ha_state_result.get('@status') == 'success':
        res = ha_state_result.get('result', {})
        if isinstance(res, dict):
            ha_value = res.get('enabled', '')
            if ha_value == 'yes':
                group_info = res.get('group', {})
                peer_info = group_info.get('peer-info', {})
                ha_peer = peer_info.get('mgmt-ip', '')

    sec_rules = ""
    if group_type == "firewalls" and isinstance(resource_limit_result, dict) and resource_limit_result.get('@status') == 'success':
        res_text = resource_limit_result.get('result', '')
        if isinstance(res_text, str):
            import re
            m = re.search(r'Security\s+(\d+)', res_text)
            if m:
                sec_rules = int(m.group(1))

    # Extract required fields from sysinfo_result
    try:
        sysinfo = sysinfo_result.get('result', {}).get('system', {}) if isinstance(sysinfo_result, dict) else {}
        # Default values for panorama fields
        panorama_ip = ""
        panorama_connected = ""
        # Panorama-specific fields
        prma_dg_count = None
        prma_tmp_count = None
        prma_tstk_count = None
        prma_device_total = None
        prma_device_connected = None
        prma_device_unconnected = None
        fw_config_MB = ""
        last_job_id = ""

        # Try to extract Panorama info if possible
        if group_type == "panoramas" and isinstance(panorama_result, dict):
            pano_res = panorama_result.get('result', '')
            if (isinstance(pano_res, str)
                and "Panorama Server" in pano_res
                and "Connected     : yes" in pano_res):
                import re
                m = re.search(r'Panorama Server 1 *: *([^\s]+)', pano_res)
                if m:
                    panorama_ip = m.group(1)
                panorama_connected = "yes"
        # For firewalls, parse panorama_result for panorama IP and connection status
        if group_type == "firewalls" and isinstance(panorama_result, dict) and panorama_result.get('@status') == 'success':
            res_text = panorama_result.get('result', '')
            if isinstance(res_text, str):
                import re
                if "Panorama Server" in res_text:
                    m = re.search(r'Panorama Server 1 *: *([^\s]+)', res_text)
                    if m:
                        panorama_ip = m.group(1)
                    if "Connected     : yes" in res_text:
                        panorama_connected = "yes"
                    else:
                        panorama_connected = "no"
                elif "Cloud management is enabled" in res_text:
                    panorama_ip = ""
                    panorama_connected = ""

        # --- Panorama-specific API parsing ---
        # Defaults for new Panorama config size/percent fields
        prma_loconfig_MB = 0
        prma_toconfig_MB = 0
        prma_config_perc = 0

        if group_type == "panoramas":
            # 1. Device Groups Count
            if isinstance(devicegroups_result, dict) and devicegroups_result.get('@status') == 'success':
                dg_entry = devicegroups_result.get('result', {}).get('devicegroups', {}).get('entry', [])
                if isinstance(dg_entry, dict):
                    prma_dg_count = 1
                elif isinstance(dg_entry, list):
                    prma_dg_count = len(dg_entry)
                else:
                    prma_dg_count = 0
            else:
                prma_dg_count = None

            # 2. Templates and Template-Stack Count
            prma_tmp_count = 0
            prma_tstk_count = 0
            if isinstance(templates_result, dict) and templates_result.get('@status') == 'success':
                tmpl_entry = templates_result.get('result', {}).get('templates', {}).get('entry', [])
                if isinstance(tmpl_entry, dict):
                    # Single entry
                    stack_val = tmpl_entry.get('template-stack', '')
                    if stack_val == "yes":
                        prma_tstk_count += 1
                    elif stack_val == "no":
                        prma_tmp_count += 1
                elif isinstance(tmpl_entry, list):
                    for ent in tmpl_entry:
                        stack_val = ent.get('template-stack', '')
                        if stack_val == "yes":
                            prma_tstk_count += 1
                        elif stack_val == "no":
                            prma_tmp_count += 1
            else:
                prma_tmp_count = None
                prma_tstk_count = None

            # 3. Devices All
            prma_device_total = 0
            prma_device_connected = 0
            prma_device_unconnected = 0
            if isinstance(devices_all_result, dict) and devices_all_result.get('@status') == 'success':
                dev_entry = devices_all_result.get('result', {}).get('devices', {}).get('entry', [])
                # entry can be dict or list
                dev_list = []
                if isinstance(dev_entry, dict):
                    dev_list = [dev_entry]
                elif isinstance(dev_entry, list):
                    dev_list = dev_entry
                prma_device_total = len(dev_list)
                for dev in dev_list:
                    if dev.get('connected', '') == "yes":
                        prma_device_connected += 1
                    elif dev.get('connected', '') == "no":
                        prma_device_unconnected += 1
            else:
                prma_device_total = None
                prma_device_connected = None
                prma_device_unconnected = None

            # 4. Last Commit Info
            if isinstance(last_commit_info_result, dict) and last_commit_info_result.get('@status') == 'success':
                lcinfo = last_commit_info_result.get('result', {}).get('last-commited-info', {})
                config_size = lcinfo.get('configSize')
                if config_size is not None:
                    try:
                        fw_config_MB = round(int(config_size) / (1024 * 1024), 2)
                    except Exception:
                        fw_config_MB = ""
                last_job_id = lcinfo.get('jobid', "")
            else:
                fw_config_MB = ""
                last_job_id = ""

            # 5. Jobs by Job ID
            if last_job_id:
                try:
                    jobs_result = panos_op_cmd(host, api_key, f"<show><jobs><id>{last_job_id}</id></jobs></show>")
                    # Parse for config size and percent if available
                    if (
                        isinstance(jobs_result, dict)
                        and jobs_result.get('@status') == 'success'
                        and 'result' in jobs_result
                        and 'job' in jobs_result['result']
                    ):
                        job = jobs_result['result']['job']
                        details = job.get('details', {})
                        lines = details.get('line', [])
                        if isinstance(lines, str):
                            lines = [lines]
                        import re
                        for line in lines:
                            # Local configuration size: 33 KB
                            m1 = re.match(r"Local configuration size:\s*([\d.]+)\s*(KB|MB)", line)
                            if m1:
                                val = float(m1.group(1))
                                unit = m1.group(2)
                                if unit == "KB":
                                    prma_loconfig_MB = round(val / 1024, 2)
                                else:
                                    prma_loconfig_MB = round(val, 2)
                            # Total configuration size(local, predefined): 20 MB
                            m2 = re.match(r"Total configuration size.*:\s*([\d.]+)\s*(KB|MB)", line)
                            if m2:
                                val = float(m2.group(1))
                                unit = m2.group(2)
                                if unit == "KB":
                                    prma_toconfig_MB = round(val / 1024, 2)
                                else:
                                    prma_toconfig_MB = round(val, 2)
                            # Maximum recommended configuration size: 120 MB (16% configured)
                            m3 = re.match(r"Maximum recommended configuration size:.*\((\d+)% configured\)", line)
                            if m3:
                                prma_config_perc = int(m3.group(1))
                except requests.exceptions.RequestException as e:
                    logging.error(f"API error on {host}: {e}")
                    jobs_result = None
                except Exception as e:
                    logging.error(f"API error on {host}: {e}")
                    jobs_result = None

        # --- fw_config_MB calculation for firewalls ---
        if group_type == "firewalls":
            if isinstance(last_committed_result, dict):
                lc_result = last_committed_result.get('result', '')
                if isinstance(lc_result, str) and lc_result.strip().endswith("bytes"):
                    import re
                    m = re.match(r'(\d+)\s*bytes', lc_result.strip())
                    if m:
                        try:
                            fw_config_MB = round(int(m.group(1)) / (1024 * 1024), 2)
                        except Exception:
                            fw_config_MB = ""

        if group_type == "firewalls":
            snmp_data = snmp_pull_firewall(host, SNMP_COMMUNITY)
            fw_log_in_rate = snmp_data.get('fw-log_in-rate')
            fw_log_wr_rate = snmp_data.get('fw-log_wr-rate')
        else:
            fw_log_in_rate = None
            fw_log_wr_rate = None

        row = {
            'node_ip': sysinfo.get('ip-address', host),
            'timestamp': int(time.time()),
            'datetime': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'hostname': sysinfo.get('hostname', ''),
            'devicename': sysinfo.get('devicename', ''),
            'family': sysinfo.get('family', ''),
            'model': sysinfo.get('model', ''),
            'serial': sysinfo.get('serial', ''),
            'sw-version': sysinfo.get('sw-version', ''),
            'ha': ha_value,
            'ha-peer': ha_peer,
            'fw-prma_ip': panorama_ip,
            'fw-prma_conn': panorama_connected,
            'fw-secrules': sec_rules,
            'fw-config_MB': fw_config_MB,
            'fw-log_status': fw_status,
            'fw-log_fwd-rate': fw_log_fwd_rate,
            'fw-log_in-rate': fw_log_in_rate,
            'fw-log_wr-rate': fw_log_wr_rate,
        }
        # For firewalls, add fw-lc_count
        if group_type == "firewalls":
            row['fw-lc_count'] = fw_lc_count
        # Add Panorama fields if group_type is panoramas
        if group_type == "panoramas":
            row['prma-dg_count'] = prma_dg_count
            row['prma-tmp_count'] = prma_tmp_count
            row['prma-tstk_count'] = prma_tstk_count
            row['prma-device_total'] = prma_device_total
            row['prma-device_connected'] = prma_device_connected
            row['prma-device_unconnected'] = prma_device_unconnected
            # Add log collector and log collector group counts
            row['prma-lc_count'] = prma_lc_count
            row['prma-lcgrp_count'] = prma_lcgrp_count
            # Add prma-lps_all (total logs-per-sec across all log collectors)
            row['prma-lps_all'] = prma_lps_all
            # Add prma-lps_own from SNMP
            row['prma-lps_own'] = prma_lps_own
            # Add Panorama config size/percent fields
            row['prma-loconfig_MB'] = prma_loconfig_MB
            row['prma-toconfig_MB'] = prma_toconfig_MB
            row['prma-config_perc'] = prma_config_perc
        return row
    except Exception as e:
        logging.error(f"    Error extracting info for {host}: {e}")
        return None

def load_yaml_files(file_list):
    data = {}
    for file_name in file_list:
        with open(file_name, 'r') as f:
            loaded = yaml.safe_load(f)
            if loaded:
                for group, group_data in loaded.get("groups", {}).items():
                    if group not in data:
                        data[group] = {}
                    api_keys = group_data.get("api_keys", {})
                    for host, api_key in api_keys.items():
                        data[group][host] = api_key
    return data

if __name__ == "__main__":
    # Accumulate rows from all input files
    rows = []
    for group_type, input_files in INPUT_FILES.items():
        for input_file in input_files:
            # Load YAML file
            with open(input_file, 'r') as f:
                loaded = yaml.safe_load(f)
            all_data = {}
            if loaded:
                for group, group_data in loaded.get("groups", {}).items():
                    if group not in all_data:
                        all_data[group] = {}
                    api_keys = group_data.get("api_keys", {})
                    for host, api_key in api_keys.items():
                        all_data[group][host] = api_key

            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = []
                for group, hosts in all_data.items():
                    logging.info(f"Group: {group}")
                    for host, api_key in hosts.items():
                        logging.info(f"  Host: {host}")
                        futures.append(executor.submit(process_host, host, api_key, group_type))
                for future in as_completed(futures):
                    row = future.result()
                    if row:
                        rows.append(row)

    # Write all accumulated rows to a single CSV file
    csv_filename = "panos_nodes_data.csv"
    if rows:
        # Gather all fieldnames from all rows for dynamic CSV columns
        all_fieldnames = set()
        for row in rows:
            all_fieldnames.update(row.keys())
        # Ensure a consistent order for main columns, then add any extras
        main_fields = [
            'node_ip',
            'timestamp',
            'datetime',
            'hostname',
            'devicename',
            'family',
            'model',
            'serial',
            'sw-version',
            'ha',
            'ha-peer',
            'fw-prma_ip',
            'fw-prma_conn',
            'fw-secrules',
            'fw-config_MB',
            'fw-log_status',
            'fw-log_fwd-rate',
            'fw-log_in-rate',
            'fw-log_wr-rate',
            'fw-lc_count',
            'prma-dg_count',
            'prma-tmp_count',
            'prma-tstk_count',
            'prma-device_total',
            'prma-device_connected',
            'prma-device_unconnected',
            'prma-lc_count',
            'prma-lcgrp_count',
            'prma-lps_all',
            'prma-lps_own',
            'prma-loconfig_MB',
            'prma-toconfig_MB',
            'prma-config_perc'
        ]
        # Add any extra fields not in main_fields
        all_fieldnames = list(main_fields) + [f for f in all_fieldnames if f not in main_fields]
        file_exists = os.path.isfile(csv_filename)
        with open(csv_filename, 'a', newline='') as csvfile:
            writer = csv.DictWriter(
                csvfile,
                fieldnames=all_fieldnames
            )
            if not file_exists or os.stat(csv_filename).st_size == 0:
                writer.writeheader()
            writer.writerows(rows)