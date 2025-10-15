#!/usr/bin/env python3
# pip install PyYAML
# sudo apt update
# sudo apt install -y python3-yaml

import logging
from panos_actions import panos_export_cfg
import yaml
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

INPUT_FILES = {
    "firewalls": ["firewalls_apikey.yaml"]
}

def process_host(host, api_key):
    if not api_key or str(api_key).lower() == "null":
        return
    try:
        # Export configuration
        xml_content = panos_export_cfg(host, api_key)
        # Try to get hostname from config, fallback to host
        nodename = host
        # Optionally, try to parse hostname from config xml (not implemented here, fallback to host)
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
    # Only process firewalls
    input_files = INPUT_FILES["firewalls"]
    all_data = {}
    for input_file in input_files:
        with open(input_file, 'r') as f:
            loaded = yaml.safe_load(f)
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
                futures.append(executor.submit(process_host, host, api_key))
        for future in as_completed(futures):
            # No return value needed, just wait for completion
            future.result()