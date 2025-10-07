#!/usr/bin/env python3
import yaml
import os
from panos_actions import panos_api_key
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_api_key_safe(host, username, password):
    try:
        key = panos_api_key(host, username, password)
    except Exception:
        key = None
    return host, key

input_files = [
    "firewalls.yaml",
    "panoramas.yaml",
]

for in_file in input_files:
    if not os.path.isfile(in_file):
        print(f"[WARN] Input file not found: {in_file}")
        continue

    with open(in_file, "r") as f:
        data = yaml.safe_load(f) or {}

    groups = data.get("groups") or {}
    output = {"groups": {}}

    for group_name, group_data in groups.items():
        username = group_data.get("username")
        password = group_data.get("password")
        hosts = group_data.get("hosts") or []

        api_keys = {}
        if username and password:
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(get_api_key_safe, host, username, password): host for host in hosts}
                for future in as_completed(futures):
                    host, key = future.result()
                    api_keys[host] = key
        else:
            # no username/password, set keys to None
            for host in hosts:
                api_keys[host] = None

        output["groups"][group_name] = {
            "api_keys": api_keys,
        }

    out_file = f"{os.path.splitext(in_file)[0]}_apikey.yaml"
    with open(out_file, "w") as f:
        yaml.safe_dump(output, f, default_flow_style=False, sort_keys=False)

    print(f"[info] Wrote output to {out_file}")
