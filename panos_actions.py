#!/usr/bin/env python3
# pip install xmltodict
# sudo apt update
# sudo apt install -y python3-xmltodict

import time
import requests
import xmltodict
import logging
import xml.dom.minidom

# Disable insecure request warnings from urllib3 (since we're likely using self-signed certs on Panorama)
requests.packages.urllib3.disable_warnings()

def panos_api_key(fw_ip, username, password):
    """
    Generate a PAN-OS API key for a given Panorama/firewall using credentials.
    Returns the API key as a string.
    """
    try:
        url = f"https://{fw_ip}/api"
        params = {"type": "keygen", "user": username, "password": password}
        response = requests.get(url, params=params, verify=False, timeout=5)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx/5xx)
        data = xmltodict.parse(response.text)["response"]
        if data.get("@status") == "success":
            api_key = data["result"]["key"]
            logging.debug("Obtained API key for user '%s' on device %s", username, fw_ip)
            return api_key
        else:
            # API responded but with an error status
            error_msg = data.get("msg", {}).get("line", data.get("msg", "Unknown error"))
            raise RuntimeError(f"API key generation failed: {error_msg}")
    except Exception as e:
        logging.error("Error generating API key from %s: %s", fw_ip, e)
        raise

def panos_op_cmd(fw_ip, fw_key, xml_cmd):
    """
    Execute an operational XML command on a PAN-OS device (Panorama or firewall).
    Returns the parsed XML <response> as a dictionary.
    """
    url = f"https://{fw_ip}/api"
    params = {"key": fw_key, "type": "op", "cmd": xml_cmd}
    try:
        response = requests.get(url, params=params, verify=False, timeout=10)
        response.raise_for_status()
        result = xmltodict.parse(response.text)["response"]
        logging.debug("Executed op command on %s: %s", fw_ip, xml_cmd)
        return result
    except Exception as e:
        logging.error("Operational command failed on %s: %s", fw_ip, e)
        raise

def panos_config_show(fw_ip, fw_key, xpath):
    """
    Retrieve configuration from a PAN-OS device at the given XPath.
    Returns the parsed XML <response> as a dictionary.
    """
    url = f"https://{fw_ip}/api"
    params = {"key": fw_key, "type": "config", "action": "get", "xpath": xpath}
    try:
        response = requests.get(url, params=params, verify=False, timeout=10)
        response.raise_for_status()
        result = xmltodict.parse(response.text)["response"]
        logging.debug("Retrieved config from %s (xpath: %s)", fw_ip, xpath)
        return result
    except Exception as e:
        logging.error("Config retrieval failed for %s (xpath: %s): %s", fw_ip, xpath, e)
        raise

def panos_config_set(fw_ip, fw_key, xpath, element):
    """Push a configuration element to the PAN-OS device at the given XPath."""
    url = f"https://{fw_ip}/api"
    params = {"key": fw_key, "type": "config", "action": "set", "xpath": xpath, "element": element}
    try:
        response = requests.get(url, params=params, verify=False, timeout=10)
        response.raise_for_status()
        result = xmltodict.parse(response.text)["response"]
        logging.debug("Set config on %s (xpath: %s)", fw_ip, xpath)
        return result
    except Exception as e:
        logging.error("Config set failed for %s (xpath: %s): %s", fw_ip, xpath, e)
        raise

def panos_config_delete(fw_ip, fw_key, xpath):
    """Delete a configuration element from the PAN-OS device at the given XPath."""
    url = f"https://{fw_ip}/api"
    params = {"key": fw_key, "type": "config", "action": "delete", "xpath": xpath}
    try:
        response = requests.get(url, params=params, verify=False, timeout=10)
        response.raise_for_status()
        result = xmltodict.parse(response.text)["response"]
        logging.debug("Deleted config on %s (xpath: %s)", fw_ip, xpath)
        return result
    except Exception as e:
        logging.error("Config delete failed for %s (xpath: %s): %s", fw_ip, xpath, e)
        raise

def panos_config_rename(fw_ip, fw_key, xpath, new_name):
    """Rename a configuration element on the PAN-OS device at the given XPath to `new_name`."""
    url = f"https://{fw_ip}/api"
    params = {"key": fw_key, "type": "config", "action": "rename", "xpath": xpath, "newname": new_name}
    try:
        response = requests.get(url, params=params, verify=False, timeout=10)
        response.raise_for_status()
        result = xmltodict.parse(response.text)["response"]
        logging.debug("Renamed config at %s to '%s'", xpath, new_name)
        return result
    except Exception as e:
        logging.error("Config rename failed for %s: %s", xpath, e)
        raise

def panos_commit_cmd(fw_ip, fw_key, xml_cmd):
    """
    Execute a commit (or partial commit) command on the PAN-OS device.
    Returns the parsed XML <response> as a dictionary.
    """
    url = f"https://{fw_ip}/api"
    params = {"key": fw_key, "type": "commit", "cmd": xml_cmd}
    try:
        response = requests.get(url, params=params, verify=False, timeout=10)
        response.raise_for_status()
        result = xmltodict.parse(response.text)["response"]
        logging.debug("Issued commit command on %s", fw_ip)
        return result
    except Exception as e:
        logging.error("Commit command failed on %s: %s", fw_ip, e)
        raise

def pan_commit_partial(fw_ip, fw_key, admin_user):
    """
    Perform a partial commit for the specified admin user on Panorama.
    Returns a message indicating the commit result.
    """
    commit_cmd = f"<commit><partial><admin><member>{admin_user}</member></admin></partial></commit>"
    # Initiate the partial commit
    try:
        result = panos_commit_cmd(fw_ip, fw_key, commit_cmd)
    except Exception as e:
        logging.error("Partial commit API call failed: %s", e)
        raise

    status = result.get("@status")
    code = result.get("@code")
    if status == "success" and code == "13":
        return "Nothing to commit"  # No changes to commit
    elif status == "success" and code == "19":
        job_id = result["result"]["job"]  # Commit job started
    else:
        # Unexpected response structure; return the whole response for debugging
        return result

    # Poll for the commit job to finish
    job_check_cmd = f"<show><jobs><id>{job_id}</id></jobs></show>"
    while True:
        try:
            job_result = panos_op_cmd(fw_ip, fw_key, job_check_cmd)
        except Exception as e:
            logging.error("Failed to check partial commit job status: %s", e)
            raise
        if job_result.get("@status") == "success":
            job_status = job_result["result"]["job"]["status"]
        else:
            return job_result  # Return error info if job status retrieval failed
        if job_status == "FIN":
            break  # Job finished
        time.sleep(5)  # Wait before polling again

    # Compile commit result details
    details = job_result["result"]["job"]["details"]["line"]
    if isinstance(details, list):
        # Multiple lines of details
        result_message = "\n".join(f"\t{line}" for line in details)
    else:
        result_message = f"\t{details}"
    if "Configuration committed successfully" not in result_message:
        logging.error("Partial commit failed: \n%s", result_message)
        # Attempt to revert config if commit failed (Panorama specific)
        revert_cmd = "<revert><config/></revert>"
        revert_result = panos_op_cmd(fw_ip, fw_key, revert_cmd)
        return revert_result.get("result", {}).get("msg", {}).get("line", "Commit failed (reverted)")
    logging.info("Partial commit successful for admin '%s'. Details:\n%s", admin_user, result_message)
    return "Commit successful"

def pan_commit_all(fw_ip, fw_key, xml_cmd):
    """
    Perform a 'commit all' in Panorama (push to managed devices) with the given XML command.
    Returns a summary of the commit-all result.
    """
    url = f"https://{fw_ip}/api"
    params = {"key": fw_key, "type": "commit", "action": "all", "cmd": xml_cmd}
    try:
        response = requests.get(url, params=params, verify=False, timeout=10)
        response.raise_for_status()
        result = xmltodict.parse(response.text)["response"]
    except Exception as e:
        logging.error("Commit-all command failed to initiate: %s", e)
        raise

    status = result.get("@status")
    code = result.get("@code")
    if status == "success" and code == "13":
        return "Nothing to commit"
    elif status == "success" and code == "19":
        job_id = result["result"]["job"]
    else:
        return result  # Return entire response if an unexpected status/code is received

    # Poll for the commit-all job to complete
    job_check_cmd = f"<show><jobs><id>{job_id}</id></jobs></show>"
    while True:
        try:
            job_result = panos_op_cmd(fw_ip, fw_key, job_check_cmd)
        except Exception as e:
            logging.error("Failed to check commit-all job status: %s", e)
            raise
        if job_result.get("@status") == "success":
            job_status = job_result["result"]["job"]["status"]
        else:
            return job_result  # Return error info if status check failed
        if job_status == "FIN":
            break
        time.sleep(5)

    # Compile a summary of results for each device
    devices = job_result["result"]["job"]["devices"]["entry"]
    if isinstance(devices, list):
        summary_list = [
            f"{dev['status'].capitalize()} on {dev['devicename']}/{dev['serial-no']}"
            for dev in devices
        ]
        summary = "; ".join(summary_list)
    else:
        summary = f"{devices['status'].capitalize()} on {devices['devicename']}/{devices['serial-no']}"
    logging.info("Commit-all job completed: %s", summary)
    return summary

def pan_config_snapshot(fw_ip, fw_key, filename):
    """
    Save a configuration snapshot on the PAN-OS device with the given filename.
    """
    save_cmd = f"<save><config><to>{filename}</to></config></save>"
    try:
        result = panos_op_cmd(fw_ip, fw_key, save_cmd)
        logging.info("Configuration snapshot saved to '%s' on device %s", filename, fw_ip)
        return result.get("result", {})
    except Exception as e:
        logging.error("Failed to save configuration snapshot to '%s': %s", filename, e)
        raise


def panos_export_cfg(fw_ip, fw_key):
    """
    Retrieve and save the local configuration file on the PAN-OS device as XML content.
    Returns the pretty-printed XML content bytes.
    """
    url = f"https://{fw_ip}/api"
    params = {"key": fw_key, "type": "export", "category": "configuration"}
    try:
        response = requests.get(url, params=params, verify=False, timeout=10)
        response.raise_for_status()
        # Parse and pretty-print XML content
        dom = xml.dom.minidom.parseString(response.content)
        pretty_xml_as_str = dom.toprettyxml(indent="  ")
        lines = pretty_xml_as_str.splitlines()
        logging.debug("Configuration export succeeded on %s, pretty-printed lines: %d", fw_ip, len(lines))
        return pretty_xml_as_str.encode('utf-8')
    except Exception as e:
        logging.error("Export configuration failed on %s: %s", fw_ip, e)
        raise
