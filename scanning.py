import requests
import pandas as pd
import time
import os
import tkinter as tk
from tkinter import filedialog
from tqdm import tqdm

# Constants
OUTPUT_CSV = "ip_analysis_results.csv"
FAILED_CSV = "failed_ips.csv"
VT_KEYS_FILE = "vt_keys.txt"
ABUSE_KEYS_FILE = "abuseipdb_keys.txt"

# Load API keys
def load_keys(filename):
    with open(filename, "r") as f:
        return [line.strip() for line in f if line.strip()]

# VirusTotal lookup (now extracts registration + last changed from RDAP events)
# VirusTotal lookup
def check_virustotal(ip, vt_keys, vt_key_index):
    while vt_key_index < len(vt_keys):
        key = vt_keys[vt_key_index]
        print(f"🌐 Using VirusTotal API Key #{vt_key_index + 1}")
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": key}
        response = requests.get(url, headers=headers)

        print(f"Response code for {ip}: {response.status_code}")  # debug

        if response.status_code == 200:
            data = response.json()
            # debug WHOIS data
            whois_data = data["data"]["attributes"].get("whois_data", {})
            # print(f"\n===== WHOIS DATA for {ip} =====")
            # print(whois_data)
            # print("================================\n")

            score = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            vt_url = f"https://www.virustotal.com/gui/ip-address/{ip}"

            reg_date, update_date = "", ""
            events = whois_data.get("events", [])
            for event in events:
                if event.get("event") == "registration":
                    reg_date = event.get("date", "")
                elif event.get("event") == "last changed":
                    update_date = event.get("date", "")

            return score, vt_url, reg_date, update_date, vt_key_index

        elif response.status_code == 429:
            print("🔁 VirusTotal rate limit hit. Trying next key...")
            vt_key_index += 1
        else:
            print(f"❌ Unexpected response for {ip}: {response.text}")
            break

    return None, None, None, None, vt_key_index

# AbuseIPDB lookup (only score + country now)
def check_abuseipdb(ip, abuse_keys, abuse_key_index):
    while abuse_key_index < len(abuse_keys):
        key = abuse_keys[abuse_key_index]
        print(f"🔐 Using AbuseIPDB API Key #{abuse_key_index + 1}")
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": "90",
            "verbose": "true"
        }
        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            data = response.json()["data"]
            score = data.get("abuseConfidenceScore", "")
            country = data.get("countryCode", "")
            return score, country, abuse_key_index

        elif response.status_code == 429:
            print("🔁 AbuseIPDB rate limit hit. Trying next key...")
            abuse_key_index += 1
        else:
            break
    return None, None, abuse_key_index

import requests

def get_rdap_dates(ip):
    rdap_servers = [
        "https://rdap.apnic.net/ip/",    # Asia
        "https://rdap.arin.net/registry/ip/",  # North America
        "https://rdap.ripe.net/ip/",     # Europe
        "https://rdap.afrinic.net/rdap/ip/",   # Africa
        "https://rdap.lacnic.net/rdap/ip/"     # Latin America
    ]
    for server in rdap_servers:
        try:
            url = server + ip
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                reg_date, last_changed = "", ""
                for event in data.get("events", []):
                    if event.get("eventAction") == "registration":
                        reg_date = event.get("eventDate", "")
                    elif event.get("eventAction") == "last changed":
                        last_changed = event.get("eventDate", "")
                if reg_date or last_changed:
                    return reg_date, last_changed
        except:
            continue
    return "", ""


# Ask user to select input CSV
def get_input_file():
    root = tk.Tk()
    root.withdraw()
    return filedialog.askopenfilename(
        title="Select CSV File with IPs",
        filetypes=[("CSV Files", "*.csv")]
    )

# Append to CSV file
def append_to_csv(filename, data, columns):
    file_exists = os.path.isfile(filename)
    df = pd.DataFrame([data], columns=columns)
    df.to_csv(filename, mode='a', header=not file_exists, index=False)

# Main logic
def main():
    vt_keys = load_keys(VT_KEYS_FILE)
    abuse_keys = load_keys(ABUSE_KEYS_FILE)

    input_file = get_input_file()
    if not input_file:
        print("❌ No file selected. Exiting.")
        return

    # Load already processed IPs to resume
    processed_ips = set()
    if os.path.exists(OUTPUT_CSV):
        try:
            processed_df = pd.read_csv(OUTPUT_CSV)
            processed_ips = set(processed_df['ip'].astype(str))
            print(f"✅ Resuming, {len(processed_ips)} IPs already processed.")
        except Exception as e:
            print(f"❌ Failed to read {OUTPUT_CSV} for resuming: {e}")

    vt_key_index = 0
    abuse_key_index = 0

    while True:
        try:
            df = pd.read_csv(input_file)
            if df.empty:
                print("✅ All IPs processed in input file.")
                break
        except Exception as e:
            print(f"❌ Failed to read input file: {e}")
            break

        total_remaining = len(df)
        with tqdm(total=total_remaining, desc="🔍 Processing IPs", unit="ip") as pbar:
            new_df = df.copy()
            for idx, row in df.iterrows():
                ip = str(row['ip'])

                # Skip already processed IPs
                if ip in processed_ips:
                    pbar.update(1)
                    continue

                if vt_key_index >= len(vt_keys):
                    print("❌ All VirusTotal API keys exhausted. Exiting.")
                    return

                if abuse_key_index >= len(abuse_keys):
                    print("❌ All AbuseIPDB API keys exhausted. Exiting.")
                    return

                try:
                    vt_score, vt_url, reg_date, update_date, vt_key_index = check_virustotal(ip, vt_keys, vt_key_index)
                    abuse_score, country, abuse_key_index = check_abuseipdb(ip, abuse_keys, abuse_key_index)

                    if None in [vt_score, vt_url, abuse_score]:
                        raise Exception("Missing data from one or more services")

                    # RDAP registration + last changed
                    rdap_reg, rdap_last_changed = get_rdap_dates(ip)

                    result_row = {
                        "ip": ip,
                        "VirusTotal_Score": vt_score,
                        "VirusTotal_URL": vt_url,
                        "abuse_confidence_score": abuse_score,
                        "location": country,
                        "WHOIS_RegDate": rdap_reg,
                        "WHOIS_Update": rdap_last_changed
                    }

                    append_to_csv(OUTPUT_CSV, result_row, result_row.keys())
                    new_df = new_df.drop(idx)
                    processed_ips.add(ip)  # mark as processed

                except Exception as e:
                    print(f"\n❌ Error with IP {ip}: {e}")
                    append_to_csv(FAILED_CSV, {"ip": ip}, ["ip"])
                    new_df = new_df.drop(idx)

                time.sleep(1)
                pbar.update(1)

            # Save remaining IPs back to input file
            new_df.to_csv(input_file, index=False)

    print("\n🏁 Script completed.")


if __name__ == "__main__":
    main()
