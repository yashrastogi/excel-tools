import requests
import json
import urllib3
import urllib
import os
import re
import time
import pandas as pd
from datetime import datetime
import csv

os.environ["no_proxy"] = "127.0.0.1,localhost"
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

scanners = {}

with open("nessus-update.csv", newline="") as csv_file:
    targets = csv.DictReader(csv_file)
    for row in targets:
        if row["do_update"] == "1":
            scanners[row["base"]] = [row["user"], row["pass"]]

for scanner in scanners:
    print("\n" + scanner + "\n")
    base_url = scanner

    url = f"{base_url}/session"
    payload = f"username={urllib.parse.quote(scanners[scanner][0])}&password={urllib.parse.quote(scanners[scanner][1])}"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = requests.request("POST", url, headers=headers, data=payload, verify=False)
    print(response.text)
    login_token = response.json()["token"]

    url = f"{base_url}/policies"
    payload = {}
    headers = {"X-Cookie": f"token={login_token}", "Content-Type": "application/json"}

    response = requests.request("GET", url, headers=headers, data=payload, verify=False)
    policies = response.json()["policies"]
    policy_id = 0
    for policy in policies:
        if policy["name"] == "1-NSG Scan":
            policy_id = policy["id"]
            break

    url = f"{base_url}/scans"

    df = pd.read_csv("scan-schedule.csv")
    data: pd.Series = df.groupby(["date", "time"])["ips"].apply(list)

    for row in data.iteritems():
        scan_datetime = datetime.strptime(row[0][0] + " " + row[0][1], r"%d-%m-%Y %H:%M")
        # import pdb; pdb.set_trace()
        payload = json.dumps(
            {
                "uuid": "ab4bacd2-05f6-425c-9d79-3ba3940ad1c24e51e1f403febe40",
                "settings": {
                    "emails": "",
                    "attach_report": "no",
                    "filter_type": "and",
                    "filters": [],
                    "launch": "ONETIME",
                    "launch_now": False,
                    "enabled": True,
                    "timezone": "Asia/Kolkata",
                    "starttime": scan_datetime.strftime(r"%Y%m%dT%H%M00"),
                    "rrules": "FREQ=ONETIME",
                    "live_results": "",
                    "name": f"NIAM VA Test | {scan_datetime.strftime(r'%d-%m-%Y %H:%M')}",
                    "description": "Auto configured",
                    "folder_id": 3,
                    "scanner_id": "1",
                    "policy_id": policy_id,
                    "text_targets": "\n".join(row[1]),
                    "file_targets": "",
                },
            }
        )
        r = requests.request("GET", f"{base_url}/nessus6.js", headers=headers, verify=False)
        m = re.search(r"([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})", r.text)
        x_api_token = m.group(0)

        headers = {
            "X-Cookie": f"token={login_token}",
            "Content-Type": "application/json",
            "X-API-Token": x_api_token,
        }
        response = requests.request("POST", url, headers=headers, data=payload, verify=False)
        print(response.text)