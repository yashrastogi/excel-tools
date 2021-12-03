import requests
import json
import urllib3
import urllib
import os
import re
import time
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

    url = f"{base_url}/scans"
    payload = {}
    headers = {"X-Cookie": f"token={login_token}", "Content-Type": "application/json"}

    response = requests.request("GET", url, headers=headers, data=payload, verify=False)
    
    print()
    folders = [(fldrjson['name'], fldrjson['id']) for fldrjson in response.json()["folders"]]
    for i, folder in enumerate(folders):
        print(f'{i+1}. {folder[0]}')
    print("\nSelect folder: ", end='')
    folder_id = folders[int(input())-1][1]
    scans = response.json()["scans"]

    print("\nSearching for corresponding scans and initiating download\n")
    # import pdb; pdb.set_trace()
    for scan in scans:
        # import pdb; pdb.set_trace()
        if scan["read"] == False and scan["status"] == "completed" and scan["folder_id"] == folder_id:
            print(scan["name"])
            url = f"{base_url}/scans/{scan['id']}/export?limit=2500"
            payload = json.dumps(
                {
                    "format": "csv",
                    "reportContents": {
                        "csvColumns": {
                            "id": True,
                            "cve": True,
                            "cvss": True,
                            "risk": True,
                            "hostname": True,
                            "protocol": True,
                            "port": True,
                            "plugin_name": True,
                            "synopsis": True,
                            "description": True,
                            "solution": True,
                            "see_also": True,
                            "plugin_output": True,
                            "stig_severity": True,
                            "cvss3_base_score": True,
                            "cvss_temporal_score": True,
                            "cvss3_temporal_score": True,
                            "risk_factor": True,
                            "references": True,
                            "plugin_information": True,
                            "exploitable_with": True,
                        }
                    },
                    "extraFilters": {"host_ids": [], "plugin_ids": []},
                }
            )
            headers = {"X-Cookie": f"token={login_token}", "Content-Type": "application/json"}
            response = requests.request("POST", url, headers=headers, data=payload, verify=False)
            csv_token = response.json()["token"]
            url = f"{base_url}/tokens/{csv_token}/download"
            payload = {}
            headers = {"X-Cookie": f"token={login_token}"}
            response = requests.request("GET", url, headers=headers, data=payload, verify=False)
            while response.headers["Content-Type"] == "application/json" and response.json()["status"] == "loading":
                time.sleep(1)
                response = requests.request("GET", url, headers=headers, data=payload, verify=False)
                print(response.text)
            pattern = re.compile(r'filename="(.*)"')
            file_name = ""
            for match in pattern.finditer(response.headers["Content-Disposition"]):
                file_name = match.group(1)
            open(f"./reports/{file_name}", "wb").write(response.content)
