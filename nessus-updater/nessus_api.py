from datetime import datetime
import json
import re
from time import time
import urllib
import requests
from functools import lru_cache
import pandas as pd


class Nessus:
    def __init__(self, base_url, username, password):
        payload = f"username={urllib.parse.quote(username)}&password={urllib.parse.quote(password)}"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = requests.request("POST", f"{base_url}/session", headers=headers, data=payload, verify=False)
        self.base_url = base_url
        self.login_token = response.json()["token"]

    def update_plugins(self, plugins_file="all-2.0.tar.gz"):
        url = f"{self.base_url}/server/upload-plugins"
        files = [("Filedata", (plugins_file, open(plugins_file, "rb"), "application/octet-stream"))]
        headers = {"X-Cookie": f"token={self.login_token}"}
        response = requests.request("POST", url, headers=headers, data={}, files=files, verify=False)
        print(f"{self.base_url}: {response.text}")

        upload_file_name = response.json()["fileuploaded"]
        url = f"{self.base_url}/server/update-plugins"
        payload = json.dumps({"filename": upload_file_name})
        headers = {"X-Cookie": f"token={self.login_token}", "Content-Type": "application/json"}
        response = requests.request("POST", url, headers=headers, data=payload, verify=False)
        print(f"{self.base_url}: {response.text}")

    def download_scan_csv(self):
        print()
        url = f"{self.base_url}/scans"
        headers = {"X-Cookie": f"token={self.login_token}", "Content-Type": "application/json"}
        response = requests.request("GET", url, headers=headers, data={}, verify=False)
        folders = [(fldrjson["name"], fldrjson["id"]) for fldrjson in response.json()["folders"]]
        for i, folder in enumerate(folders):
            print(f"{i+1}. {folder[0]}")
        print("\nSelect folder: ", end="")
        folder_id = folders[int(input()) - 1][1]
        scans = response.json()["scans"]

        print("\nSearching for corresponding scans and initiating download\n")
        for scan in scans:
            if scan["read"] == False and scan["status"] == "completed" and scan["folder_id"] == folder_id:
                print(scan["name"])
                url = f"{self.base_url}/scans/{scan['id']}/export"
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
                headers = {"X-Cookie": f"token={self.login_token}", "Content-Type": "application/json"}
                response = requests.request("POST", url, headers=headers, data=payload, verify=False)
                csv_token = response.json()["token"]
                url = f"{self.base_url}/tokens/{csv_token}/download"
                payload = {}
                headers = {"X-Cookie": f"token={self.login_token}"}
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

    def schedule_scan(self, policy_name="1-NSG Scan", scan_name="Script Configured", schedule_file="scan-schedule.csv"):
        url = f"{self.base_url}/policies"
        headers = {"X-Cookie": f"token={self.login_token}", "Content-Type": "application/json"}
        response = requests.request("GET", url, headers=headers, data={}, verify=False)

        policies = response.json()["policies"]
        policy_id = 0
        for policy in policies:
            if policy["name"] == policy_name:
                policy_id = policy["id"]
                break

        url = f"{self.base_url}/scans"
        df = pd.read_csv(schedule_file)
        data: pd.Series = df.groupby(["date", "time"])["ips"].apply(list)

        for row in data.iteritems():
            scan_datetime = datetime.strptime(row[0][0] + " " + row[0][1], r"%d-%m-%Y %H:%M")
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
                        "name": f"{scan_name} | {scan_datetime.strftime(r'%d-%m-%Y %H:%M')}",
                        "description": "Auto configured",
                        "folder_id": 3,
                        "scanner_id": "1",
                        "policy_id": policy_id,
                        "text_targets": "\n".join(row[1]),
                        "file_targets": "",
                    },
                }
            )

            headers = {
                "X-Cookie": f"token={self.login_token}",
                "Content-Type": "application/json",
                "X-API-Token": self.get_x_api_token(),
            }
            response = requests.request("POST", url, headers=headers, data=payload, verify=False)
            print(f"{self.base_url}: {response.text}")

    @lru_cache(maxsize=1)
    def get_x_api_token(self):
        headers = {"X-Cookie": f"token={self.login_token}", "Content-Type": "application/json"}
        r = requests.request("GET", f"{self.base_url}/nessus6.js", headers=headers, verify=False)
        m = re.search(r"([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})", r.text)
        return m.group(0)
