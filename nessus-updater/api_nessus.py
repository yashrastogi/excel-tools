from datetime import datetime
import json
import re
import time
import urllib
import os
import urllib3
import requests
from functools import lru_cache
import pandas as pd

os.environ["no_proxy"] = "127.0.0.1,localhost"
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {}


class Nessus:
    def __init__(self, base_url, username, password, debug=True):
        payload = f"username={urllib.parse.quote(username)}&password={urllib.parse.quote(password)}"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = requests.request("POST", f"{base_url}/session", headers=headers, data=payload, verify=False, proxies=proxies)
        self.base_url = base_url
        self.debug = debug
        self.username = username
        self.password = password
        if self.debug:
            print(f"{self.base_url}: {response.text}")
        self.login_token = response.json()["token"]

    def update_plugins(self, plugins_file="all-2.0.tar.gz"):
        url = f"{self.base_url}/server/upload-plugins"
        files = [("Filedata", (plugins_file, open(plugins_file, "rb"), "application/octet-stream"))]
        headers = {"X-Cookie": f"token={self.login_token}"}
        response = requests.request("POST", url, headers=headers, data={}, files=files, verify=False, proxies=proxies)
        if self.debug:
            print(f"{self.base_url}: {response.text}")

        upload_file_name = response.json()["fileuploaded"]
        url = f"{self.base_url}/server/update-plugins"
        payload = json.dumps({"filename": upload_file_name})
        headers = {"X-Cookie": f"token={self.login_token}", "Content-Type": "application/json"}
        response = requests.request("POST", url, headers=headers, data=payload, verify=False, proxies=proxies)
        if self.debug:
            print(f"{self.base_url}: {response.text}")

    def change_pass(self, new_pass):
        print()
        print(f"Changing password for {self.username} on {self.base_url}...")
        url = f"{self.base_url}/session/chpasswd"
        headers = {
            "X-Cookie": f"token={self.login_token}",
            "Content-Type": "application/json",
            "X-API-Token": self.get_x_api_token(),
        }
        payload = json.dumps({"password": new_pass, "current_password": self.password})
        response = requests.request("PUT", url, headers=headers, data=payload, verify=False, proxies=proxies)
        if self.debug:
            print(f"{self.base_url}: {response.text} {response.status_code}")

    def download_scan_csv(self):
        print()
        scans_response = self.query_scans()
        folder_id = self.folder_chooser(scans_response)
        scans = scans_response["scans"]
        # print(scans)

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
                headers = {
                    "X-Cookie": f"token={self.login_token}",
                    "Content-Type": "application/json",
                    "X-API-Token": self.get_x_api_token(),
                }
                response = requests.request("POST", url, headers=headers, data=payload, verify=False, proxies=proxies)
                if self.debug:
                    print(f"{self.base_url}: {response.text}")
                counter = 0
                while response.headers["Content-Type"] == "application/json" and "error" in response.json():
                    if self.debug:
                        # print("\r" + (" " * 90) + "\r", end="")
                        print(f"\r{self.base_url}: {response.text} | {counter}", end="")
                        counter += 1
                    time.sleep(1)
                    response = requests.request("POST", url, headers=headers, data=payload, verify=False, proxies=proxies)
                print()
                csv_token = response.json()["token"]
                url = f"{self.base_url}/tokens/{csv_token}/download"
                headers = {"X-Cookie": f"token={self.login_token}"}
                time.sleep(2)
                response = requests.request("GET", url, headers=headers, data={}, verify=False, proxies=proxies)
                counter = 0
                while response.headers["Content-Type"] == "application/json" and response.json()["status"] == "loading":
                    if self.debug:
                        # print("\r" + (" " * 90) + "\r", end="")
                        print(f"\r{self.base_url}: {response.text} | {counter}", end="")
                        counter += 1
                    time.sleep(1)
                    response = requests.request("GET", url, headers=headers, data=payload, verify=False, proxies=proxies)
                print()
                pattern = re.compile(r'filename="(.*)"')
                file_name = ""
                for match in pattern.finditer(response.headers["Content-Disposition"]):
                    file_name = match.group(1)
                open(f"./reports/{file_name}", "wb").write(response.content)

    def schedule_scan(self, policy_name="1-NSG Scan", scan_name="Script Configured", schedule_file="scan-schedule.csv"):
        input_string = input(f"Enter policy name or press [Enter] to select {policy_name}: ")
        if len(input_string) != 0:
            policy_name = input_string
        policy_id = self.get_policy_id(policy_name)
        folder_id = self.folder_chooser()
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
                        "folder_id": folder_id,
                        "scanner_id": 1,
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
            response = requests.request("POST", url, headers=headers, data=payload, verify=False, proxies=proxies)
            if self.debug:
                print(f"{self.base_url}: {response.text}")

    @lru_cache(maxsize=1)
    def get_x_api_token(self):
        headers = {"X-Cookie": f"token={self.login_token}", "Content-Type": "application/json"}
        r = requests.request("GET", f"{self.base_url}/nessus6.js", headers=headers, verify=False, proxies=proxies)
        m = re.search(r"([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})", r.text)
        return m.group(0)

    def query_scans(self) -> dict:
        url = f"{self.base_url}/scans"
        headers = {"X-Cookie": f"token={self.login_token}", "Content-Type": "application/json"}
        response = requests.request("GET", url, headers=headers, data={}, verify=False, proxies=proxies)
        if self.debug:
            print(f"{self.base_url}: {response.text}")
        return response.json()

    def folder_chooser(self, scans_response=None):
        if not scans_response:
            scans_response = self.query_scans()
        folders = [(fldrjson["name"], fldrjson["id"]) for fldrjson in scans_response["folders"]]
        for i, folder in enumerate(folders):
            print(f"{i+1}. {folder[0]}")
        print("\nSelect folder: ", end="")
        return folders[int(input()) - 1][1]

    def get_policy_id(self, policy_name) -> dict:
        url = f"{self.base_url}/policies"
        headers = {"X-Cookie": f"token={self.login_token}", "Content-Type": "application/json"}
        response = requests.request("GET", url, headers=headers, data={}, verify=False, proxies=proxies)
        # if self.debug:
        #     print(f"{self.base_url}: {response.text}")

        policies = response.json()["policies"]
        policy_id = -1
        for policy in policies:
            if policy["name"] == policy_name:
                return policy["id"]
