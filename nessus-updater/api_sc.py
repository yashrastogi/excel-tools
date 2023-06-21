from datetime import datetime
import os
from tenable.sc import TenableSC
import urllib3
import requests
import pandas as pd

os.environ["no_proxy"] = "127.0.0.1,localhost"
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {}


class SC:
    def __init__(
        self,
        access_key="188a98aa4e104e269dff3510b6489f1f",
        secret_key="c98e431cd8a846718d9a97d4abfb0da8",
        base_url="https://10.2.27.131/rest",
        debug=True,
    ):
        self.base_url = base_url
        self.sc = TenableSC("10.2.27.131")
        self.sc.login(access_key=access_key, secret_key=secret_key)
        self.x_apikey = f"accesskey={access_key}; secretkey={secret_key};"

    def download_scan_csv(self, scan_name):
        headers = {"x-apikey": self.x_apikey}
        response = requests.request("GET", f"{self.base_url}/report", headers=headers, verify=False, proxies=proxies)
        reports_json = response.json()["response"]["usable"]
        reports_yash = []
        for report in reports_json:
            if report["creator"]["firstname"] == "Yash":
                reports_yash.append(report)
        for report in reports_yash:
            if scan_name in report["name"]:
                print(f'{report["name"]} {report["finishTime"]}', end=" ")
                download_response = requests.request(
                    "POST", f"{self.base_url}/report/{report['id']}/download", headers=headers, verify=False, proxies=proxies
                )
                print(download_response)
                open(
                    f"./reports/{''.join(x for x in report['name'].replace(':', '_') if x.isalnum() or x in [' ','-'])[4:]}-{report['finishTime']}-vulns.csv",
                    "wb",
                ).write(download_response.content)

    def schedule_scan(self, scan_name="Script Configured", schedule_file="scan-schedule.csv"):
        scan_zones_list = [(sz["id"], sz["name"]) for sz in self.sc.scan_zones.list()]
        for sz in [f"ID: {a[0]} - Scanner: {a[1]}" for a in scan_zones_list]:
            print(sz)
        sz_sel = int(input("Choose Scanner ID: "))
        df = pd.read_csv(schedule_file)
        data: pd.Series = df.groupby(["date", "time"])["ips"].apply(list)
        for row in data.iteritems():
            scan_datetime = datetime.strptime(row[0][0] + " " + row[0][1], r"%d-%m-%Y %H:%M")
            self.sc.scans.create(
                name=f"{scan_name} | {scan_datetime.strftime(r'%d-%m-%Y %H:%M')}",
                repo=76,
                targets=row[1],
                policy_id=1000014,
                scan_zone=sz_sel,
                schedule={
                    "type": "ical",
                    "start": f"TZID=Asia/Kolkata:{scan_datetime.strftime(r'%Y%m%dT%H%M00')}",
                    "repeatRule": "",
                },
                reports=[{"id": 2764, "reportSource": "individual"}],
            )
