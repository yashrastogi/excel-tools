from concurrent.futures import ThreadPoolExecutor, wait
import requests
import json
import urllib3
import urllib
import os
import csv

os.environ["no_proxy"] = "127.0.0.1,localhost"
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def pluginUpdate(scanner, scanners):
    print(scanner)
    base_url = scanner

    url = f"{base_url}/session"
    payload = f"username={urllib.parse.quote(scanners[scanner][0])}&password={urllib.parse.quote(scanners[scanner][1])}"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = requests.request("POST", url, headers=headers, data=payload, verify=False)
    print(f"{scanner}: {response.text}")
    login_token = response.json()["token"]

    url = f"{base_url}/server/upload-plugins"
    plugins_file = "all-2.0.tar.gz"
    payload = {}
    files = [("Filedata", (plugins_file, open(plugins_file, "rb"), "application/octet-stream"))]
    headers = {"X-Cookie": f"token={login_token}"}

    response = requests.request("POST", url, headers=headers, data=payload, files=files, verify=False)
    print(f"{scanner}: {response.text}")
    upload_file_name = response.json()["fileuploaded"]
    # print(f'Uploaded file with name: {upload_file_name}')

    url = f"{base_url}/server/update-plugins"
    payload = json.dumps({"filename": upload_file_name})
    headers = {"X-Cookie": f"token={login_token}", "Content-Type": "application/json"}

    response = requests.request("POST", url, headers=headers, data=payload, verify=False)
    print(f"{scanner}: {response.text}")


def main():
    scanners = {}

    with open("nessus-update.csv", newline="") as csv_file:
        targets = csv.DictReader(csv_file)
        for row in targets:
            if row["do_update"] == "1":
                scanners[row["base"]] = [row["user"], row["pass"]]

    for scanner in scanners:
        with ThreadPoolExecutor(max_workers=10) as executor:
            result_futures = list(
                map(
                    lambda scanner: executor.submit(pluginUpdate, scanner, scanners),
                    scanners,
                )
            )
            wait(result_futures, timeout=None, return_when="ALL_COMPLETED")


main()