import csv
from concurrent.futures import ThreadPoolExecutor, wait
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def download_plugins():
    import requests
    import os
    import sys
    from datetime import datetime
    import urllib.request

    proxies = urllib.request.getproxies()

    url = "https://plugins.cloud.tenable.com/v2/plugins.php"
    if "https" in proxies:
        from urllib.parse import quote

        proxies["https"] = proxies["https"].replace("https", "http")  # required for Windows
        proxy_user = quote(input("Enter proxy username: "))
        proxy_pass = quote(input("Enter proxy password: "))
        P_temp = proxies["https"]
        proxies["https"] = P_temp[: P_temp.find("//") + 2] + proxy_user + ":" + proxy_pass + "@" + P_temp[P_temp.find("//") + 2 :]
        proxies["http"] = proxies["https"]

    response = requests.request("GET", url, verify=False, proxies=proxies)
    offline_plugins_version = online_plugins_version = datetime.strptime(response.text, r"%Y%m%d%H%M")
    if os.path.exists("plugins-version.txt"):
        offline_plugins_version = datetime.strptime(open("plugins-version.txt", "r").readline(), r"%Y%m%d%H%M")
    if offline_plugins_version < online_plugins_version or not os.path.exists("plugins-version.txt"):
        print(f"Downloading latest plugins ({response.text})")
        plugins_url = open("plugins-url.txt", "r").readline()
        with open("all-2.0.tar.gz", "wb+") as f:
            plugin_data = requests.request("GET", plugins_url, verify=False, proxies=proxies, stream=True)
            total_length = plugin_data.headers.get("content-length")

            if total_length is None:  # no content length header
                f.write(plugin_data.content)
            else:
                dl = 0
                total_length = int(total_length)
                for data in plugin_data.iter_content(chunk_size=4096):
                    dl += len(data)
                    f.write(data)
                    done = int(50 * dl / total_length)
                    sys.stdout.write("\r[%s%s] %s" % ("=" * done, " " * (50 - done), f"{round(dl*100/total_length, 1)}%"))
                    sys.stdout.flush()
        open("plugins-version.txt", "w+").write(response.text)
        print("\nPlugins downloaded")
    else:
        print("Latest plugins already downloaded")
    return


def main():
    if input("Skip downloading plugins?: ") == "y":
        pass
    else:
        download_plugins()

    from api_nessus import Nessus

    input("Press [Enter] to continue to update scanners: ")
    scanners = []
    with open("nessus-update.csv", newline="") as csv_file:
        targets = csv.DictReader(csv_file)
        for row in targets:
            if row["do_update"] == "1":
                scanners.append(Nessus(row["base"], row["user"], row["pass"]))

    with ThreadPoolExecutor(max_workers=10) as executor:
        result_futures = list(
            map(
                lambda scanner: executor.submit(scanner.update_plugins),
                scanners,
            )
        )
        wait(result_futures, timeout=None, return_when="ALL_COMPLETED")


main()
