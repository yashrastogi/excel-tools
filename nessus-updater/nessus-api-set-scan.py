import csv
from api_nessus import Nessus

scanners = []

with open("nessus-update.csv", newline="") as csv_file:
    targets = csv.DictReader(csv_file)
    for row in targets:
        if row["do_update"] == "1":
            scanners.append(Nessus(row["base"], row["user"], row["pass"]))

for scanner in scanners:
    print("\n" + scanner.base_url + "\n")
    scanner.schedule_scan()