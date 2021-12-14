from api_nessus import Nessus
import csv
from concurrent.futures import ThreadPoolExecutor, wait


def main():
    scanners = []
    with open("nessus-update.csv", newline="") as csv_file:
        targets = csv.DictReader(csv_file)
        for row in targets:
            if row["do_update"] == "1":
                scanners.append(Nessus(row["base"], row["user"], row["pass"]))

    for scanner in scanners:
        with ThreadPoolExecutor(max_workers=10) as executor:
            result_futures = list(
                map(
                    lambda scanner: executor.submit(scanner.update_plugins),
                    scanners,
                )
            )
            wait(result_futures, timeout=None, return_when="ALL_COMPLETED")


main()