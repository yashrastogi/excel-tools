from concurrent.futures import ThreadPoolExecutor, wait
import csv


def main():
    from api_nessus import Nessus

    print("Enter new password: ", end="")
    new_pass = input()
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
                lambda scanner: executor.submit(scanner.change_pass, new_pass),
                scanners,
            )
        )
        wait(result_futures, timeout=None, return_when="ALL_COMPLETED")


main()
