import csv
from api_nessus import Nessus

def main():
    n = None
    with open("nessus-update.csv", newline="") as csv_file:
        targets = csv.DictReader(csv_file)
        counter = 1
        for row in targets:
            print(f"{counter}. {row['name']}: {row['base']}")
            counter += 1
        print("\nChoose scanner: ", end='')
        scanner_id = int(input())
    
    with open("nessus-update.csv", newline="") as csv_file:
        targets = csv.DictReader(csv_file)
        counter = 1
        for row in targets:
            if counter == scanner_id:
                n = Nessus(row["base"], row["user"], row["pass"])
                import code; code.interact(local=dict(globals(), **locals()))
                break
            counter += 1
    

main()