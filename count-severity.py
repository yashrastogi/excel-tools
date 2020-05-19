#!/usr/bin/python3

import os
import sys
import pandas as pd
import openpyxl as xl
from tabulate import tabulate


def main():
    if len(sys.argv) < 2:
        print("Usage: ./count-severity.py <directory>")
        return
    else:
        path = sys.argv[1]

    count = {}
    df = pd.DataFrame(
        columns=["File Name", "Critical", "High", "Medium", "Low"])

    for root, _, files in os.walk(path):
        for file in files:
            if str(file).endswith("vulns.xlsx") and "~$" not in str(file):
                wb = xl.load_workbook(filename=f"{root}/{file}")
                ws = wb.worksheets[0]
                count.update({
                    'File Name': file,
                    'Critical': 0,
                    'High': 0,
                    'Medium': 0,
                    'Low': 0
                })
                for row in ws:
                    for cell in row:
                        if str(cell.value) in count.keys():
                            count[str(cell.value)] += 1
                df = df.append(count, ignore_index=True)

    df.sort_values(["File Name"], ascending=True)
    print(tabulate(df, headers="keys", tablefmt="fancy_grid"))


if __name__ == "__main__":
    main()
