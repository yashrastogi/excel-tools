import os
import sys
import pandas as pd
import openpyxl as xl
from tabulate import tabulate


def count_severity(path: str):
    count = {}
    df = pd.DataFrame(columns=["File Name", "Critical", "High", "Medium", "Low", "IP Count"])

    for root, _, files in os.walk(path):
        for file in files:
            if str(file).endswith("vulns.xlsx") and "~" not in str(file):
                wb = xl.load_workbook(filename=f"{root}/{file}")
                ws = wb.worksheets[0]
                count.update({"File Name": file, "Critical": 0, "High": 0, "Medium": 0, "Low": 0})
                iplist: list = []
                for row in ws:
                    counter = 0
                    for cell in row:
                        counter += 1
                        if counter == 5:
                            if cell.value not in iplist:
                                iplist.append(cell.value)
                        if counter == 4:
                            if str(cell.value) in count.keys():
                                count[str(cell.value)] += 1
                count.update({"IP Count": len(iplist) - 1})
                df = df.append(count, ignore_index=True)

    df.sort_values(["File Name"], ascending=True)
    print(
        f"Totals => Critical: {df['Critical'].sum()}, High: {df['High'].sum()}, Medium: {df['Medium'].sum()}, Low: {df['Low'].sum()}"
    )
    print(tabulate(df, headers="keys", tablefmt="fancy_grid"))
