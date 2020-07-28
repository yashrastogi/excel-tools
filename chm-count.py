import os
import sys
import pandas as pd
from tabulate import tabulate


if len(sys.argv) < 2:
    print("Usage: ./chm-count.py <nessus-report.xlsx>")
    exit(1)

countDict = {}
columns = ["IP Address", "Critical", "High", "Medium", "Low", "Total"]
fileInfoDF = pd.DataFrame(columns=columns)

df: pd.DataFrame = pd.read_excel(sys.argv[1], index_col="S. No.")
for ip in df["IP Address"].unique():
    sevCounts: pd.DataFrame = df.loc[(df["IP Address"] == ip)]["Severity"].value_counts()
    countDict = {key: 0 for key in columns}
    countDict.update(
        {"IP Address": ip, "Total": sevCounts.sum() - sevCounts.loc[sevCounts.index == "Info"].sum(),}
    )
    for key in countDict:
        if key in sevCounts.index:
            countDict[key] = sevCounts[key]
    fileInfoDF = fileInfoDF.append(countDict, ignore_index=True)

fileInfoDF.sort_values(["IP Address"], inplace=True, ignore_index=True)
print(
    f"Totals => Critical: {fileInfoDF['Critical'].sum()}, High: {fileInfoDF['High'].sum()}, Medium: {fileInfoDF['Medium'].sum()}, Low: {fileInfoDF['Low'].sum()}"
)
print(tabulate(fileInfoDF, headers="keys", tablefmt="fancy_grid"))
