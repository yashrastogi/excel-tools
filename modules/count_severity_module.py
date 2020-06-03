import os
import pandas as pd
from tabulate import tabulate


def count_severity(path: str):
    countDict = {}
    columns = ["File Name", "Critical", "High", "Medium", "Low", "Total", "IP Count"]
    fileInfoDF = pd.DataFrame(columns=columns)

    for root, _, files in os.walk(path):
        for file in files:
            if str(file).endswith("vulns.xlsx") and "~" not in str(file):
                df: pd.DataFrame = pd.read_excel(f"{root}/{file}", index_col="S. No.")
                sevCounts: pd.DataFrame = df["Severity"].value_counts()
                countDict = {key: 0 for key in columns}
                countDict.update(
                    {
                        "File Name": file,
                        "Total": sevCounts.sum() - sevCounts.loc[sevCounts.index == "Info"].sum(),
                        "IP Count": df["IP Address"].nunique(),
                    }
                )
                for key in countDict:
                    if key in sevCounts.index:
                        countDict[key] = sevCounts[key]
                fileInfoDF = fileInfoDF.append(countDict, ignore_index=True)

    fileInfoDF.sort_values(["File Name"], inplace=True)
    print(
        f"Totals => Critical: {fileInfoDF['Critical'].sum()}, High: {fileInfoDF['High'].sum()}, Medium: {fileInfoDF['Medium'].sum()}, Low: {fileInfoDF['Low'].sum()}"
    )
    print(tabulate(fileInfoDF, headers="keys", tablefmt="fancy_grid"))
