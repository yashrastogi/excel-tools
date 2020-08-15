import pandas as pd
import sys
import os
import dask.array as da
import dask.dataframe as dd

columns_dtypes = {
    "Plugin": pd.Int64Dtype(),
    "Plugin Name": pd.CategoricalDtype(ordered=False),
    "Family": pd.CategoricalDtype(ordered=False),
    "Severity": pd.CategoricalDtype(categories=["High", "Info", "Low", "Medium", "Critical"], ordered=False),
    "IP Address": "object",
    "Protocol": pd.CategoricalDtype(categories=["TCP", "UDP"], ordered=False),
    "Port": pd.Int64Dtype(),
    "Exploit?": pd.CategoricalDtype(ordered=False),
    "Repository": pd.CategoricalDtype(ordered=False),
    "MAC Address": "object",
    "DNS Name": "object",
    "NetBIOS Name": "object",
    "Plugin Text": "object",
    "Synopsis": "object",
    "Description": "object",
    "Solution": "object",
    "See Also": "object",
    "Risk Factor": pd.CategoricalDtype(ordered=False),
    "STIG Severity": pd.CategoricalDtype(ordered=False),
    "Vulnerability Priority Rating": "float64",
    "CVSS V2 Base Score": "float64",
    "CVSS V3 Base Score": "float64",
    "CVSS V2 Temporal Score": "float64",
    "CVSS V3 Temporal Score": "float64",
    "CVSS V2 Vector": "object",
    "CVSS V3 Vector": "object",
    "CPE": "object",
    "CVE": "object",
    "BID": "object",
    "Cross References": "object",
    "First Discovered": pd.CategoricalDtype(ordered=False),
    "Last Observed": pd.CategoricalDtype(ordered=False),
    "Vuln Publication Date": "object",
    "Patch Publication Date": "object",
    "Plugin Publication Date": "object",
    "Plugin Modification Date": "object",
    "Exploit Ease": pd.CategoricalDtype(
        categories=["Exploits are available", "No exploit is required", "No known exploits are available"],
        ordered=False,
    ),
    "Exploit Frameworks": pd.CategoricalDtype(ordered=False),
    "Check Type": pd.CategoricalDtype(ordered=False),
    "Version": "object",
}

colNames = [
    "Plugin",
    "Plugin Name",
    "Family",
    "Severity",
    "IP Address",
    "Protocol",
    "Port",
    "Exploit?",
    "Repository",
    "MAC Address",
    "DNS Name",
    "NetBIOS Name",
    "Exploit Frameworks",
    "Synopsis",
    "Description",
    "Solution",
    "Plugin Text",
    "CVE",
    "Risk Factor",
    "STIG Severity",
    "Vulnerability Priority Rating",
    "CVSS V2 Base Score",
    "CVSS V3 Base Score",
    "CVSS V2 Temporal Score",
    "CVSS V3 Temporal Score",
    "CVSS V2 Vector",
    "CVSS V3 Vector",
    "CPE",
    "See Also",
    "BID",
    "Cross References",
    "Vuln Publication Date",
    "Patch Publication Date",
    "Plugin Publication Date",
    "Plugin Modification Date",
    "Check Type",
    "Version",
    "First Discovered",
    "Last Observed",
    "Exploit Ease",
]

df = pd.DataFrame(columns=colNames).astype(columns_dtypes)

for root, _, files in os.walk("./"):
    for file in files:
        if str(file).endswith(".csv"):
            print("                                                                           ", end="\r")
            print(f"{file}", end="\r")
            df1 = pd.read_csv(f"{root}/{file}", dtype=columns_dtypes)[colNames]
            df = pd.concat([df, df1])

df.to_csv("combined-vulns.csv", index=False)
# df.to_parquet('combined.parquet.gz', compression='gzip')
