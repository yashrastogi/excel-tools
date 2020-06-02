import os
from datetime import datetime
import pandas as pd
import numpy as np
import sys


def generate_report(path, skip=True):
    for root, _, files in os.walk(path):
        for file in files:
            if str(file).endswith("vulns.csv") and "~$" not in str(file):
                print(f"{file}", end=": ")
                destpath: str = f'{root}/excel/{"".join(file.split(".")[0:-1])}.xlsx'
                if os.path.exists(destpath) and skip:
                    print("Excel exists, skipping...")
                else:
                    try:
                        print()
                        timeStart: datetime = datetime.now()
                        df: pd.DataFrame = pd.read_csv(f"{root}/{file}")
                        df = df[
                            [
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
                                "See Also",
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
                                "CVE",
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
                        ]
                        if not os.path.exists(f"{root}/excel/"):
                            os.makedirs(f"{root}/excel/")
                        checkAuth(df, root, file)
                        df.drop(
                            df.columns.difference(
                                [
                                    "Plugin",
                                    "Plugin Name",
                                    "Severity",
                                    "IP Address",
                                    "Protocol",
                                    "Port",
                                    "Plugin Text",
                                    "Synopsis",
                                    "Description",
                                    "Solution",
                                    "See Also",
                                    "First Discovered",
                                    "Last Observed",
                                    "CVE",
                                    "Vuln Publication Date",
                                    "Patch Publication Date",
                                    "Plugin Publication Date",
                                    "Plugin Modification Date",
                                    "Exploit Ease",
                                ]
                            ),
                            1,
                            inplace=True,
                        )
                        df.insert(len(df.columns), "Remarks", np.NaN)
                        df.insert(0, "S. No.", np.NaN)
                        for i, _ in df.iterrows():
                            df.loc[i, "S. No."] = i + 1
                        df.rename(
                            columns={
                                "See Also": "Additional Details",
                                "Plugin Name": "Vulnerability Name",
                                "Plugin": "Plugin ID",
                            },
                            inplace=True,
                        )
                        normalizeSSL(df)
                        normalizeMisc(df)
                        stripOutput(df)
                        with pd.ExcelWriter(  # pylint: disable=abstract-class-instantiated
                            destpath, engine="xlsxwriter", options={"strings_to_urls": False},
                        ) as writer:
                            df.to_excel(writer, sheet_name="Vulnerabilities", index=False)

                            # table formatting
                            worksheet = writer.sheets["Vulnerabilities"]
                            # set column widths
                            worksheet.set_column(11, len(df.columns), 15)
                            worksheet.set_column(2, 2, 23)
                            worksheet.set_column(4, 4, 14)
                            worksheet.set_column(7, 10, 23)
                            # create list of dicts for header names
                            #  (columns property accepts {'header': value} as header name)
                            col_names = [{"header": col_name} for col_name in df.columns]

                            # add table with coordinates: first row, first col, last row, last col;
                            #  header names or formating can be inserted into dict
                            worksheet.add_table(
                                0,
                                0,
                                df.shape[0],
                                df.shape[1] - 1,
                                {"columns": col_names, "style": "Table Style Light 9"},
                            )

                            # Edit Metadata
                            writer.book.set_properties(
                                {"author": "Yash Rastogi",}
                            )
                            writer.save()
                        timeEnd: datetime = datetime.now()
                        msec: int = (timeEnd - timeStart).total_seconds() * 1000
                        print("Excel file written in {:.0f}ms...\n".format(msec))

                    except ValueError:
                        exception: tuple = sys.exc_info()
                        print(f"Error: {exception[0]}. {exception[1]}, line: {exception[2].tb_lineno}")


def stripOutput(df: pd.DataFrame):
    # Total number of characters that a cell can contain, in excel: 32,767 characters
    try:
        df["Plugin Text"] = [x[0:32766] for x in df["Plugin Text"]]
    except:
        pass


def checkAuth(df: pd.DataFrame, root: str, file: str):
    destpath: str = f'{root}/excel/{"".join(file.split(".")[0:-1])}-errors.txt'
    try:
        if os.path.exists(destpath):
            os.remove(destpath)
    except:
        pass

    plugins: list = [
        "Authentication Failure(s) for Provided Credentials",
        "SSH Commands Require Privilege Escalation",
        "Authentication Failure - Local Checks Not Run",
        "Authentication Success with Intermittent Failure",
    ]
    acknowledged: dict = {}
    for plugin in plugins:
        for namedTuple in df.loc[df["Plugin Name"] == plugin, "IP Address":"Plugin Text"].itertuples():
            acknowledged.update({namedTuple._1: True})
            txtFile = open(destpath, "a")
            txtFile.write(f"({plugin}) IP Address: {namedTuple._1}:{namedTuple.Port}\n{namedTuple._9}\n\n")
            txtFile.close()
            print(f"{plugin} IP Address: {namedTuple._1}")

    for ipaddr in df["IP Address"].unique().tolist():
        if ipaddr not in acknowledged:
            for namedTuple in df.loc[
                (df["IP Address"] == ipaddr) & (df["Plugin Name"] == "Authentication Success"),
                "IP Address":"Plugin Text",
            ].itertuples():
                acknowledged.update({namedTuple._1: True})
    # print(acknowledged)
    for ipaddr in df["IP Address"].unique().tolist():
        if ipaddr not in acknowledged:
            txtFile = open(destpath, "a")
            txtFile.write(f"(No Authentication Detected) IP Address: {ipaddr}\n\n")
            txtFile.close()
            print(f"(No Authentication Detected) IP Address: {ipaddr}")


def normalizeSSL(df: pd.DataFrame):
    plugins: dict = {
        "Info": ["SSL Self-Signed Certificate", "SSL Certificate Cannot Be Trusted"],
        "Low": [
            "SSL Medium Strength Cipher Suites Supported (SWEET32)",
            "SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)",
            "SSL Certificate Signed Using Weak Hashing Algorithm",
            "SSL Weak Cipher Suites Supported",
            "SSL/TLS EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK)",
            "SSL Null Cipher Suites Supported",
            "SSL Certificate Fails to Adhere to Basic Constraints / Key Usage Extensions",
            "SSL DROWN Attack Vulnerability (Decrypting RSA with Obsolete and Weakened eNcryption)",
            "SSL Certificate Chain Contains Weak RSA Keys",
            "SSL / TLS Renegotiation Handshakes MiTM Plaintext Data Injection",
            "SSL RC4 Cipher Suites Supported (Bar Mitzvah)",
        ],
        "Medium": ["SSL Version 2 and 3 Protocol Detection", "SSL Certificate Expiry"],
    }

    for key in plugins:
        for plugin in plugins[key]:
            try:
                df.loc[df["Vulnerability Name"] == plugin, "Severity"] = key
            except:
                pass


def normalizeMisc(df: pd.DataFrame):
    high_with_sol: dict = {
        "Microsoft Windows SMB Service Detection": "Disable SMB and use secure alternatives like SFTP",
        "Unencrypted Telnet Server": "Disable Telnet and use SSH",
        "RPC portmapper Service Detection": "Disable RPC portmapper service",
        "FTP Server Detection": "Use secure alternative SFTP and disable this service",
        "DHCP Server Detection": "Disable DHCP service",
        "NFS Server Superfluous": "Disable this service",
        "RPC rstatd Service Detection": "Disable this service",
        "rsync Service Detection": "Disable this service and use secure alternatives like SFTP",
        # "HTTP Server Type and Version": "Migrate from HTTP to HTTPS", # Does not catch all occurences.
    }
    replace: str = "This test is informational only and does not denote any security problem."

    for key in high_with_sol:
        try:
            df.loc[df["Vulnerability Name"] == key, "Severity"] = "High"
            df.loc[df["Vulnerability Name"] == key, "Solution"] = high_with_sol[key]
            df.loc[df["Vulnerability Name"] == key, "Remarks"] = "Non-compliant as per MBSS Point 35"
            df.loc[(df["Vulnerability Name"] == key), "Description"].str.replace(replace, "")
        except:
            pass

    normalize_plugins: dict = {
        "Info": ["SMB Signing not required",],
        # "Medium": ["IPMI v2.0 Password Hash Disclosure",],
    }

    for key in normalize_plugins:
        for plugin in normalize_plugins[key]:
            try:
                df.loc[df["Vulnerability Name"] == plugin, "Severity"] = key
            except:
                pass

    httpp: str = "HyperText Transfer Protocol (HTTP) Information"
    sslp: str = "SSL / TLS Versions Supported"
    try:
        for port in df.loc[df["Vulnerability Name"] == httpp, "Port"]:
            for ipaddr in df.loc[(df["Vulnerability Name"] == httpp) & (df["Port"] == port), "IP Address"]:
                if ((df["Vulnerability Name"] == sslp) & (df["Port"] == port) & (df["IP Address"] == ipaddr)).any():
                    continue
                conditions = (df["Vulnerability Name"] == httpp) & (df["Port"] == port) & (df["IP Address"] == ipaddr)
                temp: pd.DataFrame = df.loc[conditions, "Description"]
                df.loc[conditions, "Severity"] = "High"
                df.loc[conditions, "Solution"] = "Migrate from HTTP to HTTPS"
                df.loc[conditions, "Remarks"] = "Non-compliant as per MBSS Point 35"
                df.loc[conditions, "Description"] = temp.str.replace(replace, "")
    except:
        pass
