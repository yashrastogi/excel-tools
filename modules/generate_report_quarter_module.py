import os
from datetime import datetime
import pandas as pd
import numpy as np
import sys
from collections import namedtuple


def generate_report(path, skip=True, checkAuthOpt=False, internetFacing=False, removeinfo=False):
    np.warnings.filterwarnings("error", category=np.VisibleDeprecationWarning)
    columns_dtypes = {
        "IP Address": "object",
        "Plugin Name": pd.CategoricalDtype(ordered=False),
        "Severity": pd.CategoricalDtype(
            categories=["Critical", "High", "Medium", "Low", "Info"], ordered=True
        ),
        "Protocol": pd.CategoricalDtype(ordered=False),
        "Port": pd.Int64Dtype(),
        "Synopsis": "object",
        "Description": "object",
        "Solution": "object",
        "Plugin Text": "object",
        "See Also": "object",
        "CVE": "object",
        "Exploit Ease": pd.CategoricalDtype(
            categories=[
                "Exploits are available",
                "No exploit is required",
                "No known exploits are available",
                "Not Available"
            ],
            ordered=False,
        ),
        "Exploit Frameworks": "object",
        "Plugin": pd.Int64Dtype(),
        "Family": pd.CategoricalDtype(ordered=False),
        "Exploit?": pd.CategoricalDtype(ordered=False),
        "Repository": pd.CategoricalDtype(ordered=False),
        "MAC Address": "object",
        "DNS Name": "object",
        "NetBIOS Name": "object",
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
        "BID": "object",
        "Cross References": "object",
        "First Discovered": "object",
        "Last Observed": "object",
        "Vuln Publication Date": "object",
        "Patch Publication Date": "object",
        "Plugin Publication Date": "object",
        "Plugin Modification Date": "object",
        "Check Type": pd.CategoricalDtype(ordered=False),
        "Version": "object",
    }

    colNames = [
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

    for root, _, files in os.walk(path):
        for file in files:
            if str(file).endswith("vulns.csv") and "~$" not in str(file):
                print(f"{file}", end=": ")
                destpath = f'{root}/excel/{"".join(file.split(".")[0:-1])}'
                if os.path.exists(f"{destpath}.xlsx") and skip:
                    print("Excel exists, skipping...")
                else:
                    try:
                        print()
                        timeStart: datetime = datetime.now()
                        df: pd.DataFrame = pd.read_csv(f"{root}/{file}", dtype=columns_dtypes)[
                            list(columns_dtypes.keys())
                        ]
                        if not os.path.exists(f"{root}/excel/"):
                            os.makedirs(f"{root}/excel/")
                        print('Checking ping.')
                        checkPing(df, destpath)
                        print('Checking authentication.')
                        checkAuth(df, destpath, checkAuthOpt)
                        print('Customizing columns.')
                        customizeCols(df, colNames)
                        print('Normalizing SSL.')
                        normalizeSSL(df, internetFacing)
                        print('Normalizing Misc.')
                        normalizeMisc(df)
                        if removeinfo: df = df[df["Severity"] != "Info"]
                        print('Stripping Plugin Output.')
                        stripOutput(df)
                        print('Filling NA in empty columns.')
                        fillNA(df)
                        print('Writing Excel.', end=' ')
                        writeExcel(df, destpath)
                        timeEnd: datetime = datetime.now()
                        msec = (timeEnd - timeStart).total_seconds() * 1000
                        print("Excel file written in {:.0f}ms...\n".format(msec))

                    except:
                        exception: tuple = sys.exc_info()
                        print(
                            f"Error: {exception[0]}. {exception[1]}, line: {exception[2].tb_lineno}"
                        )

def fillNA(df):
    # cols = ["Solution", "Plugin Text", "Additional Details", "CVE", "Exploit Ease", "Exploit Frameworks"]
    df.loc[:,'Solution':'Exploit Frameworks'] = df.loc[:,'Solution':'Exploit Frameworks'].fillna('Not Available')
    # for col in cols:
        # import pdb; pdb.set_trace()
        # df[col] = df[col].fillna('Not Available')
        # df.loc[:,'Solution':'Exploit Frameworks'].values[df.loc[:,'Solution':'Exploit Frameworks'].isna()] = 'Not Available'
        # df[col].values[df[col].isna()] = 'Not Available'
        # df[col] = df[col].replace(np.nan, 'Not Available')
    # df.loc[:,'Solution':'Exploit Frameworks'] = df.loc[:,'Solution':'Exploit Frameworks'].replace(np.nan, 'Not Available')
    # df['Exploit Ease'].fillna('Not Available', inplace=True)
    
def customizeCols(df, colNames):
    # df.drop(
    #     df.columns.difference(colNames),
    #     1,
    #     inplace=True,
    # )
    # df.insert(12, "Remarks", "")
    df.insert(0, "S. No.", 0)

    dateCols = ["Vuln Publication Date","Patch Publication Date","Plugin Publication Date","Plugin Modification Date","First Discovered","Last Observed"]
    for col in dateCols:
        if col in df.columns:
            df[col] = df[col].str[:-4]
            df[col] = pd.to_datetime(df[col], format="%b %d, %Y %H:%M:%S")
            
    df.rename(
        columns={
            "See Also": "Additional Details",
            "Plugin Name": "Vulnerability Name",
            "Plugin": "Plugin ID",
        },
        inplace=True,
    )


def writeExcel(df, destpath):
    writer = pd.ExcelWriter(
        f"{destpath}.xlsx",
        engine="xlsxwriter",
        options={"strings_to_urls": False},
    )
    df.sort_values(["Severity", "Vulnerability Name", "IP Address"], ignore_index=True, inplace=True)
    df["S. No."] = df.index + 1
    df.to_excel(writer, sheet_name="Vulnerabilities", index=False)
    # try:
    #     generatePortsDF(df).to_excel(writer, sheet_name="Ports", index=False)
    # except:
    #     pass
    # table formatting
    print()
    _worksheetFormat(writer.sheets["Vulnerabilities"], writer, df)
    writer.save()


def _worksheetFormat(worksheet, writer, df):
    def get_col(colName):
        count = -1
        for col in df.columns:
            count += 1
            if col == colName:
                break
        return count
    worksheet.set_row(0, None, writer.book.add_format({"align": "left"}))
    if len(df.columns) > 12:
        # set column widths
        # worksheet.set_column(8, 10, 35)  # Columns 8 -> 11
        worksheet.set_column(11, len(df.columns), 15)  # Columns 12 -> End
        worksheet.set_column(get_col("First Discovered"), get_col("Plugin Modification Date"), 18)
        worksheet.set_column(get_col("Synopsis"), get_col("Plugin Text"), 35, writer.book.add_format({"align": "fill"}))
        worksheet.set_column(get_col("Additional Details"), get_col("Additional Details"), 20)
        worksheet.set_column(get_col("S. No."), get_col("S. No."), 7)  # S No.
        worksheet.set_column(get_col("Plugin ID"), get_col("Plugin ID"), 7)  # Plugin ID
        worksheet.set_column(get_col("Vulnerability Name"), get_col("Vulnerability Name"), 41)  # Vuln. Name
        worksheet.set_column(get_col("IP Address"), get_col("IP Address"), 12)  # IP Addr.
        worksheet.set_column(get_col("Protocol"), get_col("Protocol"), 4)  # Protocol
        worksheet.set_column(get_col("Port"), get_col("Port"), 6)  # Port

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
        {"columns": col_names, "style": "Table Style Light 8"},
    )
    # Edit Metadata
    writer.book.set_properties(
        {
            "author": "Yash Rastogi",
        }
    )


def generatePortsDF(df: pd.DataFrame):
    portsDF = pd.DataFrame(data=df["Port"].unique(), columns=["Port"])
    portsDF = portsDF[portsDF.Port != 0]
    portsDF.sort_values(by="Port", inplace=True)
    return portsDF


def stripOutput(df: pd.DataFrame):
    # Total number of characters that a cell can contain, in excel: 32,767 characters
    try:
        df["Plugin Text"] = (
            df["Plugin Text"]
            .str.replace("Plugin Output: \n", " ")
            .str.replace("Plugin Output: ", " ")
        )
        df["Plugin Text"] = df["Plugin Text"].str[0:32760]
    except:
        pass


def checkPing(df: pd.DataFrame, destpath):
    destpath = f"{destpath}-unreachable.txt"
    try:
        if os.path.exists(destpath):
            os.remove(destpath)
    except:
        pass
    pingSuccessText = "Plugin Output: The remote host is up"
    printed: bool = False
    for namedTuple in df.loc[
        df["Plugin Name"] == "Ping the remote host", ["IP Address", "Plugin Text"]
    ].itertuples():
        if pingSuccessText not in namedTuple._2:
            if not printed:
                print("\nThe following remote hosts were found unreachable:")
                printed = True
            txtFile = open(destpath, "a")
            txtFile.write(f"{namedTuple._1}\n")
            txtFile.close()
            print(namedTuple._1)
    if printed:
        print()


def checkAuth(df: pd.DataFrame, destpath, enable: bool):
    destpath = f"{destpath}-errors.txt"
    try:
        if os.path.exists(destpath):
            os.remove(destpath)
    except:
        pass

    if enable:
        plugins = [
            "Authentication Failure(s) for Provided Credentials",
            "Target Credential Status by Authentication Protocol - Failure for Provided Credentials",
            "SSH Commands Require Privilege Escalation",
            "Authentication Failure - Local Checks Not Run",
            "Authentication Success with Intermittent Failure",
            "Target Credential Issues by Authentication Protocol - Intermittent Authentication Failure",
        ]
        acknowledged: dict = {}
        for plugin in plugins:
            for namedTuple in df.loc[
                df["Plugin Name"] == plugin, "IP Address":"Plugin Text"
            ].itertuples():
                acknowledged.update({namedTuple._1: True})
                txtFile = open(destpath, "a")
                txtFile.write(
                    f"({plugin}) IP Address: {namedTuple._1}:{namedTuple.Port}\n{namedTuple._13}\n\n"
                )
                txtFile.close()
                print(f"{plugin} IP Address: {namedTuple._1}")

        for ipaddr in df["IP Address"].unique():
            if ipaddr not in acknowledged:
                for namedTuple in df.loc[
                    (df["IP Address"] == ipaddr)
                    & (
                        (df["Plugin Name"] == "Authentication Success")
                        | (
                            df["Plugin Name"]
                            == "Target Credential Issues by Authentication Protocol - No Issues Found"
                        )
                    ),
                    "IP Address":"Plugin Text",
                ].itertuples():
                    acknowledged.update({namedTuple._1: True})

        for ipaddr in df["IP Address"].unique():
            if ipaddr not in acknowledged:
                txtFile = open(destpath, "a")
                txtFile.write(f"(No Authentication Detected) IP Address: {ipaddr}\n\n")
                txtFile.close()
                print(f"(No Authentication Detected) IP Address: {ipaddr}")


def normalizeSSL(df: pd.DataFrame, internetFacing: bool):
    plugins: dict = {}
    if internetFacing:
        plugins = {
            "Info": [],
            "Low": [
                "SSL Medium Strength Cipher Suites Supported (SWEET32)",
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
            "Medium": [],
            "High": ["SSL Certificate Expiry"],
        }
    else:
        plugins = {
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
            "High": [],
        }

    for key in plugins:
        for plugin in plugins[key]:
            try:
                df.loc[df["Vulnerability Name"] == plugin, "Severity"] = key
            except:
                pass


def normalizeMisc(df: pd.DataFrame):
    ModRowItem = namedtuple("ModRowItem", "Remarks Synopsis Description Solution")

    high_with_sol: dict = {
        # "Microsoft Windows SMB Service Detection": ModRowItem(
        #     "",
        #     "A file / print sharing service is listening on the remote host.\nAccording to MBSS point no. 35, only secure services must be enabled and secure protocol must be used.",
        #     "",
        #     "",
        # ),
        "Unencrypted Telnet Server": ModRowItem(
            "",
            "It was observed that a Telnet server is listening on a remote port which transmits data in clear text\nAccording to MBSS point no. 35, only secure services must be enabled and secure protocol must be used.",
            "The remote host is running a Telnet server over an unencrypted channel",
            "It is recommended to disable the Telnet service and use SSH instead",
        ),
        "RPC portmapper Service Detection": ModRowItem(
            "",
            "It was observed that RPC portmapper service is running on a remote port\nAccording to MBSS point no. 35, only secure services must be enabled and secure protocol must be used.",
            "The RPC portmapper is running on this port",
            "If RPC services are not used on this machine, close this service. Otherwise filter traffic to this port to allow access only from trusted machines",
        ),
        "RPC rstatd Service Detection": ModRowItem(
            "",
            "It is possible to leak information about the remote server.\nAccording to MBSS point no. 35, only secure services must be enabled and secure protocol must be used.",
            "",
            "It is recommended to close the service, if not used on this machine. Otherwise filter traffic to this port to allow access only from trusted machines",
        ),
        # "HyperText Transfer Protocol (HTTP) Information": ModRowItem(
        #     "",
        #     "It was observed that HTTP service is running on the remote port. HTTP is an unencrypted service.\nAccording to MBSS point no. 35, only secure services must be enabled and secure protocol must be used.",
        #     "This test gives some information about the remote HTTP protocol - the version used, whether HTTP Keep-Alive and HTTP pipelining are enabled, etc...",
        #     "It is recommended to use HTTPS instead of HTTP",
        # ),
        "rlogin Service Detection": ModRowItem(
            "",
            "The rlogin service is running on the remote host.\nAccording to MBSS point no. 35, only secure services must be enabled and secure protocol must be used.",
            "",
            "It is recommended to close the service, if not used on this machine. Otherwise filter traffic to this port to allow access only from trusted machines",
        ),
        "FTP Server Detection": ModRowItem(
            "",
            "It was observed that FTP server is listening on the remote port.\nAccording to MBSS point no. 35, only secure services must be enabled and secure protocol must be used.",
            "",
            "It is recommended to use FTPS (FTP over SSL/TLS) or SFTP (part of the SSH suite)",
        ),
        "Discard Service Detection": ModRowItem(
            "",
            "A discard service is running on the remote host.\nAccording to MBSS point no. 35, only secure services must be enabled and secure protocol must be used.",
            "",
            "",
        ),
        # "TFTP Server Detection": ModRowItem(
        #     "", "", "", "Use secure alternative SFTP and It is recommended to disable this service, if not used on this machine. Otherwise filter traffic to this port to allow access only from trusted machines"
        # ),
        "TFTP Daemon Detection": ModRowItem(
            "",
            "A TFTP server is listening on the remote port.\nAccording to MBSS point no. 35, only secure services must be enabled and secure protocol must be used.",
            "",
            "If TFTP services are not used on this machine, close or uninstall this service. Otherwise restrict access to trusted sources only",
        ),
        # "SNMP Protocol Version Detection": ModRowItem(
        #     "Upgrade to SNMPv3 or It is recommended to disable this service, if not used on this machine. Otherwise filter traffic to this port to allow access only from trusted machines", "", "", ""
        # ),
        # "DHCP Server Detection": ModRowItem("Disable DHCP service", "", "", ""),
        "NFS Server Superfluous": ModRowItem(
            "",
            "It was observed that NFS Service is running on the remote port.\nAccording to MBSS point no. 35, only secure services must be enabled and secure protocol must be used.",
            "",
            "",
        ),
        "NFS Share Export List": ModRowItem(
            "",
            "The remote NFS server exports a list of shares.\nAccording to MBSS point no. 35, only secure services must be enabled and secure protocol must be used.",
            "",
            "",
        ),
        "CDE Subprocess Control Service (dtspcd) Detection": ModRowItem(
            "",
            "It was observed that dtspcd service is running on the remote port\nAccording to MBSS point no. 35, only secure services must be enabled and secure protocol must be used.",
            "",
            "It is recommended to It is recommended to disable this service, if not used on this machine. Otherwise filter traffic to this port to allow access only from trusted machines, if not used on this machine. Otherwise filter traffic to this port to allow access only from trusted machines",
        ),
        "Identd Service Detection": ModRowItem(
            "",
            "",
            "",
            "It is recommended to disable this service, if not used on this machine. Otherwise filter traffic to this port to allow access only from trusted machines",
        ),
        "Systat Service Remote Information Disclosure": ModRowItem(
            "",
            "",
            "",
            "It is recommended to disable this service, if not used on this machine. Otherwise filter traffic to this port to allow access only from trusted machines",
        ),
        "RPC sprayd Service In Use": ModRowItem("", "", "", ""),
        "Daytime Service Detection": ModRowItem(
            "",
            "A daytime service is running on the remote host.\nAccording to MBSS point no. 35, only secure services must be enabled and secure protocol must be used.",
            "",
            "",
        ),
        # "Sendmail Service Detection": ModRowItem(
        #     "",
        #     "A sendmail service is running on the remote host.\nAccording to MBSS point no. 35, only secure services must be enabled and secure protocol must be used.",
        #     "",
        #     "It is recommended to disable this service, if not used on this machine. Otherwise filter traffic to this port to allow access only from trusted machines",
        # ),
        "RPC rusers Remote Information Disclosure": ModRowItem(
            "",
            "It is possible to enumerate logged in users.\nAccording to MBSS point no. 35, only secure services must be enabled and secure protocol must be used.",
            "",
            "It is recommended to close this service, if not used on this machine. Otherwise filter traffic to this port to allow access only from trusted machines",
        ),
        "Finger Service Remote Information Disclosure": ModRowItem(
            "",
            "",
            "",
            "It is recommended to disable this service, if not used on this machine. Otherwise filter traffic to this port to allow access only from trusted machines",
        ),
        "rsync Service Detection": ModRowItem(
            "",
            "A rsync service is running on the remote host.\nAccording to MBSS point no. 35, only secure services must be enabled and secure protocol must be used.",
            "",
            "It is recommended to close the service, if not used on this machine. Otherwise filter traffic to this port to allow access only from trusted machines.",
        ),
        "Echo Service Detection": ModRowItem(
            "",
            "An echo service is running on the remote host.\nAccording to MBSS point no. 35, only secure services must be enabled and secure protocol must be used.",
            "",
            "It is recommended to disable this service, if not used on this machine. Otherwise filter traffic to this port to allow access only from trusted machines",
        ),
        "Chargen UDP Service Remote DoS": ModRowItem(
            "",
            "The remote host is running a 'chargen' service.\nAccording to MBSS point no. 35, only secure services must be enabled and secure protocol must be used.",
            "",
            "",
        ),
    }
    replace: str = "This test is informational only and does not denote any security problem."

    for key in high_with_sol:
        try:
            df.loc[df["Vulnerability Name"] == key, "Severity"] = "High"
            if high_with_sol[key].Remarks != "":
                df.loc[df["Vulnerability Name"] == key, "Remarks"] = high_with_sol[key].Remarks
            if high_with_sol[key].Synopsis != "":
                df.loc[df["Vulnerability Name"] == key, "Synopsis"] = high_with_sol[key].Synopsis
            if high_with_sol[key].Description != "":
                df.loc[df["Vulnerability Name"] == key, "Description"] = high_with_sol[
                    key
                ].Description
            if high_with_sol[key].Solution != "":
                df.loc[df["Vulnerability Name"] == key, "Solution"] = high_with_sol[key].Solution
            df.loc[(df["Vulnerability Name"] == key), "Description"].str.replace(replace, "", regex=True)
        except:
            pass

    normalize_plugins: dict = {
        # "Info": [],
        # "Medium": ["IPMI v2.0 Password Hash Disclosure",],
    }

    for key in normalize_plugins:
        for plugin in normalize_plugins[key]:
            try:
                df.loc[df["Vulnerability Name"] == plugin, "Severity"] = key
            except:
                pass

    try:
        conditions = (
            (df["Vulnerability Name"] == "HyperText Transfer Protocol (HTTP) Information")
            & ~df["Plugin Text"].str.contains(
                "This combination of host and port requires TLS", na=False
            )
            & ~df["Plugin Text"].str.contains("plain HTTP request was sent to HTTPS port", na=False)
            & ~df["Plugin Text"].str.contains("SSL : yes", na=False)
            & ~df["Plugin Text"].str.contains("Location: https://", na=False)
            & ~df["Plugin Text"].str.contains(
                "You're speaking plain HTTP to an SSL-enabled server port.", na=False
            )
            & ~df["Plugin Text"].str.contains(
                "Client sent an HTTP request to an HTTPS server.", na=False
            )
        )
        temp = df.loc[conditions, "Description"]
        df.loc[conditions, ["Severity", "Synopsis", "Description", "Solution"]] = [
            "High",
            "It was observed that HTTP service is running on the remote port. HTTP is an unencrypted service.\nAccording to MBSS point no. 35, only secure services must be enabled and secure protocol must be used.",
            "This test gives some information about the remote HTTP protocol - the version used, whether HTTP Keep-Alive and HTTP pipelining are enabled, etc...",
            "It is recommended to use HTTPS instead of HTTP"
        ]
    except:
        pass