import pandas as pd
import sys
import argparse
import os

def writeExcel(df, destpath):
    writer = pd.ExcelWriter(
        f"{destpath}.xlsx",
        engine="xlsxwriter",
        options={"strings_to_urls": False},
    )
    print('\nSorting values.')
    severities = ["Critical", "High", "Medium", "Low", "Info"]
    df = df.astype({'Severity': pd.CategoricalDtype(categories=severities + [sev.upper() for sev in severities], ordered=True)})
    df.sort_values(["Severity", "Vulnerability Name", "IP Address"], ignore_index=True, inplace=True)
    df["S. No."] = df.index + 1
    df.to_excel(writer, sheet_name="Vulnerabilities", index=False)
    # table formatting
    _worksheetFormat(writer.sheets["Vulnerabilities"], writer, df)
    print('Writing excel.')
    writer.save()


def _worksheetFormat(worksheet, writer, df):
    def get_col(colName):
        count = -1
        for col in df.columns:
            count += 1
            if col == colName:
                break
        return count

    # worksheet.set_row(0, None, writer.book.add_format({"align": "left"}))
    worksheet.set_row(0, None, writer.book.add_format({"align": "left"}))
    if len(df.columns) > 12:
        worksheet.set_column(7, 10, None, writer.book.add_format({"align": "fill"}))
        # set column widths
        worksheet.set_column(11, len(df.columns), 15)  # Columns 12 -> End
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
        {"columns": col_names, "style": "Table Style Light 10"},
    )
   
    # Edit Metadata
    writer.book.set_properties(
        {
            "author": "Yash Rastogi",
        }
    )

def dir_path(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"readable_dir:{path} is not a valid path")

parser = argparse.ArgumentParser(
        description="Merge excel files."
    )
parser.add_argument("path", type=dir_path, help="specify path containing excel report(s)")
parser.add_argument("name", type=str, help="specify output file name", default="combined-vulns")
parser.add_argument(
    "-i", "--info", help="keep only info findings", action="store_true", default=False
)
parser.add_argument(
    "-q", "--quarter", help="only keep columns required for quarter", action="store_true", default=False
)
parser.add_argument(
    "-r", "--rem-info", help="remove info findings", action="store_true", default=False
)
parser.add_argument(
    "-p", "--ping", help="filter only ping findings", action="store_true", default=False
)

colNames = [
    "S. No.",
    "IP Address",
    "Vulnerability Name",
    "Severity",
    "Protocol",
    "Port",
    "Synopsis",
    "Description",
    "Solution",
    "Plugin Text",
    "Additional Details",
    "CVE",
    "Exploit Ease",
    "Exploit Frameworks"
]

df = pd.DataFrame()
args = parser.parse_args()
path = args.path

for root, _, files in os.walk(path):
    for file in files:
        if str(file).endswith(".xlsx") and "~$" not in str(file) and str(file) != "combined-vulns.xlsx":
            print(
                "                                                                           ",
                end="\r",
            )
            print(f"{file}", end="\r")
            if df.empty:
                df = pd.read_excel(f"{root}/{file}")
                if args.info:
                    df = df[(df["Severity"] == "Info") | (df["Severity"] == "INFO")]
                if args.rem_info:
                	df = df[(df["Severity"] != "Info") | (df["Severity"] != "INFO")]
                if args.quarter:
                    df.drop(df.columns.difference(colNames), 1, inplace=True)
                if args.ping:
                    df = df[df["Vulnerability Name"] == "Ping the remote host"]
            else: 
                df1 = pd.read_excel(f"{root}/{file}")
                if args.quarter:
                    df1.drop(df1.columns.difference(colNames), 1, inplace=True)
                if args.rem_info:
                	df1 = df1[(df1["Severity"] != "Info") | (df1["Severity"] != "INFO")]
                if args.info:
                    df1 = df1[(df1["Severity"] == "Info") | (df1["Severity"] == "INFO")]
                if args.ping:
                    df1 = df1[df1["Vulnerability Name"] == "Ping the remote host"]
                df = pd.concat([df, df1])

writeExcel(df, os.path.join(path, args.name))
# df.to_csv("combined-vulns.csv", index=False)
# df.to_parquet('combined.parquet.gz', compression='gzip')

