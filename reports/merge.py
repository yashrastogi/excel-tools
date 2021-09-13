import pandas as pd
import sys
import os

df = pd.DataFrame()

for root, _, files in os.walk("./"):
    for file in files:
        if str(file).endswith(".csv"):
            print(
                "                                                                           ",
                end="\r",
            )
            print(f"{file}", end="\r")
            if df.empty:
                df = pd.read_csv(f"{root}/{file}")
            else:
                df1 = pd.read_csv(f"{root}/{file}")
                df = pd.concat([df, df1])

df.to_csv("combined-vulns.csv", index=False)
# df.to_parquet('combined.parquet.gz', compression='gzip')
