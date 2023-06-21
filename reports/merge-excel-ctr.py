import pandas as pd
import sys
import os

df = pd.DataFrame()

for root, _, files in os.walk("./"):
    for file in files:
        if str(file).endswith(".xlsx"):
            # print(
            #     "                                                                           ",
            #     end="\r",
            # )
            print(f"{file}", end="\n")
            if df.empty:
                df = pd.read_excel(f"{root}/{file}")
                df['File Name'] = str(file)
            else:
                df1 = pd.read_excel(f"{root}/{file}")
                df1['File Name'] = str(file)
                df = pd.concat([df, df1])

df.to_csv("combined-vulns.csv", index=False)
# df.to_parquet('combined.parquet.gz', compression='gzip')
