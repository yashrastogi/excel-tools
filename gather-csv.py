import os
import sys
import shutil

if len(sys.argv) < 2:
    path = "../VA"
else:
    path = sys.argv[1]

if not os.path.exists("./csv"):
    os.makedirs("./csv")

for root, _, files in os.walk(path):
    for file in files:
        if str(file).endswith("vulns.csv"):
            shutil.copy(f"{root}/{file}", f"./csv/")
for file in os.listdir("./csv"):
    print(file)
