import os
import shutil
import glob

target = open("target.txt", "r")


def walklevel(some_dir, level=1):
    num_sep = some_dir.count(os.path.sep)
    for root, dirs, files in os.walk(some_dir):
        yield root, dirs, files
        num_sep_this = root.count(os.path.sep)
        if num_sep + level <= num_sep_this:
            del dirs[:]


for line in target.readlines():
    line = line.rstrip()
    filename = line + "-vulns.csv"
    filenames2 = glob.glob(line + "-" + "*" + "-vulns.csv")
    for root, dirs, files in walklevel(os.path.join("..", "VA", "NNR", line), level=1):
        if filename in files:
            print(os.path.join(root, filename))
            shutil.copy(os.path.join(root, filename), os.path.join(".", "reports"))
        # else:
        #     print(f"{line} not found.")
