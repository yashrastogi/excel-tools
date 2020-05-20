import threading
import glob
import os
import sys
import time
import openpyxl as xl


def main():
    if len(sys.argv) < 2:
        print("Usage: ./zip-mon.py <directory>")
        return
    else:
        path = sys.argv[1]
    then = glob.glob(f'{path}/*.zip')
    while True:
        now = glob.glob(f'{path}/*.zip')
        diff = set(now) - set(then)
        if len(diff) != 0:
            print(list(diff)[0].split('/')[-1])
            wb = xl.load_workbook(filename=f"{path}/VA/NNR-Tracker-Yash.xlsx")
            ws = wb.worksheets[0]
        then = now
        time.sleep(1)


if __name__ == "__main__":
    main()
