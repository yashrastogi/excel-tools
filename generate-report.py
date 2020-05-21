#!/usr/bin/python3

import sys
import pyximport  # pip install cython

pyximport.install(language_level=3, build_dir="./build")
sys.path.append("./modules")
from generate_report_module import generate_report


def main():
    skip = True
    if len(sys.argv) < 2:
        print("Usage: ./generate-report.py <directory> <erase*>")
        return
    else:
        path = sys.argv[1]
        if len(sys.argv) == 3 and sys.argv[2] == "erase":
            skip = False
    generate_report(path, skip)


if __name__ == "__main__":
    main()
