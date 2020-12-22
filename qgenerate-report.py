#!/usr/bin/python3

import sys
import os
import pyximport  # pip install cython
import argparse

pyximport.install(language_level=3, build_dir="./build")
sys.path.append("./modules")
from generate_report_quarter_module import generate_report


def main():
    parser = argparse.ArgumentParser(
        description="Generate, normalize and format an excel report from Nessus detailed CSV."
    )
    parser.add_argument("path", type=dir_path, help="specify path containing csv report(s)")
    parser.add_argument(
        "-e", "--erase", help="overwrite existing reports", action="store_true", default=False
    )
    parser.add_argument(
        "-r", "--removeinfo", help="remove info", action="store_true", default=False
    )
    parser.add_argument(
        "-i",
        "--internet",
        help="normalize according to internet facing devices",
        action="store_true",
        default=False,
    )
    args = parser.parse_args()
    generate_report(args.path, not args.erase, False, args.internet, args.removeinfo)


def dir_path(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"readable_dir:{path} is not a valid path")


if __name__ == "__main__":
    main()
