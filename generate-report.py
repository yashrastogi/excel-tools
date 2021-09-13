#!/usr/bin/python3

import sys
import os
import pyximport  # pip install cython
import argparse

pyximport.install(language_level=3, build_dir="./build")
sys.path.append("./modules")
from generate_report_module import generate_report
from generate_report_module_nessus import generate_report_nessus


def main():
    parser = argparse.ArgumentParser(description="Generate, normalize and format an excel report from Nessus detailed CSV.")
    parser.add_argument("path", type=dir_path, help="specify path containing csv report(s)")
    parser.add_argument("-e", "--erase", help="overwrite existing reports", action="store_true", default=False)
    parser.add_argument("-n", "--nessus", help="nessus mode", action="store_true", default=False)
    parser.add_argument(
        "-i",
        "--internet",
        help="normalize according to internet facing devices",
        action="store_true",
        default=False,
    )
    parser.add_argument("-r", "--removeinfo", help="remove info", action="store_true", default=False)
    parser.add_argument(
        "-d",
        "--disable-auth",
        help="disable authentication checks",
        action="store_true",
        default=False,
    )
    parser.add_argument("-o", "--oldnessus", help="Set older nessus columns", action="store_true")
    args = parser.parse_args()
    if args.nessus:
        generate_report_nessus(args.path, not args.erase, not args.disable_auth, args.internet, args.removeinfo, False, args.oldnessus)
    else:
        generate_report(args.path, not args.erase, not args.disable_auth, args.internet, args.removeinfo, False)


def dir_path(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"readable_dir:{path} is not a valid path")


if __name__ == "__main__":
    main()
