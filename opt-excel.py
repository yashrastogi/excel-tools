import argparse
import shutil
import zipfile
# import zopfli
import os

def dir_path(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"readable_dir:{path} is not a valid path")

parser = argparse.ArgumentParser(
        description="Optimize excel (/zip) files by recompressing with higher DEFLATE compression level."
    )
parser.add_argument("path", type=dir_path, help="specify path containing excel report(s)")

args = parser.parse_args()
path = args.path

def add_dir_zip(dira, zipf, basedir):
    for file in os.listdir(dira):
        fullpath = os.path.join(dira, file)
        if os.path.isfile(fullpath):
            zipf.write(fullpath, fullpath[len(basedir)+1:])
        elif os.path.isdir(fullpath):
            add_dir_zip(fullpath, zipf, basedir)


for file in os.listdir(path):
    fullpath = os.path.join(path, file)
    if os.path.isfile(fullpath) and not os.path.splitext(file)[0].endswith('-opt'):
        fullpath2 = os.path.join(path, os.path.splitext(file)[0])
        if zipfile.is_zipfile(fullpath):
            print(file)
            destoptfilename = fullpath2 + '-opt' + os.path.splitext(file)[1]
            if os.path.exists(destoptfilename):
                print(os.path.basename(destoptfilename) + ' exists! Not proceeding with this file.')
            else:
	            with zipfile.ZipFile(fullpath, 'r') as zipf:
	                if not os.path.exists(fullpath2):
	                    os.makedirs(fullpath2)
	                zipf.extractall(path=fullpath2)
	            destoptfilename = fullpath2 + '-opt' + os.path.splitext(file)[1]
	            with zipfile.ZipFile(destoptfilename, mode='x', compresslevel=9, compression=zipfile.ZIP_DEFLATED, allowZip64=False) as newzipf:
	                add_dir_zip(fullpath2, newzipf, fullpath2)
	            shutil.rmtree(fullpath2)

            