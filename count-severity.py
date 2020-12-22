import sys
import pyximport  # pip install cython

pyximport.install(language_level=3, build_dir="./build")
sys.path.append("./modules")
from count_severity_module import count_severity


def main():
    if len(sys.argv) < 2:
        print("Usage: ./count-severity.py <directory>")
        return
    else:
        path = sys.argv[1]
    count_severity(path)


if __name__ == "__main__":
    main()
