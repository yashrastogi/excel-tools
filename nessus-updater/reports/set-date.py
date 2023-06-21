import os
import re
from datetime import datetime

def main():
    for (_, _, f) in os.walk('.'): break
    for file_name in f:
        m = re.search(r'([0-9]+-[0-9]+-[0-9]+)_([0-9]+_[0-9]+)', file_name)
        if m == None or len(m.group(0)) != 16:
            continue
        datetime_obj = datetime.strptime(m.group(0), '%d-%m-%Y_%H_%M')
        os.utime(file_name, (datetime_obj.timestamp(), datetime_obj.timestamp()))
main()