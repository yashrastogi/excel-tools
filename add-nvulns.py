import os
import re
from datetime import datetime

def main():
    for (_, _, f) in os.walk('.'): break
    for file_name in f:
        if file_name.endswith('.csv'):
            print(file_name, end=' - ')
            os.rename(file_name, '.'.join(file_name.split('.')[:-1]) + '-nvulns.csv')
            print('.'.join(file_name.split('.')[:-1]) + '-nvulns.csv')
main()