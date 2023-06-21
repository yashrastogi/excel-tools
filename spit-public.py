from netaddr import *
import csv

inp = input()
li=[]
while inp:
    li.append(inp)
    inp = input()

with open('out.csv', "w", newline="", encoding="UTF-8") as reachCSV:
        writer = csv.writer(reachCSV)
        for ip in li:
            # print(f'{ip} {IPAddress(ip).is_private()}')
            writer.writerow([ip, IPAddress(ip).is_private()])
