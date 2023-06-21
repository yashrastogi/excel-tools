import ipaddress
import csv


def main():
    with open("subnet.csv", "w", newline="") as csvF:
        writer = csv.writer(csvF)
        writer.writerow(["IP Address", "Subnet"])
        print("Paste subnets, followed by x:")
        curr_input = ""
        subnet_list = []
        while True:
            curr_input = input()
            if curr_input != "x":
                subnet_list.append(curr_input)
            else:
                break
        for subnet in subnet_list:
            for ip in ipaddress.IPv4Network(subnet):
                writer.writerow([ip, subnet])
    print("Subnet to IPs mapping saved to subnet.csv")

main()
