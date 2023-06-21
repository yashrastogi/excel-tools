import csv
from paramiko import transport, SSHClient, AutoAddPolicy


def main():
    with open("servers.csv", newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        new_pass = input("Enter new password: ")
        for row in reader:
            IP = row["IPAddress"]
            Username = row["Username"]
            Password = row["Password"]

            print(f"\nConnecting to {IP} as {Username}...\n")

            with SSHClient() as client:
                client.set_missing_host_key_policy(AutoAddPolicy())
                client.connect(IP, username=Username, password=Password)
                input(f"Continue to set password to {new_pass}? (Ctrl-C to exit) ")
                print()
                _, stdout, _ = client.exec_command("whoami")
                login_user = stdout.read().decode()
                if login_user == 'root\n':
                    print("NOTICE: User is root")
                    stdin, stdout, stderr = client.exec_command(f"passwd {Username}")
                else:
                    stdin, stdout, stderr = client.exec_command(f"passwd")
                stdin.write(f"{new_pass}\n")
                stdin.write(f"{new_pass}\n")
                stdin.flush()
                stdout.channel.set_combine_stderr(True)
                print(stdout.read().decode())

main()
