import subprocess
import os
import json
import argparse

parser =  argparse.ArgumentParser(description="A bug bounty related enumeration script")
config = None

parser.add_argument(
    '-m',
    '--method',
    metavar='',
    type=str,
    choices=['enum', 'finder'],
    help="The method that will be run by the script, either for \
        enumeration, or for automated bug finding. Allowed values are enum and finder."
)

parent_directory = None

def setup(domain):
    global parent_directory
    global config
    try:
        with open("config.json", "r") as file:
            config = json.load(file)

        parent = os.path.expanduser(config["recon_dir"])

    except FileNotFoundError:
        print("[-] Config file not found")
        parent = os.path.expanduser("~/BugBounties/")

    directory = domain.split(".")[0]
    path = os.path.join(parent, directory)
    parent_directory = path + "/"

    flyover = os.path.join(path, 'flyover')

    try:
        os.makedirs(path)
        print(f"[+] Created directory for {domain} at {path}")
    except FileExistsError:
        pass

    try:
        os.mkdir(flyover)
    except FileExistsError:
        pass

def subdomain_enum(domain):
    print(f"[+] Enumerating subdomains for {domain}")
    subdomains = get_list_return(["amass", "enum", "-passive", "-d", domain, "-o", f"{parent_directory}subdomains.txt"])
    print(f"[+] Found {len(subdomains)} subdomains, results stored in {parent_directory}subdomains.txt")
    return subdomains

def probe():
    print("[+] Probing your subdomains for http/https servers")
    probed = get_list_return(
                        ["httprobe"],
                        ["cat", f"{parent_directory}subdomains.txt"]
                    )
    with open(f'{parent_directory}servers.txt', 'w') as file:
        file.writelines('\n'.join(probed))
        file.write('\n')
    print(f"[+] Found {len(probed)} http/https servers, results stored in {parent_directory}servers.txt")
    return probed

def flyover():
    print("[+] Starting subdomain flyover")
    try:
        get_list_return(
                ["aquatone", "-out", f"{parent_directory}flyover", "-silent"],
                ["cat", f"{parent_directory}servers.txt"]
        )
        print(f"[+] Results of flyover stored in {parent_directory}flyover")
    except FileNotFoundError:
        print(f"[-] The file servers.txt was not found in {parent_directory}")

    return

def response_codes():
    print("[+] Starting response code probing")

    get_list_return(
        ["httpx", "-sc", "-o", f"{parent_directory}response_codes.txt"],
        ["cat", f"{parent_directory}servers.txt"],
    )
    print(f"[+] Results of code probing stored in {parent_directory}response_codes.txt")

def get_list_return(commands, stdin=None):
    if stdin:
        echo = subprocess.Popen(
                    stdin,
                    stdout=subprocess.PIPE
                )

        results = subprocess.Popen(
                    commands,
                    stdin=echo.stdout,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
    else:
        results = subprocess.Popen(
                    commands,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
    out, _ = results.communicate()
    out = out.strip().decode("utf-8")
    output = out.split()
    return output

def enum():
    setup("owasp.org")
    subdomain_enum("owasp.org")
    probe()
    response_codes()
    flyover()

def finder():
    return

if __name__ == "__main__":
    args = parser.parse_args()

    if args.method == "enum":
        enum()
    elif args.method == "finder":
        finder()