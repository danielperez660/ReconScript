import subprocess
import os
import json

parent_directory = None

def setup(domain):
    global parent_directory
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
    print(f"[+] Found {len(subdomains)} subdomains (saved to subdomains.txt)")
    return subdomains

def probe(subdomains):
    print("[+] Probing your subdomains for http/https servers")
    probed = []
    for subdomain in subdomains:
        current = get_list_return(["httprobe"], subdomain)
        probed += current
    with open(f'{parent_directory}servers.txt', 'w') as file:
        file.writelines('\n'.join(probed))
        file.write('\n')
    print(f"[+] Found {len(probed)} http/https servers (saved to servers.txt)")
    return probed

def flyover(subdomains):
    print("[+] Starting subdomain flyover")
    cat = subprocess.Popen(
                    ["cat", subdomains],
                    stdout=subprocess.PIPE
                )
    subprocess.Popen(
                    ["aquatone", "-out", f"{parent_directory}flyover"],
                    stdout=cat.stdin
                )
    print(f"[+] Results of flyover stored in {parent_directory}flyover")
    return

def get_list_return(commands, stdin=None):
    if stdin:
        echo = subprocess.Popen(
                    ["echo", stdin],
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

setup("owasp.org")
subdomain_list = subdomain_enum("owasp.org")
probed_list = probe(subdomain_list)
flyover(probed_list)