import subprocess
import os
import json


def settup(domain):
    try:
        with open("config.json", "r") as file:
            config = json.load(file)

        parent = os.path.expanduser(config["recon_dir"])

    except FileNotFoundError:
        print("[-] Config file not found")
        parent = os.path.expanduser("~/BugBounties/")

    directory = domain.split(".")[0]
    path = os.path.join(parent, directory)

    try:
        os.makedirs(path)
        print(f"[+] Created directory for {domain} at {path}")
    except FileExistsError:
        return

def subdomain_enum(domain):
    print(f"[+] Enumerating subdomains for {domain}")
    subdomains = get_list_return(["amass", "enum", "-passive", "-d", domain, "-o", "subdomains.txt"])
    print(f"[+] Found {len(subdomains)} subdomains (saved to subdomains.txt)")
    return subdomains

def probe(subdomains):
    print("[+] Probing your subdomains for http/https servers")
    probed = []
    for subdomain in subdomains:
        current = get_list_return(["httprobe"], subdomain)
        probed += current
    with open('servers.txt', 'w') as file:
        file.writelines('\n'.join(probed))
    print(f"[+] Found {len(probed)} http/https servers (saved to servers.txt)")
    return probed

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

settup("owasp.org")
subdomain_list = subdomain_enum("owasp.org")
probed_list = probe(subdomain_list)
