import subprocess
import os
import json
import argparse
import re
from git import Repo
from git.exc import GitCommandError

### General Methods & Setup ####

def txt_regex(arg_value, pat=re.compile(r"^.*\.txt")):
    if not pat.match(arg_value):
        raise argparse.ArgumentTypeError
    return arg_value

def domain_regex(arg_value, pat=re.compile(r"^(((?!\-))(xn\-\-)?[a-z0-9\-_]{0,61}[a-z0-9]{1,1}\.)*(xn\-\-)?([a-z0-9\-]{1,61}|[a-z0-9\-]{1,30})\.[a-z]{2,}$")):
    if not pat.match(arg_value):
        raise argparse.ArgumentTypeError
    return arg_value

parser =  argparse.ArgumentParser(description="A bug bounty related enumeration script.")
config = None
parent_directory = None
custom_location = False
group = parser.add_mutually_exclusive_group(required=True)

parser.add_argument(
    '-m',
    '--method',
    metavar='',
    type=str,
    choices=['enum', 'finder', "all"],
    help="The method that will be run by the script, either for \
        enumeration, or for automated bug finding. To run finder \
        the files created by enum need to exist (servers.txt & \
        subdomains.txt). Allowed values are enum, finder, and all."
)

parser.add_argument(
    '-u',
    '--update',
    action='store_true',
    help="Setting this flag will update the nuclei repository for \
        open-soure templates we use, ensuring that we are up to date\
        with the most recent templates available."
)

parser.add_argument(
    '-t',
    '--threads',
    metavar='',
    type=int,
    help="If the tools in use have multithreading options, \
        this will allow you to set the number of threads you \
        want to work with."
)

group.add_argument(
    '-d',
    '--domain',
    metavar='',
    type=domain_regex,
    help="The domain you wish to carry a scan out on. Exclusive\
        with -dl."
)

group.add_argument(
    '-dl',
    '--domain_list',
    metavar='',
    type=txt_regex,
    help="A txt file of domains which you wish to enumerate.\
        must be separated by a newline. Exclusive with -d."
)

parser.add_argument(
    '-o',
    '--output',
    metavar='',
    type=str,
    help="This will be the name of the directory in which your results \
            will be stored. If this is not set, the directory name will just \
            be the domain name without the TLD appended."
)

def setup(domain):
    global parent_directory
    global config

    args = parser.parse_args()

    try:
        with open("config.json", "r") as file:
            config = json.load(file)

        parent = os.path.expanduser(config["recon_dir"])

    except FileNotFoundError:
        print("[-] Config file not found")
        parent = os.path.expanduser("~/BugBounties/")

    if args.output:
        directory = args.output
        path = os.path.join(parent, directory)
        path = os.path.join(path, domain)
    else:
        directory = domain
        path = os.path.join(parent, directory)

    parent_directory = path + "/"


    try:
        os.makedirs(path)
        print(f"[+] Created directory for {domain} at {path}")
    except FileExistsError:
        pass

def pull_repo():
    print("[+] Updating nuclei template repo")

    git_url = "git@github.com:projectdiscovery/nuclei-templates.git"
    repo_dir = f"{parent_directory}../dependencies/templates"

    try:
        Repo.clone_from(git_url, repo_dir)
    except GitCommandError: 
        repo = Repo(repo_dir)
        o = repo.remotes.origin
        o.pull()
        
    print("[+] Update complete")
    
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

### Enum Methods ####

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
    flyover = os.path.join(parent_directory, 'flyover')

    try:
        os.mkdir(flyover)
    except FileExistsError:
        pass

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

def enum(domain):
    subdomain_enum(domain)
    probe()
    response_codes()
    flyover()

### Finder Methods ####

def subdomain_takeover():
    print("[+] Starting subdomain takeover checks")
    
    if not os.path.exists(f"{parent_directory}subdomain_takeover.txt"):
        with open(f"{parent_directory}subdomain_takeover.txt", 'w'):
            pass

    get_list_return(
        [
            "subjack",
            "-w",
            f"{parent_directory}subdomains.txt",
            "-o",
            f"{parent_directory}subdomain_takeover.txt",
            "-a",
            "-ssl",
            '-v'
            ],
    )
    
    print(f"[+] Results of takeover checks stored in {parent_directory}subdomain_takeover.txt")


def nuclei_scans():

    get_list_return(
        ["nuclei", "-t", "template-file", "-l", f"{parent_directory}servers.txt"],
    )

    return


def finder():
    subdomain_takeover()
    # nuclei_scans()
    return

### Script Entrypoint ####

if __name__ == "__main__":
    args = parser.parse_args()
    if args.update:
        pull_repo()

    if args.domain:
        setup(args.domain)
        if args.method == "enum":
            enum(args.domain)
        elif args.method == "finder":
            finder()
        elif args.method == "all":
            enum(args.domain)
            finder()

    elif args.domain_list:
        try:
            with open(args.domain_list, "r") as file:
                for line in file:
                    domain = line.strip()

                    print(f"[+] Working on {domain} from {args.domain_list}")

                    setup(domain)
                    if args.method == "enum":
                        enum(domain)
                    elif args.method == "finder":
                        finder()
                    elif args.method == "all":
                        enum(domain)
                        finder()

                    print("")
        except FileNotFoundError:
            print(f"[-] The domain list file {args.domain_list} does not exist.")
            exit(1)