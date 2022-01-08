import subprocess

def subdomain_enum():
    subprocess.call(["amass", "enum", "-active", "-d", domain])
