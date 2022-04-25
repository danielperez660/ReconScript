# ReconScript
Recon script following XSS Rat bug bounty methodology

Usage: main.py -m [enum|finder|all] -d domain.com
 - This will automatically create a directory to store the enum info under the domain name

## Required Tools for Enum
 - [Amass](https://github.com/OWASP/Amass)
 - [httprobe](https://github.com/tomnomnom/httprobe)
 - [Aquatone](https://github.com/michenriksen/aquatone)
 - [httpx](https://github.com/projectdiscovery/httpx)

## Required Tools for Finder
 - [subjack](https://github.com/haccer/subjack)
 - [nuclei](https://github.com/projectdiscovery/nuclei)
