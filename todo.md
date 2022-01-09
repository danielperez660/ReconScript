# Other to be implemented
* Add check to see if file exists rather than having function rely on previous function
* Add flags to be able to run single tool at a given moment 
* Add disabled script section in config file

## Automated
1. Subdomain teakeover checks
2. Open redirect checks [source](https://thexssrat.medium.com/open-redirects-easy-to-detect-hard-to-fix-8eb535611cd4)

# Based on [thread](https://twitter.com/theXSSrat/status/1479535804074573826)

## Automated
1. Subdomain enum ✓
2. httprobe ✓
3. subdomain flyover ✓
4. Nuclei (develop your own templates as well)
5. Portscan
6. Write subdomains to database for later use
7. If new domain goes into db, do full nuclei scan
8. If new nuclei template, scan old domains
9. Optional, do a cronjob every 3 weeks with nuclei

## Manual
10. Look at screenshots
10. Subdirectory and file brute forcing all custom login pages
10. Look up default credentials for std. accounts
11. Go to google
11. site:http://target.com -www
11. site:http://target.com -mail
12. Look into interesting targets
13. Parameter discovery for pages you have
14. Run SQLmap on params
15. Run @KN0X55 on URLs with params
16. Investigate repo's like github
17. Look at JS files [source](https://blog.appsecco.com/static-analysis-of-client-side-javascript-for-pen-testers-and-bug-bounty-hunters-f1cb1a5d5288)

# Based on [thread](https://twitter.com/IamRenganathan/status/1477581848951738371)

## Look into 403 codes and try and do directory enumeration around it to test for bad access control
1. Filter the subdomains using httpx with status codes 
2. Fuzz 403 for endpoints and try to bypass 403
3. Scan 404 using NtHiM for subdomain takeovers 
4. 200 ok in Eye witness takes screenshots fastly
