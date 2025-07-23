
# Passive Information Gathering 
### Things to check first :
- /robots.txt
- /sitemap.xml | /sitemaps.xml
### Things that are actually good to use :
- Built With, a Wappalyzer-like extension for Firefox
- WhatWeb, Default kali tool to check versions of plugins / tools used (Like PHP)
- HTTRack, Website downloader that is useful to analyse the code of the website/ it's functioning offline.

### Whois ENUM :
- in a shell just do :  `whois example.com`
- On "whois" websites they remove some useful info, and drops some inexact info.
- The interesting fields are "Company name", "Name servers", "Website's Email".

### Website footprinting (With Netcraft) :
- Netcraft will take *passively* as much information as possible
- It will take the name of the technologies used to build you target
- It will take the whois informations
- Info of SSL/TLS certificate will be also analysed
- Name servers / all the good stuff
### DNS Recon :
- We can use the kali "dnsrecon" tool with 
	`dnsrecon -d example.com`
- One of the most interesting DNS record is the MX record (aka mail record)
- You can use DNSDumpster (.com) that is a free tool that performs a DNS check on the website
### WAF / Firewall detection (with WafW00f) :
- Use ` wafw00f -l ` to list the detectable firewalls / WAFs
- /!\\ wafw00f won't be super accurate, use -a to list every possible installed WAF or firewall.
### Subdomain Enumeration (with Sublist3r) :
- to use it, simply do `sublist3r -d example.com`
- and optionnaly add `-e [se1],[se2]` if you want to choose the search engines that will be used
### Google dorking (Can be combined) :
- "site:" exclusively show results from a site, including subdomains.
- "inurl:" show only sites with the specified keyword precised.
- "cache:" shows the google web cache of the site given site (it's a like snapshot ) you can also use the wayback machine.
- You can add the asterisk sign that means "whatever" 
### Email harvesting (with The Harvester)
- simply do `theHarvester -d example.com -b [se1],[se2],[se+]`
### Leaked passwords databases (with Internet)
- First use "haveibeenpwned.com" to check the discovered emails, then, if a leak is found, you can use google dorks to find leaks attached to the company's email.
# ========================
End of the section about : **passive** information gathering.
Notes taken by Adnane. contact me in discord : "bigbrainguy."
Note that you can use any of the techniques in this page without prior consent, The info is on the internet and can be accessed by everyone.





# Active Information Gathering 
### DNS Zone transfers :

- The DNS zone transfer is a technique that helps companies to move DNS data from the actual server to another server. If it's misconfigured an attacker can abuse this functionality to transfer the DNS zone file that can give the attacker super useful info about company's internal network layout. In **some** cases it gives internal network adresses.
- First do : `dnsrecon -d example.com` (this is peaceful passive recon) `dnsenum example.com` (this is active, you can't access the actively discovered records passively) you can also use `dig axfr @[nameserver] example.com`
- To perform DNS servers bruteforce (to check IP leaks) you can use fierce : `fierce -dns example.com` you can add `--wordlist [wlist]` to the command to use your own wordlist. 
### Host discovery (with Nmap)
- First check your IP / Subnet (often /24) with `ip a s`
- Then do `sudo nmap -sn [IPaddr XX.XXX.XXX.0]` Note : you MUST put 0 instead of the last number of your IP address. 
- You can use (instead of Nmap) Netdiscover, to do that just type :  `sudo netdiscover` (it uses ARP requests)

### Port scanning (with Nmap(again))
- Windows hosts will block ICMP requests by default, just add `-Pn` flag and the scan will start
- Use the `-p` option to custom ports that will be scanned. Note : 34,43,23,... means 34 and 43 and ... / 1-14 means from 1 to 14
- Use the `-F` option to fast scan, Nmap will only scan top 100 used ports
- To perform an UDP port scan use the `-sU` flag
- To include service versions in your scan use the `-sV` flag
- To include operating system recon to your scan use the `-O` flag (It may be not super accurate)
- Use the `-sC` flag to run the default recommended list of NSE scripts
- `-v` is to add some verbose, i use `-vv` 
- To speedup your scan add the `-T[0,1,2,3,4,5]`  0 paranoid | 1 sneaky | 2 polite | 3 normal | 4 agressive | 5 insane (use with caution).
- Use `-oN file.txt` to basically save the info as displayed in the shell and use `-oX file.XML` to save it in XML format


# End of the Information Gathering (P&A) section
