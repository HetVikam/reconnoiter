#!/bin/bash

domain=$1
wordlist="/path-to/SecLists/Discovery/DNS/dns-Jhaddix.txt" 
resolvers="/path-to/resolvers.txt"
resolve_domain="/path-to/massdns/bin/massdns -r /path-to/50resolvers.txt -t A -o S-W"

domain_enum(){

mkdir -p $domain $domain/sources $domain/Recon $domain/Recon/nuclei $domain/Recon/wayback $domain/Recon/gf $domain/Recon/wordlist $domain/Recon/masscan

subfinder -d $domain -o $domain/sources/subfinder.txt 
assetfinder -subs-only $domain | tee $domain/sources/assetdomain.com 
amass enum -passive -d $domain -o $domain/sources/passive.txt 
shuffledns -d $domain -w $wordlist -r $resolvers -o $domain/sources/shuffledns.txt

cat $domain/sources/*.txt > $domain/sources/all.txt
}
domain_enum

resolving_domains(){
shuffledns -d $domain -list $domain/sources/all.txt -o $domain/domains.txt -r $resolvers
}
resolving_domains

http_prob(){
cat $domain/domains.txt | httpx -threads 200 -o $domain/Recon/httpx.txt
}
http_prob

scanner(){
cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/cves/-c 50 -o $domain/Recon/nuclei/cves.txt 
cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/vulnerabilities/ -c 50 -o $domain/Recon/nuclei/vulnerabilities.txt 
cat $domain/Recon/httpx.txt | nuclei -t /root/nuclei-templates/files/c 50 -o $domain/Recon/nuclei/files.txt
} 
scanner

wayback_data(){

cat $domain/domains.txt | waybackurls | tee $domain/Recon/wayback/tmp.txt 
cat $domain/Recon/wayback/tmp.txt | egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpep|\.jpg|\.svg|\.css|\.ico" | sed 's/:80//g;s/:443//g' | sort -u >> $domain/Recon/wayback/wayback.txt
rm $domain/Recon/wayback/tmp.txt
}
wayback_data

valid_urls(){

fuzzer -c -u "FUZZ" -w $domain/Recon/wayback/wayback.txt -of csv -o $domain/Recon/wayback/valid-tmp.txt 
cat $domain/Recon/wayback/valid-tmp.txt | grep http | awk -F "," '{print $1}' >> $domain/Recon/wayback/valid.txt 
rm $domain/Recon/wayback/valid-tmp.txt
} 
valid_urls

gf_patterns(){
gf xss $domain/Recon/wayback/valid.txt | tee $domain/Recon/gf/xss.txt
gf sqli $domain/Recon/wayback/valid.txt | tee Sdomain/Recon/gf/sql.txt 
}
gf_patterns

custom_wordlist(){
cat $domain/Recon/wayback/wayback.txt | unfurl -unique paths > $domain/Recon/wordlist/path.txt
cat $domain/Recon/wayback/wayback.txt | unfurl -unique keys > $domain/Recon/wordlist/params.txt
}
custom_wordlist


get_ip(){
$resolve_domain $domain/Recon/masscan/results.txt $domain/domains.txt 
gf ip $domain/Recon/masscan/results.txt | sort -u> $domain/Recon/masscan/ip.txt
}
get_ip
