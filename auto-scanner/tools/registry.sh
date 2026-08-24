#!/bin/bash
# ============================================
# Tool Registry - Kali Tool Database
# ============================================
# Relational registry of categorized tools
# Usage: source tools/registry.sh
# ============================================
# shellcheck disable=SC2034

# ============================================
# CATEGORY 1: RECONNAISSANCE
# ============================================

declare -A TOOLS_RECON

# --- Network Scanning ---
TOOLS_RECON[nmap]="recon|network|port_scan|service_detection|os_detection|script_scan|1-10|https://nmap.org"
TOOLS_RECON[zmap]="recon|network|internet_scan|fast|stateless|7-10|https://zmap.io"
TOOLS_RECON[masscan]="recon|network|port_scan|fastest|asynchronous|8-10|https://github.com/robertdavidgraham/masscan"
TOOLS_RECON[unicornscan]="recon|network|port_scan|asynchronous|stateless|5-8|https://github.com/gvanvuuren/unicornscan"
TOOLS_RECON[netdiscover]="recon|network|arp_scan|host_discovery|passive|4-7|https://github.com/nicoz/netdiscover"

# --- DNS Enumeration ---
TOOLS_RECON[dnsrecon]="recon|dns|zone_transfer|subdomain_enum|brute_force|3-8|https://github.com/darkoperator/dnsrecon"
TOOLS_RECON[dig]="recon|dns|zone_query|record_lookup|1-5|builtin"
TOOLS_RECON[host]="recon|dns|reverse_dns|zone_transfer|1-4|builtin"
TOOLS_RECON[dnsenum]="recon|dns|zone_transfer|subdomain_brute|3-6|https://github.com/fwaeyt/dnsenum"
TOOLS_RECON[dnsmap]="recon|dns|subdomain_brute|wildcard|3-5|https://github.com/reconspider/dnsmap"
TOOLS_RECON[dnsdict]="recon|dns|subdomain_enum|dictionary|2-5|part_of_dnstracer"
TOOLS_RECON[sublist3r]="recon|dns|subdomain_enum|passive|multi_source|5-8|https://github.com/aboul3la/Sublist3r"
TOOLS_RECON[subfinder]="recon|dns|subdomain_enum|passive|fast|6-9|https://github.com/projectdiscovery/subfinder"
TOOLS_RECON[subdomizer]="recon|dns|subdomain_enum|passive|api_based|4-7|https://github.com/Ice3man543/Subdomizer"
TOOLS_RECON[dnsgen]="recon|dns|wordlist_mutations|permutation|3-5|https://github.com/ProjectAnte dnsgen"
TOOLS_RECON[gotator]="recon|dns|wordlist_mutations|permutation|recursive|4-6|https://github.com/Josue87/gotator"
TOOLS_RECON[dnspoodle]="recon|dns|zone_transfer|ldap|3-5|https://github.com/SpiderLabs/dnspoodle"
TOOLS_RECON[fierce]="recon|dns|subdomain_scan|dns_brute|3-6|https://github.com/mschwager/fierce"
TOOLS_RECON[subbrute]="recon|dns|subdomain_brute|vhost|3-5|https://github.com/iaruss/subbrute"

# --- Whois & Domain Info ---
TOOLS_RECON[whois]="recon|whois|domain_info|registrar|1-3|builtin"
TOOLS_RECON[whoisxmlapi]="recon|whois|api|domain_intel|3-6|https://www.whoisxmlapi.com"

# --- OSINT & Recon Frameworks ---
TOOLS_RECON[theHarvester]="recon|osint|email_harvest|subdomain_find|4-8|https://github.com/laramies/theHarvester"
TOOLS_RECON[recons101x]="recon|osint|subdomain_enum|shodan_ctl|passive|4-7|https://github.com/DevCop95/shodan_reconsx"
TOOLS_RECON[recon-ng]="recon|osint|modular|web_recon|5-9|https://github.com/lanmaster53/recon-ng"
TOOLS_RECON[amass]="recon|osint|subdomain_enum|attack_surface|6-10|https://github.com/owasp-amass/amass"
TOOLS_RECON[spiderfoot]="recon|osint|automated|multi_source|7-10|https://github.com/smicallef/spiderfoot"
TOOLS_RECON[sherlock]="recon|osint|username_enum|social_media|5-8|https://github.com/sherlock-project/sherlock"
TOOLS_RECON[holehe]="recon|osint|email_check|account_exists|3-6|https://github.com/megadose/holehe"
TOOLS_RECON[reconfpv]="recon|osint|passive|subdomain|4-7|https://github.com/saeeddhqan/ReconFPV"
TOOLS_RECON[faraday]="recon|osint|collaborative|vuln_mgmt|6-9|https://github.com/infobyte/faraday"
TOOLS_RECON[lanrdp]="recon|osint|rdp_scan|windows|3-6|https://github.com/0x4d31/lanrdp"
TOOLS_RECON[hunter]="recon|osint|email_find|company_search|4-7|https://hunter.io"
TOOLS_RECON[buster]="recon|osint|email_harvest|brute|4-7|https://github.com/sham00n/buster"
TOOLS_RECON[infoga]="recon|osint|email_geo|email_intel|4-7|https://github.com/s0md3v/Infoga"

# --- HTTP Recon ---
TOOLS_RECON[curl]="recon|http|request|header|1-5|builtin"
TOOLS_RECON[wget]="recon|http|download|mirror|1-4|builtin"
TOOLS_RECON[httpx]="recon|http|prober|tech_detect|status|6-9|https://github.com/projectdiscovery/httpx"
TOOLS_RECON[httprobe]="recon|http|alive_check|subdomain_verify|4-6|https://github.com/tomnomnom/httprobe"
TOOLS_RECON[gau]="recon|http|url_fetch|wayback|archive|5-8|https://github.com/lc/gau"
TOOLS_RECON[waybackurls]="recon|http|url_fetch|wayback|archive|4-7|https://github.com/tomnomnom/waybackurls"
TOOLS_RECON[katana]="recon|http|crawler|javascript|headless|6-9|https://github.com/projectdiscovery/katana"
TOOLS_RECON[gospider]="recon|http|crawler|javascript|deep|5-8|https://github.com/jaeles-project/gospider"
TOOLS_RECON[hakrawler]="recon|http|crawler|endpoint|js_analysis|4-7|https://github.com/hakluke/hakrawler"
TOOLS_RECON[linkfinder]="recon|http|endpoint|js_analysis|output_format|4-7|https://github.com/GerbenJav do/LinkFinder"
TOOLS_RECON[jsfinder]="recon|http|endpoint|js_analysis|subdomain|3-6|https://github.com/Threezh1/JSFinder"
TOOLS_RECON[secretfinder]="recon|http|secret_scan|api_key|token|5-8|https://github.com/mazen160/SecretFinder"
TOOLS_RECON[paramspider]="recon|http|parameter|url_mining|3-6|https://github.com/devanshbatham/paramspider"
TOOLS_RECON[arjun]="recon|http|parameter|fuzzing|hidden|5-8|https://github.com/s0md3v/Arjun"
TOOLS_RECON[x8]="recon|http|hidden_params|smuggler|5-8|https://github.com/Sh1Yo/x8"

# --- Technology Fingerprinting ---
TOOLS_RECON[whatweb]="recon|fingerprint|technology|cms_detect|1-5|https://github.com/urbanadventurer/WhatWeb"
TOOLS_RECON[wappalyzer]="recon|fingerprint|technology|web_stack|5-8|https://github.com/AliasIO/wappalyzer"
TOOLS_RECON[webanalyze]="recon|fingerprint|technology|cli|4-7|https://github.com/rverton/webanalyze"
TOOLS_RECON[retirejs]="recon|fingerprint|javascript|vuln_lib|4-7|https://github.com/RetireJS/retire.js"

# --- Port Scanning Advanced ---
TOOLS_RECON[nbtscan]="recon|netbios|name_scan|1-4|https://sourceforge.net/projects/nbtscan/"
TOOLS_RECON[unicornscan]="recon|port|async_scan|tcp_udp|5-8|https://github.com/gvanvuuren/unicornscan"
TOOLS_RECON[scanless]="recon|port|online_scan|external|1-4|https://github.com/veithen/scanless"
TOOLS_RECON[shodan]="recon|iot|device_search|banner|6-9|https://www.shodan.io"
TOOLS_RECON[censys]="recon|iot|certificate_search|host|5-8|https://censys.io"
TOOLS_RECON[zoomeye]="recon|iot|cyberspace|search|5-8|https://www.zoomeye.org"

# --- Cloud & S3 ---
TOOLS_RECON[s3scanner]="recon|cloud|s3_bucket|enum|4-7|https://github.com/sa7mon/S3Scanner"
TOOLS_RECON[cloud_enum]="recon|cloud|multi_cloud|aws_azure_gcp|5-8|https://github.com/initstring/cloud_enum"
TOOLS_RECON[lazys3]="recon|cloud|s3_bucket|brute|3-6|https://github.com/nahamsec/lazys3"
TOOLS_RECON[bucket_finder]="recon|cloud|s3_bucket|wordlist|3-5|https://github.com/bhavsec/recon_spider"

# --- Subdomain Takeover ---
TOOLS_RECON[subjack]="recon|subdomain_takeover|fingerprint|dns|5-8|https://github.com/haccer/subjack"
TOOLS_RECON[subover]="recon|subdomain_takeover|monitor|6-8|https://github.com/Ice3man543/SubOver"
TOOLS_RECON[nuclei]="recon|vuln_scan|template|config|7-10|https://github.com/projectdiscovery/nuclei"
TOOLS_RECON[canari]="recon|subdomain_takeover|wildcard|3-5|https://github.com/elitest/canari-frame"

# --- Recon Automation ---
TOOLS_RECON[reconftw]="recon|automation|full_pipeline|multi_tool|7-10|https://github.com/six2dez/reconftw"
TOOLS_RECON[reconspider]="recon|automation|osint|recon|5-8|https://github.com/veneficus/reconspider"
TOOLS_RECON[autoRecon]="recon|automation|multi_threaded|service_scan|6-9|https://github.com/TBfranks/autoRecon"
TOOLS_RECON[pentest_machine]="recon|automation|pentest|workflow|5-8|https://github.com/ewen0ne/pentest_machine"
TOOLS_RECON[Osmedeus]="recon|automation|recon|workflow|6-9|https://github.com/j3ssie/Osmedeus"
TOOLS_RECON[Legion]="recon|automation|gui|service_enum|5-8|https://github.com/Section4/Legion"

# --- IP & ASN ---
TOOLS_RECON[ipinfo]="recon|ip|geolookup|asn|1-3|https://github.com/ipinfo/cli"
TOOLS_RECON[bgp]="recon|bgp|asn_lookup|prefix|2-4|https://github.com/bgptools/bgpstream"
TOOLS_RECON[aslookup]="recon|asn|ip_lookup|prefix|2-4|https://github.com/royhills/asnlookup"

# --- Technology Specific ---
TOOLS_RECON[wapiti]="recon|web|vuln_scan|active|5-8|https://wapiti-scanner.github.io"
TOOLS_RECON[arachni]="recon|web|vuln_scan|framework|6-9|https://www.arachni-scanner.com"
TOOLS_RECON[skipfish]="recon|web|vuln_scan|google|5-8|https://code.google.com/archive/p/skipfish/"
TOOLS_RECON[openvas]="recon|web|vuln_scan|nessus_compatible|7-10|https://www.openvas.org"
TOOLS_RECON[lynis]="recon|system|audit|security_score|5-8|https://github.com/CISOfy/lynis"
TOOLS_RECON[sslyze]="recon|ssl|cipher|certificate|5-8|https://github.com/nabla-c0d3/sslyze"
TOOLS_RECON[testssl]="recon|ssl|cipher|vuln|6-9|https://github.com/drwetter/testssl.sh"
TOOLS_RECON[sslscan]="recon|ssl|cipher|certificate|4-7|https://github.com/rbsec/sslscan"
TOOLS_RECON[wpscan]="recon|wordpress|plugin_scan|theme_vuln|5-8|https://wpscan.com"
TOOLS_RECON[joomscan]="recon|joomla|component_scan|vuln|4-7|https://github.com/rezasp/joomscan"
TOOLS_RECON[droopescan]="recon|cms|drupal_silverstripe|plugin|4-7|https://github.com/droope/droopescan"
TOOLS_RECON[cmseek]="recon|cms|multi_cms|detect|4-7|https://github.com/Tuhinshubhra/CMSeeK"
TOOLS_RECON[xsstrike]="recon|xss|detect|payload_gen|5-8|https://github.com/s0md3v/XSStrike"
TOOLS_RECON[dalfox]="recon|xss|parameter_analysis|blind|6-8|https://github.com/hahwul/dalfox"
TOOLS_RECON[koxs]="recon|xss|corss|analysis|5-8|https://github.com/Emoe/kxss"
TOOLS_RECON[parameth]="recon|parameter|hidden|brute|4-7|https://github.com/maK-/parameth"
TOOLS_RECON[param-miner]="recon|parameter|hidden|wordlist|5-8|https://github.com/PortSwigger/param-miner"
TOOLS_RECON[gitrob]="recon|github|secret_scan|repo_enum|5-8|https://github.com/michenriksen/gitrob"
TOOLS_RECON[gitleaks]="recon|github|secret_scan|ci_cd|6-9|https://github.com/gitleaks/gitleaks"
TOOLS_RECON[trufflehog]="recon|github|secret_scan|entropy|6-9|https://github.com/trufflesecurity/trufflehog"
TOOLS_RECON[detect_secrets]="recon|secret_scan|preventive|baseline|5-8|https://github.com/Yelp/detect-secrets"
TOOLS_RECON[gitallsecrets]="recon|github|secret_scan|bulk|5-8|https://github.com/tillson/gitallsecrets"
TOOLS_RECON[dirsearch]="recon|web|directory_brute|path_discovery|5-8|https://github.com/maurosoria/dirsearch"
TOOLS_RECON[feroxbuster]="recon|web|directory_brute|recursive|fast|6-9|https://github.com/epi052/feroxbuster"
TOOLS_RECON[dirssearch]="recon|web|directory_brute|multi_tech|4-7|https://github.com/maurosoria/dirsearch"

# --- Network Recon Advanced ---
TOOLS_RECON[netdiscover]="recon|network|arp_scan|host_discovery|passive|4-7|https://github.com/nicoz/netdiscover"
TOOLS_RECON[arp-scan]="recon|network|arp_scan|host_discovery|local|3-5|https://github.com/royhills/arp-scan"
TOOLS_RECON[arpwatch]="recon|network|arp_monitor|mac_change|detect|4-6|https://github.com/connected-architects/arpwatch"
TOOLS_RECON[netmask]="recon|network|subnet|calculate|cidr|1-3|builtin"
TOOLS_RECON[netping]="recon|network|ping|sweep|icmp|2-4|builtin"
TOOLS_RECON[netenum]="recon|network|host_discovery|ping_sweep|3-5|https://github.com/robertdavidgraham/masscan"
TOOLS_RECON[p0f]="recon|network|os_fingerprint|passive|tcp|5-8|https://github.com/p0f/p0f"
TOOLS_RECON[p0f-ng]="recon|network|os_fingerprint|passive|modern|5-8|https://github.com/0xrawsec/p0f-ng"
TOOLS_RECON[sinfp]="recon|network|os_fingerprint|passive|3-5|https://github.com/0xrawsec/sinfp"
TOOLS_RECON[hping3]="recon|network|firewall_test|packet_gen|craft|5-8|https://github.com/tecknicaltom/hping3"
TOOLS_RECON[hping]="recon|network|firewall_test|packet_gen|craft|5-8|https://github.com/tecknicaltom/hping3"
TOOLS_RECON[colasoft]="recon|network|packet_capture|analysis|gui|5-8|https://www.colasoft.com"
TOOLS_RECON[pads]="recon|network|service_detection|passive|3-5|https://github.com/GOVCERT-LU/pads"
TOOLS_RECON[prads]="recon|network|service_detection|passive|4-6|https://github.com/gamelinux/prads"
TOOLS_RECON[ettercap]="recon|network|mitm|arp_spoof|dns_spoof|6-9|https://ettercap.github.io"
TOOLS_RECON[yersinia]="recon|network|layer2|attack|spanning_tree|5-8|https://github.com/tomac/yersinia"
TOOLS_RECON[responder]="recon|network|llmnr|nbtns|poisoning|7-10|https://github.com/lgandx/Responder"
TOOLS_RECON[mitm6]="recon|network|ipv6|dns|mitm|6-9|https://github.com/dirkjanm/mitm6"

# --- Port Scanning Variants ---
TOOLS_RECON[nmap]="recon|network|port_scan|service_detection|os_detection|script_scan|1-10|https://nmap.org"
TOOLS_RECON[zmap]="recon|network|internet_scan|fast|stateless|7-10|https://zmap.io"
TOOLS_RECON[masscan]="recon|network|port_scan|fastest|asynchronous|8-10|https://github.com/robertdavidgraham/masscan"
TOOLS_RECON[unicornscan]="recon|network|port_scan|asynchronous|stateless|5-8|https://github.com/gvanvuuren/unicornscan"
TOOLS_RECON[scanless]="recon|network|port_scan|online_scan|external|1-4|https://github.com/veithen/scanless"
TOOLS_RECON[fasttcp]="recon|network|port_scan|fast|syn|4-7|https://github.com/0xrawsec/fasttcp"
TOOLS_RECON[ports]="recon|network|port_scan|list|known|2-4|builtin"
TOOLS_RECON[portscan]="recon|network|port_scan|basic|tcp|3-5|manual"
TOOLS_RECON[randscan]="recon|network|port_scan|random|target|4-6|https://github.com/0xrawsec/randscan"
TOOLS_RECON[c_ports]="recon|network|port_scan|custom|optimized|5-8|https://github.com/crocgw9/port_scanner"

# --- Wireless Recon ---
TOOLS_RECON[aircrack-ng]="recon|wireless|wifi|capture|crack|8-10|https://www.aircrack-ng.org"
TOOLS_RECON[kismet]="recon|wireless|wifi|sniffer|detector|5-8|https://www.kismetwireless.net"
TOOLS_RECON[wifite]="recon|wireless|wifi|auto_attack|wep_wpa|6-9|https://github.com/derv82/wifite2"
TOOLS_RECON[bettercap]="recon|wireless|wifi|mitm|arp|7-10|https://www.bettercap.org"
TOOLS_RECON[airgeddon]="recon|wireless|wifi|multi_attack|gui|6-9|https://github.com/v1s1t0r1sh3r3/airgeddon"
TOOLS_RECON[wifipumpkin3]="recon|wireless|wifi|evil_twin|rogue_ap|6-9|https://github.com/P0cL4bs/wifipumpkin3"
TOOLS_RECON[eaphammer]="recon|wireless|wifi|evil_twin|credential|6-8|https://github.com/s0lst1c3/eaphammer"
TOOLS_RECON[fluxion]="recon|wireless|wifi|evil_twin|phishing|6-8|https://github.com/FluxionNetwork/fluxion"
TOOLS_RECON[hostapd-mana]="recon|wireless|wifi|evil_twin|credential|5-7|https://github.com/sensepost/hostapd-mana"
TOOLS_RECON[freeRadius-wpe]="recon|wireless|wifi|radius|credential|5-7|https://github.com/FreeRADIUS/freeradius-server"
TOOLS_RECON[gpsd]="recon|wireless|wifi|gps|location|3-5|http://www.catb.org/gpsd/"
TOOLS_RECON[reaver]="recon|wireless|wifi|wps|pixie_dust|5-8|https://github.com/t6x/reaver-wps-fork-t6x"
TOOLS_RECON[bully]="recon|wireless|wifi|wps|brute|4-7|https://github.com/aanarchyy/bully"
TOOLS_RECON[pixiewps]="recon|wireless|wifi|wps|pixie_dust|5-8|https://github.com/wiire-a/pixiewps"
TOOLS_RECON[hashcat]="recon|wireless|wifi|wpa|capture|8-10|https://hashcat.net/hashcat/"
TOOLS_RECON[cowpatty]="recon|wireless|wifi|wpa|dictionary|4-7|https://github.com/jwsurwein/cowpatty"
TOOLS_RECON[airdecap-ng]="recon|wireless|wifi|wpa|decrypt|5-8|part_of_aircrack-ng"
TOOLS_RECON[aircrack-ng]="recon|wireless|wifi|wep|wpa|crack|8-10|https://www.aircrack-ng.org"
TOOLS_RECON[airodump-ng]="recon|wireless|wifi|capture|scan|7-10|part_of_aircrack-ng"
TOOLS_RECON[aireplay-ng]="recon|wireless|wifi|inject|deauth|7-10|part_of_aircrack-ng"
TOOLS_RECON[airbase-ng]="recon|wireless|wifi|evil_twin|ap|6-9|part_of_aircrack-ng"
TOOLS_RECON[mdk3]="recon|wireless|wifi|deauth|flood|5-8|https://github.com/wiire-a/mdk3"
TOOLS_RECON[mdk4]="recon|wireless|wifi|deauth|flood|modern|6-9|https://github.com/wiire-a/mdk4"

# --- IoT & Device Recon ---
TOOLS_RECON[shodan]="recon|iot|device_search|banner|6-9|https://www.shodan.io"
TOOLS_RECON[censys]="recon|iot|certificate_search|host|5-8|https://censys.io"
TOOLS_RECON[zoomeye]="recon|iot|cyberspace|search|5-8|https://www.zoomeye.org"
TOOLS_RECON[censys-search]="recon|iot|certificate|host|6-9|https://censys.io/api"
TOOLS_RECON[shodan-cli]="recon|iot|device_search|cli|5-8|https://github.com/achillean/shodan-python"
TOOLS_RECON[recon-ng]="recon|iot|osint|modular|5-9|https://github.com/lanmaster53/recon-ng"
TOOLS_RECON[hunterio]="recon|iot|email|company|4-7|https://hunter.io"
TOOLS_RECON[crt.sh]="recon|iot|certificate_transparency|subdomain|3-5|https://crt.sh"
TOOLS_RECON[certificate-transparency]="recon|iot|certificate|subdomain|4-6|https://github.com/chris408/ct-exposer"
TOOLS_RECON[otx]="recon|iot|threat_intel|pulse|6-9|https://otx.alienvault.com"
TOOLS_RECON[virustotal]="recon|iot|threat_intel|scan|5-8|https://www.virustotal.com"
TOOLS_RECON[hybrid-analysis]="recon|iot|threat_intel|malware|6-9|https://www.hybrid-analysis.com"
TOOLS_RECON[intelligenceX]="recon|iot|osint|data_leak|5-8|https://intelx.io"
TOOLS_RECON[dehashed]="recon|iot|credential_leak|email|6-9|https://www.dehashed.com"
TOOLS_RECON[hudsonrock]="recon|iot|credential_leak|free|4-6|https://cavalier.hudsonrock.com"
TOOLS_RECON[leakcheck]="recon|iot|credential_leak|api|5-7|https://leakcheck.io"
TOOLS_RECON[holehe]="recon|iot|email|account_exists|3-6|https://github.com/megadose/holehe"
TOOLS_RECON[holehe-ng]="recon|iot|email|account_exists|modern|5-8|https://github.com/megadose/holehe"
TOOLS_RECON[sherlock]="recon|iot|username|social_media|5-8|https://github.com/sherlock-project/sherlock"
TOOLS_RECON[whatsmyname]="recon|iot|username|web|5-8|https://github.com/WebBreacher/WhatsMyName"
TOOLS_RECON[nick-to-user]="recon|iot|username|platform|3-5|https://github.com/thewhiteh4t/nick_to_user"
TOOLS_RECON[maigret]="recon|iot|username|social_media|5-8|https://github.com/soxoj/maigret"
TOOLS_RECON[userrecon]="recon|iot|username|platform|4-6|https://github.com/jobertabma/userrecon"
TOOLS_RECON[blackbird]="recon|iot|username|social_media|5-8|https://github.com/saeedezzati/blackbird"
TOOLS_RECON[socialscan]="recon|iot|email|social_media|4-7|https://github.com/lwzm/socialscan"
TOOLS_RECON[social-searcher]="recon|iot|social_media|search|3-5|https://www.social-searcher.com"
TOOLS_RECON[glassdoor]="recon|iot|company|employee|review|4-6|https://www.glassdoor.com"
TOOLS_RECON[linkedin]="recon|iot|company|employee|profile|3-5|https://www.linkedin.com"
TOOLS_RECON[crunchbase]="recon|iot|company|funding|info|4-6|https://www.crunchbase.com"
TOOLS_RECON[owler]="recon|iot|company|competitor|revenue|3-5|https://owler.com"
TOOLS_RECON[dnb]="recon|iot|company|financial|employee|5-8|https://www.dnb.com"
TOOLS_RECON[opencorporates]="recon|iot|company|registration|officer|4-6|https://opencorporates.com"
TOOLS_RECON[sec-edgar]="recon|iot|company|financial|filing|4-6|https://www.sec.gov/edgar"
TOOLS_RECON[edgar-online]="recon|iot|company|financial|data|5-7|https://www.sec.gov/cgi-bin/browse-edgar"
TOOLS_RECON[pitchbook]="recon|iot|company|startup|funding|5-8|https://pitchbook.com"
TOOLS_RECON[craft]="recon|iot|company|employee|tech_stack|5-7|https://craft.co"
TOOLS_RECON[builtwith]="recon|iot|company|technology|stack|5-8|https://builtwith.com"
TOOLS_RECON[wappalyzer]="recon|iot|company|technology|detect|5-8|https://www.wappalyzer.com"
TOOLS_RECON[similarweb]="recon|iot|company|traffic|competitor|5-8|https://www.similarweb.com"
TOOLS_RECON[semrush]="recon|iot|company|seo|traffic|6-8|https://www.semrush.com"
TOOLS_RECON[ahrefs]="recon|iot|company|seo|backlink|6-8|https://ahrefs.com"
TOOLS_RECON[majestic]="recon|iot|company|seo|backlink|5-8|https://majestic.com"
TOOLS_RECON[moz]="recon|iot|company|seo|da|5-8|https://moz.com"
TOOLS_RECON[archive.org]="recon|iot|company|history|wayback|3-5|https://archive.org"
TOOLS_RECON[common-crawl]="recon|iot|company|web|crawl|5-8|https://commoncrawl.org"
TOOLS_RECON[historical-dns]="recon|iot|dns|historical|passive|4-6|https://github.com/ernw/historical-dns"
TOOLS_RECON[dnslytics]="recon|iot|dns|passive|reverse|4-6|https://dnslytics.com"
TOOLS_RECON[securitytrails]="recon|iot|dns|historical|subdomain|5-8|https://securitytrails.com"
TOOLS_RECON[threatcrowd]="recon|iot|dns|passive|subdomain|4-6|https://www.threatcrowd.org"
TOOLS_RECON[passivedns]="recon|iot|dns|passive|historical|4-7|https://github.com/gamelinux/passivedns"
TOOLS_RECON[dnsdb]="recon|iot|dns|passive|farsight|5-8|https://www.farsightsecurity.com"
TOOLS_RECON[certspotter]="recon|iot|dns|certificate_transparency|subdomain|4-6|https://certspotter.com"
TOOLS_RECON[sublert]="recon|iot|dns|subdomain|monitor|5-8|https://github.com/signedsecurity/sublert"
TOOLS_RECON[sublist3r]="recon|iot|dns|subdomain|passive|multi_source|5-8|https://github.com/aboul3la/Sublist3r"
TOOLS_RECON[subfinder]="recon|iot|dns|subdomain|passive|fast|6-9|https://github.com/projectdiscovery/subfinder"
TOOLS_RECON[assetfinder]="recon|iot|dns|subdomain|passive|4-6|https://github.com/tomnomnom/assetfinder"
TOOLS_RECON[findomain]="recon|iot|dns|subdomain|passive|fast|6-8|https://github.com/Findomain/Findomain"
TOOLS_RECON[dnsgen]="recon|iot|dns|wordlist|mutation|permutation|3-5|https://github.com/ProjectAnte/dnsgen"
TOOLS_RECON[gotator]="recon|iot|dns|wordlist|mutation|permutation|4-6|https://github.com/Josue87/gotator"
TOOLS_RECON[interactsh]="recon|iot|dns|oast|blind|interact|6-9|https://github.com/projectdiscovery/interactsh"
TOOLS_RECON[burp]="recon|iot|proxy|intercept|spider|8-10|https://portswigger.net/burp"
TOOLS_RECON[zaproxy]="recon|iot|proxy|scanner|fuzzer|7-10|https://www.zaproxy.org"
TOOLS_RECON[mitmproxy]="recon|iot|proxy|intercept|modify|6-9|https://mitmproxy.org"
TOOLS_RECON[caido]="recon|iot|proxy|modern|fast|6-9|https://caido.io"
TOOLS_RECON[burpsuite]="recon|iot|proxy|scanner|intruder|8-10|https://portswigger.net/burp"

# ============================================
# CATEGORY 2: WEB SCANNING
# ============================================

declare -A TOOLS_WEB
TOOLS_WEB[nikto]="web|vulnerability_scan|web_server|cgi_scan|3-8|https://cirt.net/Nikto2"
TOOLS_WEB[whatweb]="web|technology_detect|fingerprint|cms_detect|1-5|https://www.morningstarsecurity.com/research/whatweb"
TOOLS_WEB[gobuster]="web|directory_brute|dns_brute|vhost_brute|3-7|https://github.com/OJ/gobuster"
TOOLS_WEB[dirb]="web|directory_brute|file_brute|2-6|https://sourceforge.net/projects/dirb/"
TOOLS_WEB[wfuzz]="web|fuzzer|parameter_fuzz|directory_fuzz|5-9|https://github.com/xmendez/wfuzz"
TOOLS_WEB[dirbuster]="web|directory_brute|java_based|3-6|https://sourceforge.net/projects/dirbuster/"
TOOLS_WEB[ffuf]="web|fuzzer|fast|filter|5-8|https://github.com/ffuf/ffuf"
TOOLS_WEB[cariddi]="web|crawler|link_extract|parameter_find|4-7|https://github.com/s0md3v/cariddi"

# ============================================
# CATEGORY 3: WEB EXPLOITATION
# ============================================

declare -A TOOLS_EXPLOIT_WEB

# --- SQL Injection ---
TOOLS_EXPLOIT_WEB[sqlmap]="exploit_web|sql_injection|auto_detect|database_dump|6-10|https://sqlmap.org"
TOOLS_EXPLOIT_WEB[sqlninja]="exploit_web|sql_injection|mssql|blind|5-8|https://sqlninja.sourceforge.net"
TOOLS_EXPLOIT_WEB[bbsql]="exploit_web|sql_injection|blind|time_based|4-7|https://github.com/amin taheri/bbsql"
TOOLS_EXPLOIT_WEB[oscanner]="exploit_web|sql_injection|oracle|enumeration|4-6|https://sourceforge.net/projects/oscanner/"
TOOLS_EXPLOIT_WEB[sqlbrute]="exploit_web|sql_injection|brute|password|3-5|https://github.com/RandomStorm/sqlbrute"
TOOLS_EXPLOIT_WEB[jsql]="exploit_web|sql_injection|java|gui|5-8|https://github.com/rmikehodges/jSQL-Injection"
TOOLS_EXPLOIT_WEB[bbqsql]="exploit_web|sql_injection|blind|automated|5-7|https://github.com/Neohapsis/bbqsql"
TOOLS_EXPLOIT_WEB[havij]="exploit_web|sql_injection|auto|gui|6-9|https://www.itsecteam.com"
TOOLS_EXPLOIT_WEB[sqlsus]="exploit_web|sql_injection|mysql|blind|5-8|https://github.com/celestix/sqlsus"
TOOLS_EXPLOIT_WEB[mole]="exploit_web|sql_injection|auto|command_line|4-7|https://github.com/cyberneohcl/mole"
TOOLS_EXPLOIT_WEB[sniper]="exploit_web|sql_injection|multi_db|auto|5-8|https://github.com/belane/SQLi-Scanner"
TOOLS_EXPLOIT_WEB[decider]="exploit_web|sql_injection|fingerprint|technique|4-6|https://github.com/mazen160/decider"

# --- XSS ---
TOOLS_EXPLOIT_WEB[xsser]="exploit_web|xss|auto_detect|payload_gen|5-8|https://github.com/epsylon/xsser"
TOOLS_EXPLOIT_WEB[xsstrike]="exploit_web|xss|detect|context_aware|5-8|https://github.com/s0md3v/XSStrike"
TOOLS_EXPLOIT_WEB[dalfox]="exploit_web|xss|parameter_analysis|blind|6-8|https://github.com/hahwul/dalfox"
TOOLS_EXPLOIT_WEB[kxss]="exploit_web|xss|reflected|analysis|3-5|https://github.com/Emoe/kxss"
TOOLS_EXPLOIT_WEB[xsser2]="exploit_web|xss|auto|payload|5-7|https://github.com/ensuring/sxss"
TOOLS_EXPLOIT_WEB[xsscon]="exploit_web|xss|console|detector|4-6|https://github.com/mazen160/xsscon"
TOOLS_EXPLOIT_WEB[domxssscan]="exploit_web|xss|dom|scanner|4-6|https://github.com/nikitastupin/domxssscan"
TOOLS_EXPLOIT_WEB[brutexss]="exploit_web|xss|brute|payload|4-6|https://github.com/xHak9x/BruteXSS"
TOOLS_EXPLOIT_WEB[pex]="exploit_web|xss|parameter|extract|3-5|https://github.com/gwen001/pex"
TOOLS_EXPLOIT_WEB[xss-payload-list]="exploit_web|xss|payload|wordlist|3-5|https://github.com/rapid7/metasploit-framework"

# --- Command Injection ---
TOOLS_EXPLOIT_WEB[commix]="exploit_web|command_injection|auto_detect|6-9|https://github.com/commix-project/commix"
TOOLS_EXPLOIT_WEB[tplmap]="exploit_web|template_injection|ssti|auto|5-8|https://github.com/epinna/tplmap"
TOOLS_EXPLOIT_WEB[dcode]="exploit_web|template|ssti|detect|4-6|https://github.com/epinna/tplmap"
TOOLS_EXPLOIT_WEB[shellshock]="exploit_web|shellshock|cgi|bash|5-8|part_of_metasploit"

# --- CMS Exploitation ---
TOOLS_EXPLOIT_WEB[wpscan]="exploit_web|wordpress|plugin_scan|theme_vuln|4-8|https://wpscan.com"
TOOLS_EXPLOIT_WEB[joomscan]="exploit_web|joomla|component_scan|vuln_detect|4-7|https://github.com/rezasp/joomscan"
TOOLS_EXPLOIT_WEB[cmseek]="exploit_web|cms|multi_cms|detect|4-7|https://github.com/Tuhinshubhra/CMSeeK"
TOOLS_EXPLOIT_WEB[droopescan]="exploit_web|cms|drupal_silverstripe|plugin|4-7|https://github.com/droope/droopescan"
TOOLS_EXPLOIT_WEB[cms_explorer]="exploit_web|cms|plugin_enum|theme_enum|3-6|https://github.com/FlavorFlav/cms-explorer"
TOOLS_EXPLOIT_WEB[drupwn]="exploit_web|drupal|exploit|module|4-7|https://github.com/immunit/drupwn"
TOOLS_EXPLOIT_WEB[wpscan-attack]="exploit_web|wordpress|brute|xmlrpc|5-8|part_of_wpscan"
TOOLS_EXPLOIT_WEB[phpmyadmin-lfi]="exploit_web|phpmyadmin|lfi|exploit|5-7|https://github.com/rezasp/joomscan"

# --- File Upload & LFI ---
TOOLS_EXPLOIT_WEB[file-upload]="exploit_web|file_upload|bypass|extension|4-6|manual"
TOOLS_EXPLOIT_WEB[lfi-scanner]="exploit_web|lfi|directory_traversal|scan|4-7|https://github.com/mazen160/lfi-scanner"
TOOLS_EXPLOIT_WEB[liffy]="exploit_web|lfi|exploit|auto|5-8|https://github.com/mazen160/Liffy"
TOOLS_EXPLOIT_WEB[dotdotpwn]="exploit_web|lfi|traversal|fuzzer|5-8|https://github.com/wireghoul/dotdotpwn"

# --- XXE & SSRF ---
TOOLS_EXPLOIT_WEB[xxeinjector]="exploit_web|xxe|exploit|blind|5-8|https://github.com/enjoiz/XXEinjector"
TOOLS_EXPLOIT_WEB[xxe-scan]="exploit_web|xxe|scan|detect|4-6|https://github.com/ozakius/xxe-scan"

# --- Deserialization ---
TOOLS_EXPLOIT_WEB[ysoserial]="exploit_web|deserialization|java|exploit|7-10|https://github.com/frohoff/ysoserial"
TOOLS_EXPLOIT_WEB[dotdotpwn]="exploit_web|deserialization|php|exploit|5-7|https://github.com/ambionics/phpggc"
TOOLS_EXPLOIT_WEB[phpggc]="exploit_web|deserialization|php|gadget|6-9|https://github.com/ambionics/phpggc"

# --- API Testing ---
TOOLS_EXPLOIT_WEB[arjun]="exploit_web|api|parameter|hidden|5-8|https://github.com/s0md3v/Arjun"
TOOLS_EXPLOIT_WEB[postman]="exploit_web|api|testing|collection|5-8|https://www.postman.com"
TOOLS_EXPLOIT_WEB[bruno]="exploit_web|api|testing|open_source|4-7|https://github.com/usebruno/bruno"

# --- Web Shell ---
TOOLS_EXPLOIT_WEB[weevely]="exploit_web|webshell|php|backdoor|5-8|https://github.com/epinna/weevely3"
TOOLS_EXPLOIT_WEB[phpmeterpreter]="exploit_web|webshell|php|meterpreter|6-9|part_of_metasploit"

# ============================================
# CATEGORY 4: BRUTE FORCE
# ============================================

declare -A TOOLS_BRUTE
TOOLS_BRUTE[hydra]="brute|online|multi_protocol|fast|7-10|https://github.com/vanhauser-thc/thc-hydra"
TOOLS_BRUTE[medusa]="brute|online|parallel|modular|6-9|https://github.com/jmk-foofus/medusa"
TOOLS_BRUTE[ncrack]="brute|online|network|performance|5-8|https://nmap.org/ncrack/"
TOOLS_BRUTE[john]="brute|offline|password_crack|wordlist|8-10|https://www.openwall.com/john/"
TOOLS_BRUTE[hashcat]="brute|offline|gpu|rule_based|8-10|https://hashcat.net/hashcat/"
TOOLS_BRUTE[cewl]="brute|wordlist_gen|website_crawl|custom_wordlist|4-7|https://github.com/digininja/CeWL"
TOOLS_BRUTE[crunch]="brute|wordlist_gen|pattern_based|3-6|https://sourceforge.net/projects/crunch-wordlist/"

# ============================================
# CATEGORY 5: ENUMERATION
# ============================================

declare -A TOOLS_ENUM

# --- SMB Enumeration ---
TOOLS_ENUM[enum4linux]="enum|smb|share_enum|user_enum|5-8|https://github.com/cddmp/enum4linux-ng"
TOOLS_ENUM[enum4linux-ng]="enum|smb|share_enum|user_enum|modern|6-9|https://github.com/cddmp/enum4linux-ng"
TOOLS_ENUM[smbclient]="enum|smb|share_access|file_download|4-7|builtin"
TOOLS_ENUM[smbmap]="enum|smb|share_list|file_search|5-8|https://github.com/ShawnDEvans/smbmap"
TOOLS_ENUM[smbget]="enum|smb|share_download|recursive|4-6|https://www.samba.org/software/smbclient/smbget.html"
TOOLS_ENUM[crackmapexec]="enum|smb|exec|credential_spray|multi_protocol|7-10|https://github.com/byt3bl33d3r/CrackMapExec"
TOOLS_ENUM[netexec]="enum|smb|exec|credential_spray|modern|7-10|https://github.com/Penntest-docker/NetExec"
TOOLS_ENUM[smbaudit]="enum|smb|audit|policy_enum|3-5|https://github.com/CiscoCXSecurity/smbaudit"
TOOLS_ENUM[smbEnumeration]="enum|smb|share_enum|user_enum|4-6|https://github.com/cddmp/enum4linux-ng"
TOOLS_ENUM[winexe]="enum|smb|exec|windows|remote|5-8|https://github.com/cusspvz/winexe"
TOOLS_ENUM[smbexec]="enum|smb|exec|shell|multi_host|6-9|part_of_impacket"
TOOLS_ENUM[goldenpac]="enum|smb|exec|exploit|ms17_010|7-10|part_of_impacket"
TOOLS_ENUM[lookupsid]="enum|smb|sid_lookup|user_enum|4-7|part_of_impacket"
TOOLS_ENUM[net]="enum|smb|windows|enum|builtin|4-7|part_of_samba"

# --- NetBIOS Enumeration ---
TOOLS_ENUM[nbtscan]="enum|netbios|name_scan|1-4|https://sourceforge.net/projects/nbtscan/"
TOOLS_ENUM[nbtcheck]="enum|netbios|name_check|1-3|builtin"
TOOLS_ENUM[nbt]="enum|netbios|enum|query|2-4|builtin"

# --- LDAP Enumeration ---
TOOLS_ENUM[ldapsearch]="enum|ldap|user_enum|group_enum|4-7|builtin"
TOOLS_ENUM[ldapenum]="enum|ldap|user_enum|password_policy|4-6|https://github.com/ropnop/ldapenum"
TOOLS_ENUM[ldeep]="enum|ldap|user_enum|machine_enum|5-8|https://github.com/franc-music/ldeep"
TOOLS_ENUM[ldapdomaindump]="enum|ldap|domain_dump|html_report|5-8|https://github.com/dirkjanm/ldapdomaindump"
TOOLS_ENUM[windapsearch]="enum|ldap|user_enum|admin_check|4-7|https://github.com/ropnop/windapsearch"
TOOLS_ENUM[lldap]="enum|ldap|user_enum|attribute_brute|4-6|https://github.com/tykowle/lldap"
TOOLS_ENUM[adidnsdump]="enum|dns|ad_dns|zone_dump|5-8|https://github.com/dirkjanm/adidnsdump"
TOOLS_ENUM[ldapnomnom]="enum|ldap|anonymous|unauthenticated|4-7|https://github.com/fox-it/ldapnomnom"
TOOLS_ENUM[ldapsearch-AD]="enum|ldap|active_directory|full_enum|5-8|https://github.com/belane/ActiveDirectoryEnumeration"

# --- SNMP Enumeration ---
TOOLS_ENUM[snmpwalk]="enum|snmp|community_enum|oid_walk|3-6|builtin"
TOOLS_ENUM[onesixtyone]="enum|snmp|community_brute|1-4|https://github.com/tecknicaltom/onesixtyone"
TOOLS_ENUM[snmp-check]="enum|snmp|info_gather|oid_enum|3-6|https://github.com/reversebrain/snmp-check"
TOOLS_ENUM[snmpenum]="enum|snmp|community_brute|oid_enum|4-6|https://github.com/RESEYAR/snmpenum"
TOOLS_ENUM[snmpwalk]="enum|snmp|walk|oid|3-6|builtin"
TOOLS_ENUM[snmpset]="enum|snmp|set|modify|oid|4-6|builtin"
TOOLS_ENUM[snmpget]="enum|snmp|get|oid|query|3-5|builtin"
TOOLS_ENUM[snmpbulkwalk]="enum|snmp|bulk|walk|oid|4-6|builtin"
TOOLS_ENUM[snmptranslate]="enum|snmp|translate|oid|name|2-4|builtin"
TOOLS_ENUM[snmpdelta]="enum|snmp|delta|counter|monitor|3-5|builtin"

# --- RPC Enumeration ---
TOOLS_ENUM[rpcclient]="enum|rpc|smb_enum|sid_lookup|4-7|builtin"
TOOLS_ENUM[rpcdump]="enum|rpc|dump|endpoint|list|4-7|part_of_metasploit"
TOOLS_ENUM[rpcinfo]="enum|rpc|info|program|list|3-5|builtin"
TOOLS_ENUM[rpcclient-enum]="enum|rpc|enum|user|group|share|5-8|part_of_impacket"
TOOLS_ENUM[impacket-rpc]="enum|rpc|wmi|dcom|exec|6-9|part_of_impacket"

# --- HTTP Enumeration ---
TOOLS_ENUM[gobuster]="enum|http|directory_brute|dns_brute|vhost|3-7|https://github.com/OJ/gobuster"
TOOLS_ENUM[dirb]="enum|http|directory_brute|file_brute|2-6|https://sourceforge.net/projects/dirb/"
TOOLS_ENUM[ffuf]="enum|http|fuzzer|parameter|directory|5-8|https://github.com/ffuf/ffuf"
TOOLS_ENUM[wfuzz]="enum|http|fuzzer|parameter|directory|5-9|https://github.com/xmendez/wfuzz"
TOOLS_ENUM[feroxbuster]="enum|http|directory_brute|recursive|fast|6-9|https://github.com/epi052/feroxbuster"
TOOLS_ENUM[dirsearch]="enum|http|directory_brute|path_discovery|5-8|https://github.com/maurosoria/dirsearch"
TOOLS_ENUM[dirbuster]="enum|http|directory_brute|java_based|3-6|https://sourceforge.net/projects/dirbuster/"
TOOLS_ENUM[hdir]="enum|http|directory_brute|recursive|fast|4-7|https://github.com/h4cc/hdir"
TOOLS_ENUM[scylla]="enum|http|directory_brute|fast|filter|4-6|https://github.com/leoplus45/scylla"
TOOLS_ENUM[arjun]="enum|http|parameter|fuzzing|hidden|5-8|https://github.com/s0md3v/Arjun"
TOOLS_ENUM[paramspider]="enum|http|parameter|url_mining|3-6|https://github.com/devanshbatham/paramspider"
TOOLS_ENUM[x8]="enum|http|hidden_params|smuggler|5-8|https://github.com/Sh1Yo/x8"

# --- DNS Enumeration ---
TOOLS_ENUM[dnsenum]="enum|dns|zone_transfer|subdomain_brute|3-6|https://github.com/fwaeyt/dnsenum"
TOOLS_ENUM[dnsmap]="enum|dns|subdomain_brute|wildcard|3-5|https://github.com/reconspider/dnsmap"
TOOLS_ENUM[dnsdict]="enum|dns|subdomain_enum|dictionary|2-5|part_of_dnstracer"
TOOLS_ENUM[sublist3r]="enum|dns|subdomain_enum|passive|multi_source|5-8|https://github.com/aboul3la/Sublist3r"
TOOLS_ENUM[subfinder]="enum|dns|subdomain_enum|passive|fast|6-9|https://github.com/projectdiscovery/subfinder"
TOOLS_ENUM[subdomizer]="enum|dns|subdomain_enum|passive|api_based|4-7|https://github.com/Ice3man543/Subdomizer"
TOOLS_ENUM[dnsgen]="enum|dns|wordlist_mutations|permutation|3-5|https://github.com/ProjectAnte/dnsgen"
TOOLS_ENUM[gotator]="enum|dns|wordlist_mutations|permutation|recursive|4-6|https://github.com/Josue87/gotator"
TOOLS_ENUM[dnspoodle]="enum|dns|zone_transfer|ldap|3-5|https://github.com/SpiderLabs/dnspoodle"
TOOLS_ENUM[fierce]="enum|dns|subdomain_scan|dns_brute|3-6|https://github.com/mschwager/fierce"
TOOLS_ENUM[subbrute]="enum|dns|subdomain_brute|vhost|3-5|https://github.com/laconicwolf/subbrute"
TOOLS_ENUM[amass]="enum|dns|subdomain_enum|passive|active|6-10|https://github.com/owasp-amass/amass"
TOOLS_ENUM[assetfinder]="enum|dns|subdomain_enum|passive|4-6|https://github.com/tomnomnom/assetfinder"
TOOLS_ENUM[crtsh]="enum|dns|certificate_transparency|subdomain|3-5|https://crt.sh"

# --- SNMP Advanced ---
TOOLS_ENUM[snmp-check]="enum|snmp|info_gather|oid_enum|3-6|https://github.com/reversebrain/snmp-check"
TOOLS_ENUM[snmpenum]="enum|snmp|community_brute|oid_enum|4-6|https://github.com/RESEYAR/snmpenum"
TOOLS_ENUM[snmpwalk]="enum|snmp|walk|oid|walk|3-6|builtin"
TOOLS_ENUM[snmpbulkwalk]="enum|snmp|bulk|walk|oid|4-6|builtin"
TOOLS_ENUM[snmpget]="enum|snmp|get|oid|query|3-5|builtin"
TOOLS_ENUM[snmpset]="enum|snmp|set|modify|oid|4-6|builtin"
TOOLS_ENUM[snmptranslate]="enum|snmp|translate|oid|name|2-4|builtin"
TOOLS_ENUM[snmpdelta]="enum|snmp|delta|counter|monitor|3-5|builtin"
TOOLS_ENUM[snmpdf]="enum|snmp|disk|usage|monitor|3-5|builtin"
TOOLS_ENUM[snmpnetstat]="enum|snmp|netstat|connections|monitor|3-5|builtin"

# --- Windows Enumeration ---
TOOLS_ENUM[enum4linux]="enum|windows|smb|user_enum|share_enum|5-8|https://github.com/cddmp/enum4linux-ng"
TOOLS_ENUM[ldeep]="enum|windows|ldap|user_enum|machine_enum|5-8|https://github.com/franc-music/ldeep"
TOOLS_ENUM[adenum]="enum|windows|ad|user_enum|group_enum|5-8|https://github.com/ytisf/adenum"
TOOLS_ENUM[windapsearch]="enum|windows|ldap|user_enum|admin_check|4-7|https://github.com/ropnop/windapsearch"
TOOLS_ENUM[ldapdomaindump]="enum|windows|ldap|domain_dump|html_report|5-8|https://github.com/dirkjanm/ldapdomaindump"
TOOLS_ENUM[adidnsdump]="enum|windows|dns|ad_dns|zone_dump|5-8|https://github.com/dirkjanm/adidnsdump"
TOOLS_ENUM[ldapnomnom]="enum|windows|ldap|anonymous|unauthenticated|4-7|https://github.com/fox-it/ldapnomnom"
TOOLS_ENUM[ldapsearch-AD]="enum|windows|ldap|active_directory|full_enum|5-8|https://github.com/belane/ActiveDirectoryEnumeration"
TOOLS_ENUM[bloodhound]="enum|windows|ad|attack_path|graph|7-10|https://github.com/BloodHoundAD/BloodHound"
TOOLS_ENUM[sharphound]="enum|windows|ad|collector|bloodhound|6-9|part_of_bloodhound"
TOOLS_ENUM[pingcastle]="enum|windows|ad|audit|score|6-9|https://github.com/netwrix/pingcastle"
TOOLS_ENUM[adfind]="enum|windows|ad|query|ldap|5-8|https://www.joeware.net/freetools/tools/adfind/"
TOOLS_ENUM[adrecon]="enum|windows|ad|report|html|6-9|https://github.com/adrecon/ADRecon"
TOOLS_ENUM[lapstool]="enum|windows|ad|laps|password|5-8|https://github.com/silverhack/lapstool"
TOOLS_ENUM[krb]="enum|windows|kerberos|ticket|roast|6-9|part_of_impacket"
TOOLS_ENUM[rubeus]="enum|windows|kerberos|ticket|asreproast|7-10|https://github.com/GhostPack/Rubeus"
TOOLS_ENUM[getuserspns]="enum|windows|kerberos|service_principal|roast|6-9|part_of_impacket"
TOOLS_ENUM[ticketparser]="enum|windows|kerberos|ticket|parse|5-8|part_of_impacket"

# --- SSH Enumeration ---
TOOLS_ENUM[ssh-audit]="enum|ssh|audit|cipher|key|5-8|https://github.com/jtesta/ssh-audit"
TOOLS_ENUM[sshgrind]="enum|ssh|key_brute|user_enum|4-6|https://github.com/leebrowntings/sshgrind"
TOOLS_ENUM[sshd]="enum|ssh|config_audit|3-5|builtin"

# --- FTP Enumeration ---
TOOLS_ENUM[ftp-anon]="enum|ftp|anon_check|1-3|builtin"
TOOLS_ENUM[ftp-user-enum]="enum|ftp|user_enum|brute|4-6|https://github.com/againse/ftp-user-enum"
TOOLS_ENUM[ftpcrack]="enum|ftp|brute|password|3-5|part_of_metasploit"
TOOLS_ENUM[hydra-ftp]="enum|ftp|brute|online|7-10|part_of_hydra"

# --- Email Enumeration ---
TOOLS_ENUM[smtp-user-enum]="enum|smtp|user_enum|vrfy|rcpt|4-6|https://pentest-tools.com"
TOOLS_ENUM[smtp-enum]="enum|smtp|user_enum|brute|3-5|part_of_hydra"
TOOLS_ENUM[swaks]="enum|smtp|test|email|send|3-5|https://github.com/greenwood/swaks"
TOOLS_ENUM[gasmask]="enum|email|harvest|osint|4-7|https://github.com/evilsocket/gasmask"

# --- Web Technologies ---
TOOLS_ENUM[wappalyzer]="enum|web|technology|fingerprint|5-8|https://github.com/AliasIO/wappalyzer"
TOOLS_ENUM[webanalyze]="enum|web|technology|cli|4-7|https://github.com/rverton/webanalyze"
TOOLS_ENUM[retirejs]="enum|web|javascript|vuln_lib|4-7|https://github.com/RetireJS/retire.js"
TOOLS_ENUM[cmseek]="enum|web|cms|multi_cms|detect|4-7|https://github.com/Tuhinshubhra/CMSeeK"
TOOLS_ENUM[droopescan]="enum|web|cms|drupal_silverstripe|plugin|4-7|https://github.com/droope/droopescan"
TOOLS_ENUM[joomscan]="enum|web|joomla|component_scan|vuln|4-7|https://github.com/rezasp/joomscan"
TOOLS_ENUM[wpscan]="enum|web|wordpress|plugin_scan|theme_vuln|5-8|https://wpscan.com"
TOOLS_ENUM[xsstrike]="enum|web|xss|detect|payload_gen|5-8|https://github.com/s0md3v/XSStrike"
TOOLS_ENUM[dalfox]="enum|web|xss|parameter_analysis|blind|6-8|https://github.com/hahwul/dalfox"
TOOLS_ENUM[tplmap]="enum|web|template_injection|ssti|5-8|https://github.com/epinna/tplmap"
TOOLS_ENUM[subdomain-takeover]="enum|web|subdomain|takeover|vhost|5-8|https://github.com/Ice3man543/subfinder"

# --- Cloud Enumeration ---
TOOLS_ENUM[cloud_enum]="enum|cloud|multi_cloud|aws_azure_gcp|5-8|https://github.com/initstring/cloud_enum"
TOOLS_ENUM[s3scanner]="enum|cloud|s3_bucket|enum|4-7|https://github.com/sa7mon/S3Scanner"
TOOLS_ENUM[lazys3]="enum|cloud|s3_bucket|brute|3-6|https://github.com/nahamsec/lazys3"
TOOLS_ENUM[bucket_finder]="enum|cloud|s3_bucket|wordlist|3-5|https://github.com/bhavsec/recon_spider"
TOOLS_ENUM[cloudbrute]="enum|cloud|service_brute|subdomain|4-6|https://github.com/0x0FB0/cloudbrute"
TOOLS_ENUM[s3grep]="enum|cloud|s3|grep|content|3-5|https://github.com/bhavsec/recon_spider"
TOOLS_ENUM[awsenum]="enum|cloud|aws|enum|iam|5-8|https://github.com/NorthWaveSecurity/awsenum"

# --- Network Enumeration ---
TOOLS_ENUM[netdiscover]="enum|network|arp_scan|host_discovery|passive|4-7|https://github.com/nicoz/netdiscover"
TOOLS_ENUM[netenum]="enum|network|host_discovery|ping_sweep|3-5|https://github.com/robertdavidgraham/masscan"
TOOLS_ENUM[netping]="enum|network|ping|sweep|icmp|2-4|builtin"
TOOLS_ENUM[netmask]="enum|network|cidr|subnet|calculate|1-3|builtin"
TOOLS_ENUM[netexec]="enum|network|smb|exec|multi_protocol|7-10|https://github.com/Penntest-docker/NetExec"
TOOLS_ENUM[nbtscan]="enum|network|netbios|name_scan|1-4|https://sourceforge.net/projects/nbtscan/"
TOOLS_ENUM[nbtenum]="enum|network|netbios|enum|name|2-4|builtin"
TOOLS_ENUM[snmp-check]="enum|network|snmp|info|3-6|https://github.com/reversebrain/snmp-check"
TOOLS_ENUM[snmpenum]="enum|network|snmp|community|brute|4-6|https://github.com/RESEYAR/snmpenum"

# --- Service Enumeration ---
TOOLS_ENUM[enum4linux]="enum|service|smb|full_enum|5-8|https://github.com/cddmp/enum4linux-ng"
TOOLS_ENUM[smbmap]="enum|service|smb|share_list|file_search|5-8|https://github.com/ShawnDEvans/smbmap"
TOOLS_ENUM[smbget]="enum|service|smb|share_download|recursive|4-6|https://www.samba.org/software/smbclient/smbget.html"
TOOLS_ENUM[crackmapexec]="enum|service|multi_protocol|exec|credential_spray|7-10|https://github.com/byt3bl33d3r/CrackMapExec"
TOOLS_ENUM[winexe]="enum|service|smb|exec|windows|remote|5-8|https://github.com/cusspvz/winexe"
TOOLS_ENUM[smbexec]="enum|service|smb|exec|shell|multi_host|6-9|part_of_impacket"
TOOLS_ENUM[goldenpac]="enum|service|smb|exec|exploit|ms17_010|7-10|part_of_impacket"
TOOLS_ENUM[lookupsid]="enum|service|smb|sid_lookup|user_enum|4-7|part_of_impacket"
TOOLS_ENUM[net]="enum|service|windows|smb|enum|builtin|4-7|part_of_samba"
TOOLS_ENUM[ldapsearch]="enum|service|ldap|user_enum|group_enum|4-7|builtin"
TOOLS_ENUM[rpcclient]="enum|service|rpc|smb_enum|sid_lookup|4-7|builtin"
TOOLS_ENUM[snmpwalk]="enum|service|snmp|community_enum|oid_walk|3-6|builtin"
TOOLS_ENUM[onesixtyone]="enum|service|snmp|community_brute|1-4|https://github.com/tecknicaltom/onesixtyone"
TOOLS_ENUM[snmp-check]="enum|service|snmp|info_gather|oid_enum|3-6|https://github.com/reversebrain/snmp-check"
TOOLS_ENUM[snmpenum]="enum|service|snmp|community_brute|oid_enum|4-6|https://github.com/RESEYAR/snmpenum"
TOOLS_ENUM[smtp-user-enum]="enum|service|smtp|user_enum|vrfy|rcpt|4-6|https://pentest-tools.com"
TOOLS_ENUM[ftp-anon]="enum|service|ftp|anon_check|1-3|builtin"
TOOLS_ENUM[ssh-audit]="enum|service|ssh|audit|cipher|key|5-8|https://github.com/jtesta/ssh-audit"

# --- User & Password Enumeration ---
TOOLS_ENUM[cewl]="enum|user|wordlist_gen|website_crawl|custom_wordlist|4-7|https://github.com/digininja/CeWL"
TOOLS_ENUM[crunch]="enum|user|wordlist_gen|pattern_based|3-6|https://sourceforge.net/projects/crunch-wordlist/"
TOOLS_ENUM[mentalist]="enum|user|wordlist_gen|hybrid|6-8|https://github.com/ytisf/mentalist"
TOOLS_ENUM[username-anarchy]="enum|user|username_gen|format|4-6|https://github.com/urbanadventurer/username-anarchy"
TOOLS_ENUM[sherlock]="enum|user|username_enum|social_media|5-8|https://github.com/sherlock-project/sherlock"
TOOLS_ENUM[holehe]="enum|user|email_check|account_exists|3-6|https://github.com/megadose/holehe"
TOOLS_ENUM[buster]="enum|user|email_harvest|brute|4-7|https://github.com/sham00n/buster"
TOOLS_ENUM[infoga]="enum|user|email_geo|email_intel|4-7|https://github.com/s0md3v/Infoga"
TOOLS_ENUM[hunter]="enum|user|email_find|company_search|4-7|https://hunter.io"
TOOLS_ENUM[recon-ng]="enum|user|osint|modular|web_recon|5-9|https://github.com/lanmaster53/recon-ng"
TOOLS_ENUM[spiderfoot]="enum|user|osint|automated|multi_source|7-10|https://github.com/smicallef/spiderfoot"
TOOLS_ENUM[amass]="enum|user|osint|subdomain_enum|attack_surface|6-10|https://github.com/owasp-amass/amass"
TOOLS_ENUM[theHarvester]="enum|user|osint|email_harvest|subdomain_find|4-8|https://github.com/laramies/theHarvester"
TOOLS_ENUM[reconspider]="enum|user|osint|recon|automation|5-8|https://github.com/veneficus/reconspider"
TOOLS_ENUM[Osmedeus]="enum|user|osint|recon|workflow|6-9|https://github.com/j3ssie/Osmedeus"
TOOLS_ENUM[Legion]="enum|user|osint|service_enum|gui|5-8|https://github.com/Section4/Legion"
TOOLS_ENUM[autoRecon]="enum|user|osint|multi_threaded|service_scan|6-9|https://github.com/TBfranks/autoRecon"
TOOLS_ENUM[reconftw]="enum|user|osint|full_pipeline|multi_tool|7-10|https://github.com/six2dez/reconftw"

# ============================================
# CATEGORY 6: EXPLOITATION
# ============================================

declare -A TOOLS_EXPLOIT

# --- Frameworks Principales ---
TOOLS_EXPLOIT[metasploit]="exploit|framework|multi_platform|payload_gen|8-10|https://www.metasploit.com"
TOOLS_EXPLOIT[searchsploit]="exploit|edb_search|exploit_db|offline|5-8|https://www.exploit-db.com"
TOOLS_EXPLOIT[msfvenom]="exploit|payload_gen|encoder|stager|7-10|part_of_metasploit"
TOOLS_EXPLOIT[shellnoob]="exploit|shellcode|convert|1-4|https://github.com/condor/shellnoob"
TOOLS_EXPLOIT[exploitdb]="exploit|edb_search|local_copy|6-9|part_of_metasploit"

# --- Exploit Frameworks Alternativos ---
TOOLS_EXPLOIT[cobaltstrike]="exploit|c2|advanced|evasion|9-10|https://www.cobaltstrike.com"
TOOLS_EXPLOIT[sliver]="exploit|c2|implant|evasion|8-10|https://github.com/BishopFox/sliver"
TOOLS_EXPLOIT[havoc]="exploit|c2|modern|evasion|8-10|https://github.com/HavocFramework/Havoc"
TOOLS_EXPLOIT[brute_ratel]="exploit|c2|evasion|red_team|9-10|https://bruteratel.com"
TOOLS_EXPLOIT[mythic]="exploit|c2|modular|macos|8-10|https://github.com/its-a-feature/Mythic"
TOOLS_EXPLOIT[ovenant]="exploit|c2|dotnet|agent|7-9|https://github.com/BC-SECURITY/Empire"
TOOLS_EXPLOIT[merlin]="exploit|c2|http2|agent|7-9|https://github.com/Ne0nd0g/merlin"
TOOLS_EXPLOIT[shadowbrokers]="exploit|nation_state|leak|eternalblue|8-10|https://github.com/misterch0c/shadowbrokers"

# --- Exploits Específicos ---
TOOLS_EXPLOIT[impacket]="exploit|windows|smb|kerberos|wmi|8-10|https://github.com/fortra/impacket"
TOOLS_EXPLOIT[psexec]="exploit|windows|smb|exec|lateral|7-9|part_of_impacket"
TOOLS_EXPLOIT[smbexec]="exploit|windows|smb|exec|shell|6-9|part_of_impacket"
TOOLS_EXPLOIT[wmiexec]="exploit|windows|wmi|exec|remote|6-9|part_of_impacket"
TOOLS_EXPLOIT[dcomexec]="exploit|windows|dcom|exec|lateral|7-9|part_of_impacket"
TOOLS_EXPLOIT[atexec]="exploit|windows|scheduled_task|exec|remote|5-8|part_of_impacket"
TOOLS_EXPLOIT[secretsdump]="exploit|windows|credential_dump|ntds|8-10|part_of_impacket"
TOOLS_EXPLOIT[ticketextractor]="exploit|windows|kerberos|ticket|extract|6-9|part_of_impacket"

# --- EternalBlue & MS17-010 ---
TOOLS_EXPLOIT[eternalblue]="exploit|windows|smb|ms17_010|rce|9-10|part_of_metasploit"
TOOLS_EXPLOIT[eternalromance]="exploit|windows|smb|ms17_010|write|8-10|part_of_metasploit"
TOOLS_EXPLOIT[eternalsynergy]="exploit|windows|smb|ms17_010|null_session|8-10|part_of_metasploit"
TOOLS_EXPLOIT[eternalchampion]="exploit|windows|smb|ms17_010|race|7-9|part_of_metasploit"

# --- Privilege Escalation Frameworks ---
TOOLS_EXPLOIT[linpeas]="exploit|linux|privesc|auto|enumerate|7-10|https://github.com/peass-ng/PEASS-ng"
TOOLS_EXPLOIT[winpeas]="exploit|windows|privesc|auto|enumerate|7-10|https://github.com/peass-ng/PEASS-ng"
TOOLS_EXPLOIT[linuxprivchecker]="exploit|linux|privesc|checker|5-8|https://github.com/sleventyeleven/linuxprivchecker"
TOOLS_EXPLOIT[beroot]="exploit|linux|privesc|enumerate|5-8|https://github.com/GianlucaBortoli/BeRoot"
TOOLS_EXPLOIT[windows-exploit-suggester]="exploit|windows|privesc|suggest|5-8|https://github.com/AonCyberLabs/Windows-Exploit-Suggester"
TOOLS_EXPLOIT[getsploit]="exploit|search|exploit|query|5-8|https://github.com/vulners-com/getsploit"

# --- Lateral Movement ---
TOOLS_EXPLOIT[crackmapexec]="exploit|windows|smb|exec|credential_spray|7-10|https://github.com/byt3bl33d3r/CrackMapExec"
TOOLS_EXPLOIT[netexec]="exploit|windows|smb|exec|modern|7-10|https://github.com/Penntest-docker/NetExec"
TOOLS_EXPLOIT[evil-winrm]="exploit|windows|winrm|shell|6-9|https://github.com/Hackplayers/evil-winrm"
TOOLS_EXPLOIT[sshuttle]="exploit|tunnel|ssh|vpn|pivot|5-8|https://github.com/sshuttle/sshuttle"
TOOLS_EXPLOIT[ligolo-ng]="exploit|tunnel|proxy|pivot|6-9|https://github.com/nicocha30/ligolo-ng"
TOOLS_EXPLOIT[chisel]="exploit|tunnel|proxy|port_forward|5-8|https://github.com/jpillora/chisel"
TOOLS_EXPLOIT[proxychains]="exploit|proxy|socks|tor|5-8|https://github.com/rofl0r/proxychains-ng"
TOOLS_EXPLOIT[resocks]="exploit|proxy|socks|tunnel|4-7|https://github.com/0xrawsec/resocks"

# --- Exploits Web ---
TOOLS_EXPLOIT[gopherus]="exploit|web|ssrf|gopher|5-8|https://github.com/tarunkant/Gopherus"
TOOLS_EXPLOIT[ssrfmap]="exploit|web|ssrf|auto|5-8|https://github.com/swisskyrepo/SSRFmap"
TOOLS_EXPLOIT[waf-bypass]="exploit|web|waf|bypass|4-7|https://github.com/0xInfection/AWAFBypass"
TOOLS_EXPLOIT[bypasswaf]="exploit|web|waf|bypass|evasion|5-8|https://github.com/owasp/wflow"
TOOLS_EXPLOIT[padbuster]="exploit|web|padding_oracle|exploit|6-9|https://github.com/AonCyberLabs/PadBuster"
TOOLS_EXPLOIT[hopla]="exploit|web|cache_poisoning|exploit|5-7|https://github.com/bitquark/hopla"
TOOLS_EXPLOIT[fpart]="exploit|web|parameter_pollution|inject|4-6|https://github.com/0xrawsec/fpart"

# --- Binary Exploitation ---
TOOLS_EXPLOIT[pwntools]="exploit|binary|rop|shellcode|7-10|https://github.com/Gallopsled/pwntools"
TOOLS_EXPLOIT[ropper]="exploit|binary|rop|gadget|6-9|https://github.com/sashs/Ropper"
TOOLS_EXPLOIT[ROPgadget]="exploit|binary|rop|gadget|5-8|https://github.com/JonathanSalwan/ROPgadget"
TOOLS_EXPLOIT[gdb]="exploit|binary|debug|reverse|5-8|builtin"
TOOLS_EXPLOIT[peda]="exploit|binary|gdb|enhanced|6-9|https://github.com/longld/peda"
TOOLS_EXPLOIT[gdb-peda]="exploit|binary|gdb|exploit_dev|6-9|https://github.com/longld/peda"
TOOLS_EXPLOIT[gef]="exploit|binary|gdb|modern|6-9|https://github.com/hugsy/gef"
TOOLS_EXPLOIT[pwndbg]="exploit|binary|gdb|modern|6-9|https://github.com/pwndbg/pwndbg"
TOOLS_EXPLOIT[radare2]="exploit|binary|disassemble|debug|7-10|https://rada.re"
TOOLS_EXPLOIT[angr]="exploit|binary|symbolic|execution|8-10|https://github.com/angr/angr"

# --- Buffer Overflow ---
TOOLS_EXPLOIT[pattern_create]="exploit|bof|pattern|create|3-5|part_of_metasploit"
TOOLS_EXPLOIT[pattern_offset]="exploit|bof|pattern|offset|3-5|part_of_metasploit"
TOOLS_EXPLOIT[msf-pattern]="exploit|bof|pattern|create|offset|3-5|part_of_metasploit"
TOOLS_EXPLOIT[shellcraft]="exploit|bof|shellcode|generate|5-8|part_of_pwnlib"

# --- Reverse Shells ---
TOOLS_EXPLOIT[revshells]="exploit|shell|reverse|generator|5-8|https://www.revshells.com"
TOOLS_EXPLOIT[weevely]="exploit|shell|php|backdoor|5-8|https://github.com/epinna/weevely3"
TOOLS_EXPLOIT[ncat]="exploit|shell|netcat|connect|3-5|builtin"
TOOLS_EXPLOIT[socat]="exploit|shell|forward|tunnel|4-7|builtin"
TOOLS_EXPLOIT[ligolo-ng]="exploit|tunnel|proxy|pivot|6-9|https://github.com/nicocha30/ligolo-ng"

# --- Exploitation Automation ---
TOOLS_EXPLOIT[autoexploit]="exploit|automation|auto|vuln|5-8|https://github.com/13o.bbr23.me4n/autoexploit"
TOOLS_EXPLOIT[exploit-suggester]="exploit|suggest|privilege|escalation|5-8|https://github.com/AonCyberLabs/Windows-Exploit-Suggester"
TOOLS_EXPLOIT[les]="exploit|suggest|linux|privilege|5-8|https://github.com/mzet-/linux-exploit-suggester"
TOOLS_EXPLOIT[wes]="exploit|suggest|windows|privilege|6-9|https://github.com/AonCyberLabs/Windows-Exploit-Suggester"

# --- Evasion ---
TOOLS_EXPLOIT[veil]="exploit|evasion|payload|av_bypass|7-10|https://github.com/UndeadSec/Veil"
TOOLS_EXPLOIT[shellter]="exploit|evasion|inject|pe_file|6-9|https://www.shellterproject.com"
TOOLS_EXPLOIT[avet]="exploit|evasion|payload|av_bypass|6-9|https://github.com/govolution/avet"
TOOLS_EXPLOIT[scarecrow]="exploit|evasion|exe|av_bypass|7-9|https://github.com/Tylous/ScareCrow"
TOOLS_EXPLOIT[donut]="exploit|evasion|shellcode|dotnet|6-9|https://github.com/TheWover/donut"
TOOLS_EXPLOIT[mona]="exploit|evasion|payload|buffer_overflow|7-9|https://www.corelan.be"
TOOLS_EXPLOIT[msf-encode]="exploit|evasion|encoder|payload|6-9|part_of_metasploit"
TOOLS_EXPLOIT[shikata-ga-nai]="exploit|evasion|encoder|polymorphic|6-9|part_of_metasploit"

# --- Domain Exploitation ---
TOOLS_EXPLOIT[bloodhound]="exploit|ad|attack_path|graph|7-10|https://github.com/BloodHoundAD/BloodHound"
TOOLS_EXPLOIT[sharphound]="exploit|ad|collector|bloodhound|6-9|part_of_bloodhound"
TOOLS_EXPLOIT[rubeus]="exploit|ad|kerberos|ticket|roast|7-10|https://github.com/GhostPack/Rubeus"
TOOLS_EXPLOIT[mimikatz]="exploit|ad|credential_dump|kerberos|8-10|https://github.com/gentilkiwi/mimikatz"
TOOLS_EXPLOIT[krbrelayx]="exploit|ad|kerberos|relay|attack|6-9|https://github.com/fox-it/krbrelayx"
TOOLS_EXPLOIT[mitm6]="exploit|ad|mitm|ipv6|dns|6-9|https://github.com/dirkjanm/mitm6"
TOOLS_EXPLOIT[certifried]="exploit|ad|certificate|abuse|8-10|https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4"
TOOLS_EXPLOIT[certipy]="exploit|ad|certificate|ntlm|relay|7-9|https://github.com/ly4k/Certipy"
TOOLS_EXPLOIT[whisker]="exploit|ad|shadow_credentials|msds_key|6-9|https://github.com/eladshamir/Whisker"
TOOLS_EXPLOIT[daft]="exploit|ad|delegations|abuse|6-9|https://github.com/fox-it/daft"
TOOLS_EXPLOIT[dangerous-spnc]="exploit|ad|spn|roast|kerberoast|6-9|https://github.com/dirkjanm/krbrelayx"

# ============================================
# CATEGORY 7: POST-EXPLOITATION
# ============================================

declare -A TOOLS_POST

# --- Post-Exploitation Frameworks ---
TOOLS_POST[meterpreter]="post|session|multi_function|pivoting|9-10|part_of_metasploit"
TOOLS_POST[empire]="post|c2|powershell|agent|7-10|https://github.com/BC-SECURITY/Empire"
TOOLS_POST[starkiller]="post|c2|gui|empire_frontend|7-10|https://github.com/BC-SECURITY/Starkiller"
TOOLS_POST[sliver]="post|c2|implant|evasion|8-10|https://github.com/BishopFox/sliver"
TOOLS_POST[havoc]="post|c2|modern|evasion|8-10|https://github.com/HavocFramework/Havoc"
TOOLS_POST[mythic]="post|c2|modular|macos|8-10|https://github.com/its-a-feature/Mythic"

# --- Credential Access ---
TOOLS_POST[mimikatz]="post|credential_dump|kerberos|lsass|8-10|https://github.com/gentilkiwi/mimikatz"
TOOLS_POST[secretsdump]="post|credential_dump|ntds|sam|8-10|part_of_impacket"
TOOLS_POST[laZagne]="post|credential_dump|browser|wifi|6-9|https://github.com/AlessandroZ/LaZagne"
TOOLS_POST[sharpdpapi]="post|credential_dump|dpapi|chrome|6-9|https://github.com/GhostPack/SharpDPAPI"
TOOLS_POST[sharpchrome]="post|credential_dump|chrome|passwords|5-8|https://github.com/GhostPack/SharpChrome"
TOOLS_POST[brute-force-cc]="post|credential_dump|credit_card|4-6|manual"
TOOLS_POST[trufflehog]="post|credential_dump|secret_scan|github|6-9|https://github.com/trufflesecurity/trufflehog"
TOOLS_POST[gitleaks]="post|credential_dump|secret_scan|ci_cd|6-9|https://github.com/gitleaks/gitleaks"

# --- Lateral Movement ---
TOOLS_POST[crackmapexec]="post|smb|exec|credential_spray|7-10|https://github.com/byt3bl33d3r/CrackMapExec"
TOOLS_POST[netexec]="post|smb|exec|credential_spray|modern|7-10|https://github.com/Penntest-docker/NetExec"
TOOLS_POST[impacket]="post|windows|smb|kerberos|dcom|8-10|https://github.com/fortra/impacket"
TOOLS_POST[evil-winrm]="post|windows|winrm|shell|6-9|https://github.com/Hackplayers/evil-winrm"
TOOLS_POST[sshuttle]="post|tunnel|ssh|vpn|pivot|5-8|https://github.com/sshuttle/sshuttle"
TOOLS_POST[ligolo-ng]="post|tunnel|proxy|pivot|6-9|https://github.com/nicocha30/ligolo-ng"
TOOLS_POST[chisel]="post|tunnel|proxy|port_forward|5-8|https://github.com/jpillora/chisel"
TOOLS_POST[proxychains]="post|proxy|socks|tor|5-8|https://github.com/rofl0r/proxychains-ng"
TOOLS_POST[resocks]="post|proxy|socks|tunnel|4-7|https://github.com/0xrawsec/resocks"

# --- Persistence ---
TOOLS_POST[empire-persist]="post|persistence|c2|agent|boot|7-10|part_of_empire"
TOOLS_POST[metasploit-persist]="post|persistence|auto_run|registry|7-9|part_of_metasploit"
TOOLS_POST[schtasks]="post|persistence|scheduled_task|windows|5-7|builtin"
TOOLS_POST[registry]="post|persistence|registry|run_key|5-7|builtin"
TOOLS_POST[wmic]="post|persistence|wmi|subscription|6-8|builtin"

# --- Privilege Escalation ---
TOOLS_POST[linpeas]="post|privesc|linux|auto|enumerate|7-10|https://github.com/peass-ng/PEASS-ng"
TOOLS_POST[winpeas]="post|privesc|windows|auto|enumerate|7-10|https://github.com/peass-ng/PEASS-ng"
TOOLS_POST[linuxprivchecker]="post|privesc|linux|checker|5-8|https://github.com/sleventyeleven/linuxprivchecker"
TOOLS_POST[beroot]="post|privesc|linux|enumerate|5-8|https://github.com/GianlucaBortoli/BeRoot"
TOOLS_POST[windows-exploit-suggester]="post|privesc|windows|suggest|5-8|https://github.com/AonCyberLabs/Windows-Exploit-Suggester"
TOOLS_POST[getsploit]="post|privesc|search|exploit|query|5-8|https://github.com/vulners-com/getsploit"
TOOLS_POST[godmode]="post|privesc|windows|auto|privilege|6-9|https://github.com/CyberAndrii/GodMode-RDP"

# --- Data Exfiltration ---
TOOLS_POST[data-exfil]="post|exfiltration|file|transfer|5-7|manual"
TOOLS_POST[exfil-over-dns]="post|exfiltration|dns|tunnel|6-8|https://github.com/leechristensen/Unicodetransfer"
TOOLS_POST[exfil-over-http]="post|exfiltration|http|upload|5-7|manual"
TOOLS_POST[exfil-over-icmp]="post|exfiltration|icmp|tunnel|6-8|https://github.com/0xrawsec/exfil-over-icmp"

# --- Pivoting ---
TOOLS_POST[metasploit-pivot]="post|pivoting|port_forward|session|7-9|part_of_metasploit"
TOOLS_POST[sshuttle]="post|pivoting|ssh|vpn|pivot|5-8|https://github.com/sshuttle/sshuttle"
TOOLS_POST[ligolo-ng]="post|pivoting|tunnel|proxy|pivot|6-9|https://github.com/nicocha30/ligolo-ng"
TOOLS_POST[chisel]="post|pivoting|tunnel|proxy|port_forward|5-8|https://github.com/jpillora/chisel"
TOOLS_POST[proxychains]="post|pivoting|proxy|socks|5-8|https://github.com/rofl0r/proxychains-ng"

# --- Persistence Frameworks ---
TOOLS_POST[empire-persist]="post|persistence|c2|agent|boot|7-10|part_of_empire"
TOOLS_POST[metasploit-persist]="post|persistence|auto_run|registry|7-9|part_of_metasploit"
TOOLS_POST[sharpcradle]="post|persistence|dotnet|download|execute|5-7|https://github.com/anthemtotheo/sharpcradle"
TOOLS_POST[dnscat2]="post|persistence|dns|tunnel|c2|6-9|https://github.com/iagox86/dnscat2"
TOOLS_POST[http-revshell]="post|persistence|http|reverse|shell|4-6|https://github.com/BeichenDream/HTTP-RevShell"

# --- Post-Exploitation Automation ---
TOOLS_POST[lazyscript]="post|automation|linux|privesc|auto|5-8|https://github.com/d4n13l13/lazyscript"
TOOLS_POST[linenum]="post|automation|linux|enumerate|auto|5-8|https://github.com/rebootuser/LinEnum"
TOOLS_POST[linux-exploit-suggester]="post|automation|linux|privesc|suggest|5-8|https://github.com/mzet-/linux-exploit-suggester"
TOOLS_POST[wes-ng]="post|automation|windows|privesc|suggest|6-9|https://github.com/belane/Windows-Exploit-Suggester"

# --- Defense Evasion ---
TOOLS_POST[unhook]="post|evasion|amsi|bypass|hook|6-9|https://github.com/groundedSAC/Unhook"
TOOLS_POST[amsi-bypass]="post|evasion|amsi|bypass|powershell|6-9|multiple_sources"
TOOLS_POST[etw-bypass]="post|evasion|etw|bypass|tracing|6-8|https://github.com/leechristensen/Unhook"
TOOLS_POST[suspend-av]="post|evasion|defender|suspend|process|5-7|manual"
TOOLS_POST[obfuscate]="post|evasion|obfuscation|powershell|5-8|https://github.com/danielbohannon/Invoke-Obfuscation"
TOOLS_POST[scarecrow]="post|evasion|exe|av_bypass|7-9|https://github.com/Tylous/ScareCrow"

# --- Information Gathering ---
TOOLS_POST[net]="post|info_gathering|network|share|enum|5-7|builtin"
TOOLS_POST[systeminfo]="post|info_gathering|windows|system|info|3-5|builtin"
TOOLS_POST[ipconfig]="post|info_gathering|network|interface|config|2-4|builtin"
TOOLS_POST[whoami]="post|info_gathering|user|privilege|info|1-3|builtin"
TOOLS_POST[tasklist]="post|info_gathering|process|list|running|2-4|builtin"
TOOLS_POST[netstat]="post|info_gathering|network|connection|list|2-4|builtin"
TOOLS_POST[wmic]="post|info_gathering|wmi|query|system|3-6|builtin"
TOOLS_POST[cmdkey]="post|info_gathering|credential|stored|list|2-4|builtin"
TOOLS_POST[vaultcmd]="post|info_gathering|credential|vault|list|3-5|builtin"

# ============================================
# CATEGORY 8: TRAFFIC ANALYSIS
# ============================================

declare -A TOOLS_TRAFFIC
TOOLS_TRAFFIC[wireshark]="traffic|capture|analysis|gui|8-10|https://www.wireshark.org"
TOOLS_TRAFFIC[tshark]="traffic|capture|cli|filter|7-10|part_of_wireshark"
TOOLS_TRAFFIC[tcpdump]="traffic|capture|basic|filter|5-8|builtin"
TOOLS_TRAFFIC[ettercap]="traffic|mitm|arp_spoof|dns_spoof|6-9|https://ettercap.github.io"
TOOLS_TRAFFIC[responder]="traffic|llmnr|nbtns|poisoning|7-10|https://github.com/lgandx/Responder"
TOOLS_TRAFFIC[mitmproxy]="traffic|proxy|intercept|modify|6-9|https://mitmproxy.org"

# ============================================
# CATEGORY 9: WIRELESS
# ============================================

declare -A TOOLS_WIRELESS
TOOLS_WIRELESS[aircrack-ng]="wireless|wifi|crack|capture|8-10|https://www.aircrack-ng.org"
TOOLS_WIRELESS[wifite]="wireless|wifi|auto_attack|wep_wpa|6-9|https://github.com/derv82/wifite2"
TOOLS_WIRELESS[kismet]="wireless|wifi|sniffer|detector|5-8|https://www.kismetwireless.net"
TOOLS_WIRELESS[bully]="wireless|wifi|wps|brute|4-7|https://github.com/aanarchyy/bully"
TOOLS_WIRELESS[reaver]="wireless|wifi|wps|pixie_dust|5-8|https://github.com/t6x/reaver-wps-fork-t6x"
TOOLS_WIRELESS[fern]="wireless|wifi|gui|auto_attack|5-8|https://github.com/savio-code/fern-wifi-cracker"

# ============================================
# CATEGORY 10: SNIFFING & SPOOFING
# ============================================

declare -A TOOLS_SNIFF
TOOLS_SNIFF[arpspoof]="sniff|arp|mitm|redirect|5-8|part_of_ettercap"
TOOLS_SNIFF[dsniff]="sniff|credential|capture|password|4-7|https://www.monkey.org/~dugsong/dsniff/"
TOOLS_SNIFF[macchanger]="sniff|mac|spoof|change|3-5|https://github.com/alobbs/macchanger"
TOOLS_SNIFF[arpoison]="sniff|arp|poison|redirect|4-6|https://github.com/infamy/arpoison"

# ============================================
# CATEGORY 11: SOCIAL ENGINEERING
# ============================================

declare -A TOOLS_SOCIAL
TOOLS_SOCIAL[set]="social|phishing|credential_harvest|attack_vector|7-10|https://github.com/trustedsec/social-engineer-toolkit"
TOOLS_SOCIAL[king-phisher]="social|phishing|campaign|template|6-9|https://github.com/securestate/king-phisher"
TOOLS_SOCIAL[gophish]="social|phishing|campaign|analytics|5-8|https://github.com/gophish/gophish"

# ============================================
# CATEGORY 12: FORENSICS & LOGS
# ============================================

declare -A TOOLS_FORENSICS
TOOLS_FORENSICS[volatility]="forensics|memory|dump|analysis|7-10|https://github.com/volatilityfoundation/volatility3"
TOOLS_FORENSICS[autopsy]="forensics|disk|gui|timeline|6-9|https://www.autopsy.com"
TOOLS_FORENSICS[binwalk]="forensics|firmware|extract|reverse|5-8|https://github.com/ReFirmLabs/binwalk"
TOOLS_FORENSICS[foremost]="forensics|file_recovery|carve|3-6|https://github.com/korczis/foremost"
TOOLS_FORENSICS[sleuthkit]="forensics|disk|filesystem|timeline|6-9|https://www.sleuthkit.org"

# ============================================
# CATEGORY 13: PASSWORD ATTACKS
# ============================================

declare -A TOOLS_PASSWORD
TOOLS_PASSWORD[ophcrack]="password|rainbow_table|windows|gui|5-8|https://ophcrack.sourceforge.net"
TOOLS_PASSWORD[chntpw]="password|windows|sam_edit|reset|3-6|https://pogostick.net/~pnh/ntpasswd/"
TOOLS_PASSWORD[mimikatz]="password|windows|credential_dump|kerberos|8-10|https://github.com/gentilkiwi/mimikatz"
TOOLS_PASSWORD[lazagne]="password|credential_dump|browser|wifi|6-9|https://github.com/AlessandroZ/LaZagne"

# ============================================
# CATEGORY 14: REVERSING
# ============================================

declare -A TOOLS_REVERSING
TOOLS_REVERSING[ghidra]="reversing|decompiler|disassemble|gui|8-10|https://ghidra-sre.org"
TOOLS_REVERSING[radare2]="reversing|disassemble|debug|cli|7-10|https://rada.re"
TOOLS_REVERSING[strace]="reversing|syscall|trace|debug|5-8|builtin"
TOOLS_REVERSING[ltrace]="reversing|library|trace|debug|4-7|builtin"
TOOLS_REVERSING[objdump]="reversing|disassemble|binary|3-6|builtin"
TOOLS_REVERSING[file]="reversing|identify|magic|type|1-4|builtin"

# ============================================
# QUERY FUNCTIONS
# ============================================

# Search tools by category
search_by_category() {
    local category="$1"
    echo "=== Tools in category: $category ==="
    for registry in TOOLS_RECON TOOLS_WEB TOOLS_EXPLOIT_WEB TOOLS_BRUTE TOOLS_ENUM TOOLS_EXPLOIT TOOLS_POST TOOLS_TRAFFIC TOOLS_WIRELESS TOOLS_SNIFF TOOLS_SOCIAL TOOLS_FORENSICS TOOLS_PASSWORD TOOLS_REVERSING; do
        for tool in "${!registry[@]}"; do
            IFS='|' read -r cat type func extra risk url <<< "${registry[$tool]}"
            if [[ "$cat" == *"$category"* ]]; then
                echo "  $tool: $type | $func | Risk: $risk"
            fi
        done
    done
}

# Search tools by function
search_by_function() {
    local function="$1"
    echo "=== Tools for: $function ==="
    for registry in TOOLS_RECON TOOLS_WEB TOOLS_EXPLOIT_WEB TOOLS_BRUTE TOOLS_ENUM TOOLS_EXPLOIT TOOLS_POST TOOLS_TRAFFIC TOOLS_WIRELESS TOOLS_SNIFF TOOLS_SOCIAL TOOLS_FORENSICS TOOLS_PASSWORD TOOLS_REVERSING; do
        for tool in "${!registry[@]}"; do
            IFS='|' read -r cat type func extra risk url <<< "${registry[$tool]}"
            if [[ "$func" == *"$function"* ]]; then
                echo "  $tool [$cat]: $extra | Risk: $risk"
            fi
        done
    done
}

# Verify if a tool is installed
check_tool() {
    local tool="$1"
    if command -v "$tool" &>/dev/null; then
        echo "[✓] $tool: INSTALLED"
        return 0
    else
        echo "[✗] $tool: NOT INSTALLED"
        return 1
    fi
}

# Verify all tools
check_all_tools() {
    echo "=== Tool Verification ==="
    echo ""
    local installed=0
    local missing=0
    
    for registry in TOOLS_RECON TOOLS_WEB TOOLS_EXPLOIT_WEB TOOLS_BRUTE TOOLS_ENUM TOOLS_EXPLOIT TOOLS_POST TOOLS_TRAFFIC TOOLS_WIRELESS TOOLS_SNIFF TOOLS_SOCIAL TOOLS_FORENSICS TOOLS_PASSWORD TOOLS_REVERSING; do
        for tool in "${!registry[@]}"; do
            if command -v "$tool" &>/dev/null; then
                ((installed++))
            else
                ((missing++))
            fi
        done
    done
    
    echo "Installed: $installed"
    echo "Missing: $missing"
}

# Get recommendation by level
recommend_by_level() {
    local level="$1"  # low, medium, high, critical
    echo "=== Recommendations for level: $level ==="
    
    case $level in
        low)
            echo "Use: nmap, whatweb, dig, host, whois"
            ;;
        medium)
            echo "Use: nikto, gobuster, enum4linux, hydra"
            ;;
        high)
            echo "Use: sqlmap, metasploit, responder, crackmapexec"
            ;;
        critical)
            echo "Use: meterpreter, mimikatz, empire, impacket"
            ;;
    esac
}

# Generate tool matrix by phase
generate_matrix() {
    echo "=== TOOL MATRIX BY PENTEST PHASE ==="
    echo ""
    echo "PHASE 1: RECONNAISSANCE"
    echo "  nmap, dnsrecon, theHarvester, amass, recon-ng"
    echo ""
    echo "PHASE 2: SCANNING"
    echo "  nikto, whatweb, gobuster, dirb, wfuzz"
    echo ""
    echo "PHASE 3: ENUMERATION"
    echo "  enum4linux, smbclient, ldapsearch, rpcclient"
    echo ""
    echo "PHASE 4: EXPLOITATION"
    echo "  sqlmap, metasploit, searchsploit, msfvenom"
    echo ""
    echo "PHASE 5: POST-EXPLOITATION"
    echo "  meterpreter, crackmapexec, impacket, chisel"
    echo ""
    echo "PHASE 6: EXFILTRATION"
    echo "  chisel, socat, netcat, meterpreter"
}

echo "[✓] Tool Registry loaded"
echo "    Use: search_by_category, search_by_function, check_tool, check_all_tools"
