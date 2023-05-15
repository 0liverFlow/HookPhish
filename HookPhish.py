import argparse
from datetime import datetime
import time
import configparser

from phish_detector import PhishDetector
from rich import print as printc

if __name__ == "__main__":
    # Arguments
    parser = argparse.ArgumentParser(prog='HookPhish.py', description='A Python script designed to aid in the detection of phishing websites.', epilog='Ping me: 0liverFlow@proton.me')
    parser.add_argument('-v', '--verbose', action='store_true', help='increase verbosity')
    parser.add_argument('-f','--file', metavar="", help='config.ini file containing the API keys', nargs=1)
    parser.add_argument('-u','--url', metavar="URL", help='suspected URL to check', required=True)
    args = parser.parse_args()
    
    # Banner
    print("""
                                                ℍ 𝕆 𝕆 𝕂 ℙ ℍ 𝕀 𝕊 ℍ
                                                        |
                                                        |
                                                        |
                                                        |
                Version: 1.1 ~-~-~-~-~-~-~~-~-~-~~-~-~~-|-~~-~-~-~-~-~-~-~-~--~~--~~ Author: 0LIVERFLOW  
                                                        |       1
                ,-.           ,.---'''^\                |                  O        1
                {   \       ,__\,---'''''`-.,           |      O    O
                I   \    K`,'^           _  `'.         | O                   1
                \  ,.J..-'`          // (O)   ,,X,      |    O      1 
                /  (_               ((   ~  ,;:''<------┘               O  
                /   ,.X'.,            \\      ':;;;:
                (_../      -._                  ,'`
                            K.=,;.__ /^~/___..'`         # First Check, Then Click!
                                /~~/`
    \n""")
    phish_detector =PhishDetector(args.url)
    printc(f"\n[bright_blue][*][/bright_blue] Target URL: [red3]{phish_detector.defanged_url}[/red3]\n{'-'*60}\n")
    phish_detector.get_url_redirections(args.verbose)

    if phish_detector.url != phish_detector.expanded_url and len(phish_detector.expanded_url) > 60:
        printc(f"[spring_green2][+][/spring_green2] Destination url: {phish_detector.expanded_url}")
    # Check Google Safe Browsing Database
    printc(f"\n[bright_blue][*][/bright_blue] Checking Google Safe Browsing Database\n{'-'*42}")
    phish_detector.check_google_safe_browsing()
    # Check IP Tracking Domains
    printc(f"\n[bright_blue][*][/bright_blue] Checking IP Tracking Domains Database\n{'-'*42}")
    phish_detector.check_tracking_domain_name()
    # Check Shortened URLs
    printc(f"\n[bright_blue][*][/bright_blue] Checking URL Shortener Domains Database\n{'-'*44}")
    phish_detector.check_url_shortener_domain()

    # Check if the user specifies the API Key file
    config = configparser.ConfigParser()
    config.read('config/config.ini')
    abuse_ip_db_api_key, urlscan_io_api_key, virustotal_api_key = config['APIs']['ABUSEIPDB_API_KEY'], config['APIs']['URLSCAN_API_KEY'], config['APIs']['VIRUSTOTAL_API_KEY']
    printc(f"\n[bright_blue][*][/bright_blue] Virustotal.com Reports For [red3]{phish_detector.defanged_url.replace('hxxps[://]', '').replace('hxxp[://]', '')}[/red3]\n{'-'*55}")
    if virustotal_api_key == "your_virustotal_api_key":
        printc("[red3][-][/red3] Virustotal.io api's key missing!")
    else:
        phish_detector.check_virustotal(phish_detector.expanded_url, virustotal_api_key, args.verbose)
    time.sleep(2)
    printc(f"\n[bright_blue][*][/bright_blue] Urlscan.io Reports For [red3]{phish_detector.defanged_url.replace('hxxps[://]', '').replace('hxxp[://]', '')}[/red3]\n{'-'*55}")
    if urlscan_io_api_key == "your_urlscan_api_key":
        printc("[red3][-][/red3] Urlscan.io api's key missing!")
    else:
        phish_detector.check_urlscan_io(phish_detector.expanded_url, urlscan_io_api_key, args.verbose)
    time.sleep(2.5)
    printc(f"\n[bright_blue][*][/bright_blue] IP Abuse DB Reports For [red3]{phish_detector.target_ip_address}[/red3]\n{'-'*49}")
    if abuse_ip_db_api_key == "your_abuseipdb_api_key":
        printc("[red3][-][/red3] Abuse ip db api's key missing!")
    else:
        if phish_detector.target_ip_address == "0.0.0.0":
            printc(f"[red3][-][/red3] Unable to resolve {phish_detector.get_domain_name(phish_detector.expanded_url)}")
        else:
            phish_detector.check_abuse_ip_db(phish_detector.target_ip_address, abuse_ip_db_api_key, args.verbose)
    time.sleep(2)
    # Whois Lookup
    printc(f"\n[bright_blue][*][/bright_blue] Whois Lookup For [red3]{phish_detector.target_ip_address}[/red3]\n{'-'*42}")
    if phish_detector.target_ip_address == "0.0.0.0":
        printc(f"[red3][-][/red3] Unable to resolve {phish_detector.get_domain_name(phish_detector.expanded_url)}")
    else:
        phish_detector.get_whois_info(phish_detector.target_ip_address, args.verbose)  
    # Real-time Screenshot
    printc(f"\n[bright_blue][*][/bright_blue] Real-time Screenshot\n{'-'*42}")
    phish_detector.webpage_illustration() 
    # Script execution's information
    date, time = datetime.now().date(), datetime.now().strftime("%H:%M:%S")
    printc(f"\nHookPhish >-))))->: [red3]{phish_detector.defanged_url}[/red3]'s scan finished at {date} {time}")
