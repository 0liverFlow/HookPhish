import random
import sys
import json
import argparse
from datetime import datetime
import time

from PIL import Image
import requests
import whois
from bs4 import BeautifulSoup as bsoup
from rich import print as printc
from rich.table import Table


class HookPhish:
    """
    
    """
    def __init__(self,url: str):
            if url.startswith('http'):
                self.url = url
                self.defanged_url = self.get_defanged_url(self.url)
                self.expanded_url = ""
                self.servers = ""
                self.target_webpage_screenshot = ""
            else:
                sys.exit(printc(f"[red3][-][/red3] {url}: Invalid url specified!"))

    def get_whois_info(self, target_ip_address: str, verbosity: bool) -> None:
        try:
            target_whois_info = whois.whois(target_ip_address)
            if verbosity:
                for key,value in target_whois_info.items():
                    if key != "status":
                        if isinstance(value, list):
                            if 'date' in key:
                                printc(f"[spring_green2][+][/spring_green2] {key.capitalize()}: {value[0]}")
                            else:
                                printc(f"[spring_green2][+][/spring_green2] {key.capitalize()}:", *value)
                        else:
                            if value is None:
                                printc(f"[red3][-][/red3] {key.capitalize()}: N/A")
                            else:
                                printc(f"[spring_green2][+][/spring_green2] {key.capitalize()}: {value}") 
            else:
                whois_keys = ['name', 'emails', 'address', 'registrant_postal_code', 'registrar', 'creation_date', 'updated_date', 'expiration_date', 'country']
                for key,value in target_whois_info.items():
                    if key in whois_keys:
                        if isinstance(value, list):
                            if 'date' in key:
                                printc(f"[spring_green2][+][/spring_green2] {key.capitalize()}: {value[0]}")
                            else:
                                printc(f"[spring_green2][+][/spring_green2] {key.capitalize()}:", *value)
                        else:
                            if value is None:
                                printc(f"[red3][-][/red3] {key.capitalize()}: N/A")
                            else:
                                printc(f"[spring_green2][+][/spring_green2] {key.capitalize()}: {value}")
        except Exception:
            printc("[red3][-][/red3] Ooops, something went wrong :(")
            printc("[red3][-] Unable to retrieve whois information!!![/red3]")
    
    @staticmethod
    def get_user_agent() -> str:
        # Generate a random user-agent
        with open('db/user_agents.db') as f:
            user_agents = f.readlines()
            return random.choice(user_agents)[:-1]
        

    def get_url_redirections(self, verbosity: bool) -> None:
        '''
        
        '''
     
        # Set the HTTP Request header
        headers = {
            'Accept-Encoding': 'gzip, deflate, br',
            'User-Agent': self.get_user_agent(),
            'Referer': 'https://iplogger.org/',
            'DNT': '1',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Check the target url's redirection(s)
        ip_logger_url_checker = "https://iplogger.org/url-checker/"
        with requests.Session() as session:
            response = session.get(ip_logger_url_checker, headers=headers)
            # Mimic an authentic request (Avoid detection)
            if 'Set-Cookie' in response.headers:
                headers['Cookie'] = response.headers['Set-Cookie']
            if 'Cache-Control' in response.headers:
                headers['Cache-Control'] = response.headers['Cache-Control']
            if 'Last-Modified' in response.headers:
                headers['If-Modified-Since'] = response.headers['Last-Modified']
            params = {"url": self.url}
            response = session.get(ip_logger_url_checker, headers=headers, params=params)
            self.servers = list() # List of dictionaries
            if response.ok:
                soup = bsoup(response.content, 'html.parser')
                servers_info = soup.find_all("div", class_="server-info")
                for server_info in servers_info:
                    server_items = server_info.find_all("div", class_="server-item")
                    server_antivirus = server_info.find("div", class_="server-antivirus")
                    server_next = server_info.find("div", class_="server-next")
                    server_item_info = list()
                    server_dict = dict() # Dictionary containing information about each server from which the request goes through
                    for server_item in server_items:
                        for item in server_item:
                            if item != "\n":
                                server_item_info.append(item)
                        if server_item_info[0].string == "Host":
                            server_dict[server_item_info[0].string] = server_item_info[-1].string
                            self.expanded_url = server_item_info[-1].string
                        elif server_item_info[0].string == "IP address":
                            server_dict[server_item_info[0].string] = server_item_info[-1].contents[-2].string
                            self.target_ip_address = server_item_info[-1].contents[-2].string
                        else:
                           server_dict[server_item_info[0].string] = server_item_info[-1].string
                        server_item_info.clear()
                    server_dict["Status code"] = server_next.contents[1].string
                    server_dict["Google Safe Browsing Database"] = server_antivirus.contents[1].string
                    self.servers.append(server_dict)
                
                # Display url's information based on the verbosity
                number_of_redirections = len(self.servers)
                if verbosity and number_of_redirections > 1:
                    table = Table(title="ℝ 𝔼 𝔻 𝕀 ℝ 𝔼 ℂ 𝕋 𝕀 𝕆 ℕ 𝕊",show_lines=True)
                    table.add_column("ID", justify="center")
                    table.add_column("URL", justify="center", max_width=60)
                    table.add_column("Status Code", justify="center")
                    table.add_column("IP Address", justify="center")
                    table.add_column("Country by IP", justify="center")
                    for server_index in range(number_of_redirections):
                        table.add_row(str(server_index+1), self.servers[server_index]['Host'], self.servers[server_index]['Status code'], self.servers[server_index]['IP address'], self.servers[server_index]['Country by IP'])
                    printc(table)
                elif number_of_redirections > 1:
                    table = Table(title="ℝ 𝔼 𝔻 𝕀 ℝ 𝔼 ℂ 𝕋 𝕀 𝕆 ℕ 𝕊",show_lines=True)
                    table.add_column("Source URL", justify="center", max_width=60)
                    table.add_column("Source Domain", justify="center")
                    table.add_column("Destination URL", justify="center", max_width=60)
                    table.add_column("Destination Domain", justify="center")
                    table.add_row(self.url, self.get_domain_name(self.url), self.expanded_url, self.get_domain_name(self.expanded_url))
                    printc(table)
                else:
                    printc('[red3][-][/red3] No redirection found!')
    
    def get_defanged_url(self, url: str) -> str:
        url_parts = url.split("/")
        scheme = url_parts[0].replace("https:", "hxxps").replace("http:", "hxxp")
        authority = self.get_domain_name(url).replace(".", "[.]")
        path = url_parts[-1]
        defanged_url = scheme + "[://]" + authority + "/" + path
        return defanged_url
                
    
    def check_google_safe_browsing(self) -> None:
        # Check Google Safe Browsing
        number_of_redirections = len(self.servers) - 1
        # Remove the protocol from the target url
        target_url = self.expanded_url.replace("https://","").replace("http://","")
        if "no such URL in our anti-virus databases" in self.servers[number_of_redirections]['Google Safe Browsing Database']:
            print("N/A")
        else:
            printc(f"[gold1][!][/gold1] [gold1]{target_url}[/gold1]: [red3 b]{self.servers[number_of_redirections]['Google Safe Browsing Database']}[/red3 b]")
    
    def get_domain_name(self, url: str) -> str:
        url_parts = url.split('/')
        return url_parts[2]

    def check_tracking_domain_name(self) -> None:
        target_domain_name = self.get_domain_name(self.url)
        with open("db/ip_tracking_domains.json") as f:
            data = json.load(f)
        for ip_tracker_provider,ip_tracking_domain in data.items():
            if ip_tracking_domain == target_domain_name:
                printc(f"[gold1][!][/gold1] [gold1]{target_domain_name}[/gold1] is an IP tracking domain name own by [gold1]{ip_tracker_provider}[/gold1]!")       
                break
        else:
            print("N/A")
    
    def check_url_shortener_domain(self) -> None:
        target_domain_name = self.get_domain_name(self.url)
        with open('db/url_shortener_domains.db') as f:
            url_shortener_domains = f.readlines()
            for url_shortener_domain in url_shortener_domains:
                if url_shortener_domain[:-1] == target_domain_name:
                    printc(f"[gold1][!][/gold1] [gold1]{target_domain_name}[/gold1] found in url shortener domains database!")
                    printc(f"[gold1][!][/gold1] [red3]{self.defanged_url}[/red3] is a [gold1]shortened[/gold1] url!")
                    break
            else:
                print("N/A")
    
    def webpage_illustration(self):
        if self.target_webpage_screenshot != "":
            webpage_screenshot = requests.get(self.target_webpage_screenshot, stream=True)
        else:
            pagekeeper_url = "https://api.pagepeeker.com/v2/thumbs.php"
            params = {"size": "x", "url": self.expanded_url}
            webpage_screenshot = requests.get(pagekeeper_url, headers = {"User-Agent": self.get_user_agent(), "Referer": "https://pagepeeker.com/"}, params=params, stream=True)
        if webpage_screenshot.status_code == 200:
            user_choice = input(f"Would you like to see a real-time screenshot of [red3]{self.defanged_url}[/red3] [Yes/no]: ")
            if user_choice.lower() in ['','y', 'yes', 'yep', 'yeah', 'yay']:
                with Image.open(webpage_screenshot.raw) as img:
                            img.show()
        

    def check_urlscan_io(self, target_url: str, api_key: str, verbosity: bool) -> None:
        max_wait_time = 120 # 2 minutes
        wait_time = 10  # initial wait time
        elapsed_time = 0
        headers = {'API-Key': api_key, 'Content-Type':'application/json'}
        data = {"url": target_url, "visibility": "unlisted"}
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))
        if response.status_code == 200:
            response_json = response.json()
            result_api_url = response_json['api']
            while elapsed_time < max_wait_time:
                response_api_url = requests.get(result_api_url)
                if response_api_url.status_code == 200:
                    self.target_webpage_screenshot = response_api_url.json()['task']['screenshotURL']
                    verdict_overall = response_api_url.json()['verdicts']['overall']
                    verdict_urlscan = response_api_url.json()['verdicts']['urlscan']
                    if verdict_overall['score'] > 0:
                        printc(f"\n[spring_green2][+][/spring_green2] Verdict overall\n{'-'*20}")
                        printc(f"[spring_green2][+][/spring_green2] Time: {response_api_url.json()['task']['time']}")
                        for verdict_overall_property,verdict_overall_value in verdict_overall.items():
                            if isinstance(verdict_overall_value, list):
                                    printc(f"[gold1][!][/gold1] {verdict_overall_property}:  {verdict_overall_value[0]}")
                            else:
                                printc(f"[gold1][!][/gold1] {verdict_overall_property}:  {verdict_overall_value}")
                        if verbosity:
                            printc(f"\n[spring_green2][+][/spring_green2] Verdict urlscan\n{'-'*20}")
                            for verdict_urlscan_property,verdict_urlscan_value in verdict_urlscan.items():
                                if isinstance(verdict_urlscan_value, list):
                                    if verdict_urlscan_property == 'brands':
                                        for brand_key,brand_value in verdict_urlscan_value[0].items():
                                            if brand_value != "":
                                                printc(f"[gold1][!][/gold1] Brand {brand_key}:  {brand_value}")
                                            else:
                                                printc(f"[red3][-][/red3] Brand {brand_key}:  N/A")
                                else:
                                    if verdict_urlscan_property in ['score', 'malicious']:
                                        printc(f"[gold1][!][/gold1] {verdict_urlscan_property}:  {verdict_urlscan_value}")

                        printc(f"[gold1][!][/gold1] For more information about the report you can check the link below ↓")
                        printc(f"[spring_green2][+][/spring_green2] {response_api_url.json()['task']['reportURL']}")
                    else:
                        printc(f"\n[gold1][!][/gold1] Overall score: {verdict_overall['score']}")
                        printc(f"[gold1][!][/gold1] Urlscan score: {verdict_urlscan['score']}")
                        printc(f"[gold1][!][/gold1] Malicious: {verdict_overall['malicious']}")
                        printc(f"[gold1][!][/gold1] For more information about the report you can check the link below ↓")
                        printc(f"[spring_green2][+][/spring_green2] {response_api_url.json()['task']['reportURL']}")
                    break
                elif response_api_url.status_code == 404:
                    printc(f"[gold1][!][/gold1] Scan still in progress. Waiting for {wait_time} seconds...")
                    time.sleep(wait_time)
                    elapsed_time += wait_time
                    wait_time = 5
                else:
                    printc("[red3][-][/red3] Unexpected HTTP response code ({response_api_url.status_code}) returned!!")
        elif response.status_code == 400:
                printc(f"[red3][-][/red3] {response.json()['message']}")
                printc(f"[gold1][!][/gold1] Thanks to read the documentation: https://github.com/0liverFlow/HookPhish/blob/main/README.md")
        elif response.status_code == 429:
                printc(f"[red3][!][/red3] urlscan.io rate-limit exceeded!")
                printc(f"[gold1][!][/gold1] You can find more information here: https://urlscan.io/docs/api/#ratelimit")
        else:
            printc(f"[red3][-][/red3] {response.text}")
            printc(f"[gold1][!][/gold1] Thanks to report this issue at https://github.com/0liverFlow/HookPhish/issues")

    def check_abuse_ip_db(self, ip_address: str, api_key: str, verbosity: bool) -> None:
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {
            'ipAddress': ip_address,
            'maxAgeInDays': '365'
        }

        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }

        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
        if response.ok:
            # Formatted output
            decodedResponse = json.loads(response.text)
            ip_info_dict = dict(decodedResponse['data'])
            if ip_info_dict['totalReports']:
                printc(f"[gold1][!][/gold1] [gold1]{ip_address}[/gold1] was found in Abuse IP DB!")
                printc(f"[gold1][!][/gold1] This IP was reported [gold1]{ip_info_dict['totalReports']}[/gold1] times by [gold1]{ip_info_dict['numDistinctUsers']}[/gold1] distinct users.")
                printc(f"[gold1][!][/gold1] Confidence of Abuse is [gold1]{ip_info_dict['abuseConfidenceScore']}[/gold1]")
                if verbosity:
                    for property in sorted(ip_info_dict.keys()):
                        if property not in ['abuseConfidenceScore', 'numDistinctUsers', 'totalReports']:
                            printc(f"[spring_green2][+][/spring_green2] {property}:  {ip_info_dict[property]}")
                else:
                    for property in sorted(ip_info_dict.keys()):
                        if property in ['isp', 'isTor', 'isWhiteListed', 'usageType', 'lastReportedAt']:
                            printc(f"[spring_green2][+][/spring_green2] {property}:  {ip_info_dict[property]}")
            else:
                printc(f"N/A")
        elif response.status_code == 401:
            printc(f"[red3][-][/red3] {response.json()['errors'][0]['detail']}")
            printc(f"[gold1][!][/gold1] Thanks to read the documentation: https://github.com/0liverFlow/HookPhish/blob/main/README.md")
        else:
            printc(f"[red3][-][/red3] {response.text}")
            printc(f"[gold1][!][/gold1] Thanks to report this issue at https://github.com/0liverFlow/HookPhish/issues")

if __name__ == "__main__":
    # Arguments
    parser = argparse.ArgumentParser(prog='HookPhish.py', description='', epilog='Ping me: 0liverFlow@proton.me')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-v', '--verbose', action='store_true', default=0, help='Increase verbosity')
    group.add_argument('-q', '--quiet',  action='store_true', default=0, help='No verbosity')
    parser.add_argument('-f','--file', metavar="URL", help='JSON file containing the API keys', nargs=1)
    parser.add_argument('-u','--url', metavar="URL", help='URL to check', required=True)
    args = parser.parse_args()
    
    # Banner
    print("""
                                                ℍ 𝕆 𝕆 𝕂 ℙ ℍ 𝕀 𝕊 ℍ
                                                        |
                                                        |
                                                        |
                                                        |
                Version: 1.0 ~-~-~-~-~-~-~~-~-~-~~-~-~~-|-~~-~-~-~-~-~-~-~-~--~~--~~ Author: 0LIVERFLOW  
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
    hookphish = HookPhish(args.url)
    printc(f"\n[bright_blue][*][/bright_blue] Target URL: [red3]{hookphish.defanged_url}[/red3]\n{'-'*55}\n")
    hookphish.get_url_redirections(args.verbose)
    if len(hookphish.expanded_url) > 60:
        printc(f"spring_green2[+][/spring_green2] Destination url: {hookphish.expanded_url}")
    printc(f"\n[bright_blue][*][/bright_blue] Checking Google Safe Browsing Database\n{'-'*42}")
    hookphish.check_google_safe_browsing()
    printc(f"\n[bright_blue][*][/bright_blue] Checking IP Tracking Domains Database\n{'-'*42}")
    hookphish.check_tracking_domain_name()
    printc(f"\n[bright_blue][*][/bright_blue] Checking URL Shortener Domains Database\n{'-'*44}")
    hookphish.check_url_shortener_domain()
    # Check if the user specifies the API Key file
    if args.file:
        with open(args.file[0]) as f:
            data = json.load(f)
        abuse_ip_db_api_key, urlscan_io_api_key = data['abuse_ip_db'], data['urlscan_io']
        printc(f"\n[bright_blue][*][/bright_blue] Urlscan.io Reports For [red3]{hookphish.defanged_url.replace('hxxps[://]', '').replace('hxxp[://]', '')}[/red3]\n{'-'*55}")
        if not urlscan_io_api_key:
            printc("[red3][-][/red3] Urlscan.io api's key missing!")
        else:
            hookphish.check_urlscan_io(hookphish.expanded_url, urlscan_io_api_key, args.verbose)
        printc(f"\n[bright_blue][*][/bright_blue] IP Abuse DB Reports For [red3]{hookphish.target_ip_address}[/red3]\n{'-'*49}")
        if not abuse_ip_db_api_key:
            printc("[red3][-][/red3] Abuse ip db api's key missing!")
        else:
            hookphish.check_abuse_ip_db(hookphish.target_ip_address, abuse_ip_db_api_key, args.verbose)

    printc(f"\n[bright_blue][*][/bright_blue] Whois Lookup For [red3]{hookphish.target_ip_address}[/red3]\n{'-'*42}")
    hookphish.get_whois_info(hookphish.target_ip_address, args.verbose)  
    printc(f"\n[bright_blue][*][/bright_blue] Real-time Screenshot\n{'-'*42}")
    hookphish.webpage_illustration()
    
    date, time = datetime.now().date(), datetime.now().strftime("%H:%M:%S")
    printc(f"\nHookPhish >-)))->: [red3]{hookphish.defanged_url}[/red3]'s scan finished at {date} {time}")