import random
import sys
import json
import time

import requests
import whois
from bs4 import BeautifulSoup as bsoup
from PIL import Image
from rich.table import Table
from rich import print as printc


class PhishDetector:

    def __init__(self,url: str):
            if url.startswith('http') and not self.get_domain_name(url).replace(".","").isdigit():
                self.url = url
                self.defanged_url = self.get_defanged_url(self.url)
                self.expanded_url = ""
                self.servers = ""
                self.target_webpage_screenshot = ""
            else:
                sys.exit(printc(f"[red3][-][/red3] {url}: Invalid url specified (e.g.: https://example.com)!"))

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
            printc("[red3][-] Unable to retrieve whois information!![/red3]")
    
    @staticmethod
    def get_user_agent() -> str:
        # Generate a random user-agent
        with open('db/user_agents.db') as f:
            user_agents = f.readlines()
            return random.choice(user_agents)[:-1]
        

    def get_url_redirections(self, verbosity: bool) -> None:
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
            user_choice = input(f"Would you like to see a real-time screenshot of {self.defanged_url} [Yes/no]: ")
            if user_choice.lower() in ['','y', 'yes', 'yep', 'yeah', 'yay']:
                with Image.open(webpage_screenshot.raw) as img:
                    try:
                        img.show()
                    except BaseException as e:
                        printc("[red3][-][/red3] An error occured: screenshot unavailable")
        else:
            printc("[red3][-][/red3] Screenshot unavailable!!")

    def check_virustotal (self, target_url: str, api_key: str, verbosity: bool) -> None:
        url = "https://www.virustotal.com/api/v3/urls"
        payload = f"url={target_url}"
        headers = {
            "accept": "application/json",
            "x-apikey": api_key,
            "content-type": "application/x-www-form-urlencoded"
        }
        max_wait_time = 60
        wait_time = 10
        elapsed_time = 0
        response = requests.post(url, data=payload, headers=headers)
        if response.status_code == 200:
            url_scan_link = response.json()['data']['links']['self']
            while elapsed_time < max_wait_time:
                url_analysis_report = requests.get(url_scan_link, headers=headers)
                if url_analysis_report.status_code == 200:
                    url_analysis_report_json = url_analysis_report.json()
                    url_analysis_report_id = url_analysis_report_json['meta']['url_info']['id']
                    total_number_of_vendors = len(url_analysis_report_json['data']['attributes']['results'].keys())
                    url_report_gui = "https://www.virustotal.com/gui/url/" + url_analysis_report_id
                    url_scan_stats = url_analysis_report_json['data']['attributes']['stats']
                    malicious_stats = url_scan_stats['malicious']
                    results = url_analysis_report_json['data']['attributes']['results']
                    if total_number_of_vendors > 0:
                        if malicious_stats > 0:
                            printc(f"[gold1][!][/gold1] [red3]{malicious_stats} security vendors flagged this URL as malicious[/red3]")
                        else:
                            printc(f"[spring_green2][+][/spring_green2] No security vendors flagged this URL as malicious")
                        printc(f"[spring_green2][+][/spring_green2] Security vendors' analysis\n{'-'*32}")
                        if verbosity > 0:
                            for stat, stat_value in url_scan_stats.items():
                                printc(f"[gold1][!][/gold1] {stat}: {stat_value}/{total_number_of_vendors}")
                            if malicious_stats > 0:
                                table = Table(title="𝔻 𝔼 𝕋 𝔸 𝕀 𝕃 𝕊", show_lines=True)
                                table.add_column("VENDOR", justify="center", max_width=60)
                                table.add_column("RESULT", justify="center", )
                                table.add_column("METHOD", justify="center")
                                for key,value in results.items():
                                    if value['category'] == "malicious":
                                        table.add_row(key, value['result'], value['method'])
                                printc(table)
                        else:
                            for stat,stat_value in url_scan_stats.items():
                                printc(f"[gold1][!][/gold1] {stat}: {stat_value}/{total_number_of_vendors}")
                        printc(f"[spring_green2][+][/spring_green2] For more information, you can check the link below ↓")
                        printc(f"[spring_green2][+][/spring_green2] {url_report_gui}")
                        break
                    else:
                        printc(f"[gold1][!][/gold1] Scan still in progress. Waiting for {wait_time} seconds...")
                        time.sleep(wait_time)
                        elapsed_time += wait_time
                        wait_time = 5
                else:
                    printc(f"[red3][-][/red3] {url_analysis_report.text}")
        else:
            printc(f"[red3][-][/red3] {response.text}")
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
                        printc(f"\n[gold1][!][/gold1] Verdict urlscan\n{'-'*20}")
                        printc(f"[gold1][!][/gold1] Score: {verdict_urlscan['score']}")
                        printc(f"[gold1][!][/gold1] Malicious: {verdict_urlscan['malicious']}")
                        printc(f"\n[gold1][!][/gold1] Verdict Overall\n{'-'*20}")
                        printc(f"[gold1][!][/gold1] Score: {verdict_overall['score']}")
                        printc(f"[gold1][!][/gold1] Malicious: {verdict_overall['malicious']}")
                        printc(f"[spring_green2][+][/spring_green2] For more information about the report you can check the link below ↓")
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
