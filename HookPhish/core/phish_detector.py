import sys
import os
import json
import time
import re

import requests
from bs4 import BeautifulSoup as bsoup
from rich import print as rprint
from playwright.sync_api import sync_playwright

from HookPhish.core.config import BASE_DIR
from HookPhish.core.user_agents import get_user_agent
from HookPhish.core.http_headers import get_http_headers


class PhishDetector:
    """
    PhishDetector is a class that will perform various checks to determine whether a suspicious URL is malicious.
    """

    def __init__(self, suspicious_url: str):
        if not suspicious_url.startswith(("http://", "https://")):
            rprint(
                f"[red3][-][/red3] {suspicious_url} is an invalid URL (e.g.: https://example.com)"
            )
            sys.exit(-1)
        if re.search(
            "[a-z0-9.]+\.[a-z0-9]+", self.get_domain_name(suspicious_url), re.I
        ):
            self.suspicious_url = suspicious_url
            self.suspicious_domain_name = self.get_domain_name(suspicious_url)
            self.redirections = {}
            self.masked_url = ""
            self.destination_url = ""
            self.destination_ip_address = "0.0.0.0"
            self.destination_domain_name = ""
            self.destination_webpage_screenshot = None
        else:
            rprint(
                f"[red3][-][/red3] {suspicious_url} is an invalid URL (e.g.: https://example.com)"
            )
            sys.exit(-1)

    def get_url_redirections(self):
        """
        This method returns the URL redirections.

        :param self: Current instance of the class
        """
        redirectchecker_url = "https://redirectchecker.org/api/redirectcheck"
        data = {"url": self.suspicious_url}
        headers = {"Content-Type": "application/json", "User-Agent": get_user_agent()}
        response = requests.post(redirectchecker_url, headers=headers, json=data)
        if response.status_code == 200:
            return response.json()
        else:
            return None

    def get_dns_lookup(self, domain_name):
        """
        This method returns the IP address of a domain name using whatsmydns.

        :param self: Current instance of the class
        :param domain_name: A domain name
        """
        url_to_check = f"https://www.whatsmydns.net/dns-lookup/a-records?query={domain_name}&server=cloudflare"
        headers = get_http_headers("https://www.whatsmydns.net/")
        with sync_playwright() as p:
            browser = p.chromium.launch()
            request_context = browser.new_context()
            dns_lookup_page = request_context.new_page()
            dns_lookup_page.set_extra_http_headers(headers)
            try:
                dns_lookup_page.goto(url_to_check)
                dns_lookup_page.wait_for_selector(
                    'td.border-gray-400 a[href*="ptr-records"]'
                )
            except Exception:
                return "0.0.0.0"
            soup = bsoup(dns_lookup_page.content(), "html.parser")
            ip_tag = soup.select_one('td.border-gray-400 a[href*="ptr-records"]')
            ip_address = ip_tag.text if ip_tag else "0.0.0.0"
            return ip_address

    def get_ip_info(self, ip_address):
        """
        This method returns an IP address information (Country name, City Name, etc.).

        :param self: Current instance of the class
        :param ip_address: A domain name
        """
        url = "https://freeipapi.com/api/json/" + ip_address
        headers = {
            "User-Agent": get_user_agent(),
            "Referer": "https://freeipapi.com/",
            "DNT": "1",
        }
        with sync_playwright() as p:
            request_context = p.request.new_context()
            ip_info = request_context.get(url, headers=headers)
            if ip_info.status == 200 and ip_info.json()["ipAddress"] != "":
                return ip_info.json()
            else:
                return "N/A"

    def check_url_obfuscation(self):
        """
        This method checks if a URL is obfuscated (Url encoding, cyrillic characters, punny code, etc).

        :param self: Current instance of the class
        """
        if re.search("%[0-9A-F]{2}", self.suspicious_url, re.I):
            return "The URL is encoded"
        elif re.search("xn--", self.suspicious_url, re.I):
            return "The URL contains punycode"
        elif re.search(r"[\u0400-\u04FF]", self.suspicious_url):
            return "The URL contains cyrillic characters"
        elif any(ord(s) > 127 for s in self.suspicious_url):
            return "The URL contains non ASCII characters"
        elif re.search("https?://[^/]*@[^/]+", self.suspicious_url, re.I):
            return "The URL schema was obfuscated"
        elif self.suspicious_url.startswith(
            ("https://www.google.com/url?q=", "http://www.google.com/url?q=")
        ):
            self.suspicious_url = self.suspicious_url.split(
                "https://www.google.com/url?q="
            )[-1]
            return "Google open redirection detected"
        else:
            return None

    def check_google_safe_browsing(self):
        """
        This method checks whether a URL is malicious using Google Safe Browsing.

        :param self: Current instance of the class
        """
        url_to_check = (
            "https://transparencyreport.google.com/safe-browsing/search?url="
            + self.destination_url
            + "&hl=en"
        )
        with sync_playwright() as p:
            browser = p.chromium.launch()
            context = browser.new_context()
            google_safe_browsing = context.new_page()
            headers = get_http_headers(
                "https://transparencyreport.google.com/safe-browsing/search?hl=en"
            )
            google_safe_browsing.set_extra_http_headers(headers)
            try:
                google_safe_browsing.goto(url_to_check)
                google_safe_browsing.wait_for_selector(
                    'div.title[role="heading"][aria-level="3"]'
                )
            except Exception as e:
                False, e
            google_safe_browsing_content = google_safe_browsing.content()
            return True, google_safe_browsing_content

    def get_domain_name(self, url):
        """
        This method retrieves the domain name from a URL.

        :param self: Current instance of the class
        :param url: A URL
        """
        return url.split("/")[2]

    def check_ip_tracker_domain_name(self):
        """
        This method checks whether a domain name is IP tracking domain.

        :param self: Current instance of the class
        """
        suspicious_domain_name = self.get_domain_name(self.suspicious_url)
        with open(os.path.join(BASE_DIR, "../data", "ip_tracker_domains.json")) as f:
            data = json.load(f)
        for ip_tracker_provider, ip_tracker_domain in data.items():
            if ip_tracker_domain == suspicious_domain_name:
                return True, ip_tracker_domain, ip_tracker_provider
        return False, None, None

    def check_url_shortener_domain(self):
        """
        This method checks if a URL was shortened.

        :param self: Current instance of the class
        """
        suspicious_domain_name = self.get_domain_name(self.suspicious_url)
        with open(os.path.join(BASE_DIR, "../data", "url_shortener_domains.txt")) as f:
            url_shortener_domains = f.readlines()
            for url_shortener_domain in url_shortener_domains:
                if url_shortener_domain[:-1] == suspicious_domain_name:
                    return True, url_shortener_domain[:-1]
            return False, None

    def check_tunnel_domains(self):
        """
        This method checks if a domain is a tunnel (ngrok, cloudflared, serveo, localxpose, etc).

        :param self: Current instance of the class
        :param :
        """
        with open(os.path.join(BASE_DIR, "../data", "tunnels.json")) as f:
            tunnel_domains_db = json.load(f)
            for tunnel_service, tunnel_domains in tunnel_domains_db.items():
                for tunnel_domain in tunnel_domains:
                    if self.suspicious_domain_name.endswith(tunnel_domain):
                        return True, tunnel_domain, tunnel_service
            return False, None, None

    def check_url_masking(self):
        """
        This method checks whether a URL was masked.

        :param self: Current instance of the class
        """
        # Url_masking_services is a list of URL shortners and tunnelers used by attackers to mask their malicious URLs
        url_masking_services = [
            "is.gd",
            "tinyurl.com",
            "osdb.link",
            "da.gd",
            "clck.ru",
            "loclx.io",
            "lhr.life",
            "serveo.net",
            "trycloudflare.com",
        ]
        for url_masking_service in url_masking_services:
            # suspicious_url
            if re.search(
                f"@{url_masking_service}/[A-Z0-9]+", self.suspicious_url, re.I
            ) or re.search(f"@.*\.{url_masking_service}$", self.suspicious_url, re.I):
                self.masked_url = re.sub("https?://", "", self.suspicious_url).lower()
                return True, url_masking_service
            # destination_url (this check is useful if suspicious_url was shortened for instance)
            elif re.search(
                f"@{url_masking_service}/[A-Z0-9]+", self.destination_url, re.I
            ) or re.search(f"@.*\.{url_masking_service}$", self.destination_url, re.I):
                self.masked_url = re.sub("https?://", "", self.suspicious_url).lower()
                return True, url_masking_service
        return False, None

    def get_masked_url_parts(self):
        """
        This method returns the different parts of a masked URL.

        :param self: Current instance of the class
        """
        masked_url_parts = self.masked_url.split("@")
        shortened_link = masked_url_parts[-1]
        custom_domain_name = masked_url_parts[0]
        return custom_domain_name, shortened_link

    def detect_phishing_toolkit(self):
        """
        This method detects the usage of phishing toolkits like GoPhish, Evilginx, Storm-Breaker, Pyphisher, Zphisher, Facad1ng.
        The method will search for IoCs used by default by phishing toolkits.

        :param self: Current instance of the class
        """
        # This code snippet was created after analyzing the source code of well known phishing toolkits like Pyphisher, Storm-Breaker, Facad1ng, GoPhish, Evilginx
        # Try to detect Pyphisher
        with open(
            os.path.join(BASE_DIR, "../data", "pyphisher-default-templates.json")
        ) as f:
            pyphisher_templates = json.load(f)
            for website, template in pyphisher_templates.items():
                # In case where the malicious user try to hide their phishing toolkits
                if self.destination_url.startswith(
                    template.strip()
                ) or self.suspicious_url.startswith(template.strip()):
                    return True, "Pyphisher", website
        # Try to detect Storm-Breaker
        with open(os.path.join(BASE_DIR, "../data", "storm-breaker.json")) as st:
            st_data = json.load(st)
            for data_collected, malicious_path in st_data.items():
                if self.destination_url.endswith(
                    malicious_path
                ) or self.suspicious_url.endswith(malicious_path):
                    return [True, "Storm-Breaker", data_collected]
        # Try to detect Facad1ng
        facad1ng_url_shorteners = r"(tinyurl.com|da.gd|clck.ru|osdb.link)"
        if self.masked_url and re.search(
            facad1ng_url_shorteners, self.masked_url, re.I
        ):
            fake_domain = self.masked_url.split("@")[0].split("-", 1)[0]
            bait = self.masked_url.split("@")[0].split("-", 1)[-1]
            if len(bait) <= 15 and re.match(
                "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", fake_domain
            ):
                return True, "Facad1ng", self.defang_url(fake_domain)
        # Try to detect GoPhish
        if re.search("\?id=[A-Za-z0-9]{7}", self.destination_url):
            return True, "GoPhish", self.destination_url.split("?id=")[-1]
        # Try to detect Evilginx (Add new checks to increase the detection likelihood)
        lure = self.destination_url.split("/")[-1]
        if len(lure) == 8 and re.search("^[A-Za-z]{8}$", lure) is not None:
            return True, "Evilginx", lure
        return False, "", ""

    def get_github_profile_info(self, username):
        """
        This method retrieves a GitHub profile's information.

        :param self: Current instance of the class
        :param username: GitHub username
        """
        username_profile_url = "https://api.github.com/users/" + username
        headers = {"User-Agent": get_user_agent()}
        with sync_playwright() as p:
            request_context = p.request.new_context()
            github_profile_information = request_context.get(
                username_profile_url, headers=headers
            )
        if github_profile_information.status == 404:
            return None
        else:
            return github_profile_information.json()

    def check_tls_certificate_info(self):
        """
        This method retrieves a SSL/TLS certificate information.

        :param self: Current instance of the class
        """
        query_params = {
            "q": ".".join(self.destination_domain_name.split(".")[1:]),
            "output": "json",
        }
        headers = {"User-Agent": get_user_agent()}
        certificate_information = requests.get(
            "https://crt.sh/", params=query_params, headers=headers
        )
        if certificate_information.status_code == 200:
            return certificate_information.json()
        else:
            return None

    def check_virustotal(self, api_key):
        """
        This method performs a VirusTotal scan against a suspicious URL.

        :param: self: Current instance of the class
        :param api_key: VirusTotal API key
        """
        vt_url = "https://www.virustotal.com/api/v3/urls"
        data = {"url": self.suspicious_url}
        headers = {"accept": "application/json", "x-apikey": api_key}
        max_wait_time = 60
        wait_time = 10
        elapsed_time = 0
        response = requests.post(vt_url, data=data, headers=headers)
        if response.status_code == 200:
            url_to_scan_id = response.json()["data"]["links"]["self"].split("-")[1]
            url_to_scan = vt_url + "/" + url_to_scan_id
            while elapsed_time <= max_wait_time:
                vt_analysis_report = requests.get(url_to_scan, headers=headers)
                if vt_analysis_report.status_code == 200:
                    return True, vt_analysis_report.json()
                else:
                    rprint(
                        f"[gold1][!][/gold1] Scan still in progress. Waiting for {wait_time} seconds..."
                    )
                    time.sleep(wait_time)
                    elapsed_time += wait_time
                    wait_time = 5
            if elapsed_time >= max_wait_time and vt_analysis_report.status_code != 200:
                return False, "Timeout"
        else:
            return False, response.status_code

    def check_urlscan_io(self, api_key):
        """
        This method performs a scan against a suspicious URL using Urlscan.

        :param: self: Current instance of the class
        :param api_key: Urlscan API key
        """
        max_wait_time = 120
        wait_time = 10
        elapsed_time = 0
        headers = {"API-Key": api_key, "Content-Type": "application/json"}
        data = {"url": self.suspicious_url, "visibility": "unlisted"}
        response = requests.post(
            "https://urlscan.io/api/v1/scan/", headers=headers, data=json.dumps(data)
        )
        if response.status_code == 200:
            urlscan_results_url = response.json()["api"]
            while elapsed_time <= max_wait_time:
                urlscan_analysis_report = requests.get(
                    urlscan_results_url, headers=headers
                )
                if urlscan_analysis_report.status_code == 200:
                    return True, urlscan_analysis_report.json()
                elif urlscan_analysis_report.status_code == 404:
                    rprint(
                        f"[gold1][!][/gold1] Scan still in progress. Waiting for {wait_time} seconds..."
                    )
                    time.sleep(wait_time)
                    elapsed_time += wait_time
                    wait_time = 5
                else:
                    return False, "urlscan_analysis_report error"
        elif response.status_code == 400:
            return False, response
        elif response.status_code == 429:
            return False, "response error"
        else:
            return False, response

    def check_abuse_ip_db(self, api_key):
        """
        This method performs an AbuseIPDB scan against a suspicious URL.

        :param: self: Current instance of the class
        :param api_key: AbuseIPDB API key
        """
        query_params = {"ipAddress": self.destination_ip_address, "maxAgeInDays": "365"}
        headers = {"Accept": "application/json", "Key": api_key}
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=query_params,
        )
        if response.status_code == 200:
            return True, response.json()
        else:
            return False, response

    def check_urlhaus(self, api_key):
        """
        This method performs a scan against a suspicious URL using URLhaus.

        :param: self: Current instance of the class
        :param api_key: URLhaus API key
        """
        query_url_information_api_endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        headers = {"User-Agent": get_user_agent(), "Auth-Key": api_key}
        suspicious_url_response = requests.post(
            query_url_information_api_endpoint,
            headers=headers,
            data={"url": self.suspicious_url},
        )
        destination_url_response = requests.post(
            query_url_information_api_endpoint,
            headers=headers,
            data={"url": self.destination_url},
        )
        if suspicious_url_response.status_code == 200:
            return suspicious_url_response.json()
        elif destination_url_response.status_code == 200:
            return destination_url_response.json()
        else:
            return None

    def check_phishstats(self):
        """
        This method scans a suspicious URL using PhishStats.

        :param: self: Current instance of the class
        """
        url = "https://api.phishstats.info/api/phishing"
        query_params = {"_where": f"(url,eq,{self.suspicious_url})"}
        headers = {"User-Agent": get_user_agent()}
        with sync_playwright() as p:
            request_context = p.request.new_context()
            response = request_context.get(url, params=query_params, headers=headers)
            if response.status == 200:
                # response.json() is a list that contains a dictionary [{}]. That's why I used response.json()[0] to only return the dictionary
                return response.json()[0] if len(response.json()) else None
            else:
                return None

    def check_redflagdomains(self):
        """
        This method checks whether a suspicious URL was found in Red Flag Domains database.

        :param: self: Current instance of the class
        """
        url = "https://dl.red.flag.domains/red.flag.domains.txt"
        headers = {"User-Agent": get_user_agent()}
        with sync_playwright() as p:
            request_context = p.request.new_context()
            response = request_context.get(url, headers=headers)
            if response.status == 200:
                malicious_domains = response.text().splitlines()
                last_update = (
                    malicious_domains[0].split(":")[-1]
                    if malicious_domains[0].startswith("#")
                    else "N/A"
                )
                return (
                    (True, last_update)
                    if self.suspicious_domain_name in malicious_domains
                    or self.destination_domain_name in malicious_domains
                    else (False, last_update)
                )
            else:
                return None

    def check_phishing_army(self):
        """
        This method checks whether a suspicious URL was found in Phishing Army database.

        :param: self: Current instance of the class
        """
        url = "https://phishing.army/download/phishing_army_blocklist.txt"
        headers = {"User-Agent": get_user_agent()}
        with sync_playwright() as p:
            request_context = p.request.new_context()
            response = request_context.get(url, headers=headers)
            if response.status == 200:
                malicious_domains = response.text().splitlines()
                last_update = (
                    malicious_domains[3].split(":", 1)[-1].strip()
                    if malicious_domains[3].startswith("#")
                    else "N/A"
                )
                return (
                    (True, last_update)
                    if self.suspicious_domain_name in malicious_domains
                    or self.destination_domain_name in malicious_domains
                    else (False, last_update)
                )
            else:
                return None

    def check_archive_org(self):
        """
        This method checks if a suspicious URL was captured in Archive.org. If yes, it returns the corresponding URL.

        :param: self: Current instance of the class
        """
        url = "https://web.archive.org/cdx/search/cdx"
        query_params = {"url": self.destination_url, "collapse": "urlkey"}
        headers = {
            "User-Agent": get_user_agent(),
            "Referer": "https://web.archive.org/",
        }
        with sync_playwright() as p:
            request_context = p.request.new_context()
            response = request_context.get(
                url, params=query_params, headers=headers, timeout=45000
            )
            if response.status == 200:
                return (
                    f"https://web.archive.org/web/20260000000000/{self.destination_url}"
                    if response.text() != ""
                    else None
                )
            else:
                return None

    def unfurl_url(self):
        """
        This method unfurls a URL using hindsig.ht.

        :param: self: Current instance of the class
        """
        return f"https://hindsig.ht/unfurl/?url={self.suspicious_url}"

    def get_webpage_screenshot(self):
        """
        This method returns a website screenshot.

        :param self: Current instance of the class
        """
        if self.destination_webpage_screenshot is not None:
            webpage_screenshot = requests.get(
                self.destination_webpage_screenshot, stream=True
            )
            return (
                (True, webpage_screenshot)
                if webpage_screenshot.status_code == 200
                else (False, None)
            )
        else:
            return False, None
