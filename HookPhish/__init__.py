#!/usr/bin/env python3

import argparse
from datetime import datetime
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from getpass import getpass

from bs4 import BeautifulSoup as bsoup
from PIL import Image
from rich import print as rprint
from rich.progress import Progress, SpinnerColumn, TextColumn
from playwright.sync_api import Error
from rich.table import Table
from dotenv import load_dotenv, set_key

from HookPhish.core.phish_detector import PhishDetector
from HookPhish.core.config import BASE_DIR
from HookPhish.core.banner import banner
from HookPhish.core.is_vpn import is_vpn
from HookPhish.core.is_tor_node import is_tor_node
from HookPhish.core.defang_url import defang_url
from HookPhish.core.check_dict_keys import check_dict_keys


def main():
    parser = argparse.ArgumentParser(
        prog="HookPhish.py",
        description="A Python script that helps detecting phishing websites using passive detection techniques.",
        formatter_class=lambda prog: argparse.HelpFormatter(
            prog, width=112, max_help_position=40
        ),
    )
    parser.add_argument("-u", "--url", metavar="URL", help="Suspicious URL to check")
    parser.add_argument(
        "--api-keys",
        action="store_true",
        help="Configure your VirusTotal, Urlscan, URLhaus, and AbuseIPDB API keys (Recommended)",
    )
    parser.add_argument("--no-banner", action="store_true", help="Remove banner")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbosity")
    args = parser.parse_args()

    # Display banner
    if not args.no_banner:
        banner()

    # Load environment variables from .env file
    load_dotenv()
    env_path = os.path.join(BASE_DIR, "..", ".env")
    # API Keys Configuration
    if args.api_keys is True:
        apis = {
            "VirusTotal API Key Configuration": "VIRUSTOTAL_API_KEY",
            "Urlscan API Key Configuration": "URLSCAN_API_KEY",
            "AbuseIPDB API Key Configuration": "ABUSEIPDB_API_KEY",
            "URLhaus API Key Configuration": "URLHAUS_API_KEY",
        }
        for config_message, api_key_name in apis.items():
            print(f"\n{config_message}\n{'-' * len(config_message)}")
            if os.getenv(api_key_name) is None:
                rprint(
                    f"[bright_blue][*][/bright_blue] Enter your {config_message.split(' ')[0]} API key: ",
                    end="",
                )
                api_key_value = getpass("")
                if api_key_value == "":
                    rprint(
                        "[gold1][!][/gold1] No API key was specified!"
                    )
                else:
                    success, _, _ = set_key(env_path, api_key_name, api_key_value)
                    if success and api_key_value != "":
                        rprint(
                            "[spring_green2][+][/spring_green2] Your API key was successfully added!"
                        )
                    else:
                        rprint(
                            "[red3][-][/red3] Failed to write the API key! Try again!"
                        )
                        sys.exit(1)
            else:
                rprint(
                    f"[gold1][!][/gold1] A {' '.join(config_message.split(' ')[:-1])} already exists!\n[bright_blue][*][/bright_blue] Would you like to overwritte it? [Y/n] ",
                    end="",
                )
                user_choice = input("")
                if user_choice.lower() in ["", "y", "yes"]:
                    rprint(
                        f"[bright_blue][*][/bright_blue] Enter your {' '.join(config_message.split(' ')[:-1])}: ",
                        end="",
                    )
                    api_key_value = getpass("")
                    success, _, _ = set_key(env_path, api_key_name, api_key_value)
                    if success:
                        rprint(
                            "[spring_green2][+][/spring_green2] Your API key was successfully added!"
                        )
                    else:
                        rprint(
                            "[red3][-][/red3] Failed to write the API key! Try again!"
                        )
                        sys.exit(1)
        sys.exit(0)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task("")
        if not args.url:
            rprint("[red3][-][/red3] Please specify an URL!\n")
            parser.print_help(sys.stderr)
            sys.exit(1)
        # Instantiate a new object using PhishDetector class
        phish_detector = PhishDetector(args.url)
        rprint(
            f"\n[bright_blue][*][/bright_blue] Target URL: [red3]{defang_url(phish_detector.suspicious_url)}[/red3]\n{'-' * 80}"
        )
        final_verdict = {}
        # Check if URL is obfuscated
        rprint(f"\n[bright_blue][*][/bright_blue] Checking URL Obfuscation\n{'-' * 50}")
        url_obfuscation_result = phish_detector.check_url_obfuscation()
        if url_obfuscation_result is not None:
            rprint(f"[gold1][!][/gold1] {url_obfuscation_result}")
            final_verdict["is_url_obfuscated"] = "True"
        else:
            rprint("[spring_green2][+][/spring_green2] No obfuscation detected!")
            final_verdict["is_url_obfuscated"] = "Probably Not"

        # Pool for multithreading
        pool = ThreadPoolExecutor()

        # Check URL redirections
        # A worker is created for each check
        worker1 = pool.submit(phish_detector.get_url_redirections)
        redirection_chain = worker1.result()
        if redirection_chain is not None:
            rprint(
                f"\n[bright_blue][*][/bright_blue] Checking URL Redirections\n{'-' * 50}"
            )
            number_of_redirections = len(redirection_chain)
            phish_detector.destination_url = redirection_chain[-1]["url"]
            phish_detector.destination_domain_name = redirection_chain[-1]["host"]
            phish_detector.destination_ip_address = phish_detector.get_dns_lookup(
                phish_detector.destination_domain_name
            )
            destination_ip_address_info = (
                phish_detector.get_ip_info(phish_detector.destination_ip_address)
                if phish_detector.destination_ip_address != "0.0.0.0"
                else None
            )
            if redirection_chain[0]["status"] == 530:
                rprint(
                    f"[bright_magenta][-][/bright_magenta] DNS resolution failed for {defang_url(redirection_chain[0]['host'])}!"
                )
            else:
                table = Table(
                    header_style="bold",
                    title_style="bold",
                    title_justify="center",
                    show_lines=True,
                )
                table.add_column("ID", justify="center")
                table.add_column("URL", justify="center", max_width=60, overflow="fold")
                table.add_column("Status Code", justify="center")
                table.add_column("IP Address", justify="center")
                table.add_column("Is VPN", justify="center")
                table.add_column("Is TOR", justify="center")
                table.add_column("Country Name", justify="center")
                # Display URL redirection(s)
                if (
                    number_of_redirections == 1
                    and redirection_chain[-1]["url"] == phish_detector.suspicious_url
                    and (
                        redirection_chain[-1]["status"] == 200
                        or redirection_chain[-1]["status"] == 404
                    )
                ):
                    if destination_ip_address_info is not None:
                        destination_ip_address_country_name = (
                            destination_ip_address_info["countryName"]
                        )
                        table.add_row(
                            str(number_of_redirections),
                            defang_url(phish_detector.destination_url),
                            str(redirection_chain[-1]["status"]),
                            str(phish_detector.destination_ip_address),
                            str(is_vpn(phish_detector.destination_ip_address)),
                            str(is_tor_node(phish_detector.destination_ip_address)),
                            str(destination_ip_address_country_name),
                        )
                    else:
                        table.add_row(
                            str(number_of_redirections),
                            defang_url(phish_detector.destination_url),
                            str(redirection_chain[-1]["status"]),
                            "N/A",
                            "N/A",
                            "N/A",
                            "N/A",
                        )
                    rprint(table)
                else:
                    hop = 0
                    while hop < number_of_redirections:
                        intermediate_url = redirection_chain[hop]["url"]
                        intermediate_url_status_code = redirection_chain[hop]["status"]
                        intermediate_domain_name = redirection_chain[hop]["host"]
                        intermediate_ip_address = phish_detector.get_dns_lookup(
                            intermediate_domain_name
                        )
                        intermediate_ip_is_tor = "N/A"
                        intermediate_ip_is_vpn = "N/A"
                        if intermediate_ip_address != "0.0.0.0":
                            intermediate_ip_address_info = phish_detector.get_ip_info(
                                intermediate_ip_address
                            )
                            intermediate_ip_is_tor = is_tor_node(
                                intermediate_ip_address
                            )
                            intermediate_ip_is_vpn = is_vpn(intermediate_ip_address)
                            if intermediate_ip_address_info is not None:
                                intermediate_ip_address_country_name = (
                                    intermediate_ip_address_info["countryName"]
                                )
                                table.add_row(
                                    str(hop + 1),
                                    defang_url(intermediate_url),
                                    str(intermediate_url_status_code),
                                    str(intermediate_ip_address),
                                    str(intermediate_ip_is_vpn),
                                    str(intermediate_ip_is_tor),
                                    str(intermediate_ip_address_country_name),
                                )
                            else:
                                table.add_row(
                                    str(hop + 1),
                                    defang_url(intermediate_url),
                                    str(intermediate_url_status_code),
                                    str(intermediate_ip_address),
                                    str(intermediate_ip_is_vpn),
                                    str(intermediate_ip_is_tor),
                                    "N/A",
                                )
                        else:
                            table.add_row(
                                str(hop + 1),
                                defang_url(intermediate_url),
                                str(intermediate_url_status_code),
                                "N/A",
                                "N/A",
                                "N/A",
                                "N/A",
                            )
                        hop += 1
                    rprint(table)
            if (
                phish_detector.destination_ip_address == "0.0.0.0"
                and redirection_chain[0]["status"] != 530
            ):
                rprint(
                    f"[bright_magenta][-][/bright_magenta] No DNS (A) records found for [red3]{defang_url(phish_detector.destination_url)}[/red3]"
                )
        else:
            sys.exit(
                rprint(
                    "[bright_magenta][-][/bright_magenta] Redirections check failed: Please, try again! If the issue persists, report it at https://github.com/0liverFlow/HookPhish/issues"
                )
            )

        # Check if destination URL is antiphishing.biz (This is a threat intelligence platform that proactively detect, analyze, and document active phishing campaigns, deceptive web interfaces, and malicious infrastructure)
        if phish_detector.destination_url.startswith("https://antiphishing.biz/"):
            rprint(
                f"[red3]/!\ {defang_url(phish_detector.suspicious_url)} is malicious![/red3]\n[gold1][!][/gold1] The URL was blocked by Antiphishing.biz, a threat intelligence platform used to detect and analyze active phishing campaigns."
            )
            rprint(f"\n[bright_blue][*][/bright_blue] Report Phishing URL\n{'-' * 50}")
            rprint(
                "[spring_green2][+][/spring_green2] Contribute to make the Internet a safer place by reporting the URL at one of the websites below ↓"
            )
            rprint(
                "[spring_green2][+][/spring_green2] https://phishing-initiative.eu/contrib/"
            )
            rprint(
                "[spring_green2][+][/spring_green2] https://safebrowsing.google.com/safebrowsing/report_phish/"
            )
            rprint(
                "[spring_green2][+][/spring_green2] https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest"
            )
            sys.exit(0)

        # Launch workers for Google Safe Browsing, IP Tracking Domains, Tunneling Domains, URL shorteners, URL masking and phishing toolkits detection
        worker2 = pool.submit(phish_detector.check_google_safe_browsing)
        worker3 = pool.submit(phish_detector.check_ip_tracker_domain_name)
        worker4 = pool.submit(phish_detector.check_tunnel_domains)
        worker5 = pool.submit(phish_detector.check_url_shortener_domain)
        worker6 = pool.submit(phish_detector.check_url_masking)
        worker7 = pool.submit(phish_detector.detect_phishing_toolkit)

        # Check Google Safe Browsing (https://safebrowsing.google.com/)
        rprint(
            f"\n[bright_blue][*][/bright_blue] Checking Google Safe Browsing Database\n{'-' * 50}"
        )
        success, google_safe_browsing_content = worker2.result()
        if success:
            soup = bsoup(google_safe_browsing_content, "html.parser")
            result = soup.select_one('span[aria-label="figure value"]')
            # Malicious website
            if result.text.capitalize() == "This site is unsafe":
                rprint(f"[red3]/!\ [/red3][red3]{result.text.strip()}[/red3]")
                # Potential malicious actions
                infos = soup.select(
                    'div.details[role="heading"][aria-level="4"] > ul > li'
                )
                if len(infos):
                    rprint(
                        f"\n[gold1][!][/gold1] Potential malicious actions\n{'-' * len('Potential malicious actions')}"
                    )
                    for info in infos:
                        rprint(f"{info.text.strip()}")
                info_last_update = soup.find(
                    "h3", string=lambda text: text == "Site info"
                )
                if (
                    info_last_update is not None
                    and info_last_update.text.capitalize() == "Site info"
                    and args.verbose
                ):
                    rprint(
                        f"\n[gold1][!][/gold1] Last update:{info_last_update.find_next('p').text.strip()}"
                    )
                final_verdict["Google Safe Browsing"] = "Found"
            # Safe website
            elif result.text.capitalize() == "No unsafe content found":
                rprint(f"[spring_green2][+][/spring_green2] {result.text.strip()}")
                info_last_update = soup.find(
                    "h3", string=lambda text: text == "Site info"
                )
                if info_last_update.text.capitalize() == "Site info" and args.verbose:
                    rprint(
                        f"[gold1][!][/gold1] Last update: {info_last_update.find_next('p').text.strip()}"
                    )
                final_verdict["Google Safe Browsing"] = "Not Found"
            # Unable to know whether or not the website is malicious
            elif result.text.capitalize() == "Check a specific url":
                rprint(
                    "[gold1][!][/gold1] It's hard to provide a simple safety status for websites like this one."
                )
                final_verdict["Google Safe Browsing"] = "N/A"
            else:
                rprint(f"{result.text.capitalize().strip()}")
                final_verdict["Google Safe Browsing"] = "N/A"
        else:
            sys.exit(
                rprint(
                    f"[bright_magenta][-][/bright_magenta] Google Safe Browsing returned this error: {google_safe_browsing_content}"
                )
            )

        # Check IP Tracker Domains
        rprint(
            f"\n[bright_blue][*][/bright_blue] Checking IP Tracker Domains\n{'-' * 50}"
        )
        is_domain_tracker, suspicious_domain, ip_tracker_provider = worker3.result()
        if is_domain_tracker:
            rprint(
                f"[red3]/!\ [/red3]{suspicious_domain} is an IP tracker domain, owned by [gold1]{ip_tracker_provider}[/gold1]"
            )
            final_verdict["is_ip_tracker_domain"] = "True"
        else:
            rprint("[spring_green2][+][/spring_green2] Not found!")
            final_verdict["is_ip_tracker_domain"] = "Probably Not"

        # Check Tunneling Domain
        rprint(
            f"\n[bright_blue][*][/bright_blue] Checking Tunneling Domains\n{'-' * 50}"
        )
        is_tunnel_domain, tunnel_domain, tunnel_service = worker4.result()
        if is_tunnel_domain:
            rprint(
                f"[red3]/!\ {tunnel_domain}[/red3] was found in our database! The tunneling tool used is {tunnel_service}"
            )
            rprint(
                "[gold1][!][/gold1] This is a known technique used by threat actors to mask their phishing links."
            )
            final_verdict["is_tunneling_domain"] = "True"
        else:
            rprint("[spring_green2][+][/spring_green2] Not Found!")
            final_verdict["is_tunneling_domain"] = "Probably Not"

        # Check Shortened URLs
        rprint(
            f"\n[bright_blue][*][/bright_blue] Checking URL Shortener Domains\n{'-' * 50}"
        )
        is_url_shortener, suspicious_domain_name = worker5.result()
        if is_url_shortener:
            rprint(
                f"[red3]/!\ [/red3]The URL was shortened using [gold1]{suspicious_domain_name}[/gold1]!"
            )
            final_verdict["is_url_shortened"] = "True"
        else:
            rprint("[spring_green2][+][/spring_green2] Not found!")
            final_verdict["is_url_shortened"] = "Probably Not"

        # Check URL Masking
        rprint(f"\n[bright_blue][*][/bright_blue] Checking URL Masking\n{'-' * 50}")
        is_url_masked, url_shortener_service = worker6.result()
        if is_url_masked:
            rprint(
                f"[gold1][!][/gold1][red3] {defang_url(phish_detector.masked_url)}[/red3] was masked with [red3]{url_shortener_service}[/red3]!"
            )
            custom_domain_name, shortened_link = phish_detector.get_masked_url_parts()
            rprint(f"[gold1][!][/gold1] Fake domain: {custom_domain_name}")
            rprint(f"[gold1][!][/gold1] Shortened link: {shortened_link}")
            final_verdict["is_url_masked"] = "True"
        else:
            rprint("[spring_green2][+][/spring_green2] URL masking not detected!")
            final_verdict["is_url_masked"] = "Probably not"

        # Detect Phishing Toolkits
        rprint(
            f"\n[bright_blue][*][/bright_blue] Checking Phishing Toolkits\n{'-' * 50}"
        )
        phishing_toolkit_found, phishing_toolkit_name, phishing_toolkit_info = (
            worker7.result()
        )
        if phishing_toolkit_found:
            if phishing_toolkit_name == "Evilginx":
                rprint(
                    f"[red3]/!\{phishing_toolkit_name}[/red3] was used to generate this link!"
                )
                rprint(
                    f"[gold1][!][/gold1] The potential lure is: [red3]{phishing_toolkit_info}[/red3]"
                )
            else:
                rprint(
                    f"[red3]/!\ {phishing_toolkit_name}[/red3] was used to generate this link"
                )
            if phishing_toolkit_name == "GoPhish":
                # rid is a unique identifier used by GoPhish to track campaigns
                rprint(
                    f"[gold1][!][/gold1] The recipient parameter (rid) is: [red3]{phishing_toolkit_info}[/red3]"
                )
            elif phishing_toolkit_name == "Pyphisher":
                rprint(
                    f"[gold1][!][/gold1] This is probably a fake [red3]{phishing_toolkit_info}[/red3] website"
                )
            elif phishing_toolkit_name == "Storm-Breaker":
                rprint(
                    f"[gold1][!][/gold1] This malicious website can access your [red3]{phishing_toolkit_info}[/red3] information"
                )
            else:
                rprint(
                    f"[gold1][!][/gold1] The fake domain is: [red3]{phishing_toolkit_info}[/red3]"
                )
            final_verdict["is_phishing_toolkit"] = f"True ({phishing_toolkit_name})"
        else:
            rprint("[spring_green2][+][/spring_green2] Not Found!")
            final_verdict["is_phishing_toolkit"] = "Not Found"

        # Detect GitHub malicious pages
        if phish_detector.suspicious_domain_name.lower().endswith(
            "github.io"
        ) or phish_detector.destination_domain_name.lower().endswith("github.io"):
            rprint(
                f"\n[bright_blue][*][/bright_blue] Checking GitHub page information\n{'-' * 50}"
            )
            username = (
                phish_detector.suspicious_url.split(".github.io")[0]
                .replace("https://", "")
                .replace("http://", "")
                if phish_detector.suspicious_domain_name.lower().endswith("github.io")
                else phish_detector.destination_url.split(".github.io")[0]
                .replace("https://", "")
                .replace("http://", "")
            )
            profile_info = phish_detector.get_github_profile_info(username)
            if profile_info is not None:
                interesting_fields = [
                    "login",
                    "name",
                    "public_repos",
                    "followers",
                    "following",
                    "created_at",
                ]
                for field in interesting_fields:
                    if field == "created_at":
                        rprint(
                            f"[gold1][!][/gold1] {field.capitalize()}: {datetime.fromisoformat(profile_info.get(field, 'N/A')).strftime('%d %b %Y %H:%M:%S')}"
                        )
                    else:
                        rprint(
                            f"[gold1][!][/gold1] {field.capitalize()}: {profile_info.get(field, 'N/A')}"
                        )
            else:
                print(f"[bright_magenta][-][/bright_magenta] {username} not found!")

        # Check SSL/TLS certificate information
        if phish_detector.destination_url.startswith("https://"):
            rprint(
                f"\n[bright_blue][*][/bright_blue] TLS certificate information\n{'-' * 50}"
            )
            certs_info = phish_detector.check_tls_certificate_info()
            if certs_info is not None and len(certs_info):
                for cert in certs_info:
                    if (
                        cert["common_name"] == phish_detector.destination_domain_name
                        or f"*.{phish_detector.destination_domain_name}"
                        in cert["name_value"].split("\n")
                    ):
                        dt_not_before = datetime.fromisoformat(cert["not_before"])
                        dt_not_after = datetime.fromisoformat(cert["not_after"])
                        if cert["issuer_name"].capitalize() == "Gophish":
                            rprint(
                                "[red3]/!\ [/red3]This certificate was generated with [red3]GoPhish[/red3]"
                            )
                        else:
                            rprint(f"- Issuer name: {cert['issuer_name']}")
                        rprint(
                            f"- Not valid before: {dt_not_before.strftime('%d %b %Y %H:%M:%S')}"
                        )
                        rprint(
                            f"- Not valid After: {dt_not_after.strftime('%d %b %Y %H:%M:%S')}"
                        )
                        rprint(
                            f"- Validity (Period in days): {(dt_not_after - dt_not_before).days}"
                        )
                        rprint(f"- Serial Number: {cert['serial_number']}")
                        break
                else:
                    rprint(
                        "[bright_magenta][-][/bright_magenta] Certificate information not found!"
                    )
            else:
                rprint("No certificate found!")

        # Set API Keys
        virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        urlscan_io_api_key = os.getenv("URLSCAN_API_KEY")
        abuse_ip_db_api_key = os.getenv("ABUSEIPDB_API_KEY")
        urlhaus_api_key = os.getenv("URLHAUS_API_KEY")
        if urlscan_io_api_key:
            worker8 = pool.submit(phish_detector.check_urlscan_io, urlscan_io_api_key)
        if virustotal_api_key:
            worker9 = pool.submit(phish_detector.check_virustotal, virustotal_api_key)
        if urlhaus_api_key:
            worker14 = pool.submit(phish_detector.check_urlhaus, urlhaus_api_key)
        if abuse_ip_db_api_key and phish_detector.destination_ip_address != "0.0.0.0":
            worker10 = pool.submit(
                phish_detector.check_abuse_ip_db, abuse_ip_db_api_key
            )

        # Launch workers for Phsihing Army, Red Flag Domains, PhishStats, Wayback Machine and Unfurl,
        worker12 = pool.submit(phish_detector.check_archive_org)
        worker13 = pool.submit(phish_detector.unfurl_url)
        worker15 = pool.submit(phish_detector.check_phishing_army)
        worker16 = pool.submit(phish_detector.check_redflagdomains)
        worker17 = pool.submit(phish_detector.check_phishstats)

        # Retrieve Urlscan report
        rprint(f"\n[bright_blue][*][/bright_blue] Urlscan Report\n{'-' * 50}")
        if urlscan_io_api_key == "" or urlscan_io_api_key is None:
            rprint("[bright_magenta][-][/bright_magenta] Urlscan API key is required!")
            final_verdict["Urlscan"] = "N/A"
        else:
            success, urlscan_analysis_report = worker8.result()
            if success:
                phish_detector.destination_webpage_screenshot = urlscan_analysis_report[
                    "task"
                ]["screenshotURL"]
                verdict_overall = urlscan_analysis_report["verdicts"]["overall"]
                verdict_urlscan = urlscan_analysis_report["verdicts"]["urlscan"]
                if verdict_overall["score"] > 0:
                    rprint(f"Verdict overall\n{'-' * 15}")
                    for (
                        verdict_overall_property,
                        verdict_overall_value,
                    ) in verdict_overall.items():
                        if isinstance(verdict_overall_value, list):
                            rprint(
                                f"[gold1][!][/gold1] {verdict_overall_property}:  {verdict_overall_value[0]}"
                            )
                        else:
                            rprint(
                                f"[gold1][!][/gold1] {verdict_overall_property}:  {verdict_overall_value}"
                            )
                    final_verdict["Urlscan"] = "Found"
                else:
                    rprint(f"Verdict urlscan\n{'-' * 15}")
                    rprint(f"[gold1][!][/gold1] Score: {verdict_urlscan['score']}")
                    rprint(
                        f"[gold1][!][/gold1] Malicious: {verdict_urlscan['malicious']}"
                    )
                    rprint(f"\nVerdict overall\n{'-' * 15}")
                    rprint(f"[gold1][!][/gold1] Score: {verdict_overall['score']}")
                    rprint(
                        f"[gold1][!][/gold1] Malicious: {verdict_overall['malicious']}"
                    )
                    final_verdict["Urlscan"] = "Not Found"
                rprint(
                    "[spring_green2][+][/spring_green2] For more information, check the link below ↓"
                )
                rprint(
                    f"[spring_green2][+][/spring_green2] {urlscan_analysis_report['task']['reportURL']}"
                )
            elif urlscan_analysis_report.status_code == 400:
                rprint(
                    f"[bright_magenta][-][/bright_magenta] {urlscan_analysis_report.json()['message']}"
                )
                final_verdict["Urlscan"] = "N/A"
            elif urlscan_analysis_report.status_code == 429:
                rprint("[gold1][!] urlscan.io rate-limit exceeded![/gold1]")
                rprint(
                    "[gold1][!][/gold1] For more information check here: https://urlscan.io/docs/api/#ratelimit"
                )
                final_verdict["Urlscan"] = "N/A"
            elif urlscan_analysis_report == "urlscan_analysis_report error":
                rprint(
                    "[bright_magenta][-][/bright_magenta] Unexpected HTTP response code [bright_magenta]({urlscan_analysis_report.status_code})[/bright_magenta] returned!"
                )
                rprint(
                    "[gold1][!] Please report this issue at https://github.com/0liverFlow/HookPhish/issues [/gold1]"
                )
                final_verdict["Urlscan"] = "N/A"
            elif urlscan_analysis_report == "response error":
                rprint(
                    f"[bright_magenta][-][/bright_magenta] {urlscan_analysis_report.text}"
                )
                rprint(
                    "[gold1][!][/gold1] Please report the issue at https://github.com/0liverFlow/HookPhish/issues"
                )
                final_verdict["Urlscan"] = "N/A"
            else:
                rprint("[bright_magenta][-][/bright_magenta] Unknown error!")
                rprint(
                    "[gold1][!][/gold1] Please report the issue at https://github.com/0liverFlow/HookPhish/issues"
                )
                final_verdict["Urlscan"] = "N/A"

        # Retrieve VirusTotal report
        rprint(f"\n[bright_blue][*][/bright_blue] VirusTotal Report\n{'-' * 50}")
        if virustotal_api_key == "" or virustotal_api_key is None:
            rprint(
                "[bright_magenta][-][/bright_magenta] VirusTotal API key is required!"
            )
            final_verdict["VirusTotal"] = "N/A"
        else:
            final_verdict["VirusTotal"] = "N/A"
            try:
                success, vt_analysis_report = worker9.result()
            except Exception as e:
                print(f"VirusTotal task failed with this error {e}!")
            if success:
                vt_analysis_report_id = vt_analysis_report["data"]["id"]
                total_number_of_vendors = len(
                    vt_analysis_report["data"]["attributes"][
                        "last_analysis_results"
                    ].keys()
                )
                url_report_details = (
                    "https://www.virustotal.com/gui/url/"
                    + vt_analysis_report_id
                    + "/details"
                )
                url_scan_stats = vt_analysis_report["data"]["attributes"][
                    "last_analysis_stats"
                ]
                malicious_stats = url_scan_stats["malicious"]
                if total_number_of_vendors > 0:
                    rprint(f"Security vendors' analysis\n{'-' * 26}")
                    if malicious_stats <= 0:
                        final_verdict["VirusTotal"] = "Not Found"
                    else:
                        final_verdict["VirusTotal"] = "Found"
                    for category, category_scan_result in url_scan_stats.items():
                        rprint(
                            f"[gold1][!][/gold1] {category.capitalize()}: {category_scan_result}/{total_number_of_vendors}"
                        )
                    # Retrieve other interesting information
                    vt_other_info = {
                        "First submission date": datetime.fromtimestamp(
                            vt_analysis_report["data"]["attributes"][
                                "first_submission_date"
                            ]
                        ),
                        "Last submission date": datetime.fromtimestamp(
                            vt_analysis_report["data"]["attributes"][
                                "last_submission_date"
                            ]
                        ),
                        "Web_server_info": check_dict_keys(
                            vt_analysis_report,
                            [
                                "data",
                                "attributes",
                                "last_http_response_headers",
                                "Server",
                            ],
                        ),
                        "Web page title": check_dict_keys(
                            vt_analysis_report, ["data", "attributes", "title"]
                        ),
                        "Response content sha256": check_dict_keys(
                            vt_analysis_report,
                            ["data", "attributes", "last_http_response_content_sha256"],
                        ),
                        "Threat names": check_dict_keys(
                            vt_analysis_report, ["data", "attributes", "threat_names"]
                        ),
                        "Times submitted": check_dict_keys(
                            vt_analysis_report,
                            ["data", "attributes", "times_submitted"],
                        ),
                    }
                    for key, value in vt_other_info.items():
                        if value:
                            rprint(f"[gold1][!][/gold1] {key}: {value}")
                        else:
                            rprint(f"[gold1][!][/gold1] {key}: N/A")
                    rprint(
                        "[spring_green2][+][/spring_green2] For more information, check the link below ↓"
                    )
                    rprint(f"[spring_green2][+][/spring_green2] {url_report_details}")
            elif vt_analysis_report == "Timeout":
                rprint("[gold1][!][/gold1] Timeout exceeded 60 seconds!")
                pass
            else:
                rprint(
                    f"[bright_magenta][-][/bright_magenta] VirusTotal returned an unexpected status code: {vt_analysis_report}"
                )
                rprint(
                    "[gold1][!][/gold1] Please report the issue at https://github.com/0liverFlow/HookPhish/issues"
                )
                # You can also check VirusTotal documentation if you want to investigate the error: https://docs.virustotal.com/reference/errors

        # Check PhishStats
        rprint(f"\n[bright_blue][*][/bright_blue] PhishStats Report\n{'-' * 50}")
        phish_stats_results = worker17.result()
        if phish_stats_results is not None:
            phish_stats_info = {
                "Threat score": f"{phish_stats_results['score']}/10"
                if phish_stats_results["score"] is not None
                else "N/A",
                "Webpage Title": phish_stats_results["title"],
                "Web server info": phish_stats_results["http_server"],
                "Web server OS": phish_stats_results["os"],
                "Domain registered N days ago": phish_stats_results[
                    "domain_registered_n_days_ago"
                ],
                "First seen": datetime.fromisoformat(
                    phish_stats_results["date"].split(".000Z")[0]
                ).strftime("%d %b %Y %H:%M:%S UTC"),
                "ISP": phish_stats_results["isp"],
                "ASN": phish_stats_results["asn"],
                "BGP": phish_stats_results["bgp"],
                "HTTP code": phish_stats_results["http_code"],
                "Open ports": phish_stats_results["ports"],
            }

            for key, value in phish_stats_info.items():
                if value is not None:
                    rprint(f"[gold1][!][/gold1] {key}: {value}")

            phish_stats_abuse_contacts = phish_stats_results["abuse_contact"]
            rprint(
                "[spring_green2][+][/spring_green2] For more information, check the link below ↓"
            )
            rprint(
                f"[spring_green2][+][/spring_green2] https://phishstats.info/search/{phish_stats_results['hash']}"
            )
            if phish_stats_results.get("date_update") and args.verbose:
                rprint(
                    f"Last update: {datetime.fromisoformat(phish_stats_results['date_update'].split('.000Z')[0]).strftime('%d %b %Y %H:%M:%S UTC')}"
                )
            final_verdict["PhishStats"] = "Found"
        else:
            rprint("[spring_green2][+][/spring_green2] Not Found!")
            phish_stats_abuse_contacts = None
            final_verdict["PhishStats"] = "Not Found"

        # Check URLhaus for malicious URLs used for malware distribution
        rprint(f"\n[bright_blue][*][/bright_blue] URLhaus Report\n{'-' * 50}")
        if urlhaus_api_key == "" or urlhaus_api_key is None:
            rprint("[bright_magenta][-][/bright_magenta] URLhaus API key is required!")
            final_verdict["Urlhaus"] = "N/A"
        else:
            result = worker14.result()
            if result is not None:
                query_status = result["query_status"]
                if query_status == "ok":
                    urlhaus_reference = result["urlhaus_reference"]
                    threat = result["threat"].capitalize()
                    added_date = result["date_added"]
                    url_status = result["url_status"].capitalize()
                    rprint("[red3]/!\ The URL is malicious![/red3]")
                    rprint(f"[gold1][!][/gold1] URL status: {url_status}")
                    rprint(f"[gold1][!][/gold1] Threat: {threat}")
                    if args.verbose:
                        rprint(f"[gold1][!][/gold1] Date added: {added_date}")
                    rprint(
                        "[spring_green2][+][/spring_green2] For more information, check the link below ↓"
                    )
                    rprint(f"[spring_green2][+][/spring_green2] {urlhaus_reference}")
                    final_verdict["Urlhaus"] = "Found"
                elif query_status == "no_results":
                    rprint("[spring_green2][+][/spring_green2] Not Found!")
                    final_verdict["Urlhaus"] = "Not Found"
                elif query_status == "invalid_url":
                    rprint("[gold1][!][/gold1] The URL provided is not a valid URL.")
                    final_verdict["Urlhaus"] = "Not Found"
                elif query_status == "http_post_expected":
                    rprint("[gold1][!][/gold1] The HTTP request was not HTTP POST")
                    final_verdict["Urlhaus"] = "Not Found"
                else:
                    rprint("N/A")
                    final_verdict["Urlhaus"] = "N/A"
            else:
                rprint("N/A")
                final_verdict["Urlhaus"] = "N/A"
                    
        # Check Phishing Army Database
        rprint(f"\n[bright_blue][*][/bright_blue] Phishing Army Report\n{'-' * 50}")
        result, db_last_update = worker15.result()
        if result:
            rprint("[red3]/!\ [/red3][red3]The domain is malicious![/red3]")
            if args.verbose:
                rprint(f"Last update: {db_last_update}")
            final_verdict["Phishing Army"] = "Found"
        else:
            rprint("[spring_green2][+][/spring_green2] Not Found!")
            if args.verbose:
                rprint(f"Last update: {db_last_update}")
            final_verdict["Phishing Army"] = "Not Found"

        # Check Red Flag Domains
        rprint(
            f"\n[bright_blue][*][/bright_blue] Checking Red Flag Domains\n{'-' * 50}"
        )
        result, db_last_update = worker16.result()
        if result:
            rprint("[red3]/!\ [/red3][red3]The domain is malicious![/red3]")
            if args.verbose:
                rprint(f"Last update: {db_last_update}")
            final_verdict["Red Flag Domains"] = "Found"
        else:
            rprint("[spring_green2][+][/spring_green2] Not Found!")
            if args.verbose:
                rprint(f"Last update: {db_last_update}")
            final_verdict["Red Flag Domains"] = "Not Found"

        # Retrieve AbuseIPDB report
        rprint(f"\n[bright_blue][*][/bright_blue] AbuseIPDB Report\n{'-' * 50}")
        if abuse_ip_db_api_key == "" or abuse_ip_db_api_key is None:
            rprint(
                "[bright_magenta][-][/bright_magenta] AbuseIPDB API key is required!"
            )
            final_verdict["AbuseIPDB"] = "N/A"
        elif phish_detector.destination_ip_address == "0.0.0.0":
            rprint(
                f"[bright_magenta][-][/bright_magenta] Unable to resolve {phish_detector.destination_domain_name.replace('.', '[.]')}"
            )
            final_verdict["AbuseIPDB"] = "N/A"
        else:
            success, abuse_ip_db_analysis_report = worker10.result()
            if success:
                ip_reputation = abuse_ip_db_analysis_report["data"]
                if ip_reputation["lastReportedAt"] is not None:
                    last_report_date, last_report_time = (
                        datetime.fromisoformat(ip_reputation["lastReportedAt"]).date(),
                        datetime.fromisoformat(ip_reputation["lastReportedAt"]).time(),
                    )
                else:
                    last_report_date = "N/A"
                if ip_reputation["totalReports"]:
                    rprint(
                        f"[red3]/!\ [/red3]{phish_detector.destination_ip_address} was found in our database!"
                    )
                    rprint(
                        f"[gold1][!][/gold1] This IP address was reported [gold1]{ip_reputation['totalReports']}[/gold1] times by [gold1]{ip_reputation['numDistinctUsers']}[/gold1] distinct users."
                    )
                    rprint(f"[gold1][!][/gold1] ISP: {ip_reputation['isp']}")
                    rprint(
                        f"[gold1][!][/gold1] Usage Type: {ip_reputation['usageType']}"
                    )
                    rprint(
                        f"[gold1][!][/gold1] Confidence of Abuse is [gold1]{ip_reputation['abuseConfidenceScore']}%[/gold1]"
                    )
                    if last_report_date != "N/A":
                        rprint(
                            f"[gold1][!][/gold1] This IP address was last reported on {last_report_date} at {last_report_time}"
                        )
                    else:
                        rprint("[gold1][!][/gold1] Last reported date: N/A")
                    rprint(
                        "[spring_green2][+][/spring_green2] For more information, check the link below ↓"
                    )
                    rprint(
                        f"[spring_green2][+][/spring_green2] https://www.abuseipdb.com/check/{phish_detector.destination_ip_address}"
                    )
                    final_verdict["AbuseIPDB"] = "Found"
                else:
                    rprint("[spring_green2][+][/spring_green2] Not Found!")
                    final_verdict["AbuseIPDB"] = "Not Found"
            elif abuse_ip_db_analysis_report.status_code == 401:
                rprint(
                    f"[bright_magenta][-][/bright_magenta] Status code: 401\nError message: {abuse_ip_db_analysis_report.json()['errors'][0]['detail']}"
                )
                final_verdict["AbuseIPDB"] = "N/A"
            else:
                rprint(
                    f"[bright_magenta][-][/bright_magenta] Status code: {abuse_ip_db_analysis_report.status_code}\nError message: {abuse_ip_db_analysis_report.text}"
                )
                rprint(
                    "[gold1][!][/gold1] Please report this issue at https://github.com/0liverFlow/HookPhish/issues"
                )
                final_verdict["AbuseIPDB"] = "N/A"

        # Check Archive.org (Wayback Machine)
        rprint(f"\n[bright_blue][*][/bright_blue] Checking Wayback Machine\n{'-' * 50}")
        try:
            wayback_machine_result = worker12.result()
            if wayback_machine_result is not None:
                rprint("[gold1][!][/gold1] URL found in Wayback Machine!")
                rprint(
                    "[gold1][!][/gold1] For more information, check the link below ↓"
                )
                rprint(f"[spring_green2][+][/spring_green2] {wayback_machine_result}")
                final_verdict["Wayback Machine"] = "Found"
            else:
                rprint("Not Found!")
                final_verdict["Wayback Machine"] = "Not Found"
        except Error:
            rprint("N/A")
            final_verdict["Wayback Machine"] = "N/A"
            pass

        # Unfurl URL
        rprint(f"\n[bright_blue][*][/bright_blue] Unfurl URL\n{'-' * 50}")
        unfurl = worker13.result()
        rprint(
            "[gold1][!][/gold1] To gain further insights about the URL structure, check the link below ↓"
        )
        rprint(f"[spring_green2][+][/spring_green2] {unfurl}")

        # Final Verdict (This is a summary of the all the scan results obtained)
        rprint(f"\n[bright_blue][*][/bright_blue] Final Verdict\n{'-' * 50}")
        table = Table(
            header_style="bold",
            title_style="bold",
            title_justify="center",
            show_lines=True,
        )
        table.add_column("Check", justify="center", min_width=35)
        table.add_column("Verdict", justify="center", min_width=35)
        verdict_keys_rank = [
            "VirusTotal",
            "Urlscan",
            "Google Safe Browsing",
            "PhishStats",
            "Urlhaus",
            "Red Flag Domains",
            "Phishing Army",
            "AbuseIPDB",
            "Wayback Machine",
            "is_phishing_toolkit",
            "is_url_shortened",
            "is_url_masked",
            "is_url_obfuscated",
            "is_ip_tracker_domain",
            "is_tunneling_domain",
        ]
        for check in verdict_keys_rank:
            if final_verdict[check] == "Found" or "True" in final_verdict[check]:
                verdict_color = f"[red3]{final_verdict[check]}[/red3]"
            elif final_verdict[check] == "Not Found" or final_verdict[check] == "False":
                verdict_color = f"[spring_green2]{final_verdict[check]}[/spring_green2]"
            elif final_verdict[check] == "N/A":
                verdict_color = f"{final_verdict[check]}"
            else:
                verdict_color = f"[gold1]{final_verdict[check]}[/gold1]"
            match check:
                case "is_phishing_toolkit":
                    check = "Phishing Toolkit Detected?"
                case "is_url_shortened":
                    check = "Is URL Shortened?"
                case "is_url_masked":
                    check = "Is URL Masked?"
                case "is_url_obfuscated":
                    check = "Is URL Obfuscated?"
                case "is_ip_tracker_domain":
                    check = "IP Tracker Detected?"
                case "is_tunneling_domain":
                    check = "Tunneling Domain Detected?"
            table.add_row(check, verdict_color)
        rprint(table)

        verdict_phishing_url = False
        # verdict_found represent the number of times where the URL was flagged as malicious
        verdict_found = list(final_verdict.values()).count("Found")

        # Heuristics used to determine whether a URL is malicious
        if (
            final_verdict["VirusTotal"] == "Found"
            and final_verdict["Urlscan"] == "Found"
        ):
            rprint(
                f"[red3]/!\ {defang_url(phish_detector.suspicious_url)} is malicious![/red3]"
            )
            verdict_phishing_url = True
        elif (
            final_verdict["VirusTotal"] == "Found"
            and final_verdict["Google Safe Browsing"] == "Found"
        ) or (
            final_verdict["Urlscan"] == "Found"
            and final_verdict["Google Safe Browsing"] == "Found"
        ):
            rprint(
                f"[red3]/!\ {defang_url(phish_detector.suspicious_url)} is malicious![/red3]"
            )
            verdict_phishing_url = True
        elif (
            final_verdict["VirusTotal"] == "Found"
            and final_verdict["PhishStats"] == "Found"
        ) or (
            final_verdict["Urlscan"] == "Found"
            and final_verdict["PhishStats"] == "Found"
        ):
            rprint(
                f"[red3]/!\ {defang_url(phish_detector.suspicious_url)} is malicious![/red3]"
            )
            verdict_phishing_url = True
        elif (
            final_verdict["Phishing Army"] == "Found"
            and final_verdict["PhishStats"] == "Found"
        ) or (
            final_verdict["Phishing Army"] == "Found"
            and final_verdict["Google Safe Browsing"] == "Found"
        ):
            rprint(
                f"[red3]/!\ {defang_url(phish_detector.suspicious_url)} is malicious![/red3]"
            )
            verdict_phishing_url = True
        elif (
            final_verdict["Google Safe Browsing"] == "Found"
            and final_verdict["PhishStats"] == "Found"
        ) or (
            final_verdict["PhishStats"] == "Found"
            and final_verdict["AbuseIPDB"] == "Found"
        ):
            rprint(
                f"[red3]/!\ {defang_url(phish_detector.suspicious_url)} is malicious![/red3]"
            )
            verdict_phishing_url = True
        elif final_verdict["is_phishing_toolkit"] == "Found":
            rprint(
                f"[red3]/!\ {defang_url(phish_detector.suspicious_url)} is malicious![/red3]"
            )
            verdict_phishing_url = True
        elif verdict_found >= 3:
            rprint(
                f"[red3]/!\ {defang_url(phish_detector.suspicious_url)} is malicious![/red3]"
            )
            verdict_phishing_url = True
        elif (
            final_verdict["VirusTotal"] == "Found"
            or final_verdict["Urlscan"] == "Found"
            or final_verdict["Google Safe Browsing"] == "Found"
            or final_verdict["Urlhaus"] == "Found"
            or final_verdict["Red Flag Domains"] == "Found"
            or final_verdict["PhishStats"] == "Found"
            or final_verdict["is_phishing_toolkit"] != "Not Found"
            or final_verdict["Phishing Army"] == "Found"
            or final_verdict["AbuseIPDB"] == "Found"
        ):
            rprint(
                f"[gold1][!][/gold1] {defang_url(phish_detector.suspicious_url)} is [red3]potentially malicious![/red3]"
            )
        else:
            rprint(
                f"[spring_green2][+][/spring_green2] {defang_url(phish_detector.suspicious_url)} was not detected as malicious!"
            )
            rprint(
                f"\n[bright_blue][*][/bright_blue] For additional guidance on how to detect phishing websites, refer to the resources below ↓\n{'-' * 94}"
            )
            rprint(
                "[spring_green2][+][/spring_green2] https://www.nist.gov/itl/smallbusinesscyber/guidance-topic/phishing (EN)"
            )
            rprint(
                "[spring_green2][+][/spring_green2] https://www.cybermalveillance.gouv.fr/tous-nos-contenus/fiches-reflexes/hameconnage-phishing (FR)"
            )
            rprint(
                "[spring_green2][+][/spring_green2] https://www.incibe.es/index.php/ciudadania/tematicas/ingenieria-social-fraudes-online/phishing (ES)"
            )

        # Real-time Screenshot
        rprint(f"\n[bright_blue][*][/bright_blue] Real-time Screenshot\n{'-' * 50}")
        progress.stop()
        success, webpage_screenshot = phish_detector.get_webpage_screenshot()
        if success:
            user_choice = input(
                f"Would you like to see a real-time screenshot of {defang_url(phish_detector.suspicious_url)} [Yes/no]: "
            )
            if user_choice.lower() in ["", "y", "yes", "yep", "yeah", "yay"]:
                with Image.open(webpage_screenshot.raw) as img:
                    try:
                        img.show()
                    except BaseException:
                        rprint(
                            "[red3][-] An error occured: screenshot is unavailable![/red3]"
                        )
        else:
            rprint("[red3][-] No screenshot available![/red3]")

        # Report suspicious URL to phishing report websites
        if verdict_phishing_url is True:
            rprint(f"\n[bright_blue][*][/bright_blue] Report Phishing URL\n{'-' * 50}")
            rprint(
                "[spring_green2][+][/spring_green2] Contribute to make the Internet a safer place by reporting the URL at one of the websites below ↓"
            )
            rprint(
                "[spring_green2][+][/spring_green2] https://phishing-initiative.eu/contrib/"
            )
            rprint(
                "[spring_green2][+][/spring_green2] https://safebrowsing.google.com/safebrowsing/report_phish/"
            )
            rprint(
                "[spring_green2][+][/spring_green2] https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest"
            )
        if phish_stats_abuse_contacts is not None:
            rprint(
                f"[spring_green2][+][/spring_green2] Do not also hesitate to report the URL at [spring_green2]{phish_stats_abuse_contacts}[/spring_green2]"
            )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
