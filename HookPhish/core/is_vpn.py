import ipaddress
import requests

from HookPhish.core.user_agents import get_user_agent

def is_vpn(ip_address):
    """
    This function checks if an IP address is a VPN IP address.
    The VPN list used below doesn't list all VPN IP addresses, but you can find the vast majority of them.

    :param ip_address: The IP address to be checked.
    """
    response = requests.get("https://raw.githubusercontent.com/X4BNet/lists_vpn/refs/heads/main/output/vpn/ipv4.txt", headers={'User-Agent': get_user_agent()})
    if response.status_code == 200:
        output_vpn_ip_cidr = response.text.splitlines()
        output_vpn_ipv4 = []
        for ip_cidr in output_vpn_ip_cidr:
            network = ipaddress.ip_network(ip_cidr, strict=False)
            for ipv4 in network.hosts():
                output_vpn_ipv4.append(str(ipv4))
        return True if ip_address in output_vpn_ipv4 else False
    else:
        return "N/A"
