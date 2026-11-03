import requests

from HookPhish.core.user_agents import get_user_agent

def is_tor_node(ip_address):
  """
  This function checks whether an IP address is related to a TOR node (guard, middle or exit node).

  :param ip_address: The IP address to be checked
  """
  response = requests.get("https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main/Lists/TOR/tor_nodes_history.json", headers={'User-Agent': get_user_agent()})
  if response.status_code == 200 :
      tor_nodes_info = response.json()
      tor_nodes_ips = list(tor_nodes_info['ips'].keys())
      return True if ip_address in tor_nodes_ips else False
  else:
      return "N/A"
