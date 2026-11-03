from HookPhish.core.user_agents import get_user_agent

def get_http_headers(referer) :
    headers = {
        'Accept': '*/*',
        'Accept-Language': 'en-US;q=0.9,en;q=0.8',
        'User-Agent': get_user_agent(),
        'Referer': referer,
        'DNT': '1',
        'Upgrade-insecure-requests': '1'
    }
    return headers    
