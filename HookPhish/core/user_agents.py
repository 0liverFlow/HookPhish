import os
import random

from HookPhish.core.config import BASE_DIR

def get_user_agent():
    # Generate a random user-agent
    with open(os.path.join(BASE_DIR, "../data", "user_agents.txt")) as f:
        user_agents = f.readlines()
        return random.choice(user_agents)[:-1]
