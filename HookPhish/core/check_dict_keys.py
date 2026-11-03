def check_dict_keys(dictionary, dict_keys, default="N/A"):
  # This function is used to reduce Key Error exceptions
    d = dictionary
    for key in dict_keys[:-1]:
        if isinstance(d, dict):
            d = d.get(key, {})
        else:
            d = {}
            break
    if isinstance(d, dict):
        return d.get(dict_keys[-1], default)
    return default
