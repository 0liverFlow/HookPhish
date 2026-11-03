def defang_url(url):
    """
    This function will defang the URL submitted by the user and returns it.
    It will replace http with hxxp, . with [.] and :// with [://]
    :param url: This the URL that will be defanged
    """
    return url.replace("https", "hxxps").replace("http", "hxxp").replace(".", "[.]").replace("://", "[://]")
