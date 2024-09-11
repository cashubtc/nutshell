def sanitize_url(url: str) -> str:
    # extract host from url and lower case it, remove trailing slash from url
    protocol = url.split("://")[0]
    host = url.split("://")[1].split("/")[0].lower()
    path = (
        url.split("://")[1].split("/", 1)[1].rstrip("/")
        if "/" in url.split("://")[1]
        else ""
    )
    return f"{protocol}://{host}{'/' + path if path else ''}"
