import base64


def load_macaroon(macaroon: str) -> str:
    """Returns hex version of a macaroon encoded in base64 or the file path.

    :param macaroon: Macaroon encoded in base64 or file path.
    :type macaroon: str
    :return: Hex version of macaroon.
    :rtype: str
    """

    # if the macaroon is a file path, load it and return hex version
    if macaroon.split(".")[-1] == "macaroon":
        try:
            with open(macaroon, "rb") as f:
                macaroon_bytes = f.read()
                return macaroon_bytes.hex()
        except FileNotFoundError:
            raise Exception(f"Macaroon file not found: {macaroon}")
    else:
        # if macaroon is a provided string
        # check if it is hex, if so, return
        try:
            bytes.fromhex(macaroon)
            return macaroon
        except ValueError:
            pass
        # convert the bas64 macaroon to hex
        try:
            macaroon = base64.b64decode(macaroon).hex()
        except Exception:
            pass
    return macaroon
