import minecraft.authentication
import requests
import os.path
from typing import Optional
import uuid
import urllib.parse
import json
client_id = "b0bf91e4-17f7-4de8-af20-92b987662a96"
client_secret = "U3I7Q~pKr7RMkLCbEfVnOWmjFlJH2JKsWC1FI"

redirect_uri = "http://localhost:65529"

client_token_file = "mc_client_token.txt"
save_file = "msft_refresh_token.txt"


url_base = "https://login.live.com/oauth20_{}.srf"
AUTH_SERVER = "https://authserver.mojang.com"
SESSION_SERVER = "https://sessionserver.mojang.com/session/minecraft"
# Need this content type, or authserver will complain
CONTENT_TYPE = "application/json"
HEADERS = {"content-type": CONTENT_TYPE}
AGENT_NAME = "Minecraft"
AGENT_VERSION = 1


def authenticate_with_msft() -> (str, str):
    auth_url_query = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,  # just needs to be an inaccessible url so the user can yoink the token
    }
    auth_url = f"{url_base.format ('authorize')}?{urllib.parse.urlencode (auth_url_query)}&scope=XboxLive.signin%20offline_access"
    print(auth_url)
    auth_code = input("Enter the code param from the url: ")
    print(auth_code)
    return _make_msft_token_resp(code=auth_code, grant_type="authorization_code")


def reauthenticate_with_msft(*, refresh_token: str) -> (str, str):
    return _make_msft_token_resp(refresh_token=refresh_token, grant_type="refresh_token")


def _get_from_json(resp: requests.Response, *items: str): return map(resp.json().__getitem__, items)


def _check_resp(resp: requests.Response):
    try:
        resp.raise_for_status()
    except:
        print(resp.text)
        raise


def _json_req(url: str, data: Optional[dict] = None, *, auth_token: Optional[str] = None) -> dict:
    req_headers = {"Accept": "application/json"}
    if auth_token is not None:
        req_headers["Authorization"] = f"Bearer {auth_token}"
    function_call_kwargs = {}
    meth = "post" if data is not None else "get"
    if data is not None:
        req_headers["Content-Type"] = "application/json"
        function_call_kwargs["data"] = json.dumps(data).encode()
    function_call_kwargs["headers"] = req_headers
    resp = getattr(requests, meth)(url, **function_call_kwargs)
    _check_resp(resp)
    return resp.json()


def _make_msft_token_resp(*, code: Optional[str] = None, refresh_token: Optional[str] = None, grant_type: str) -> (str, str):
    pass
    token_url_query = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": grant_type,
        "redirect_uri": redirect_uri
    }
    if code is not None:
        token_url_query["code"] = code
    elif refresh_token is not None:
        token_url_query["refresh_token"] = refresh_token
    else:
        raise Exception("need either code or refresh_token")
    token_resp = requests.post(f"{url_base.format ('token')}", headers={
                               "Content-Type": "application/x-www-form-urlencoded"}, data=urllib.parse.urlencode(token_url_query).encode())
    _check_resp(token_resp)
    return _get_from_json(token_resp, "access_token", "refresh_token")


def get_mc_auth_token(*, force_use_new_msft_account: bool = False, force_regenerate_mc_client_token: bool = False) -> minecraft.authentication.AuthenticationToken:
    if (not os.path.exists(save_file)) or force_use_new_msft_account:
        msft_access_token, msft_refresh_token = authenticate_with_msft()
        open(save_file, "w+").write(msft_refresh_token)
    else:
        msft_refresh_token = open(save_file, "r").read()
        msft_access_token, msft_refresh_token = reauthenticate_with_msft(
            refresh_token=msft_refresh_token)
        open(save_file, "w+").write(msft_refresh_token)

    xbl_req_json = {
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": f"d={msft_access_token}"
        },
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT"
    }
    xbl_resp = _json_req("https://user.auth.xboxlive.com/user/authenticate", xbl_req_json)
    xbl_token: str = xbl_resp["Token"]
    xbl_userhash: str = xbl_resp["DisplayClaims"]["xui"][0]["uhs"]

    xsts_req_json = {
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [
                xbl_token
            ]
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT"
    }
    xsts_resp = _json_req("https://xsts.auth.xboxlive.com/xsts/authorize", xsts_req_json)
    xsts_token: str = xsts_resp["Token"]
    xsts_userhash: str = xsts_resp["DisplayClaims"]["xui"][0]["uhs"]
    assert xbl_userhash == xsts_userhash

    mc_auth_req_json = {"identityToken": f"XBL3.0 x={xbl_userhash};{xsts_token}"}
    mc_auth_resp = _json_req(
        "https://api.minecraftservices.com/authentication/login_with_xbox", mc_auth_req_json)
    mc_access_token: str = mc_auth_resp["access_token"]

    mc_ownership_check_resp = _json_req(
        "https://api.minecraftservices.com/entitlements/mcstore", auth_token=mc_access_token)
    if not any(map(lambda item_name: item_name.endswith("minecraft"), map(
        lambda item: item["name"], mc_ownership_check_resp["items"]))): raise Exception("account does not own minecraft!")

    mc_profile = _json_req(
        "https://api.minecraftservices.com/minecraft/profile", auth_token=mc_access_token)
    mc_uuid = mc_profile["id"]
    mc_username = mc_profile["name"]

    if (not os.path.exists(client_token_file)) or force_regenerate_mc_client_token:
        client_token = uuid.uuid4().hex
        open(client_token_file, "w+").write(client_token)
    else:
        client_token = open(client_token_file, "r").read()

    auth_token = minecraft.authentication.AuthenticationToken(
        username=mc_username, access_token=mc_access_token, client_token=client_token)
    auth_token.profile = minecraft.authentication.Profile(id_=mc_uuid, name=mc_username)

    return auth_token


def join(server_id_hash, json_resp):
    res = sendrequest(SESSION_SERVER, "join",
                      {"accessToken": json_resp.access_token,
                       "selectedProfile": json_resp.profile.id_,
                       "serverId": server_id_hash})

    if res.status_code != 204:
        print("Authentication Fail!")
        raise ValueError

    return True


def sendrequest(server, endpoint, data):
    res = requests.post(server + "/" + endpoint, data=json.dumps(data),
                        headers=HEADERS)
    return res


if __name__ == "__main__":
    print(get_mc_auth_token())
