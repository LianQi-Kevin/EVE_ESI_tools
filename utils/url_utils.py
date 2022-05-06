import urllib
import requests
import sys
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTError, JWTClaimsError

'''
publicData  公开数据
esi-location.read_location.v1   读取位置 
esi-skills.read_skillqueue.v1   读取技能队列
esi-wallet.read_character_wallet.v1 读取角色钱包
esi-bookmarks.read_character_bookmarks.v1   读取书签
# esi-ui.open_window.v1   打开窗口
# esi-ui.write_waypoint.v1    设置航点
esi-characters.read_loyalty.v1 读取LP
esi-location.read_online.v1    读取在线状态
'''


def validate_eve_jwt(jwt_token):
    """Validate a JWT token retrieved from the EVE SSO.

    Args:
        jwt_token: A JWT token originating from the EVE SSO
    Returns
        dict: The contents of the validated JWT token if there are no
              validation errors
    """

    jwk_set_url = "https://login.eveonline.com/oauth/jwks"

    res = requests.get(jwk_set_url)
    res.raise_for_status()

    data = res.json()

    try:
        jwk_sets = data["keys"]
    except KeyError as e:
        print("Something went wrong when retrieving the JWK set. The returned "
              "payload did not have the expected key {}. \nPayload returned "
              "from the SSO looks like: {}".format(e, data))
        sys.exit(1)

    jwk_set = next((item for item in jwk_sets if item["alg"] == "RS256"))

    try:
        return jwt.decode(
            jwt_token,
            jwk_set,
            algorithms=jwk_set["alg"],
            issuer="login.eveonline.com"
        )
    except ExpiredSignatureError:
        print("The JWT token has expired: {}")
        sys.exit(1)
    except JWTError as e:
        print("The JWT signature was invalid: {}").format(str(e))
        sys.exit(1)
    except JWTClaimsError as e:
        try:
            return jwt.decode(
                jwt_token,
                jwk_set,
                algorithms=jwk_set["alg"],
                issuer="https://login.eveonline.com"
            )
        except JWTClaimsError as e:
            print("The issuer claim was not from login.eveonline.com or "
                  "https://login.eveonline.com: {}".format(str(e)))
            sys.exit(1)


def print_auth_url(client_id, code_challenge=None):
    """Prints the URL to redirect users to.

    Args:
        client_id: The client ID of an EVE SSO application
        code_challenge: A PKCE code challenge
    """

    base_auth_url = "https://login.eveonline.com/v2/oauth/authorize/"
    params = {
        "response_type": "code",
        "redirect_uri": "https://localhost/callback/",
        "client_id": client_id,
        "scope": "publicData "
                 "esi-location.read_location.v1 "
                 "esi-skills.read_skillqueue.v1 "
                 "esi-wallet.read_character_wallet.v1 "
                 "esi-bookmarks.read_character_bookmarks.v1 "
                 "esi-ui.open_window.v1 "
                 "esi-ui.write_waypoint.v1 "
                 "esi-characters.read_loyalty.v1 "
                 "esi-location.read_online.v1",
        # "scope": "esi-characters.read_loyalty.v1",
        "state": "unique-state"
    }

    if code_challenge:
        # 使用code_challenge中的值和键更新params
        params.update({
            "code_challenge": code_challenge,
            "code_challenge_method": "S256"
        })

    string_params = urllib.parse.urlencode(params)
    full_auth_url = "{}?{}".format(base_auth_url, string_params)

    return full_auth_url


def send_token_request(form_values, add_headers={}):
    """Sends a request for an authorization token to the EVE SSO.

    Args:
        form_values: A dict containing the form encoded values that should be
                     sent with the request
        add_headers: A dict containing additional headers to send
    Returns:
        requests.Response: A requests Response object
    """

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "login.eveonline.com",
        # "grant_type":"refresh_token",
        # "refresh_token":"9L0jHN/YGE+6uNzsYL7qyQ==",
        # "client_id": "68dfba8597464c02928ca96793b7690f",
    }

    if add_headers:
        # 使用add_headers中的值和键更新headers
        headers.update(add_headers)

    res = requests.post(
        "https://login.eveonline.com/v2/oauth/token",
        data=form_values,
        headers=headers,
    )

    # print("Request sent to URL {} with headers {} and form values: "
    #       "{}\n".format(res.url, headers, form_values))
    res.raise_for_status()
    return res


def send_token_request_bk(form_values, add_headers={}):
    """Sends a request for an authorization token to the EVE SSO.

    Args:
        form_values: A dict containing the form encoded values that should be
                     sent with the request
        add_headers: A dict containing additional headers to send
    Returns:
        requests.Response: A requests Response object
    """

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "login.eveonline.com",
    }

    if add_headers:
        headers.update(add_headers)

    res = requests.post(
        "https://login.eveonline.com/v2/oauth/token",
        data=form_values,
        headers=headers,
    )

    print("Request sent to URL {} with headers {} and form values: "
          "{}\n".format(res.url, headers, form_values))
    res.raise_for_status()

    return res


def handle_sso_token_response(sso_response):
    """Handles the authorization code response from the EVE SSO.

    Args:
        sso_response: A requests Response object gotten by calling the EVE
                      SSO /v2/oauth/token endpoint
    """

    if sso_response.status_code == 200:
        data = sso_response.json()
        access_token = data["access_token"]

        print("\nVerifying access token JWT...")

        jwt = validate_eve_jwt(access_token)
        character_id = jwt["sub"].split(":")[2]
        character_name = jwt["name"]

        # location_path = ("https://esi.evetech.net/latest/characters/{}/"
        #                   "location/".format(character_id))
        LP_path = ("https://esi.evetech.net/latest/characters/{}/loyalty/points/".format(character_id))

        # print("\nSuccess! Here is the payload received from the EVE SSO: {}"
        #       "\nYou can use the access_token to make an authenticated "
        #       "request to {}".format(data, blueprint_path))

        # input("\nPress any key to have this program make the request for you:")

        headers = {
            "Authorization": "Bearer {}".format(access_token)
        }

        res = requests.get(LP_path, headers=headers)
        # with open("res.json","w") as f:
        #     f.write(str(res))
        #     f.close()
        print("\nMade request to {} with headers: "
              "{}".format(LP_path, res.request.headers))
        res.raise_for_status()

        data = res.json()
        with open("output_data/final_data.json", "w") as f:
            f.write(str(data))
        # print("\n{} has {} blueprints".format(character_name, len(data)))
        print(character_name, data)
    else:
        print("\nSomething went wrong! Re read the comment at the top of this "
              "file and make sure you completed all the prerequisites then "
              "try again. Here's some debug info to help you out:")
        print("\nSent request with url: {} \nbody: {} \nheaders: {}".format(
            sso_response.request.url,
            sso_response.request.body,
            sso_response.request.headers
        ))
        print("\nSSO response code is: {}".format(sso_response.status_code))
        print("\nSSO response JSON is: {}".format(sso_response.json()))
