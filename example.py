import base64
import codecs
import hashlib
import json
import os
import secrets
import time
import urllib
import webbrowser
from datetime import datetime
from urllib import parse

import requests
import yaml
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTError, JWTClaimsError


# 给钱数添加','
def add_(num):
    num_L = str(num).split(".")
    ZSW = num_L[0]
    DD = ZSW[::-1]
    OL = []
    for i in range(len(DD)):
        OL.append(DD[i])
        if i in [2, 5, 8, 11, 14, 17, 20, 23, 26]:
            OL.append(",")
    OL = OL[::-1]
    OL.append(".")
    OL.append(num_L[1])
    OL = "".join(OL)
    if OL[0] == ",":
        OL = OL[1:]
    return OL


# 获取可刷新令牌
def get_refresh_token(client_id, scope, token_path):
    # 尝试创建数据输出文件夹
    try:
        os.mkdir(token_path)
    except:
        pass
    # 生成PKCE代码
    random = base64.urlsafe_b64encode(secrets.token_bytes(32))
    m = hashlib.sha256()
    m.update(random)
    d = m.digest()
    code_challenge = base64.urlsafe_b64encode(d).decode().replace("=", "")

    # 组装验证页面
    base_auth_url = "https://login.eveonline.com/v2/oauth/authorize/"
    params = {
        "response_type": "code",
        "redirect_uri": "https://localhost/callback/",
        "client_id": client_id,
        "scope": scope,
        "state": "unique-state",
        "code_challenge_method": "S256",
        "code_challenge": code_challenge}
    string_params = urllib.parse.urlencode(params)
    full_auth_url = "{}?{}".format(base_auth_url, string_params)

    # 验证页面并提取code参数
    webbrowser.open_new(full_auth_url)
    current_url = input("\n请复制验证之后以'https://localhost/callback/'开头的完整网址url至此: ")
    # url_result = parse.urlparse(browser.current_url)
    url_result = parse.urlparse(current_url)
    query_dict = parse.parse_qs(url_result.query)
    print("\ncode: " + query_dict["code"][0])

    # 创建POST获取访问令牌和可刷新令牌
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "login.eveonline.com"}
    form_values = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": query_dict["code"][0],
        "code_verifier": random}
    res = requests.post(
        "https://login.eveonline.com/v2/oauth/token",
        data=form_values,
        headers=headers)
    res.raise_for_status()
    # 验证status_code值并写入文件
    if res.status_code == 200:
        data = res.json()
        print("\n验证访问令牌JWT...")
        JWT = validate_eve_jwt(data["access_token"])
        character_name = JWT["name"].replace(" ", "_")
        verify_dict = {"res": data, "jwt": JWT}
        # 写入token文件
        path = os.path.join(token_path, character_name + ".json")
        with open(path, "w") as f:
            json.dump(verify_dict, f, indent=2, sort_keys=True, ensure_ascii=False)  # 写为多行
            f.close()
        return verify_dict, path
    else:
        print("status_code is not 200, ERROR")
        exit()


# 根据可刷新令牌获取访问令牌,并刷新存储文件
def refresh_token_post(client_id, scope, token_path, name):
    # 读取存储的json文件
    path = os.path.join(token_path, name.replace(" ", "_") + ".json")
    # print(path)
    with open(path, "r") as f:
        verify_dict = json.load(f)
        refresh_token = verify_dict["res"]["refresh_token"]
        f.close()
    # 根据可刷新令牌获取访问令牌
    # HTTP标头
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "login.eveonline.com"}
    # POST参数
    form_values = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token,
        "scope": scope}
    res = requests.post(
        "https://login.eveonline.com/v2/oauth/token",
        data=form_values,
        headers=headers, )
    res.raise_for_status()
    if res.status_code == 200:
        data = res.json()
        # 获取新的access_token和refresh_token并覆盖写入
        verify_dict["res"]["access_token"] = data["access_token"]
        verify_dict["res"]["refresh_token"] = data["refresh_token"]
        with open(path, "w") as f:
            json.dump(verify_dict, f, indent=2, sort_keys=True, ensure_ascii=False)  # 写为多行
            f.close()
        return data["access_token"], data["refresh_token"]
    else:
        print("status_code is not 200, ERROR")
        exit()


# 根据access_token获取jwt验证信息
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


# 获取数据
def get_data(token_path, name, data_title, data_out_path, refush_seconds, print_mode=True):
    # 尝试创建数据输出文件夹
    try:
        os.mkdir(data_out_path)
    except:
        pass

    # 定义检测类型对应的网址
    Swagger_Path = {
        "publicData": "/characters/{}/",
        "read_location": "/characters/{}/location/",
        "read_skillqueue": "/characters/{}/skillqueue/",
        "read_character_wallet": "/characters/{}/wallet/",
        # "read_character_bookmarks": "/characters/{}/bookmarks/",
        "read_loyalty": "/characters/{}/loyalty/points/",
        "read_online": "/characters/{}/online/"}

    # 读取存储的token文件
    path = os.path.join(token_path, name.replace(" ", "_") + ".json")
    # print(path)
    with open(path, "r") as f:
        verify_dict = json.load(f)
        access_token = verify_dict["res"]["access_token"]
        character_id = verify_dict["jwt"]["sub"].split(":")[2]
        character_name = verify_dict["jwt"]["name"]
        f.close()

    # 构建url
    URL = ("https://esi.evetech.net/latest" + Swagger_Path[data_title].format(character_id))
    # print(URL)

    # 定义HTTP标头
    headers = {
        "Authorization": "Bearer {}".format(access_token)}

    # 声明基础字典并组装文件路径
    basic_dict = {}
    path = os.path.join(data_out_path, character_name.replace(" ", "_") + ".json")

    # 判断文件是否存在及是否为空
    file_OK = False
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            json_str = "".join(f.readlines())
            if json_str not in ["", " ", "{}"]:
                rf_data = json.loads(json_str)
                basic_dict.update(rf_data)
                if data_title in list(rf_data.keys()):
                    file_OK = True
            f.close()

    # 获取文件/写文件
    if file_OK:
        # 判断时间差, 如果距离上一次请求大于1小时则重新请求，否则读取之前的记录
        ntime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        time_1_struct = datetime.strptime(basic_dict[data_title]["last_refush_time"], "%Y-%m-%d %H:%M:%S")
        time_2_struct = datetime.strptime(ntime, "%Y-%m-%d %H:%M:%S")
        total_seconds = (time_2_struct - time_1_struct).total_seconds()
        if total_seconds <= refush_seconds:
            # print("{}的{}距上次请求仅{}小时, 不重复请求".format(character_name, data_title, total_seconds))
            return basic_dict[data_title]["data"], path
        else:
            if print_mode == True:
                print("{} 的 {} 距上次请求已 {} 秒, 请求新的数据".format(character_name, data_title, total_seconds))
            # 创建get请求
            res = requests.get(URL, headers=headers)
            res.raise_for_status()
            if res.status_code == 200:
                data = res.json()
                with open(path, "w", encoding="utf-8") as f:
                    basic_dict[data_title] = {}
                    basic_dict[data_title]["last_refush_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    basic_dict[data_title]["data"] = data
                    json.dump(basic_dict, f, indent=2, sort_keys=True, ensure_ascii=False)  # 写为多行
                    f.close()
                    return data, path
    else:
        if print_mode == True:
            print("{} 文件不存在或 {} 项不存在, 创建/更新文件.".format(path, data_title))
        # 创建get请求
        res = requests.get(URL, headers=headers)
        res.raise_for_status()
        if res.status_code == 200:
            data = res.json()
            with open(path, "w", encoding="utf-8") as f:
                basic_dict[data_title] = {}
                basic_dict[data_title]["last_refush_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                basic_dict[data_title]["data"] = data
                json.dump(basic_dict, f, indent=2, sort_keys=True, ensure_ascii=False)  # 写为多行
                f.close()
                return data, path


def translate_NPCcorpID(NPCcorp_ID, Language):
    with codecs.open("sde/fsd/npcCorporations.yaml", "r", "utf-8") as corp_yaml:
        data = yaml.load(corp_yaml, Loader=yaml.FullLoader)
        return data[NPCcorp_ID]["nameID"][Language]


if __name__ == '__main__':
    '''
    注: read_character_bookmarks现已停止支持 返回一个空列表
    '''
    # 应用ID
    client_id = "68dfba8597464c02928ca96793b7690f"
    # 应用申请信息列表
    scope = "publicData " \
            "esi-location.read_location.v1 " \
            "esi-skills.read_skillqueue.v1 " \
            "esi-wallet.read_character_wallet.v1 " \
            "esi-ui.open_window.v1 " \
            "esi-ui.write_waypoint.v1 " \
            "esi-characters.read_loyalty.v1 " \
            "esi-location.read_online.v1"
    # 信息刷新时间
    refush_time_sec = {
        "publicData": 86400,
        "read_location": 5,
        "read_skillqueue": 120,
        "read_character_wallet": 120,
        "read_loyalty": 3600,
        "read_online": 60,
    }

    # 获取access_token和refush_token
    # 存储新的token(绑定新账户)
    # verify_dict, path = get_refresh_token(client_id, scope,"token")
    # print("\naccess_token: " + verify_dict["res"]["access_token"])
    # print("\nrefresh_token: " + verify_dict["res"]["refresh_token"])
    # print("\n" + path)

    # 用刷新令牌提取
    # for filename in os.listdir("./token"):
    #     name = filename.split('.')[0]
    #     new_access_token, new_refresh_token = refresh_token_post(client_id, scope, "token/", name)
    #     print("\nnew access token : " + new_access_token)
    #     print("\nnew refush token : " + new_refresh_token)
    #
    #     # 获取数据
    #     for data_title in list(refush_time_sec.keys()):
    #         data, path = get_data("token", name, data_title, "data", refush_time_sec[data_title])
    #         # print(path)
    #         print(data)

    # LP
    Key_ship = 0
    LP_dict = {}
    for filename in os.listdir("./token"):
        name = filename.split('.')[0]
        new_access_token, new_refresh_token = refresh_token_post(client_id, scope, "token/", name)
        data, path = get_data("token", name, "read_loyalty", "data", 10, False)
        # print(data)
        for corp in data:
            corp_name = translate_NPCcorpID(corp["corporation_id"], "zh")
            # if corp_name in ["古斯塔斯集团"]:
            if corp_name in ["实力派", "忠实制造"]:
                # 噩梦
                if corp["loyalty_points"] >= 800000:
                    EM = int(corp["loyalty_points"] / 800000)
                    Key_ship += EM
                print(name, corp_name, str(corp["loyalty_points"]))
            if corp_name not in LP_dict.keys():
                LP_dict[corp_name] = 0
            LP_dict[corp_name] += corp["loyalty_points"]
    print("噩梦数量: {}".format(Key_ship))
    print(LP_dict)

    # Wallet
    money = 0.0
    for filename in os.listdir("./token"):
        name = filename.split('.')[0]
        # new_access_token, new_refresh_token = refresh_token_post(client_id, scope, "token/", name)
        data, path = get_data("token", name, "read_character_wallet", "data", 180, False)
        print(name, add_(data))
        money += int(data)
    print("\n各账号isk总量: {}".format(add_(money)))

