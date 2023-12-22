import os

from utils.resourse_utils import get_refresh_token, refresh_token_post, get_data, translate_NPC_corpID, add_

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
refresh_time_sec = {
    "publicData": 86400,
    "read_location": 5,
    "read_skillqueue": 120,
    "read_character_wallet": 120,
    "read_loyalty": 3600,
    "read_online": 60,
}


def get_all_info(token_path: str = "token", data_path: str = "data"):
    # 用刷新令牌提取新访问令牌
    for filename in os.listdir(token_path):
        name = filename.split('.')[0]
        new_access_token, new_refresh_token = refresh_token_post(client_id, scope, token_path, name)
        print("\n new access token : " + new_access_token)
        print("\n new refresh token : " + new_refresh_token)

        # 获取数据
        for data_title in list(refresh_time_sec.keys()):
            data, _ = get_data(token_path, name, data_title, data_path, refresh_time_sec[data_title])
            print(data)


def bind_new_account(token_path: str = "token"):
    # 获取access_token和refresh_token
    # 存储新的token(绑定新账户)
    verify_dict, path = get_refresh_token(client_id, scope, token_path)
    print("\naccess_token: " + verify_dict["res"]["access_token"])
    print("\nrefresh_token: " + verify_dict["res"]["refresh_token"])
    print("\n" + path)


def get_LP(token_path: str = "token", data_path: str = "data", key_corp: list = None):
    if key_corp is None:
        key_corp = ["古斯塔斯集团"]
    LP_dict = {}
    for filename in os.listdir(token_path):
        name = filename.split('.')[0]
        data, _ = get_data(token_path, name, "read_loyalty", data_path, 10, False)
        for corp in data:
            corp_name = translate_NPC_corpID(corp["corporation_id"], "zh")
            if corp_name in key_corp:
                print(name, corp_name, str(corp["loyalty_points"]))
            if corp_name not in LP_dict.keys():
                LP_dict[corp_name] = 0
            LP_dict[corp_name] += corp["loyalty_points"]
    print(LP_dict)


def get_ISK(token_path: str = "token", data_path: str = "data"):
    money = 0.0
    for filename in os.listdir(token_path):
        name = filename.split('.')[0]
        data, _ = get_data(token_path, name, "read_character_wallet", data_path, 180, False)
        print(name, add_(data))
        money += int(data)
    print("\n各账号isk总量: {}".format(add_(money)))


if __name__ == '__main__':
    # set proxy
    # os.environ["http_proxy"] = "http://127.0.0.1:52539"
    # os.environ["https_proxy"] = "http://127.0.0.1:52539"

    get_LP("token", "data", ["古斯塔斯集团"])
    get_ISK("token", "data")
