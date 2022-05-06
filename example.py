import os
from utils.resourse_utils import get_refresh_token, refresh_token_post, get_data, translate_NPC_corpID, add_


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
    refresh_time_sec = {
        "publicData": 86400,
        "read_location": 5,
        "read_skillqueue": 120,
        "read_character_wallet": 120,
        "read_loyalty": 3600,
        "read_online": 60,
    }

    # 获取access_token和refresh_token
    # 存储新的token(绑定新账户)
    # verify_dict, path = get_refresh_token(client_id, scope, "token")
    # print("\naccess_token: " + verify_dict["res"]["access_token"])
    # print("\nrefresh_token: " + verify_dict["res"]["refresh_token"])
    # print("\n" + path)

    # 用刷新令牌提取
    for filename in os.listdir("./token"):
        name = filename.split('.')[0]
        new_access_token, new_refresh_token = refresh_token_post(client_id, scope, "token/", name)
        print("\nnew access token : " + new_access_token)
        print("\nnew refresh token : " + new_refresh_token)

        # 获取数据
        for data_title in list(refresh_time_sec.keys()):
            data, path = get_data("token", name, data_title, "data", refresh_time_sec[data_title])
            # print(path)
            print(data)

    # LP
    Key_ship = 0
    LP_dict = {}
    for filename in os.listdir("./token"):
        name = filename.split('.')[0]
        new_access_token, new_refresh_token = refresh_token_post(client_id, scope, "token/", name)
        data, path = get_data("token", name, "read_loyalty", "data", 10, False)
        # print(data)
        for corp in data:
            corp_name = translate_NPC_corpID(corp["corporation_id"], "zh")
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
