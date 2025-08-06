from urllib.parse import urlparse, parse_qsl
import requests
import time
from http.cookies import SimpleCookie

from xauth import XAuth


# 定义常量和通用请求头
BASE_URL = "https://addplus.org"
COMMON_HEADERS = {
    "accept": "*/*",
    "accept-language": "zh-CN,zh;q=0.9",
    "sec-ch-ua": "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Google Chrome\";v=\"138\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\""
}

# Cookie名称常量
CSRF_TOKEN = "__Host-authjs.csrf-token"
CALLBACK_URL = "__Secure-authjs.callback-url"
STATE_COOKIE = "__Secure-authjs.state"
CODE_VERIFIER = "__Secure-authjs.pkce.code_verifier"
SESSION_TOKEN = "__Secure-authjs.session-token"

# Cookie管理类
class CookieManager:
    def __init__(self):
        self.cookies = {}
    
    def parse_set_cookie(self, set_cookie_header):
        """解析Set-Cookie头并更新cookie字典"""
        if not set_cookie_header:
            return {}
            
        cookie = SimpleCookie()
        cookie.load(set_cookie_header)
        
        for key, morsel in cookie.items():
            self.cookies[key] = morsel.value
        
        return self.cookies
    
    def get_cookie(self, name):
        """获取指定名称的cookie值"""
        return self.cookies.get(name)
    
    def set_cookie(self, name, value):
        """设置cookie"""
        self.cookies[name] = value
    
    def get_cookie_header(self, names=None):
        """生成cookie头
        
        Args:
            names: 指定要包含的cookie名称列表，如果为None则包含所有cookie
        """
        if not self.cookies:
            return ""
            
        if names:
            cookies = {name: self.cookies[name] for name in names if name in self.cookies}
        else:
            cookies = self.cookies
            
        return "; ".join([f"{name}={value}" for name, value in cookies.items()])


def get_csrf():
    """获取CSRF令牌"""
    url = f"{BASE_URL}/api/auth/csrf"
    headers = {
        **COMMON_HEADERS,
        "content-type": "application/json",
        "priority": "u=1, i",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "Referer": BASE_URL + "/"
    }
    
    cookie_manager = CookieManager()
    response = requests.get(url, headers=headers)
    
    # 解析Set-Cookie头
    cookie_manager.parse_set_cookie(response.headers.get("set-cookie"))
    csrf_token = cookie_manager.get_cookie(CSRF_TOKEN)
    
    print(f"CSRF Token: {csrf_token}")
    return csrf_token, cookie_manager


def get_twitter(csrf_token, cookie_manager):
    """获取Twitter认证URL"""
    # 处理CSRF令牌，有时候令牌中包含%字符，需要截取前面部分
    csrfToken = csrf_token.split("%")[0] if "%" in csrf_token else csrf_token
    url = f"{BASE_URL}/api/auth/signin/twitter"
    
    # 设置callback URL cookie
    cookie_manager.set_cookie(CALLBACK_URL, "https%3A%2F%2Faddplus.org")
    
    headers = {
        **COMMON_HEADERS,
        "content-type": "application/x-www-form-urlencoded",
        "priority": "u=1, i",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "x-auth-return-redirect": "1",
        "Referer": f"{BASE_URL}/",
        "cookie": cookie_manager.get_cookie_header([CSRF_TOKEN, CALLBACK_URL])
    }

    data = {
        "callbackUrl": f"{BASE_URL}/",
        "csrfToken": csrfToken
    }

    resp = requests.post(url, headers=headers, data=data, allow_redirects=False)
    
    # 获取重定向URL
    redirect_url = resp.headers.get("location")
    
    # 解析Set-Cookie头
    cookie_manager.parse_set_cookie(resp.headers.get("set-cookie"))
    state = cookie_manager.get_cookie(STATE_COOKIE)
    code_verifier = cookie_manager.get_cookie(CODE_VERIFIER)
    
    print(f"Redirect URL: {redirect_url}")
    print(f"State: {state}")
    print(f"Code Verifier: {code_verifier}")
    
    return redirect_url, state, code_verifier, cookie_manager


def get_x_oauth2(redirect_url, x_token=None):
    """获取X(Twitter)的OAuth2认证码
    
    Args:
        redirect_url: 重定向URL
        x_token: X认证token
        
    Returns:
        (state, auth_code): 状态和认证码元组
    """
    if not x_token:
        raise ValueError("x_token不能为空")
        
    x = XAuth(x_token)
    
    # 解析redirect_url中的参数
    params = urlparse(redirect_url).query
    params = dict(parse_qsl(params))
    state = params.get("state")
    
    # 执行OAuth2认证流程
    auth_code = x.oauth2(params)
    
    print(f"Auth Code: {auth_code}")
    print(f"State: {state}")
    
    return state, auth_code


def get_auth_token(csrf_token, state_cookie, state, auth_code, code_verifier, cookie_manager):
    """获取认证会话令牌"""
    # 使用用户提供的完整URL，不做任何修改
    url = f"https://addplus.org/api/auth/callback/twitter?state={state}&code={auth_code}"
    
    # 使用用户提供的完整cookie字符串，确保完全匹配
    cookie_str = f"__Host-authjs.csrf-token={csrf_token}; __Secure-authjs.callback-url=https%3A%2F%2Faddplus.org%2F; __Secure-authjs.state={state_cookie}; __Secure-authjs.pkce.code_verifier={code_verifier}; _ga_5MEMREWY9G=GS2.1.s1754462263$o2$g1$t1754462350$j60$l0$h0"
    
    # 使用与成功请求完全相同的headers
    headers = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-language": "zh-CN,zh;q=0.9",
        "priority": "u=0, i",
        "sec-ch-ua": '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "cross-site",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
        "cookie": cookie_str,
        "Referer": "https://x.com/"
    }
    
    # 打印详细的请求信息以便调试
    print("\n==== 请求信息 ====")
    print(f"Request URL: {url}")
    print(f"Cookie: {cookie_str[:100]}...")
    print(f"State: {state[:50]}...")
    print(f"Auth Code: {auth_code}")
    
    # 使用fetch风格的请求，不包含body
    try:
        resp = requests.get(url, headers=headers, allow_redirects=False)
        print(f"\n==== 响应信息 ====")
        print(f"Response Status: {resp.status_code}")
        print(f"Response URL: {resp.url}")
        
        # 打印所有响应头
        print("\n响应头:")
        for key, value in resp.headers.items():
            print(f"{key}: {value}")
        
        if resp.status_code != 200:
            print(f"\n错误响应内容:\n{resp.text[:500]}...")
        
        # 解析Set-Cookie头
        set_cookie = resp.headers.get("set-cookie")
        if set_cookie:
            print(f"\nSet-Cookie: {set_cookie}")
        else:
            print("\n响应中没有Set-Cookie头")
        
        if set_cookie and SESSION_TOKEN in set_cookie:
            cookie_manager.parse_set_cookie(set_cookie)
            session_token = cookie_manager.get_cookie(SESSION_TOKEN)
            print(f"Session Token: {session_token}")
            return session_token, cookie_manager
        else:
            print("No session token found in response")
            return None, cookie_manager
    except Exception as e:
        print(f"请求异常: {str(e)}")
        return None, cookie_manager

def get_userinfo(cookie_manager):
    """获取用户信息"""
    url = f"{BASE_URL}/api/auth/session"
    
    headers = {
        **COMMON_HEADERS,
        "Connection": "keep-alive",
        "content-type": "application/json",
        "priority": "u=1, i",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "cookie": cookie_manager.get_cookie_header([CSRF_TOKEN, SESSION_TOKEN]),
        "Referer": f"{BASE_URL}/"
    }
    
    response = requests.get(url, headers=headers)
    print("User Info:")
    print(response.text)
    username = response.json()["user"]["username"]
    ref_url = f"https://addplus.org/boost/{username}"
    #保存ref_url,添加换行符
    with open("ref_url.txt", "a") as f:
        f.write(f"{ref_url}:{cookie_manager.get_cookie_header([CSRF_TOKEN, SESSION_TOKEN])}\n")


def read_tokens_from_file(file_path):
    """从文件中读取X认证token列表
    
    Args:
        file_path: token文件路径
        
    Returns:
        token列表
    """
    tokens = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                token = line.strip()
                if token:  # 跳过空行
                    tokens.append(token)
        return tokens
    except Exception as e:
        print(f"读取token文件失败: {str(e)}")
        return []

def process_single_token(x_token):
    """使用单个token处理完整的认证流程
    
    Args:
        x_token: X认证token
        
    Returns:
        是否成功获取用户信息
    """
    print(f"\n正在处理token: {x_token[:8]}...")
    
    try:
        # 初始化认证流程
        csrf_token, cookie_manager = get_csrf()
        
        # 获取Twitter认证URL
        redirect_url, state_cookie, code_verifier, cookie_manager = get_twitter(csrf_token, cookie_manager)
        
        # 使用当前token获取认证码
        state, auth_code = get_x_oauth2(redirect_url, x_token)
        
        # 获取会话令牌
        session_token, cookie_manager = get_auth_token(csrf_token, state_cookie, state, auth_code, code_verifier, cookie_manager)
        
        # 获取用户信息，只有在成功获取会话令牌时才尝试获取用户信息
        if session_token:
            get_userinfo(cookie_manager)
            return True
        else:
            print("无法获取用户信息，因为会话令牌获取失败")
            return False
    except Exception as e:
        print(f"处理token时发生错误: {str(e)}")
        return False

if __name__ == '__main__':
    # 从文件读取token列表
    token_file = "xtoken.txt"
    tokens = read_tokens_from_file(token_file)
    
    if not tokens:
        print(f"未找到有效的token，请检查{token_file}文件")
        exit(1)
    
    print(f"共读取到{len(tokens)}个token，开始处理...")
    
    # 记录成功和失败的次数
    success_count = 0
    fail_count = 0
    
    # 依次处理每个token
    for i, token in enumerate(tokens):
        print(f"\n[{i+1}/{len(tokens)}] 处理token...")
        result = process_single_token(token)
        if result:
            success_count += 1
        else:
            fail_count += 1
        
        # 每个token处理完后暂停一下，避免请求过于频繁
        if i < len(tokens) - 1:
            print("等待5秒后处理下一个token...")
            time.sleep(5)
    
    # 打印处理结果统计
    print(f"\n处理完成! 成功: {success_count}, 失败: {fail_count}, 总计: {len(tokens)}")

