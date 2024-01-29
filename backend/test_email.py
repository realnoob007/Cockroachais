import requests

# Flask应用的URL
BASE_URL = "http://localhost:5000"

def send_email_code(email):
    url = f"{BASE_URL}/send_email_code"
    data = {"email": email}
    response = requests.post(url, json=data)
    return response.json()

def register_user(username, email, password, code):
    url = f"{BASE_URL}/register"
    data = {
        "username": username,
        "email": email,
        "password": password,
        "code": code
    }
    response = requests.post(url, json=data)
    return response.json()

if __name__ == "__main__":
    # 用户输入
    username = "test2"
    email = "yintongchen05@gmail.com"
    password = "testtest"

    # 发送验证码到邮箱
    send_email_result = send_email_code(email)
    print(send_email_result)

    # 从用户获取验证码
    code = input("Enter the email code you received: ")

    # 注册用户
    result = register_user(username, email, password, code)
    print(result)
