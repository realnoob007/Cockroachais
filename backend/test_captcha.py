import requests
from PIL import Image
from io import BytesIO

# Flask应用的URL
BASE_URL = "http://127.0.0.1:5000"

def get_captcha(username):
    """获取图形验证码"""
    response = requests.get(f"{BASE_URL}/get_captcha/{username}")
    if response.status_code == 200:
        # 将响应的内容转换为图像
        img = Image.open(BytesIO(response.content))
        img.show()  # 显示图像，以便手动查看验证码
        return True
    else:
        print("Failed to get captcha")
        return False

def register(username, email, password, captcha_code):
    """使用图形验证码进行注册"""
    user_data = {
        "username": username,
        "email": email,
        "password": password,
        "code": captcha_code
    }
    response = requests.post(f"{BASE_URL}/register", json=user_data)

    try:
        # Attempt to parse JSON
        response_data = response.json()
        print("Registration response:", response_data)
    except requests.exceptions.JSONDecodeError:
        # Handle responses that are not in JSON format
        print("Registration failed or didn't return JSON. Status Code:", response.status_code)
        print("Response Content:", response.text)


if __name__ == "__main__":
    test_username = "testuser"
    test_email = "testuser@qq.com"
    test_password = "password123"

    # 第一步：获取验证码
    if get_captcha(test_username):
        # 第二步：手动输入看到的验证码
        captcha_code = input("Enter the captcha code: ")

        # 第三步：尝试注册
        register(test_username, test_email, test_password, captcha_code)


