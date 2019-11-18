# %% Asuri 招新赛 20191117
# WEB 快速计算
import requests
import re
import time

s = requests.Session()
r = s.get("http://47.102.107.100:39012/")

for i in range(20):
    time.sleep(1)
    equation = re.findall(r'<div>(.*)=(.*)</div>', r.text)[0]
    print(equation)
    answer = eval(equation[0])
    if answer == eval(equation[1]):
        values = {'answer': 'true'}
    else:
        values = {'answer': 'false'}
    r = s.post("http://47.102.107.100:39012/", data=values)
    r.encoding = 'utf-8'
    print(r.text)

# flag: `Asuri{python_1s_th3_be3t_l4ngu4ge}`
