# /*
#  * @Author: zhizhuo
#  * @Date: 2022-07-06 08:57:13
#  * @Last Modified by: zhizhuo
#  * @Last Modified time: 2022-07-14 20:03:18
#  */

import argparse
import base64
import json
import os
import re
import time
import warnings
import requests
import random
from concurrent.futures import ThreadPoolExecutor
import mmh3

requests.packages.urllib3.disable_warnings()
warnings.filterwarnings('ignore')
os.environ["TF_CPP_MIN_LOG_LEVEL"] = '1'

# 默认线程数量大小
max_threads = 50

config = {
    'email': '',  # fofa的登录邮箱
    'key': '',  # fofa个人中心的key
    'size': '100',  # 默认是是普通会员，普通会员做多100条，高级会员10000条
    'base_url': 'https://fofa.info/api/v1/search/all',  # fofa api接口地址
    'user_url': 'https://fofa.info/api/v1/info/my',  # fofa 账户信息接口
    'cdn_url': 'https://sc.toolnb.com/api/web-ping.json'  # cdn查询API接口
}

# 代理列表
proxylist = ['', 'socks5://36.170.50.110:8888', 'socks5://47.242.82.91:7777', 'socks5://43.139.246.229:8888', 'socks5://58.48.224.170:20202', 'socks5://47.108.87.92:1080', 'socks5://47.243.239.146:1080', 'socks5://8.217.32.69:8888', 'socks5://47.120.12.206:7777', 'socks5://124.221.210.81:5555', 'socks5://1.117.169.32:7777', 'socks5://180.76.178.40:7777', 'socks5://43.143.223.153:7777', 'socks5://124.71.131.6:1080', 'socks5://81.69.199.97:1080',
             'socks5://119.184.155.164:7777']


user_agent_list = [
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) Gecko/20100101 Firefox/61.0",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
    "Mozilla/5.0 (Macintosh; U; PPC Mac OS X 10.5; en-US; rv:1.9.2.15) Gecko/20110303 Firefox/3.6.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
]
# 全局header头
headers = {
    'User-Agent': user_agent_list[random.randint(0, len(user_agent_list)-1)],
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    # 'Connection':'keep-alive',#默认时链接一次，多次爬取之后不能产生新的链接就会产生报错Max retries exceeded with url
    'Upgrade-Insecure-Requests': '1',
    'Pragma': 'no-cache',
    'Cache-Control': 'no-cache',
    'Connection': 'close',  # 解决Max retries exceeded with url报错
}

a = 0  # 可以访问次数
b = 0  # 404站点次数
c = 0  # 访问超时
f = 0  # 需要人工确认站点次数

# 获取fofa信息


def get_url_info(url_arg, file_arg):
    print('开始域名信息读取')
    totals = 0
    count = 0
    output_url = open('./result/fofa.txt', 'a+', encoding='utf-8')
    output_url.truncate(0)  # 对文件进行初始化操作
    output_url.close()
    if url_arg is None:
        urlfile = open('{}'.format(file_arg),
                       encoding='utf8').read().splitlines()
    else:
        urlfile = ['{}'.format(url_arg)]
    for url in urlfile:
        fofa_search = 'domain="{}"'.format(url)
        base_fofa_search = base64.b64encode(fofa_search.encode('utf8'))
        data = {
            'email': config['email'],
            'key': config['key'],
            'qbase64': base_fofa_search,
            'full': 'true',
            'size': config['size'],
        }
        resp = requests.get(
            url=config['base_url'], headers=headers, data=data, timeout=120).json()
        if resp['error'] == True:
            print('FOFA查询出错，错误信息：{}'.format(resp))
            exit()
        else:
            print(url+'关联资产有{}个'.format(resp['size']))
            totals = totals + resp['size']
            if resp['size'] > config['size']:
                count = config['size']
            else:
                count = count + resp['size']
            if resp['size'] > 0:
                for key in range(0, int(len(resp['results']))):
                    with open('result/fofa.txt', 'a+', encoding='utf-8') as fa:
                        fa.write(resp['results'][key][0])
                        fa.write('\n')
            else:
                with open('result/fofa.txt', 'a+', encoding='utf-8') as fa:
                    fa.write(url)
                    fa.write('\n')
    print('总共收集到{}个关联资产'.format(totals))
    print('已经写入{}个关联资产'.format(count))
    print('结果已保存至result/fofa.txt中')

# 获取ip信息


def get_ip_info(ip_arg, ip_file_arg):
    print('开始ip信息读取')
    totals = 0
    count = 0
    output_ip = open('./result/fofa.txt', 'a+', encoding='utf-8')
    output_ip.truncate(0)  # 对文件进行初始化操作
    output_ip.close()
    if ip_arg is None:
        ipfile = open('{}'.format(ip_file_arg),
                      encoding='utf8').read().splitlines()
    else:
        ipfile = ['{}'.format(ip_arg)]
    for url in ipfile:
        fofa_search = 'ip="{}"'.format(url)
        base_fofa_search = base64.b64encode(fofa_search.encode('utf8'))
        data = {
            'email': config['email'],
            'key': config['key'],
            'qbase64': base_fofa_search,
            'size': config['size'],
        }
        resp = requests.get(
            url=config['base_url'], headers=headers, data=data, timeout=120).json()
        if resp['error'] == True:
            print('FOFA查询出错，错误信息：{}'.format(resp))
            exit()
        else:
            print(url+'关联资产有{}个'.format(resp['size']))
            totals = totals + resp['size']
            if resp['size'] > config['size']:
                count = config['size']
            else:
                count = count+resp['size']
            if resp['size'] > 0:
                for key in range(0, int(len(resp['results']))):
                    with open('result/fofa.txt', 'a+', encoding='utf-8') as fa:
                        fa.write(resp['results'][key][0])
                        fa.write('\n')
            else:
                with open('result/fofa.txt', 'a+', encoding='utf-8') as fa:
                    fa.write(url)
                    fa.write('\n')
        time_sleep = random.randint(0,1)
        print(f'程序随机休眠{time_sleep}秒')
        time.sleep(time_sleep)
    print('总共收集到{}个关联资产'.format(totals))
    print('已经写入{}个关联资产'.format(count))
    print('结果已保存至result/fofa.txt中')

# fofa查询函数


def fofa_search(self):
    totals = 0
    count = 0
    output_search = open('./result/fofa.txt', 'a+', encoding='utf-8')
    output_search.truncate(0)  # 对文件进行初始化操作
    output_search.close()
    print('FOFA查询语句为：{}'.format(self))
    base_fofa_search = base64.b64encode(self.encode('utf8'))
    data = {
        'email': config['email'],
        'key': config['key'],
        'qbase64': base_fofa_search,
        'size': config['size'],
    }
    resp = requests.get(config['base_url'], data, timeout=10).json()
    print('FOFA语句：{} 关联资产有{}个'.format(self, resp['size']))
    totals = totals + resp['size']
    if resp['size'] > config['size']:
        count = config['size']
    else:
        count = count+resp['size']
    if resp['size'] > 0:
        for key in range(0, int(len(resp['results']))):
            with open('result/fofa.txt', 'a+', encoding='utf-8') as fa:
                fa.write(resp['results'][key][0])
                fa.write('\n')
    else:
        pass
    print('总共收集到{}个关联资产'.format(totals))
    print('已经写入{}个关联资产'.format(count))
    print('结果已保存至result/fofa.txt中')

# 获取fofa用户信息


def get_user_info(url_arg, file_arg, ip_arg, ip_file_arg, search_arg):
    print('开始检测fofa账户信息')
    data = {
        'email': config['email'],
        'key': config['key'],
    }
    resp = requests.get(
        url=config['user_url'], headers=headers, data=data, timeout=120).json()
    print('================================================')
    print('用户名：'+resp['username'])
    print('邮箱：'+resp['email'])
    if resp['isvip'] == True:
        print('是否是VIP：是')
    else:
        print('是否是VIP：否')
    if resp['vip_level'] == 2:
        config['size'] = 10000
    print('VIP等级：'+str(resp['vip_level']))
    print('fofa cli版本：'+str(resp['fofacli_ver']))
    print('================================================')
    if url_arg is not None or file_arg is not None:
        get_url_info(url_arg, file_arg)
    elif search_arg is not None:
        fofa_search(search_arg)
    else:
        get_ip_info(ip_arg, ip_file_arg)

# 资产的存活检测


def Detection():
    ThreadPool = []
    p = ThreadPoolExecutor(max_threads)
    print('================================================')
    print('开始资产存活检测')
    print('================================================')
    urlfile = open('./result/fofa.txt', encoding='utf-8')
    urllist = urlfile.read().splitlines()
    urlfile.close()
    for d in urllist:
        if 'http' in d:
            url = d
        else:
            url = 'http://' + str(d)
        print('开始检测：' + url)
        proxies = {
            'http': str(proxylist[random.randint(0, len(proxylist)-1)]),
            'https': str(proxylist[random.randint(0, len(proxylist)-1)]),
        }
        task = p.submit(verify, url, proxies)
        ThreadPool.append(task)
    p.shutdown(wait=True)

# 存活检测扫描函数


def verify(url, proxy):
    global a, b, c, f
    title = ""
    try:
        print(f'使用代理{proxy}')
        resp = requests.get(url, headers, proxies=proxy,
                            timeout=10, verify=False, allow_redirects=True,)
        resp.encoding = resp.apparent_encoding
        print(f'站点{url}状态码：' + str(resp.status_code))
        title_list = re.findall(r'<title>(.*?)</title>',
                                resp.text, re.I | re.M | re.S)
        # whatcms = fingerprint(resp.text, resp.headers, url)
        Server = dict(resp.headers).get('Server', '')
        cdn_result = str(is_cdn(url))
        print(f'站点{url} Server识别结果：{Server}')
        print(f'站点{url} CDN识别结果：{cdn_result}')
        # print('站点指纹识别结果', whatcms)
        if len(title_list) == 0:
            title = ""
            print(f"站点{url}未识别到title")
        else:
            title = str(title_list[0]).replace(
                '\r', "").replace('\n', "").replace('\t', "")
            print(f"站点{url}识别到title：" + title)
        if resp.status_code == 404:
            b = b + 1
            with open('./result/active_url.txt', 'a+', encoding='utf-8') as fa:
                fa.write(url+'\t'+title+'\t' +
                         str(resp.status_code)+'\t'+cdn_result+'\t'+Server)
                fa.write('\n')
        else:
            a = a + 1
            with open('./result/active_url.txt', 'a+', encoding='utf-8') as fa:
                fa.write(url+'\t'+title+'\t' +
                         str(resp.status_code)+'\t'+cdn_result+'\t'+Server)
                fa.write('\n')
    except Exception as e:
        print(e)
        if 'Connection' in str(e) and 'BadStatusLine' in str(e):
            titlelist = re.findall(
                r"BadStatusLine\('(.*?)\\.*'", str(e))
            if len(titlelist) > 0:
                title = titlelist[0].replace('-', '')
            a = a + 1
            Servername = ''
            if 'SSH' in str(e):
                Servername = 'SSH'
            elif 'FTP' in str(e):
                Servername = 'FTP'
            else:
                Servername = title
            with open('./result/active_url.txt', 'a+', encoding='utf-8') as ft:
                ft.write(url + '\t' + title + '\t' +
                         '200' + '\t' + '' + '\t' + Servername)
                ft.write('\n')
        elif 'timeout' not in str(e):
            with open('./result/vul_url.txt', 'a+', encoding='utf-8') as fe:
                fe.write(url)
                fe.write('\n')
            f = f + 1
            print('[+] 此站点需要人工确认')
        else:
            print('[+] 站点请求超时')
            c = c + 1
        pass

# cdn检测函数，采用多地ping的结构


def is_cdn(self):
    """
    用于检测用户是否使用cdn
    """
    url = self
    if 'http://' in url:
        url = url.replace('http://', '')
    if 'https://' in url:
        url = url.replace('https://', '')
    urllist = url.split('/')
    if len(urllist) > 0:
        url = urllist[0]
    else:
        url = url
    ips = []
    is_cdn_result = ""
    data1 = {
        'hash': 'd7d5344b-656d-3d4a-bc43-b812c2ceb8eb',
        'host': url
    }
    data2 = {
        'hash': '7195eed3-5660-37f1-acbf-51677b9d4ce5',
        'host': url
    }
    data3 = {
        'hash': '8002b9a5-9676-33e1-ac7e-e72a09dff94d',
        'host': url
    }
    data4 = {
        'hash': '9d1b3120-174a-38d9-b761-8cd4c7c16929',
        'host': url
    }
    data5 = {
        'hash': 'cc53b796-5b87-3bac-a0cd-4d05a7ad88d4',
        'host': url
    }
    data6 = {
        'hash': '51de8912-3770-3a77-a0d0-32b01c9ac069',
        'host': url
    }
    data7 = {
        'hash': '9faded3f-05a8-380a-8d7f-4cc0f7faf97d',
        'host': url
    }
    data8 = {
        'hash': 'e116e62d-1161-32fc-9dd5-bcbefc622b3a',
        'host': url
    }
    data9 = {
        'hash': 'a2dcc454-c1c2-3b49-86f8-97ecdb2ccb69',
        'host': url
    }
    try:
        r1 = requests.post(url=config['cdn_url'], data=data1,
                           headers=headers, proxies={
                               'http': str(proxylist[random.randint(0, len(proxylist)-1)]),
                               'https': str(proxylist[random.randint(0, len(proxylist)-1)]),
        }, timeout=10)
        r1_ip = re.findall(r'"ip":"(.*?)","ip_list', r1.text)
        r1_ip = "".join(r1_ip)
        ips.append(r1_ip)
    except:
        pass
    try:
        r2 = requests.post(url=config['cdn_url'], data=data2,
                           headers=headers, proxies={
                               'http': str(proxylist[random.randint(0, len(proxylist)-1)]),
                               'https': str(proxylist[random.randint(0, len(proxylist)-1)]),
        }, timeout=10)
        r2_ip = re.findall(r'"ip":"(.*?)","ip_list', r2.text)
        r2_ip = "".join(r2_ip)
        ips.append(r2_ip)
    except:
        pass
    try:
        r3 = requests.post(url=config['cdn_url'], data=data3,
                           headers=headers, proxies={
                               'http': str(proxylist[random.randint(0, len(proxylist)-1)]),
                               'https': str(proxylist[random.randint(0, len(proxylist)-1)]),
        }, timeout=10)
        r3_ip = re.findall(r'"ip":"(.*?)","ip_list', r3.text)
        r3_ip = "".join(r3_ip)
        ips.append(r3_ip)
    except:
        pass
    try:
        r4 = requests.post(url=config['cdn_url'], data=data4,
                           headers=headers, proxies={
                               'http': str(proxylist[random.randint(0, len(proxylist)-1)]),
                               'https': str(proxylist[random.randint(0, len(proxylist)-1)]),
        }, timeout=10)
        r4_ip = re.findall(r'"ip":"(.*?)","ip_list', r4.text)
        r4_ip = "".join(r4_ip)
        ips.append(r4_ip)
    except:
        pass
    try:
        r5 = requests.post(url=config['cdn_url'], data=data5,
                           headers=headers, proxies={
                               'http': str(proxylist[random.randint(0, len(proxylist)-1)]),
                               'https': str(proxylist[random.randint(0, len(proxylist)-1)]),
        }, timeout=10)
        r5_ip = re.findall(r'"ip":"(.*?)","ip_list', r5.text)
        r5_ip = "".join(r5_ip)
        ips.append(r5_ip)
    except:
        pass
    try:
        r6 = requests.post(url=config['cdn_url'], data=data6,
                           headers=headers, proxies={
                               'http': str(proxylist[random.randint(0, len(proxylist)-1)]),
                               'https': str(proxylist[random.randint(0, len(proxylist)-1)]),
        }, timeout=10)
        r6_ip = re.findall(r'"ip":"(.*?)","ip_list', r6.text)
        r6_ip = "".join(r6_ip)
        ips.append(r6_ip)
    except:
        pass
    try:
        r7 = requests.post(url=config['cdn_url'], data=data7,
                           headers=headers, proxies={
                               'http': str(proxylist[random.randint(0, len(proxylist)-1)]),
                               'https': str(proxylist[random.randint(0, len(proxylist)-1)]),
        }, timeout=10)
        r7_ip = re.findall(r'"ip":"(.*?)","ip_list', r7.text)
        r7_ip = "".join(r7_ip)
        ips.append(r7_ip)
    except:
        pass
    try:
        r8 = requests.post(url=config['cdn_url'], data=data8,
                           headers=headers, proxies={
                               'http': str(proxylist[random.randint(0, len(proxylist)-1)]),
                               'https': str(proxylist[random.randint(0, len(proxylist)-1)]),
        }, timeout=10)
        r8_ip = re.findall(r'"ip":"(.*?)","ip_list', r8.text)
        r8_ip = "".join(r8_ip)
        ips.append(r8_ip)
    except:
        pass
    try:
        r9 = requests.post(url=config['cdn_url'], data=data9,
                           headers=headers, proxies={
                               'http': str(proxylist[random.randint(0, len(proxylist)-1)]),
                               'https': str(proxylist[random.randint(0, len(proxylist)-1)]),
        }, timeout=10)
        r9_ip = re.findall(r'"ip":"(.*?)","ip_list', r9.text)
        r9_ip = "".join(r9_ip)
        ips.append(r9_ip)
    except:
        pass
    ips = list(set([i for i in ips if i != '']))
    if len(ips) == 1:
        is_cdn_result = False
    elif len(ips) == 0:
        is_cdn_result = ""
    else:
        is_cdn_result = True
    return is_cdn_result


# 站点指纹识别
def read_config():
    config_file = os.path.join("web_finger.json")
    with open(config_file, 'r') as f:
        mark_list = json.load(f)
    return mark_list

# 指纹识别类，用于判断站点指纹类型


class Fofacms:

    def __init__(self, html, title, header, icon_hash):
        self.html = html.lower()
        self.title = title.lower()
        self.header = header.lower()
        self.icon_hash = icon_hash.lower()

    def get_result(self, a):
        builts = ["(body)\s*=\s*\"", "(title)\s*=\s*\"",
                  "(header)\s*=\s*\"", "(icon_hash)\s*=\s*\""]
        if a is True:
            return True
        if a is False:
            return False
        for regx in builts:
            match = re.search(regx, a, re.I | re.S | re.M)
            if match:
                name = match.group(1)
                length = len(match.group(0))
                content = a[length: -1]
                if name == "body":
                    if content.lower() in self.html:
                        return True
                    else:
                        return False
                elif name == "title":
                    if content.lower() in self.title:
                        return True
                    else:
                        return False
                elif name == "header":
                    if content.lower() in self.header:
                        return True
                    else:
                        return False
                elif name == "icon_hash":
                    if content.lower() in self.icon_hash:
                        return True
                    else:
                        return False
        raise Exception("不能识别的a:" + str(a))

    def calc_express(self, expr):
        expr = self.in2post(expr)

        stack = []
        special_sign = ["||", "&&"]
        if len(expr) > 1:
            for exp in expr:
                if exp not in special_sign:
                    stack.append(exp)
                else:
                    a = self.get_result(stack.pop())
                    b = self.get_result(stack.pop())
                    c = None
                    if exp == "||":
                        c = a or b
                    elif exp == "&&":
                        c = a and b
                    stack.append(c)
            if stack:
                return stack.pop()
        else:
            return self.get_result(expr[0])

    def in2post(self, expr):

        stack = []
        post = []
        special_sign = ["&&", "||", "(", ")"]
        builts = ["body\s*=\s*\"", "title\s*=\s*\"",
                  "header\s*=\s*\"", "icon_hash\s*=\s*\""]

        exprs = []
        tmp = ""
        in_quote = 0
        for z in expr:
            is_continue = False
            tmp += z
            if in_quote == 0:
                for regx in builts:
                    if re.search(regx, tmp, re.I):
                        in_quote = 1
                        is_continue = True
                        break
            elif in_quote == 1:
                if z == "\"":
                    in_quote = 2
            if is_continue:
                continue
            for i in special_sign:
                if tmp.endswith(i):

                    if i == ")" and in_quote == 2:
                        zuo = 0
                        you = 0
                        for q in exprs:
                            if q == "(":
                                zuo += 1
                            elif q == ")":
                                you += 1
                        if zuo - you < 1:
                            continue
                    length = len(i)
                    _ = tmp[0:-length]
                    if in_quote == 2 or in_quote == 0:
                        if in_quote == 2 and not _.strip().endswith("\""):
                            continue
                        if _.strip() != "":
                            exprs.append(_.strip())
                        exprs.append(i)
                        tmp = ""
                        in_quote = 0
                        break
        if tmp != "":
            exprs.append(tmp)
        if not exprs:
            return [expr]
        for z in exprs:
            if z not in special_sign:
                post.append(z)
            else:
                if z != ')' and (not stack or z == '(' or stack[-1] == '('):
                    stack.append(z)  # 运算符入栈

                elif z == ')':  # 右括号出栈
                    while True:
                        x = stack.pop()
                        if x != '(':
                            post.append(x)
                        else:
                            break

                else:  # 比较运算符优先级，看是否入栈出栈
                    while True:
                        if stack and stack[-1] != '(':
                            post.append(stack.pop())
                        else:
                            stack.append(z)
                            break
        while stack:  # 还未出栈的运算符，需要加到表达式末尾
            post.append(stack.pop())
        return post

# 指纹识别处理函数


def fingerprint(body, header, url):
    mark_list = read_config()
    # title
    m = re.search('<title>(.*?)<\/title>', body, re.I | re.M | re.S)

    title = ""
    if m:
        title = m.group(1).strip()
    icon_hash = ''
    p0 = re.findall(r'href="(.*?)\.ico', body)
    if len(p0) == 0:
        p0 = ['favicon']
    hash_url = url + '/' + p0[0] + '.ico'
    p1 = requests.get(url=hash_url, headers=headers,
                      proxies={
                          'http': str(proxylist[random.randint(0, len(proxylist)-1)]),
                          'https': str(proxylist[random.randint(0, len(proxylist)-1)]),
                      }, timeout=10, verify=False, allow_redirects=True,).content
    p2 = base64.encodebytes(p1)
    p3 = mmh3.hash(p2)
    icon_hash = str(p3)
    fofa = Fofacms(str(body), str(title), str(header), str(icon_hash))
    whatweb = ""
    for item in mark_list:
        express = item["rule"]
        name = item["name"]
        try:
            if fofa.calc_express(express):
                whatweb = {name.lower()}
                break
        except Exception:
            print("config error express:{} name:{}".format(express, name))
    return whatweb

# 扫描函数


def Scan():
    print('================================================')
    print('开始使用afrog进行资产漏洞扫描')
    print('================================================')
    file_num = 0
    try:
        scanactivefile = open('./result/active_url.txt', encoding='utf-8')
        scanactivelist = scanactivefile.read().splitlines()
        file_num = len(scanactivelist)
    except Exception as e:
        pass
    if file_num > 0:
        filename = 'active_url'
    else:
        filename = 'fofa'
    targetfile = './result/{}.txt'.format(filename)
    outputfilename = "result.html"
    scan_command = ".\\afrog\\afrog.exe -T {} -o {}".format(
        targetfile, outputfilename)
    os.system(scan_command)
    print("\n扫面结果已经保存到reports/result.html中")

# 总入口函数


def main():
    global a, b, c, f
    parser = argparse.ArgumentParser(
        description='''
        \n 关联资产收集基于FOFA API --By zhizhuo \n
        \n 由于FOFA会员等级限制，普通会员最多100条，高级会员做多10000条 \n
        \n 程序默认下载api可获取最大数量 \n
        ''')
    parser.add_argument('-u', '-url', dest="url",
                        help='单个url关联资产收集，例如：baidu.com顶级域名', required=False)
    parser.add_argument('-uf', '--url-file', dest="url_file", nargs='?',
                        help='多个url关联资产收集，以文件形式存储,文件中的url格式为baidu.com顶级域名', required=False)
    parser.add_argument('-i', '-ip', dest="ip",
                        help='单个ip关联资产收集，例如：192.168.0.1', required=False)
    parser.add_argument('-if', '--ip-file', dest="ip_file", nargs='?',
                        help='多个ip关联资产收集，以文件形式存储,文件中的ip格式为192.168.0.1', required=False)
    parser.add_argument('-d', '-D', dest="detection", nargs='?', default='False',
                        help='检测通过FOFA获取到的资产存活状态', required=False)
    parser.add_argument('-s', '-S', dest="scan", nargs='?', default='False',
                        help='使用afrog对从fofa获取的资产进行扫描', required=False)
    parser.add_argument('-se', '--search', dest="search", nargs='?',
                        help='fofa语法查询，输入fofa的查询语句即可，程序会自动进行Base64加密', required=False)
    url_arg = parser.parse_args().url
    file_arg = parser.parse_args().url_file
    ip_arg = parser.parse_args().ip
    ip_file_arg = parser.parse_args().ip_file
    detection_arg = parser.parse_args().detection
    scan_arg = parser.parse_args().scan
    search_arg = parser.parse_args().search
    print('关联资产收集基于FOFA API --By zhizhuo \n由于FOFA会员等级限制，普通会员最多100条，高级会员做多10000条 \n程序默认下载api可获取最大数量')
    if url_arg is None and ip_arg is None and ip_file_arg is None and file_arg is None and search_arg is None:
        print('请使用命令-h查看使用命令')
        return
    print('开始资产收集')
    httpurl = open('./result/active_url.txt', 'a+', encoding='utf-8')
    vulurl = open('./result/vul_url.txt', 'a+', encoding='utf-8')
    vulurl.truncate(0)
    httpurl.truncate(0)
    httpurl.close()
    vulurl.close()
    with open('./result/active_url.txt', 'a+', encoding='utf-8') as fa:
        fa.write('网址\t网站标题\t站点状态\t是否使用cdn\t站点server信息')
        fa.write('\n')
    time_start = time.time()
    get_user_info(url_arg, file_arg, ip_arg, ip_file_arg, search_arg)
    time_end = time.time()
    time_total = time_end - time_start
    if detection_arg is None:
        time_start = time.time()
        Detection()
        time_end = time.time()
        time_total = time_end - time_start
        print('================================================')
        print("可访问站点个数：", a)
        print("404站点个数：", b)
        print("访问超时站点个数：", c)
        print("需要人工验证站点个数：", f)
        print("存活资产文件已写入到active_url.txt文件中")
        print("需要手工检测资产文件已写入到vul_url.txt文件中")
        print(f'总共用时{time_total}')
    else:
        pass
    if scan_arg is None:
        time_start = time.time()
        Scan()
        time_end = time.time()
        time_total = time_end - time_start
        print(f'总共用时{time_total}')
    else:
        pass


if __name__ == '__main__':
    main()
