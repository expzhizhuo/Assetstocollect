# /*
#  * @Author: zhizhuo 
#  * @Date: 2022-07-06 08:57:13
#  * @Last Modified by: zhizhuo
#  * @Last Modified time: 2022-07-14 20:03:18
#  */

import argparse
import base64
import os
import re
import warnings
import requests

requests.packages.urllib3.disable_warnings()
warnings.filterwarnings('ignore')
os.environ["TF_CPP_MIN_LOG_LEVEL"] = '1'

config = {
    'email': '',  # fofa的登录邮箱
    'key': '',  # fofa个人中心的key
    'size': '100',  # 默认是是普通会员，普通会员做多100条，高级会员10000条
    'base_url': 'https://fofa.info/api/v1/search/all',  # fofa api接口地址
    'user_url': 'https://fofa.info/api/v1/info/my',  # fofa 账户信息接口
}


def get_url_info(url_arg, file_arg):
    print('开始域名信息读取')
    totals = 0
    count = 0
    output_url = open('./result/fofa.txt', 'a+', encoding='utf-8')
    output_url.truncate(0)  # 对文件进行初始化操作
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
            'full':'true',
            'size': config['size'],
        }
        resp = requests.get(config['base_url'], data, timeout=60).json()
        print(url+'关联资产有{}个'.format(resp['size']))
        totals = totals + resp['size']
        if resp['size'] > config['size']:
            count = config['size']
        else:
            count = count + resp['size']
        if resp['size'] > 0:
            for key in range(0, int(len(resp['results']))):
                output_url.write(resp['results'][key][0])
                output_url.write('\n')
        else:
            output_url.write(url)
            output_url.write('\n')
    output_url.close()
    print('总共收集到{}个关联资产'.format(totals))
    print('已经写入{}个关联资产'.format(count))


def get_ip_info(ip_arg, ip_file_arg):
    print('开始ip信息读取')
    totals = 0
    count = 0
    output_ip = open('./result/fofa.txt', 'a+', encoding='utf-8')
    output_ip.truncate(0)  # 对文件进行初始化操作
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
        resp = requests.get(config['base_url'], data, timeout=60).json()
        print(url+'关联资产有{}个'.format(resp['size']))
        totals = totals + resp['size']
        if resp['size'] > config['size']:
            count = config['size']
        else:
            count = count+resp['size']
        if resp['size'] > 0:
            for key in range(0, int(len(resp['results']))):
                output_ip.write(resp['results'][key][0])
                output_ip.write('\n')
        else:
            output_ip.write(url)
            output_ip.write('\n')
    output_ip.close()
    print('总共收集到{}个关联资产'.format(totals))
    print('已经写入{}个关联资产'.format(count))
    print('结果已保存至result/fofa.txt中')


def get_user_info(url_arg, file_arg, ip_arg, ip_file_arg):
    print('开始检测fofa账户信息')
    data = {
        'email': config['email'],
        'key': config['key'],
    }
    resp = requests.get(config['user_url'], data, timeout=60).json()
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
    else:
        get_ip_info(ip_arg, ip_file_arg)

def Detection():
    print('================================================')
    print('开始资产存活检测')
    headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
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
    print('================================================')
    urlfile = open('./result/fofa.txt', encoding='utf-8')
    urllist = urlfile.read().splitlines()
    httpurl = open('./result/active_url.txt', 'a+', encoding='utf-8')
    vulurl = open('./result/vul_url.txt', 'a+', encoding='utf-8')
    vulurl.truncate(0)
    httpurl.truncate(0)
    for d in urllist:
        if 'http' in d:
            url = d
        else:
            url = 'http://'+str(d)
        print('开始检测：'+url)
        try:
            resp = requests.get(url, headers, timeout=5, verify=False)
            print('站点状态码：'+str(resp.status_code))
            if 'title' in resp.text or 'charset' in resp.text:
                title_type = re.findall('charset=(.*?)"', resp.text)
                title_type_or_url = re.findall('charset="(.*?)"', resp.text)
            else:
                title_type = []
                title_type_or_url = []
            if len(title_type) != 0 and (title_type[0] == 'gb2312' or (len(title_type_or_url) != 0 and title_type_or_url[0] == 'gb2312')):
                resp.encoding = "gb2312"
                title_list = re.findall(r'<title>(.*?)</title>', resp.text)
                # error_msg = re.findall(r'<h1>(.*?)</h1>', resp.text)
            else:
                resp.encoding = "utf-8"
                title_list = re.findall(r'<title>(.*?)</title>', resp.text)
                # error_msg = re.findall(r'<h1>(.*?)</h1>', resp.text)
            if len(title_list) == 0:
                title = ""
                print("未识别到title")
            else:
                title = str(title_list[0]).replace(
                    '\r', "").replace('\n', "").replace('\t', "")
                print("识别到title："+title)
            if resp.status_code == 404:
                b = b+1
                if 'Error' in resp.text or 'error' in resp.text or 'ERROR' in resp.text:
                    # if len(error_msg) > 0:
                    #     Error_msg = error_msg[0]
                    # else:
                    #     Error_msg = ""
                    httpurl.write(url)
                    httpurl.write('\n')
                else:
                    pass
            else:
                a = a+1
                httpurl.write(url)
                httpurl.write('\n')
        except Exception as e:
            if 'timeout' not in str(e):
                vulurl.write(url)
                vulurl.write('\n')
                f = f+1
                print('[+] 此站点需要人工确认')
            else:
                print('[+] 站点请求超时')
                c = c+1
            pass

    urlfile.close()
    httpurl.close()
    vulurl.close()

    print('================================================')
    print("可访问站点个数：", a)
    print("404站点个数：", b)
    print("访问超时站点个数：", c)
    print("需要人工验证站点个数：", f)
    print("存活资产文件已写入到active_url.txt文件中")
    print("需要手工检测资产文件已写入到vul_url.txt文件中")

def Scan():
    print('================================================')
    print('开始使用afrog进行资产漏洞扫描')
    print('================================================')
    targetfile= './result/active_url.txt'
    outputfilename="result.html"
    scan_command=".\\afrog\\afrog.exe -T {} -o {}".format(targetfile,outputfilename)
    os.system(scan_command)
    print("\n扫面结果已经保存到reports/result.html中")

def main():
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
    parser.add_argument('-d', '-D', dest="detection", nargs='?',default='False',
                        help='检测通过FOFA获取到的资产存活状态', required=False)
    parser.add_argument('-s', '-S', dest="scan", nargs='?',default='False',
                        help='使用afrog对从fofa获取的资产进行扫描', required=False)
    url_arg = parser.parse_args().url
    file_arg = parser.parse_args().url_file
    ip_arg = parser.parse_args().ip
    ip_file_arg = parser.parse_args().ip_file
    detection_arg = parser.parse_args().detection
    scan_arg = parser.parse_args().scan
    print('关联资产收集基于FOFA API --By zhizhuo \n由于FOFA会员等级限制，普通会员最多100条，高级会员做多10000条 \n程序默认下载api可获取最大数量')
    if url_arg is None and ip_arg is None and ip_file_arg is None and file_arg is None:
        print('请使用命令-h查看使用命令')
        return
    print('开始资产收集')
    get_user_info(url_arg, file_arg, ip_arg, ip_file_arg)
    if detection_arg is None:
        Detection()
    else:
        pass
    if scan_arg is None:
        Scan()
    else:
        pass
    print('================================================')


if __name__ == '__main__':
    main()
