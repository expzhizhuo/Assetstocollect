# /*
#  * @Author: zhizhuo
#  * @Date: 2022-07-06 08:57:13
#  * @Last Modified by:   zhizhuo
#  * @Last Modified time: 2022-07-06 08:57:13
#  */

import argparse
import base64
import requests


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
    output_url = open('./url_result.txt', 'a+', encoding='utf-8')
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
    output_ip = open('./ip_result.txt', 'a+', encoding='utf-8')
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

    url_arg = parser.parse_args().url
    file_arg = parser.parse_args().url_file
    ip_arg = parser.parse_args().ip
    ip_file_arg = parser.parse_args().ip_file

    print('关联资产收集基于FOFA API --By zhizhuo \n由于FOFA会员等级限制，普通会员最多100条，高级会员做多10000条 \n程序默认下载api可获取最大数量')
    print('开始资产收集')
    get_user_info(url_arg, file_arg, ip_arg, ip_file_arg)
    print('================================================')
    print('资产收集结束')


if __name__ == '__main__':
    main()
